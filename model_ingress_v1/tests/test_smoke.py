"""非证据通道的定向测试：只证明「三段串联正确、失败也留痕、凭据不落盘」。

这些用例**不**证明任何授权、合规或预算约束——那是 stage_b 的职责。
它们只回答一个问题：把真实端点换成可替换的网络层之后，smoke 通道的每条
分支是否都按声明的退出码和落盘行为走完。
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from model_ingress_v1 import provider as provider_mod
from model_ingress_v1 import registry as registry_mod
from model_ingress_v1 import smoke

ORIGIN = "https://integrate.api.nvidia.com:443"
BASE_URL = "https://integrate.api.nvidia.com/v1"
MODEL = "nvidia/nemotron-test"
SCENARIO = "S-C01"
INTENT = "我想查询一下这个事项是否适用"


def envelope(content, model=MODEL):
    """构造一个 OpenAI 兼容的 200 响应体（bytes）。"""
    body = content if isinstance(content, str) else json.dumps(
        content, ensure_ascii=False)
    return json.dumps({
        "id": "resp_smoke",
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": body}}],
        "usage": {"prompt_tokens": 1200, "completion_tokens": 48},
    }, ensure_ascii=False).encode("utf-8")


def selection(sid=SCENARIO):
    return {"decision": "SELECT", "scenario_id": sid,
            "clarification_question": None, "reason": "匹配到已登记场景",
            "confidence": 0.9}


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def run_smoke(self, post_return=None, post_side_effect=None,
                  root="ev", key="k-secret"):
        seen = []

        def fake_post(url, data, headers, timeout):
            seen.append((url, data, dict(headers)))
            if post_side_effect is not None:
                raise post_side_effect
            return post_return

        with mock.patch.object(provider_mod, "_post", fake_post):
            res = smoke.run_smoke(BASE_URL, MODEL, key, ORIGIN,
                                  self.tmp / root, INTENT)
        return res, seen


class TestSmokeHappyPath(Base):
    def test_T1_accepted_call_lands_evidence_without_credential(self):
        res, seen = self.run_smoke(post_return=(200, envelope(selection()), {}))

        self.assertEqual(res["exit"], 0, res["meta"].get("error"))
        self.assertEqual(res["outcome"], "CALL_OK_VALIDATED")
        self.assertEqual(len(seen), 1, "只允许一次调用，不重试")
        self.assertEqual(seen[0][0], BASE_URL + "/chat/completions")
        self.assertEqual(seen[0][2]["Authorization"], "Bearer k-secret")

        d = self.tmp / "ev"
        for name in (smoke.META_FILE, smoke.REQUEST_FILE,
                     smoke.RAW_FILE, smoke.VERDICT_FILE):
            self.assertTrue((d / name).exists(), "%s 必须落盘" % name)

        meta = json.loads((d / smoke.META_FILE).read_text(encoding="utf-8"))
        self.assertEqual(meta["chain_mark"], "NOT_EVIDENCE_CHAIN")
        self.assertEqual(meta["outcome"], "CALL_OK_VALIDATED")
        self.assertEqual(meta["http_status"], 200)
        self.assertEqual(meta["endpoint"]["model_id"], MODEL)
        self.assertEqual(meta["endpoint"]["origin"], ORIGIN)
        self.assertEqual(meta["endpoint"]["attempts"], 1)
        self.assertEqual(meta["endpoint"]["redirects_followed"], 0)
        # 调试通道绝不调内核：调了只会产生与真实意图无关的假记录
        self.assertFalse(meta["kernel"]["invoked"])
        # usage 结构被真实记录下来（这是调试要确认的三件事之一）
        self.assertEqual(meta["usage"]["prompt_tokens"], 1200)
        self.assertTrue(meta["usage_field_present"])
        self.assertEqual(meta["validate"]["decision"], "ACCEPTED")

        # 凭据不得以任何形式进入证据目录
        blob = b"".join(p.read_bytes() for p in d.iterdir() if p.is_file())
        self.assertNotIn(b"k-secret", blob)
        self.assertNotIn(b"Bearer", blob)

    def test_T2_raw_response_bytes_are_preserved_verbatim(self):
        raw = envelope(selection())
        self.run_smoke(post_return=(200, raw, {}))
        got = (self.tmp / "ev" / smoke.RAW_FILE).read_bytes()
        self.assertEqual(got, raw, "原始响应必须逐字节保留")
        meta = json.loads((self.tmp / "ev" / smoke.META_FILE)
                          .read_text(encoding="utf-8"))
        import hashlib
        self.assertEqual(meta["response_raw"]["sha256"],
                         hashlib.sha256(raw).hexdigest())

    def test_T3_request_body_is_the_byte_string_actually_sent(self):
        res, seen = self.run_smoke(post_return=(200, envelope(selection()), {}))
        sent = seen[0][1]
        kept = (self.tmp / "ev" / smoke.REQUEST_FILE).read_bytes()
        self.assertEqual(kept, sent, "落盘的请求体必须就是发出去的那份字节")
        payload = json.loads(kept.decode("utf-8"))
        self.assertEqual(payload["model"], MODEL)
        self.assertEqual(payload["temperature"], 0)
        self.assertFalse(payload["stream"])
        import hashlib
        self.assertEqual(res["meta"]["request_body"]["sha256"],
                         hashlib.sha256(sent).hexdigest())


class TestSmokeRejections(Base):
    def test_T4_validation_rejected_still_keeps_raw_and_exits_2(self):
        # 模型回了不合规内容：调用成功，但校验不过 -> exit 2，原始响应仍留档
        res, _ = self.run_smoke(post_return=(200, envelope("我觉得可以放行"), {}))
        self.assertEqual(res["exit"], 2)
        self.assertEqual(res["outcome"], "CALL_OK_REJECTED")
        self.assertTrue((self.tmp / "ev" / smoke.RAW_FILE).exists())
        d = json.loads((self.tmp / "ev" / smoke.VERDICT_FILE)
                       .read_text(encoding="utf-8"))
        self.assertNotEqual(d["decision"], "ACCEPTED")

    def test_T5_unregistered_scenario_is_rejected(self):
        res, _ = self.run_smoke(
            post_return=(200, envelope(selection(sid="S-ZZZ")), {}))
        self.assertEqual(res["exit"], 2)
        self.assertNotEqual(res["verdict"]["decision"], "ACCEPTED")

    def test_T6_http_401_preserves_body_and_exits_4(self):
        err = provider_mod.ProviderError(
            "HTTP 401", http_status=401, raw=b'{"error":"bad key"}',
            request_body=b'{"model":"x"}', origin=ORIGIN)
        res, _ = self.run_smoke(post_side_effect=err)
        self.assertEqual(res["exit"], 4)
        self.assertEqual(res["outcome"], "TRANSPORT_FAILED")
        d = self.tmp / "ev"
        self.assertEqual((d / smoke.RAW_FILE).read_bytes(),
                         b'{"error":"bad key"}')
        self.assertIn(b"model", (d / smoke.REQUEST_FILE).read_bytes())
        meta = json.loads((d / smoke.META_FILE).read_text(encoding="utf-8"))
        self.assertEqual(meta["error"]["http_status"], 401)
        self.assertEqual(meta["chain_mark"], "NOT_EVIDENCE_CHAIN")

    def test_T7_existing_dir_is_refused(self):
        (self.tmp / "ev").mkdir()
        with self.assertRaises(RuntimeError):
            self.run_smoke(post_return=(200, envelope(selection()), {}))
        self.assertEqual(list((self.tmp / "ev").iterdir()), [],
                         "拒绝时不得写入任何文件")


class TestSmokeCli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def main(self, *argv, env=None):
        with mock.patch.dict("os.environ", env or {}, clear=True):
            return smoke.main(list(argv))

    def test_T8_requires_execute_switch(self):
        self.assertEqual(self.main("--origin", ORIGIN), 3)

    def test_T9_origin_must_match_base_url(self):
        rc = self.main("--execute", "--origin", "https://evil.example:443",
                       "--base-url", BASE_URL, "--model-id", MODEL,
                       "--root", str(self.tmp / "ev"),
                       env={"NEBIUS_API_KEY": "k"})
        self.assertEqual(rc, 4)
        self.assertFalse((self.tmp / "ev").exists())

    def test_T10_missing_key_exits_4_without_creating_dir(self):
        rc = self.main("--execute", "--origin", ORIGIN, "--base-url", BASE_URL,
                       "--model-id", MODEL, "--root", str(self.tmp / "ev"),
                       env={})
        self.assertEqual(rc, 4)
        self.assertFalse((self.tmp / "ev").exists())

    def test_T11_key_env_switch_works(self):
        # 变量名可切：NEBIUS_API_KEY 空、NVIDIA_API_KEY 有值时应能取到
        with mock.patch.object(provider_mod, "_post",
                               lambda *a, **k: (200, envelope(selection()), {})):
            rc = self.main("--execute", "--origin", ORIGIN, "--base-url", BASE_URL,
                           "--model-id", MODEL, "--root", str(self.tmp / "ev"),
                           "--key-env", "NVIDIA_API_KEY",
                           env={"NVIDIA_API_KEY": "k-nv"})
        self.assertEqual(rc, 0)
        meta = json.loads((self.tmp / "ev" / smoke.META_FILE)
                          .read_text(encoding="utf-8"))
        self.assertEqual(meta["credential"]["env_var_name"], "NVIDIA_API_KEY")
        self.assertFalse(meta["credential"]["recorded"])

    def test_T12_missing_required_flags_exit_3(self):
        self.assertEqual(self.main("--execute", "--origin", ORIGIN), 3)
        self.assertEqual(self.main("--execute", "--origin", ORIGIN,
                                   "--base-url", BASE_URL), 3)

    def test_T13_intent_falls_back_to_plan_R1(self):
        # 不给 --intent 时借用计划里 R1 的 intent_text，保证调的是真实意图
        from model_ingress_v1 import stage_b
        plan = stage_b.load_plan()
        r1 = [r for r in plan["requests"] if r["request_id"] == "R1"][0]
        with mock.patch.object(provider_mod, "_post",
                               lambda *a, **k: (200, envelope(selection()), {})):
            rc = self.main("--execute", "--origin", ORIGIN, "--base-url", BASE_URL,
                           "--model-id", MODEL, "--root", str(self.tmp / "ev"),
                           env={"NEBIUS_API_KEY": "k"})
        self.assertEqual(rc, 0)
        meta = json.loads((self.tmp / "ev" / smoke.META_FILE)
                          .read_text(encoding="utf-8"))
        import hashlib
        self.assertEqual(meta["prompt"]["intent_sha256"],
                         hashlib.sha256(r1["intent_text"].encode("utf-8"))
                         .hexdigest())


class TestRequestConfigAlignment(Base):
    """请求配置必须与正式阶段 B 同源：少发一个键就不是同一次请求。"""

    def run_smoke(self, **kw):
        seen = []

        def fake_post(url, data, headers, timeout):
            seen.append(data)
            return 200, envelope(selection()), {}

        with mock.patch.object(provider_mod, "_post", fake_post):
            res = smoke.run_smoke(BASE_URL, MODEL, "k-secret", ORIGIN,
                                  self.tmp / "ev", INTENT, **kw)
        return res, (json.loads(seen[0].decode("utf-8")) if seen else None)

    def test_T17_thinking_switch_is_really_sent_when_declared(self):
        res, sent = self.run_smoke(enable_thinking=False, max_tokens=400)
        self.assertEqual(res["exit"], 0, res["meta"].get("error"))
        self.assertEqual(sent["chat_template_kwargs"], {"enable_thinking": False},
                         "阶段 B 会发这个键，调试通道必须发同一个键")
        self.assertEqual(sent["max_tokens"], 400)
        cfg = res["meta"]["request_config"]
        self.assertIs(cfg["enable_thinking"], False)
        self.assertTrue(cfg["thinking_param"]["sent_in_request"])
        # 调用方自己给的配置，没有计划参照可比 -> None，不能假装「一致」
        self.assertIsNone(cfg["matches_stage_b"])
        self.assertTrue(any("不进入" in d or "四核" in d
                            for d in cfg["residual_differences_vs_stage_b"]))

    def test_T18_omitting_thinking_changes_the_request_body(self):
        # 反证：不传 enable_thinking 时请求体确实少一个键 —— 这正是本轮要修的地方。
        res, sent = self.run_smoke()
        self.assertNotIn("chat_template_kwargs", sent)
        self.assertIsNone(res["meta"]["request_config"]["enable_thinking"])
        self.assertFalse(res["meta"]["request_config"]["thinking_param"]
                         ["sent_in_request"])

    def test_T19_main_derives_config_from_the_same_plan_source(self):
        # 走 main()：enable_thinking / max_tokens 取自计划（params + R1），
        # 并逐项与「阶段 B 对 R1 会发什么」比较。
        from model_ingress_v1 import stage_b
        plan = stage_b.load_plan()
        r1 = [r for r in plan["requests"] if r["request_id"] == "R1"][0]
        sent = {}

        def fake_post(url, data, headers, timeout):
            sent.update(json.loads(data.decode("utf-8")))
            return 200, envelope(selection()), {}

        with mock.patch.object(provider_mod, "_post", fake_post):
            with mock.patch.dict("os.environ", {"NEBIUS_API_KEY": "k"},
                                 clear=True):
                rc = smoke.main(["--execute", "--origin", ORIGIN,
                                 "--base-url", BASE_URL, "--model-id", MODEL,
                                 "--root", str(self.tmp / "ev")])
        self.assertEqual(rc, 0)
        meta = json.loads((self.tmp / "ev" / smoke.META_FILE)
                          .read_text(encoding="utf-8"))
        cfg = meta["request_config"]
        self.assertEqual(cfg["enable_thinking"],
                         plan["params"]["enable_thinking"])
        self.assertEqual(cfg["max_tokens"], r1["max_output_tokens"])
        self.assertIs(cfg["matches_stage_b"], True)
        self.assertEqual(sent["chat_template_kwargs"],
                         {"enable_thinking": plan["params"]["enable_thinking"]})


class TestKeyEnvSwitchOnOfficialPath(unittest.TestCase):
    """密钥变量名可切，但「必须有值」这条不放松。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_T14_preflight_reports_the_switched_var_name(self):
        from model_ingress_v1 import stage_b
        plan = stage_b.load_plan()
        try:
            stage_b.preflight(plan, plan["model"]["endpoint"]["origin"],
                              environ={}, approved_requests=["R1"])
            self.fail("应当被拒绝")
        except stage_b.StageBError as exc:
            self.assertIn("NEBIUS_API_KEY", str(exc),
                          "默认仍报原变量名，行为不变")

    def test_T15_switched_var_name_appears_in_blocker_text(self):
        from model_ingress_v1 import stage_b
        plan = stage_b.load_plan()
        try:
            stage_b.preflight(plan, plan["model"]["endpoint"]["origin"],
                              environ={}, approved_requests=["R1"],
                              key_env="NVIDIA_API_KEY")
            self.fail("应当被拒绝")
        except stage_b.StageBError as exc:
            self.assertIn("NVIDIA_API_KEY", str(exc),
                          "切了变量名，阻断项必须如实报新名字")

    def test_T16_empty_switched_var_still_blocks(self):
        from model_ingress_v1 import stage_b
        plan = stage_b.load_plan()
        try:
            stage_b.preflight(plan, plan["model"]["endpoint"]["origin"],
                              environ={"NVIDIA_API_KEY": ""},
                              approved_requests=["R1"],
                              key_env="NVIDIA_API_KEY")
            self.fail("空值也必须有值才算通过")
        except stage_b.StageBError as exc:
            self.assertIn("credential.present", str(exc))


if __name__ == "__main__":
    unittest.main()
