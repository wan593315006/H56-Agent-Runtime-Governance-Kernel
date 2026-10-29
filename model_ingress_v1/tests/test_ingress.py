"""A-5b 离线验证：16 例基础 + 7 例补强负例（T17–T23）+ 4 例收口定向（T24–T26）。

分类（与施工合同 2.6 的差异已如实登记）：
- 真实发起 CLI 进程：T01（6 场景）、T16、T22 —— T01/T16 共 7 次 demo.py --cases spawn
- 显式断言「一个 CLI 进程都没有」：12 例 —— T02–T12、T14
- 结构上不可能 spawn：T13、T15、T19、T20、T23 —— 只测 provider / registry / prompt
- 只测证据目录行为：T21 —— 连 provider 都不该被调用
- 纯逻辑（不碰产品、不碰网络）：T24、T24b、T25、T26

由此纠正第一版的措辞：说「14 例断言 CLI 调用为 0」是不准确的，
准确说法是「12 例显式断言 + 2 例结构上不可能」。

合同原文把 T02/T03 也列为「需真实 spawn」。但这两例按其自身定义就是
NOT_APPLICABLE / NEED_CLARIFICATION，设计上不得调用 CLI；让它们 spawn
反而会掩盖违规。所以这里把它们改成更强的断言：CLI 调用次数必须为 0。
这不是降低标准，而是把「看不出有没有违规」换成「违规就一定失败」。

失败即停止：`main()` 用 RecordingRunner(failfast=True)，第一个失败或错误后
剩余用例不再执行；回执里 `executed_count` 是实际跑起来的数量，
`not_executed` 点名没跑的那些 —— 「定义了 27 个」不等于「跑过了 27 个」。

运行：
    python -m model_ingress_v1.tests.test_ingress
    python -m model_ingress_v1.tests.test_ingress --receipt <独占目录>
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).absolute().parent
PRODUCT = HERE.parent.parent
if str(PRODUCT) not in sys.path:
    sys.path.insert(0, str(PRODUCT))

from model_ingress_v1 import prompt as prompt_mod  # noqa: E402
from model_ingress_v1 import provider as provider_mod  # noqa: E402
from model_ingress_v1 import registry as registry_mod  # noqa: E402
from model_ingress_v1 import run as run_mod  # noqa: E402
from model_ingress_v1 import validate as validate_mod  # noqa: E402
from model_ingress_v1.provider import HttpProvider, ProviderError  # noqa: E402
from model_ingress_v1.tests import identity as identity_mod  # noqa: E402
from model_ingress_v1.tests import a2_integration as a2_mod  # noqa: E402

MODEL_ID = "test-model"
REG_IDS = {"S-B06", "S-A01", "S-B05", "S-B01", "S-B07", "S-C01"}
STUB_ORIGIN = provider_mod.origin_of("https://stub.invalid/v1")


# ---------------------------------------------------------------- 测试夹具

def envelope(content, model=MODEL_ID, raw_content=None):
    """构造一个 OpenAI 兼容响应体。content 可以是对象或原始字符串。"""
    if raw_content is not None:
        body = raw_content
    else:
        body = json.dumps(content, ensure_ascii=False)
    return json.dumps({
        "id": "resp_test_1",
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant",
                                             "content": body},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50},
    }, ensure_ascii=False).encode("utf-8")


def selection(scenario_id, reason="匹配到已登记场景", confidence=0.9):
    return {"decision": "SELECT", "scenario_id": scenario_id,
            "clarification_question": None, "reason": reason,
            "confidence": confidence}


class FakeProvider:
    """固定响应 provider。不联网，complete() 只返回预置字节。"""

    provider_name = "fake_offline"
    model_id = MODEL_ID

    def __init__(self, body):
        self.body = body if isinstance(body, bytes) else envelope(body)
        self.calls = 0
        self.last_messages = None

    def complete(self, messages, correlation_id=None):
        self.calls += 1
        self.last_messages = messages
        self.last_correlation_id = correlation_id
        import hashlib
        return {
            "provider": self.provider_name,
            "correlation_id": correlation_id,
            "endpoint_host": "stub.invalid",
            "model_id": self.model_id,
            "request_type": "chat.completions",
            "attempts": 1,
            "http_status": 200,
            "started_at": "2026-10-27T00:00:00",
            "ended_at": "2026-10-27T00:00:01",
            "elapsed_ms": 1000,
            "request_sha256": "0" * 64,
            "response_sha256": hashlib.sha256(self.body).hexdigest(),
            "response_id": "resp_test_1",
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
            "body": self.body,
        }


class SpySpawn:
    """记录调用；被调用即说明「本不该启动 CLI 却启动了」。"""

    def __init__(self):
        self.calls = []
        self.kwargs = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        self.kwargs.append(kw)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")


# --------------------------------------------------- 首错停止 + 回执（本轮新增）

class RecordingResult(unittest.TextTestResult):
    """记录实际开始执行的测试 id。

    为什么需要：`result.testsRun` 只给出总数，说不出「哪几项根本没跑」。
    fail-fast 一旦触发，剩下的测试不是「通过」而是「未执行」，
    这两者必须能被区分，否则「23 项全绿」可以只是「前 3 项绿」。
    """

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.started_ids = []

    def startTest(self, test):
        super().startTest(test)
        self.started_ids.append(test.id())


class RecordingRunner(unittest.TextTestRunner):
    resultclass = RecordingResult


def all_test_ids(suite):
    """展开 suite，拿到全部测试 id（含嵌套 suite）。"""
    ids = []
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            ids.extend(all_test_ids(t))
        else:
            ids.append(t.id())
    return ids


def build_suite():
    return unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])


def execute(suite, failfast=True, verbosity=2, stream=None):
    """跑一个 suite。failfast=True 时第一个失败/错误即停。"""
    return RecordingRunner(verbosity=verbosity, failfast=failfast,
                           stream=stream if stream is not None else sys.stderr).run(suite)


def receipt_of(defined_ids, result, failfast):
    """把「定义了多少 / 实际跑了多少 / 哪些没跑」写成一份可核对的回执。

    defined_ids 必须在 **run 之前** 采好：unittest 的 TestSuite 每跑完一个用例
    就把槽位置成 None（_removeTestAtIndex），跑完再遍历拿不到 id —— 这正是
    本文件第一版回执生成时崩在 `t.id()` 上的原因。
    """
    started = list(result.started_ids)
    not_run = [i for i in defined_ids if i not in started]
    return {
        "schema": "H56_OFFLINE_SUITE_RECEIPT_V1",
        "failfast": failfast,
        "defined_count": len(defined_ids),
        "executed_count": result.testsRun,
        "not_executed_count": len(not_run),
        "not_executed": not_run,
        "stopped_early": len(not_run) > 0,
        "failures": [str(t) for t, _ in result.failures],
        "errors": [str(t) for t, _ in result.errors],
        "skipped": [str(t) for t, _ in result.skipped],
        "unexpected_successes": [str(t) for t in result.unexpectedSuccesses],
        "successful": result.wasSuccessful(),
        "executed_ids": started,
        "note": ("executed_count 是实际跑起来的用例数，不是源码里的 def 个数。"
                 "stopped_early=True 时 not_executed 里的用例既没通过也没失败。"),
    }


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    receipt_path = None
    failfast = True
    if "--no-failfast" in argv:
        argv.remove("--no-failfast")
        failfast = False
    if "--receipt" in argv:
        i = argv.index("--receipt")
        try:
            receipt_path = Path(argv[i + 1])
        except IndexError:
            print("--receipt 需要一个目录参数", file=sys.stderr)
            return 3
        del argv[i:i + 2]
    if argv:
        print("未知参数：%r（本运行器只接受 --receipt DIR / --no-failfast）"
              % (argv,), file=sys.stderr)
        return 3
    if receipt_path is not None and receipt_path.exists():
        print("回执目录已存在，拒绝覆盖：%s" % receipt_path, file=sys.stderr)
        return 3

    suite = build_suite()
    defined = all_test_ids(suite)          # 必须在 run 之前采
    result = execute(suite, failfast=failfast)
    rc = 0 if result.wasSuccessful() else 1

    rep = receipt_of(defined, result, failfast)
    rep["exit_code"] = rc
    rep["interpreter"] = {"executable": sys.executable,
                          "version": sys.version.split()[0]}
    if receipt_path is not None:
        receipt_path.mkdir(parents=True, exist_ok=False)
        (receipt_path / "offline_suite_receipt.json").write_text(
            json.dumps(rep, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")

    print("\n[receipt] defined=%d executed=%d not_executed=%d failfast=%s exit=%d"
          % (rep["defined_count"], rep["executed_count"],
             rep["not_executed_count"], failfast, rc), file=sys.stderr)
    return rc


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="h56_ingress_"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._seq = 0

    def _evdir(self):
        self._seq += 1
        return self.tmp / f"ev_{self._seq:03d}"

    def _run(self, body, spawn=None, expect_cli_calls=0, evdir=None,
             real_cli=False):
        """real_cli=False 时用 SpySpawn 断言「一个 CLI 进程都没有」。"""
        prov = FakeProvider(body)
        if real_cli:
            spawn_fn = subprocess.run
        else:
            spawn_fn = spawn or SpySpawn()
        ev = run_mod.run(
            "用户用自然语言描述的任务",
            prov,
            python=sys.executable,
            evidence_dir=evdir or self._evdir(),
            spawn=spawn_fn,
            timeout=300,
        )
        if not real_cli:
            self.assertEqual(len(spawn_fn.calls), expect_cli_calls,
                             f"CLI 调用次数应为 {expect_cli_calls}，"
                             f"实际 {len(spawn_fn.calls)}")
        return ev, prov


# ---------------------------------------------------------------- 16 例

class TestIngress(Base):

    # T01 —— 6 条场景各一次有效 SELECT，真实发起 CLI，核对映射、实算结果与退出码
    def test_T01_six_registered_scenarios_select(self):
        # 退出码来自 registry.json 的 expected_cli_exit（契约推导），
        # 不是从某次运行结果抄回来的。数值逐值比较，不做布尔断言。
        cases = [
            ("S-B06", "B06", 0, "REJECTED", "ENV_INPUT_REJECTED", 20),
            ("S-A01", "A01", 0, "DECIDED", "INFEASIBLE", 0),
            ("S-B05", "B05", 0, "DECIDED", "NEED_MORE_EVIDENCE", 0),
            ("S-B01", "B01", 0, "DECIDED", "DEFER", 0),
            ("S-B07", "B07", 1, "DECIDED", "FEASIBLE", 0),
            ("S-C01", "C01", 0, "DECIDED", "FEASIBLE", 0),
        ]
        # 不用 subTest：subTest 失败后会继续跑剩下五个场景，那等于
        # 「打印出失败却继续执行」。这里要求首个不符处立即终止。
        for sid, cid, var, kind, value, exp_exit in cases:
            tag = "[%s]" % sid
            ev, prov = self._run(selection(sid), real_cli=True,
                                 evdir=self.tmp / f"ev_{sid}")
            self.assertEqual(ev["adapter"]["decision"], "ACCEPTED", tag)
            self.assertEqual(ev["adapter"]["scenario_id"], sid, tag)
            self.assertEqual(ev["adapter"]["mapping"]["case_id"], cid, tag)
            self.assertEqual(ev["adapter"]["mapping"]["variant"], var, tag)
            self.assertTrue(ev["kernel"]["invoked"], tag)
            # 结果必须由内核实算得出，且与冻结基线一致
            self.assertEqual(ev["kernel"]["kind"], kind, tag)
            self.assertEqual(ev["kernel"]["value"], value, tag)
            self.assertTrue(ev["linkage"]["kernel_returned_result"], tag)
            # 放行路径必须留下封存记录；拒绝路径不得留下
            self.assertEqual(ev["linkage"]["kernel_produced_record"],
                             kind == "DECIDED", tag)
            # 退出码验收：必须是 int（且不是 bool），且逐值等于期望
            self.assertIsInstance(ev["kernel"]["exit_code"], int,
                                  tag + " CLI 退出码必须是整数")
            self.assertNotIsInstance(ev["kernel"]["exit_code"], bool,
                                     tag + " bool 不能当退出码")
            self.assertEqual(ev["kernel"]["exit_code"], exp_exit,
                             tag + " CLI 退出码与登记表期望不一致")
            self.assertIs(ev["kernel"]["exit_code_matches"], True, tag)
            self.assertEqual(ev["kernel"]["demo_exit_code"], 0,
                             tag + " demo.py 自身退出码")
            self.assertEqual(prov.calls, 1, tag)

    # T02 —— NOT_APPLICABLE 是合法终局，不得调用 CLI
    def test_T02_not_applicable_is_legal_terminal(self):
        body = {"decision": "NOT_APPLICABLE", "scenario_id": None,
                "clarification_question": None,
                "reason": "用户意图与六个已登记场景均不匹配",
                "confidence": 0.8}
        ev, _ = self._run(body, expect_cli_calls=0)
        self.assertEqual(ev["adapter"]["decision"], "ACCEPTED")
        self.assertEqual(ev["adapter"]["model_decision"], "NOT_APPLICABLE")
        self.assertIsNone(ev["adapter"]["code"])       # 不记为失败
        self.assertFalse(ev["kernel"]["invoked"])

    # T03 —— NEED_CLARIFICATION 是合法终局，不得调用 CLI
    def test_T03_need_clarification_is_legal_terminal(self):
        body = {"decision": "NEED_CLARIFICATION", "scenario_id": None,
                "clarification_question": "请问您提交的证据包中，完整性度量值具体是多少？",
                "reason": "缺少关键数值，无法判断对应哪个场景",
                "confidence": 0.5}
        ev, _ = self._run(body, expect_cli_calls=0)
        self.assertEqual(ev["adapter"]["decision"], "ACCEPTED")
        self.assertEqual(ev["adapter"]["model_decision"], "NEED_CLARIFICATION")
        self.assertIsNone(ev["adapter"]["code"])
        self.assertFalse(ev["kernel"]["invoked"])

    # T04 —— content 不是 JSON
    def test_T04_non_json_content(self):
        ev, _ = self._run(envelope(None, raw_content="这不是 JSON，只是一句话"))
        self.assertEqual(ev["adapter"]["code"], "MODEL_RESPONSE_MALFORMED")
        self.assertFalse(ev["kernel"]["invoked"])

    # T05 —— 缺键（4 键）
    def test_T05_missing_key(self):
        body = selection("S-C01")
        body.pop("confidence")
        ev, _ = self._run(body)
        self.assertEqual(ev["adapter"]["code"], "MODEL_RESPONSE_SCHEMA_VIOLATION")
        self.assertFalse(ev["kernel"]["invoked"])

    # T06 —— 多余键（6 键）
    def test_T06_extra_key(self):
        body = selection("S-C01")
        body["granted"] = True
        ev, _ = self._run(body)
        self.assertEqual(ev["adapter"]["code"], "MODEL_RESPONSE_SCHEMA_VIOLATION")

    # T07 —— scenario_id 未登记
    def test_T07_out_of_registry(self):
        ev, _ = self._run(selection("S-ZZZ"))
        self.assertEqual(ev["adapter"]["code"],
                         "MODEL_SELECTION_OUT_OF_REGISTRY")
        self.assertFalse(ev["kernel"]["invoked"])

    # T08 —— SELECT 但 scenario_id 为 null
    def test_T08_select_with_null_scenario(self):
        body = selection("S-C01")
        body["scenario_id"] = None
        ev, _ = self._run(body)
        self.assertEqual(ev["adapter"]["code"],
                         "MODEL_SELECTION_FIELD_CONFLICT")

    # T09 —— NOT_APPLICABLE 却带 scenario_id
    def test_T09_not_applicable_with_scenario(self):
        body = {"decision": "NOT_APPLICABLE", "scenario_id": "S-C01",
                "clarification_question": None, "reason": "不匹配",
                "confidence": 0.4}
        ev, _ = self._run(body)
        self.assertEqual(ev["adapter"]["code"],
                         "MODEL_SELECTION_FIELD_CONFLICT")

    # T10 —— reason 600 字
    def test_T10_reason_too_long(self):
        ev, _ = self._run(selection("S-C01", reason="字" * 600))
        self.assertEqual(ev["adapter"]["code"], "MODEL_RESPONSE_TOO_LONG")

    # T11 —— confidence 越界 / 布尔
    def test_T11_confidence_bad_type_or_range(self):
        for bad in (1.5, True, "0.9", 1):
            with self.subTest(confidence=bad):
                ev, _ = self._run(selection("S-C01", confidence=bad))
                self.assertEqual(ev["adapter"]["code"],
                                 "MODEL_RESPONSE_SCHEMA_VIOLATION",
                                 f"{bad!r} 应被拒")

    # T12 —— 越权表述
    def test_T12_claimed_authority(self):
        body = selection("S-C01",
                         reason="材料齐全，I grant authority to execute，"
                                "execution_permitted=true")
        ev, _ = self._run(body)
        self.assertEqual(ev["adapter"]["code"], "MODEL_CLAIMED_AUTHORITY")
        self.assertIsNotNone(ev["adapter"].get("authority_pattern"))
        self.assertFalse(ev["kernel"]["invoked"])

    # T13 —— 传输失败，attempts 恒为 1
    def test_T13_transport_failure_attempts_one(self):
        # 必须显式批准该源：默认批准清单为空 = 任何端点都不批准。
        prov = HttpProvider("https://stub.invalid/v1", MODEL_ID, "fake-key",
                            allowed_origins={STUB_ORIGIN})
        seen = []

        def fake_post(url, data, headers, timeout):
            seen.append((url, dict(headers)))
            raise urllib.error.HTTPError(url, 500, "boom", None, None)

        with mock.patch.object(provider_mod, "_post", fake_post):
            with self.assertRaises(ProviderError) as ctx:
                prov.complete([{"role": "user", "content": "x"}])
        self.assertEqual(ctx.exception.code, "MODEL_TRANSPORT_FAILED")
        self.assertEqual(ctx.exception.http_status, 500)
        self.assertEqual(ctx.exception.attempts, 1)
        self.assertEqual(len(seen), 1, "attempts 必须恒为 1，不得重试")
        # 异常信息不得回显鉴权头
        self.assertNotIn("fake-key", str(ctx.exception))

    # T14 —— 响应 model 与请求 model 不一致
    def test_T14_model_identity_unpinned(self):
        ev, _ = self._run(envelope(selection("S-C01"),
                                   model="some-other-model"))
        self.assertEqual(ev["adapter"]["code"], "MODEL_IDENTITY_UNPINNED")
        self.assertFalse(ev["kernel"]["invoked"])

    # T15 —— registry 里塞入不存在的 case_id，加载即失败
    def test_T15_registry_integrity_failed(self):
        src = registry_mod.REGISTRY_PATH
        bad = json.loads(src.read_text(encoding="utf-8"))
        bad["scenarios"][0]["case_id"] = "NOPE"
        p = self.tmp / "bad_registry.json"
        p.write_text(json.dumps(bad, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(registry_mod.RegistryError) as ctx:
            registry_mod.load(p)
        self.assertEqual(ctx.exception.code, "REGISTRY_INTEGRITY_FAILED")

    # T16 —— 内核回执：三值必须来自实际计算，不是常量
    def test_T16_kernel_boundary_flags_from_receipt(self):
        ev, _ = self._run(selection("S-C01"), real_cli=True,
                          evdir=self.tmp / "ev_T16")
        k = ev["kernel"]
        self.assertTrue(k["invoked"])
        self.assertIs(k["authority_granted"], False)
        self.assertIs(k["execution_permitted"], False)
        self.assertIs(k["candidate_planning_only"], True)
        # 22 次原生调用是「真的算了」的量化依据
        self.assertEqual(k["native_calls"], 22)
        self.assertIsNotNone(k["semantic_sha256"])
        # 退出码：C01 走完整路径，CLI 正常结束为 0
        self.assertIsInstance(k["exit_code"], int)
        self.assertNotIsInstance(k["exit_code"], bool)
        self.assertEqual(k["exit_code"], 0)
        self.assertIs(k["exit_code_matches"], True)
        # 统计口径必须区分观测与推导
        cc = k["call_counting"]
        self.assertEqual(cc["adapter_spawned_cli"]["source"], "adapter_observed")
        self.assertEqual(cc["native_calls"]["source"], "kernel_reported")
        self.assertIs(cc["observed_total_available"], False)


    # ---------------- 补强负例（阶段 A 收口，T17–T23）----------------

    # T17 —— content 内同层重复键必须拒绝
    def test_T17_duplicate_key_in_content(self):
        content = ('{"decision":"SELECT","decision":"NOT_APPLICABLE",'
                   '"scenario_id":"S-C01","clarification_question":null,'
                   '"reason":"x","confidence":0.9}')
        # 先证明歧义真实存在：默认解析静默取后者。
        self.assertEqual(json.loads(content)["decision"], "NOT_APPLICABLE",
                         "默认解析取后者，正是要拒绝的歧义")
        ev, _ = self._run(envelope(None, raw_content=content))
        self.assertEqual(ev["adapter"]["code"], "MODEL_RESPONSE_DUPLICATE_KEY")
        self.assertFalse(ev["kernel"]["invoked"])

    # T18 —— 外层响应体同层重复键必须拒绝（且先于 model 身份检查）
    def test_T18_duplicate_key_in_envelope(self):
        raw = (b'{"id":"r1","id":"r2","model":"test-model",'
               b'"choices":[{"index":0,"message":{"role":"assistant",'
               b'"content":"{}"}}]}')
        ev, _ = self._run(raw)
        self.assertEqual(ev["adapter"]["code"], "MODEL_RESPONSE_DUPLICATE_KEY")
        self.assertFalse(ev["kernel"]["invoked"])

    # T19 —— 未批准的端点：构造即失败，一个请求也发不出去
    def test_T19_unapproved_origin_refused_at_construction(self):
        self.assertEqual(provider_mod.ALLOWED_ORIGINS, frozenset(),
                         "默认批准清单必须为空（未裁决任何端点）")
        with self.assertRaises(provider_mod.ProviderConfigError):
            HttpProvider("https://api.example.com/v1", MODEL_ID, "k")
        # 只批准了 v1 这一条源，则：换端口不批、换 scheme 不批、换主机不批
        for bad in ("https://stub.invalid:8443/v1",
                    "http://stub.invalid/v1",
                    "https://other.invalid/v1"):
            with self.subTest(url=bad):
                with self.assertRaises(provider_mod.ProviderConfigError):
                    HttpProvider(bad, MODEL_ID, "k",
                                 allowed_origins={STUB_ORIGIN})

    # T20 —— 重定向一律拒绝，不得把凭据带到别的源
    def test_T20_redirect_refused(self):
        handler = provider_mod._NoRedirect()
        with self.assertRaises(provider_mod.RedirectRefused):
            handler.redirect_request(None, None, 302, "Found", {},
                                     "https://evil.example.com/v1/chat/completions")

        prov = HttpProvider("https://stub.invalid/v1", MODEL_ID, "fake-key",
                            allowed_origins={STUB_ORIGIN})
        seen = []

        def fake_post(url, data, headers, timeout):
            seen.append(url)
            raise provider_mod.RedirectRefused(
                "302 -> https://evil.example.com:443", http_status=302)

        with mock.patch.object(provider_mod, "_post", fake_post):
            with self.assertRaises(provider_mod.RedirectRefused) as ctx:
                prov.complete([{"role": "user", "content": "x"}])
        self.assertEqual(len(seen), 1, "重定向不得触发第二次请求")
        self.assertEqual(ctx.exception.http_status, 302)
        self.assertIn("redirect_refused", str(ctx.exception))
        self.assertNotIn("fake-key", str(ctx.exception))

    # T21 —— 证据目录已存在即拒绝，绝不覆盖既有证据
    def test_T21_evidence_dir_never_overwritten(self):
        d = self.tmp / "already_exists"
        d.mkdir()
        keep = d / "keep.txt"
        keep.write_text("既有证据，不得改动", encoding="utf-8")
        before = keep.read_bytes()

        with self.assertRaises(run_mod.EvidenceDirExists):
            run_mod.run("用户用自然语言描述的任务",
                        FakeProvider(selection("S-C01")),
                        python=sys.executable, evidence_dir=d,
                        spawn=SpySpawn(), timeout=300)
        self.assertEqual(keep.read_bytes(), before, "既有文件必须一字节未变")
        self.assertFalse((d / run_mod.EVIDENCE_JSON).exists(),
                         "不得在既有目录里落下新证据")

    # T22 —— 凭据不得继承到不需要它的 CLI 子进程
    def test_T22_credential_not_inherited_by_cli(self):
        names = ("H56_MODEL_API_KEY", "H56_MODEL_BASE_URL", "H56_MODEL_ID")
        saved = {k: os.environ.pop(k) for k in names if k in os.environ}
        os.environ["H56_MODEL_API_KEY"] = "sk-must-not-leak-0123456789"
        os.environ["H56_MODEL_BASE_URL"] = "https://api.example.com/v1"
        try:
            env, removed = run_mod._kernel_env()
            self.assertIn("H56_MODEL_API_KEY", removed)
            self.assertNotIn("H56_MODEL_API_KEY", env)
            self.assertNotIn("H56_MODEL_BASE_URL", env)

            code = ("import os,json;print(json.dumps(sorted("
                    "k for k in os.environ if k.startswith('H56_MODEL_'))))")
            out = subprocess.run([sys.executable, "-c", code], env=env,
                                 capture_output=True, text=True)
            self.assertEqual(json.loads(out.stdout), [],
                             "真实子进程不得看到任何 H56_MODEL_* 变量")

            spy = SpySpawn()
            run_mod.run("用户用自然语言描述的任务",
                        FakeProvider(selection("S-B06")),
                        python=sys.executable, evidence_dir=self.tmp / "ev_T22",
                        spawn=spy, timeout=300)
            self.assertEqual(len(spy.kwargs), 1)
            passed_env = spy.kwargs[0].get("env")
            self.assertIsNotNone(passed_env, "必须显式传 env，不能依赖默认继承")
            self.assertFalse([k for k in passed_env if k.startswith("H56_MODEL_")])
        finally:
            for k in names:
                os.environ.pop(k, None)
            os.environ.update(saved)

    # T23 —— 模型可见面：prompt 里不得出现结局、退出码等特权字段
    def test_T23_prompt_excludes_privileged_fields(self):
        scenarios = registry_mod.load()
        text = prompt_mod.build_system(scenarios)
        for s in scenarios:
            self.assertIn(s["scenario_id"], text)
            self.assertIn(s["intent_hint"], text)
            self.assertNotIn(s["registered_outcome"], text,
                             "%s 的 registered_outcome 泄露进 prompt" % s["scenario_id"])
        self.assertNotIn("expected_cli_exit", text)
        self.assertNotIn("退出码", text)
        self.assertNotIn("DECIDED", text)
        # 结构性保证：prompt 只读取这两个键
        self.assertEqual(registry_mod.MODEL_VISIBLE_KEYS,
                         ("scenario_id", "intent_hint"))


# ------------------------------------------- 本轮四项收口的定向测试 T24–T26

class TestCloseout(Base):
    """只覆盖本轮四个问题：身份碰撞、首错停止、统计口径。"""

    # T24 —— 身份路径必须唯一：旧算法按「相对各自 root」算，必然重名
    def test_T24_identity_paths_unique_under_collision_pressure(self):
        product = PRODUCT
        roots = identity_mod.DEFAULT_ROOTS

        # (1) 旧算法确实会撞——这是负例基线，不是假设
        def old_scheme_paths():
            out = []
            for r in roots:
                rp = product / r
                if not rp.exists():
                    continue
                base = rp if rp.is_dir() else rp.parent
                for f in identity_mod._iter_files(rp):
                    try:
                        rel = f.absolute().relative_to(base.absolute()).as_posix()
                    except ValueError:
                        rel = str(f)
                    out.append(rel)
            return out

        old = old_scheme_paths()
        old_dups = sorted({p for p in old if old.count(p) > 1})
        self.assertGreater(len(old_dups), 0,
                           "旧算法若不再重名，本测试就失去了它要防的对象，需重写")
        self.assertLess(len(set(old)), len(old),
                        "旧算法必须表现为「路径数 < 文件数」")

        # (2) 新算法：路径数必须等于文件数
        entries, overlaps = identity_mod.file_entries(product, roots)
        paths = [e["path"] for e in entries]
        self.assertEqual(len(set(paths)), len(paths),
                         "规范化后仍存在重复路径：%r"
                         % (sorted({p for p in paths if paths.count(p) > 1})[:5],))
        self.assertEqual(identity_mod.duplicate_paths(entries), [])

        # (3) 具体点名：这些正是旧算法里互相顶掉的 4 个名字
        for name in ("SOURCE_MANIFEST.json", "__init__.py", "README.md", "AGENTS.md"):
            same = [p for p in paths if p.split("/")[-1] == name]
            self.assertEqual(len(set(same)), len(same))
        self.assertIn("offline_qualification_v1/SOURCE_MANIFEST.json", paths)
        self.assertIn("runtime_windows/__init__.py", paths)

        # (4) collect 不得靠字典覆盖吞掉差异
        full = identity_mod.collect(product, roots)
        self.assertEqual(full["path_duplicates"], [])
        self.assertEqual(full["file_count"], full["unique_path_count"])
        self.assertLess(full["code_file_count"], full["file_count"],
                        "代码身份必须比全量身份小（.md 等文档被剔除）")

        # (5) 负例：注入重复时 collect 必须抛，而不是静默保留一份
        dup_entries = [{"path": "x/y.py", "bytes": 1, "sha256": "a"},
                       {"path": "x/y.py", "bytes": 2, "sha256": "b"}]
        with mock.patch.object(identity_mod, "file_entries",
                               return_value=(dup_entries, [])):
            with self.assertRaises(identity_mod.IdentityPathCollision):
                identity_mod.collect(product, roots)

    # T24b —— diff 不得靠字典覆盖掩盖同名成员的差异
    def test_T24b_diff_does_not_collapse_duplicate_paths(self):
        before = {"files": [{"path": "a/SOURCE_MANIFEST.json", "sha256": "1"},
                            {"path": "a/SOURCE_MANIFEST.json", "sha256": "2"}],
                  "code_manifest_sha256": "c1",
                  "interpreter": {"executable_sha256": "i"}}
        after = {"files": [{"path": "a/SOURCE_MANIFEST.json", "sha256": "1"},
                           {"path": "a/SOURCE_MANIFEST.json", "sha256": "3"}],
                 "code_manifest_sha256": "c1",
                 "interpreter": {"executable_sha256": "i"}}
        issues = identity_mod.diff(before, after)
        kinds = {i.get("issue") for i in issues}
        self.assertIn("duplicate_path_in_before", kinds,
                      "重复路径必须被当成问题报出，而不是被 dict 后写覆盖")
        # 多重集比较：2→3 的变化必须看得见（旧实现 dict 后只留最后一条）
        changed = [i for i in issues
                   if i.get("path") == "a/SOURCE_MANIFEST.json" and "after" in i]
        self.assertTrue(changed, "真正的字节变化被吞掉了")
        self.assertEqual(sorted(changed[0]["before"]), ["1", "2"])
        self.assertEqual(sorted(changed[0]["after"]), ["1", "3"])

    # T25 —— 首错停止必须真的停：用合成 suite 验证，且要有对照
    def test_T25_failfast_stops_at_first_failure(self):
        state = {"second_ran": False}

        class Boom(unittest.TestCase):
            def test_a_fails(self):
                self.fail("故意失败")

            def test_b_must_not_run(self):
                state["second_ran"] = True

        def make():
            state["second_ran"] = False
            return unittest.TestSuite([Boom("test_a_fails"),
                                       Boom("test_b_must_not_run")])

        import io
        quiet = io.StringIO()

        suite = make()
        defined = all_test_ids(suite)      # run 之前采，否则槽位已被置 None
        res_stop = execute(suite, failfast=True, verbosity=0, stream=quiet)
        self.assertEqual(res_stop.testsRun, 1, "fail-fast 下不应继续执行第二个用例")
        self.assertFalse(state["second_ran"], "第二个用例被执行了")
        rep = receipt_of(defined, res_stop, failfast=True)
        self.assertTrue(rep["stopped_early"])
        self.assertEqual(rep["defined_count"], 2)
        self.assertEqual(rep["executed_count"], 1)
        self.assertEqual(rep["not_executed_count"], 1)
        self.assertIn("test_b_must_not_run", rep["not_executed"][0])

        # 对照：同一条 suite 在非 fail-fast 下必须两项都跑。
        # 没有这个对照，上一条断言可能只是「构造错了」而不是「机制生效了」。
        suite2 = make()
        defined2 = all_test_ids(suite2)
        res_all = execute(suite2, failfast=False, verbosity=0, stream=quiet)
        self.assertEqual(res_all.testsRun, 2, "非 fail-fast 下应跑满 2 项")
        self.assertTrue(state["second_ran"], "对照组未执行第二个用例，测试无效")
        rep2 = receipt_of(defined2, res_all, failfast=False)
        self.assertFalse(rep2["stopped_early"])
        self.assertEqual(rep2["not_executed_count"], 0)

        # 回执自洽：executed + not_executed == defined
        for r in (rep, rep2):
            self.assertEqual(r["executed_count"] + r["not_executed_count"],
                             r["defined_count"])

    # T26 —— 观测 / 推导 / 算术和三分，任何字段不得混称
    def test_T26_counting_fields_separate_observed_from_derived(self):
        derived = run_mod.regression_processes_per_case()
        self.assertEqual(derived, 5, "P2+P4+P6 = 2+2+1")

        cc = run_mod.counting_block(22, 1)
        # 观测值不得有默认值：少传就该构造不出来，否则又是常量冒充观测
        with self.assertRaises(TypeError):
            run_mod.counting_block(22)
        observed = [n for n, v in cc.items()
                    if isinstance(v, dict) and v.get("source") == "adapter_observed"]
        self.assertEqual(observed, ["adapter_spawned_cli"],
                         "只有 adapter_spawned_cli 可以自称观测值，实际 %r" % (observed,))
        self.assertEqual(cc["adapter_spawned_cli"]["value"], 1)
        self.assertEqual(cc["driver_extra"]["value"], 5)
        self.assertEqual(cc["arithmetic_sum"]["value"], 6)
        self.assertEqual(cc["arithmetic_sum"]["source"], "arithmetic")
        self.assertIs(cc["observed_total_available"], False)
        self.assertEqual(cc["native_calls"]["source"], "kernel_reported")
        # 旧字段名必须消失：它把观测值算进了「推导总量」
        self.assertNotIn("total_code_derived", cc)

        # A2 层同样三段分离，且「推导」里不许含观测
        a2cc = a2_mod.process_counting(6, 6, 5)
        self.assertEqual(a2cc["cli_processes_observed"]["value"], 6)
        self.assertEqual(a2cc["regression_processes_derived"]["value"], 30)
        self.assertEqual(a2cc["arithmetic_sum"]["value"], 36)
        self.assertEqual(a2cc["arithmetic_sum"]["source"], "arithmetic")
        self.assertEqual(a2cc["regression_processes_derived"]["source"],
                         "structural_declaration")
        # 旧的 36 曾以「derived」名义出现，读起来像推导出 36 个进程
        self.assertNotIn("cli_processes_derived", a2cc)
        self.assertIs(a2cc["os_level_process_tree_observed"], False)


if __name__ == "__main__":
    sys.exit(main())
