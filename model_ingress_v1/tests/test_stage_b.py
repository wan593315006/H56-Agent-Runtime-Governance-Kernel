"""阶段 B 离线验证：请求体、计划文件、统一闸门、执行范围、目录来源、预算、R7 负对照、取证。

**证明范围先于证明内容。** 本套件零网络、零真实内核启动：所有「没有发生」都是在某个
被替换的函数上观测到的。三个缝隙，结论只能各自在自己的缝隙上成立：

  缝隙   怎么断开                                  结论的准确含义
  ------------------------------------------------------------------------------
  网络   provider._post / _get_once 换成记录器     「没发请求」= 没调用网络函数。
                                                    不是「没建 TCP 连接」。本套件
                                                    无抓包、无代理日志，**不得**
                                                    宣称「观测到零流量」。
  内核   execute(spawn=, run=) 或 run.py 的 spawn  「内核零调用」= 没有调用 spawn。
         换成记录器                                 不是 OS 级进程树观测。
  文件   证据目录建在 tempfile 下                   「没有产物」= 该路径下不存在。

为什么这些必须在真实调用之前跑完：
真有 7 次额度时，任何一个"本可离线发现"的错误都要用预算去买。请求体构造、
预算算术、闸门逻辑、执行范围、停止条件全部可以在本地用固定字节验证，所以先验证。

七条必须由具名用例承担的事（对应每个用例的 PROOF 行）：
  P1 未获授权不越过网络函数              -> S11 / S16 / S36
  P2 目录证据不匹配不构造推理请求         -> S17 / S18 / S19 / S1A / S1B / S1G–S1J
  P3 超出请求或费用预算不再调用网络函数   -> S50 / S51 / S53 / S53c / S39
  P4 R7 错误 SELECT 不触发 spawn（真实 run.py） -> S38 / S32
  P5 HTTP 错误仍保留脱敏请求证据          -> S25 / S27 / S27b
  P6 请求与响应字节在本地可独立重算       -> S26 / S28 / S2D
  P7 执行范围只覆盖获准 id                -> S41–S47

运行：
    python -m unittest model_ingress_v1.tests.test_stage_b -v
"""

import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).absolute().parent.parent.parent
sys.path.insert(0, str(ROOT))

from model_ingress_v1 import catalog as catalog_mod  # noqa: E402
from model_ingress_v1 import provider as provider_mod  # noqa: E402
from model_ingress_v1 import registry as registry_mod  # noqa: E402
from model_ingress_v1 import stage_b  # noqa: E402
from model_ingress_v1.provider import HttpProvider, ProviderConfigError  # noqa: E402
from model_ingress_v1.tests.a2_integration import MOCK_INTENT  # noqa: E402

MODEL_ID = "nvidia/Test-Nano-For-Offline-Only"
STUB_URL = "https://stub.invalid/v1"
STUB_ORIGIN = provider_mod.origin_of(STUB_URL)

# 目录里 Nebius 这类端点给的是「每 token」的价格；计划里写的是「每 1M token」。
# 故意用每 token 写法，好让归一化逻辑每次都真的被执行到。
CATALOG_PRICING = {"prompt": "0.00000006", "completion": "0.00000024"}
RULING_TEXT = "同意四项定点修复，并同意一次具名目录查询与 R1 首次真实请求（离线夹具）。"


def catalog_raw(model_id=MODEL_ID, pricing=None, extra_ids=()):
    pricing = pricing or CATALOG_PRICING
    ids = [model_id] + list(extra_ids)
    data = {
        "object": "list",
        "data": [{
            "id": i,
            "context_length": 131072,
            "supported_features": ["chat", "tools"],
            "pricing": {"prompt": pricing["prompt"],
                        "completion": pricing["completion"]},
        } for i in ids],
    }
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def catalog_raw_no_pricing(model_id=MODEL_ID):
    """DeepSeek 形态：模型条目存在，但**完全没有** pricing 字段。

    这是降级档唯一合法的前提。注意它与"有价格"在结构上是两件事，不能靠
    "三项检查失败"间接推断 —— 有价但不一致时那三项同样会失败。
    """
    data = {
        "object": "list",
        "data": [{
            "id": model_id,
            "context_length": 1048576,
            "supported_features": ["chat"],
        }],
    }
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def write_catalog(dirpath, raw=None, status=200, declared_sha=None,
                  raw_file_name=None, source=None, url_sha256=None):
    """造一份目录证据。raw 才是真凭据 —— verify() 只从它重新解析。

    source 覆盖来源字段（origin/method/path/query/url），用于负例：
    内容对得上但"不是这次获准的 GET"，必须被 catalog.request_source 拦下。
    """
    d = Path(dirpath)
    d.mkdir(parents=True, exist_ok=True)
    raw = catalog_raw() if raw is None else raw
    name = raw_file_name or catalog_mod.RAW_FILE
    (d / name).write_bytes(raw)
    try:
        ids = [m.get("id") for m in json.loads(raw.decode("utf-8")).get("data") or []]
    except Exception:
        ids = []
    # 默认来源 = 由真实计划派生（origin / 路径 / 查询参数 / 完整 URL）
    want = catalog_mod.expected_request_of(stage_b.load_plan())
    src = dict(want)
    src.update(source or {})
    ev = {
        "schema": catalog_mod.CATALOG_SCHEMA,
        "retrieved_at": "2026-10-27T14:00:00",
        "endpoint_origin": src.get("origin"),
        "request_method": src.get("method"),
        "request_path": src.get("path"),
        "request_query": src.get("query"),
        "request_url": src.get("url"),
        # url_sha256 可被显式覆盖，用来造"改了 URL 但没更新摘要"的负例。
        "request_url_sha256": url_sha256 or hashlib.sha256(
            str(src.get("url")).encode("utf-8")).hexdigest(),
        "http_status": status,
        "attempts": 1,
        "redirects_followed": 0,
        "credential_recorded": False,
        "raw_file": name,
        "raw_bytes": len(raw),
        "raw_sha256": declared_sha or hashlib.sha256(raw).hexdigest(),
        "model_count": len(ids),
        "model_ids": ids,
    }
    p = d / catalog_mod.EVIDENCE_FILE
    p.write_text(json.dumps(ev, ensure_ascii=False), encoding="utf-8")
    return p


ALL_IDS = ["R1", "R2", "R3", "R4", "R5", "R6", "R7"]


def granted_plan(catalog_path=None, scope=None):
    """把真实计划复制一份并"完成"全部前置项，只用于测闸门之后的执行逻辑。

    每一项都必须**同时**与派生结果一致：这正是新闸门的要求 ——
    只改一个布尔值不会让检查通过。

    scope：本轮获准执行的请求集合。默认给全部 7 条（好让"跑七条"的用例可测）；
    真实计划文件里是 ["R1"] —— 测试里的宽范围**不会**写回文件。
    `test_S43_real_plan_scope_is_r1_only` 专门守住这一点。
    """
    plan = copy.deepcopy(stage_b.load_plan())
    plan["authorization"].update({
        "state": "GRANTED",
        "granted_by": "Human Controller",
        "granted_at": "2026-10-27T14:00:00",
        "ruling_text": RULING_TEXT,
        "ruling_sha256": hashlib.sha256(RULING_TEXT.encode("utf-8")).hexdigest(),
    })
    plan["model"]["model_id_expected"] = MODEL_ID
    plan["model"]["model_id_confirmed"] = MODEL_ID
    plan["model"]["pricing"]["verified_against_catalog"] = True
    plan["model"]["model_id_verification"]["state"] = "VERIFIED"
    plan["model"]["confirmation"]["evidence_file"] = (
        str(catalog_path) if catalog_path else None)
    plan["execution_scope"]["approved_request_ids"] = (
        list(scope) if scope is not None else list(ALL_IDS))
    plan["execution_scope"]["approved_count"] = len(
        plan["execution_scope"]["approved_request_ids"])
    plan["execution_gate"]["ready"] = True
    plan["execution_gate"]["blocking"] = []
    return plan


def envelope(content, model=MODEL_ID):
    """content 可以是对象或原始字符串；对象要变成**字符串**放进 message.content。"""
    body = content if isinstance(content, str) else json.dumps(
        content, ensure_ascii=False)
    return json.dumps({
        "id": "resp_1",
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": body}}],
        "usage": {"prompt_tokens": 1100, "completion_tokens": 60},
    }, ensure_ascii=False).encode("utf-8")


def selection(scenario_id, reason="匹配到已登记场景", confidence=0.9):
    return {"decision": "SELECT", "scenario_id": scenario_id,
            "clarification_question": None, "reason": reason,
            "confidence": confidence}


def ok_evidence(decision="ACCEPTED", model_decision="SELECT", sid="S-C01",
                invoked=True, exit_code=0, kind="DECIDED", value="FEASIBLE",
                outcome="SELECT_KERNEL_EXECUTED", usage=None):
    return {
        "call": {"http_status": 200, "attempts": 1,
                 "provider_impl": {"impl":
                                   "model_ingress_v1.provider.HttpProvider",
                                   "in_product_tree": True},
                 "usage": usage if usage is not None else {
                     "prompt_tokens": 1100, "completion_tokens": 60}},
        "adapter": {"decision": decision, "code": None,
                    "model_decision": model_decision, "scenario_id": sid,
                    "outcome": outcome},
        "kernel": {"invoked": invoked, "exit_code": exit_code,
                   "kind": kind, "value": value,
                   "suppressed_by_contract": False},
    }


# patch 之前先抓住真实的 run()：否则 fake_run 里再调 run_mod.run 会调到自己。
_REAL_RUN = stage_b.run_mod.run


class _SelectProvider:
    """固定返回合法 SELECT 的 provider。用来验证 R7 的止损路径。"""

    provider_name = "offline_select_stub"
    model_id = MODEL_ID

    def __init__(self, body):
        self.body = body if isinstance(body, bytes) else envelope(body)
        self.calls = 0

    def complete(self, messages, correlation_id=None):
        self.calls += 1
        self.last_correlation_id = correlation_id
        return {
            "provider": self.provider_name, "correlation_id": correlation_id,
            "endpoint_host": "stub.invalid", "model_id": self.model_id,
            "request_type": "chat.completions", "attempts": 1, "http_status": 200,
            "request_sha256": "0" * 64,
            "response_sha256": hashlib.sha256(self.body).hexdigest(),
            "response_id": "stub_1",
            "usage": {"prompt_tokens": 1100, "completion_tokens": 60},
            "body": self.body,
        }


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="h56_stageb_"))
        self.cat = write_catalog(self.tmp / "catalog")
        self.env = {stage_b.KEY_ENV: "offline-placeholder"}
        self.origin = stage_b.load_plan()["model"]["endpoint"]["origin"]
        self.all_ids = list(ALL_IDS)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def plan(self, scope=None, **over):
        p = granted_plan(self.cat, scope=scope)
        for path, value in over.items():
            node = p
            keys = path.split(".")
            for k in keys[:-1]:
                node = node[k]
            node[keys[-1]] = value
        return p

    def scope_of(self, plan):
        """命令行要再写一遍的那个集合，从计划里取 —— 保持两处一致。"""
        return list(plan["execution_scope"]["approved_request_ids"])

    def _run(self, plan, patch_run=None, post=None, root=None, approved=None, **kw):
        """跑一次 execute。patch_run 时替换 run()，否则替换 provider._post。"""
        args = dict(python=sys.executable, environ=self.env, verbose=False,
                    approved_origin=self.origin,
                    approved_requests=(self.scope_of(plan) if approved is None
                                       else approved))
        args.update(kw)
        target = (mock.patch.object(stage_b.run_mod, "run", new=patch_run)
                  if patch_run is not None
                  else mock.patch.object(provider_mod, "_post", side_effect=post))
        with target:
            return stage_b.execute(plan, root or (self.tmp / "ev"), **args)


class TestPlanFile(unittest.TestCase):
    """计划文件本身：静态一致性，一分钱不花就能查。"""

    def setUp(self):
        self.plan = stage_b.load_plan()

    def test_S01_plan_static_validation_clean(self):
        self.assertEqual(stage_b.validate_plan(self.plan), [])

    def test_S02_plan_is_not_self_authorized(self):
        # 这条是防呆：计划文件不得自己变成"已批准"。
        self.assertEqual(self.plan["authorization"]["state"], "NOT_GRANTED")
        self.assertEqual(self.plan["status"], "AWAITING_HUMAN_RULING")
        self.assertFalse(self.plan["execution_gate"]["ready"])
        self.assertIsNone(self.plan["model"]["model_id_confirmed"])
        self.assertFalse(self.plan["model"]["pricing"]["verified_against_catalog"])
        # 新增三项：授权原文未绑定、目录证据未取得、模型身份未派生
        self.assertIsNone(self.plan["authorization"]["ruling_text"])
        self.assertIsNone(self.plan["authorization"]["ruling_sha256"])
        self.assertIsNone(self.plan["model"]["confirmation"]["evidence_file"])
        self.assertEqual(
            self.plan["model"]["model_id_verification"]["state"], "UNVERIFIED")

    def test_S03_seven_requests_cover_six_scenarios_plus_one_control(self):
        reqs = self.plan["requests"]
        self.assertEqual([r["request_id"] for r in reqs],
                         ["R1", "R2", "R3", "R4", "R5", "R6", "R7"])
        covered = [r["scenario_id"] for r in reqs if r["scenario_id"]]
        self.assertEqual(len(covered), 6)
        self.assertEqual(set(covered), set(registry_mod.ids()))
        self.assertIsNone(reqs[6]["scenario_id"], "R7 必须是域外对照，不能占场景名额")

    def test_S04_r1_to_r6_intents_are_byte_identical_to_a2_mock(self):
        # 同一输入，两个产出方（固定 Mock / 真实模型），才谈得上"差异来自模型"。
        for r in self.plan["requests"][:6]:
            self.assertEqual(r["intent_text"], MOCK_INTENT[r["scenario_id"]],
                             "%s 的意图文本与 A2 不一致，比较基准就变了"
                             % r["request_id"])

    def test_S05_budget_arithmetic(self):
        b = self.plan["budget"]
        total = sum(r["budget_usd_estimate"] for r in self.plan["requests"])
        self.assertAlmostEqual(total, b["estimated_usd_at_expected_prompt"], places=9)
        self.assertLess(total, b["max_total_usd"])
        # 最坏值必须按声明的上限顶格算，不能拿预估当最坏值
        caps = 7 * (2000 / 1e6 * 0.06 + 400 / 1e6 * 0.24)
        self.assertAlmostEqual(b["worst_case_usd_at_declared_caps"], caps, places=8)
        self.assertGreater(b["worst_case_usd_at_declared_caps"],
                           b["estimated_usd_at_expected_prompt"],
                           "最坏值必须大于预估，否则说明两个口径被混用了")
        self.assertFalse(b["retry_allowed"])
        self.assertEqual(b["max_inference_requests"], 7)
        self.assertEqual(b["max_catalog_queries"], 1)
        self.assertEqual(b["max_input_tokens_per_request"], 2000)
        self.assertEqual(b["max_output_tokens_per_request"], 400)

    def test_S06_every_request_is_stoppable_and_carries_its_own_purpose(self):
        for r in self.plan["requests"]:
            self.assertGreaterEqual(len(r["stop_conditions"]), 5, r["request_id"])
            self.assertEqual(r["retry"], 0, r["request_id"])
            self.assertEqual(r["on_failure"], "stop_and_report", r["request_id"])
            self.assertTrue(r["purpose"].strip(), r["request_id"])

    def test_S07_stage_a_closure_is_named_not_implied(self):
        # 计划必须显式写出"不动 139 项闭包"，不能靠口头约定。
        text = json.dumps(self.plan, ensure_ascii=False)
        self.assertIn("139", text)
        self.assertIn("adeca462", text)

    def test_S08_missing_budget_fields_are_caught_not_silently_skipped(self):
        # 字段一改名，检查就变成永不触发的死代码。这条就是防那个的。
        for field in ("estimated_usd_at_expected_prompt",
                      "worst_case_usd_at_declared_caps"):
            with self.subTest(field=field):
                plan = copy.deepcopy(self.plan)
                plan["budget"].pop(field, None)
                issues = stage_b.validate_plan(plan)
                self.assertTrue(any(field in i for i in issues),
                                "缺少 %s 时 validate_plan 没有报错：%s"
                                % (field, issues))

    def test_S09_per_request_budget_is_recomputed_not_typed(self):
        # 逐条预算必须是算出来的：改了 token 估计却没改钱，必须立刻暴露。
        plan = copy.deepcopy(self.plan)
        plan["requests"][0]["estimated_input_tokens_upper"] += 100
        issues = stage_b.validate_plan(plan)
        self.assertTrue(any("budget_usd_estimate" in i for i in issues),
                        "token 估计被改了而钱没改，validate_plan 没发现：%s" % issues)

    def test_S0A_kernel_contract_must_match_scenario_id(self):
        # 域外对照必须 FORBIDDEN；六条具名请求必须 REQUIRED。改一个就报错。
        plan = copy.deepcopy(self.plan)
        plan["requests"][6]["kernel_contract"] = "REQUIRED"
        self.assertTrue(any("kernel_contract" in i
                            for i in stage_b.validate_plan(plan)))
        plan = copy.deepcopy(self.plan)
        plan["requests"][0]["kernel_contract"] = "FORBIDDEN"
        self.assertTrue(any("kernel_contract" in i
                            for i in stage_b.validate_plan(plan)))


class TestPreflightUnifiedGate(Base):
    """统一闸门：每一项都必须由证据算出，不能只看非空字符串或手改布尔。"""

    def gate_error(self, plan, origin=None, env=None, approved=None):
        with self.assertRaises(stage_b.StageBError) as cm:
            stage_b.preflight(
                plan, self.origin if origin is None else origin,
                environ=self.env if env is None else env,
                approved_requests=(self.scope_of(plan) if approved is None
                                   else approved))
        return str(cm.exception)

    def test_S10_passes_when_everything_is_in_place(self):
        p = self.plan()
        got = stage_b.preflight(p, self.origin, environ=self.env,
                                approved_requests=self.scope_of(p))
        self.assertEqual(got["request_count"], 7)
        self.assertEqual(got["model_id"], MODEL_ID)
        self.assertTrue(got["gate"]["ready_derived"])
        self.assertEqual(got["gate"]["catalog"]["model_id_verified"], MODEL_ID)
        self.assertEqual(got["scope"]["approved_request_ids"], ALL_IDS)

    def test_S11_refuses_unless_authorization_granted(self):
        # PROOF P1（入口）：未获授权，连 provider 都不构造。
        msg = self.gate_error(self.plan(**{"authorization.state": "NOT_GRANTED"}))
        self.assertIn("authorization.state", msg)

    def test_S11b_ruling_text_must_match_hash(self):
        # 把 state 改成 GRANTED 但裁决原文对不上摘要 —— 仍然拒绝。
        msg = self.gate_error(self.plan(**{"authorization.ruling_sha256": "0" * 64}))
        self.assertIn("authorization.ruling_sha256", msg)

    def test_S11c_granted_by_and_time_are_required(self):
        self.assertIn("authorization.granted_by",
                      self.gate_error(self.plan(**{"authorization.granted_by": "  "})))
        self.assertIn("authorization.granted_at",
                      self.gate_error(self.plan(**{"authorization.granted_at": "昨天"})))

    def test_S12_refuses_without_confirmed_model_id(self):
        msg = self.gate_error(self.plan(**{"model.model_id_confirmed": None}))
        self.assertIn("model.identity", msg)

    def test_S12b_model_id_must_match_catalog_verbatim(self):
        # 近似名不算命中：目录里没有这个名字，就必须停。
        msg = self.gate_error(
            self.plan(**{"model.model_id_confirmed": MODEL_ID + "-suffix"}))
        self.assertIn("model.identity", msg)

    def test_S13_refuses_when_declared_pricing_flag_contradicts_catalog(self):
        # 目录证据说价格一致，声明却写 false：不一致即拒绝，不允许"留个 false 以后再说"。
        msg = self.gate_error(
            self.plan(**{"model.pricing.verified_against_catalog": False}))
        self.assertIn("model.pricing_declared_flag", msg)

    def _no_catalog_plan(self):
        p = self.plan()
        p["model"]["confirmation"]["evidence_file"] = None
        return p

    def test_S14_refuses_on_origin_mismatch(self):
        # PROOF P2（端点侧）：origin 必须逐字给出，不批裸主机名、不批别的源。
        for bad in (STUB_ORIGIN, "https://api.tokenfactory.nebius.com", ""):
            with self.subTest(origin=bad):
                self.assertIn("endpoint.approved",
                              self.gate_error(self.plan(), origin=bad))

    def test_S15_refuses_without_api_key_env(self):
        self.assertIn(stage_b.KEY_ENV, self.gate_error(self.plan(), env={}))

    def test_S16_preflight_failure_sends_zero_requests(self):
        # PROOF P1：闸门拒绝时，网络层一次都没被调用。
        seen = []
        p = self.plan(**{"authorization.state": "x"})
        with mock.patch.object(provider_mod, "_post",
                               side_effect=lambda *a, **k: seen.append(a)):
            with self.assertRaises(stage_b.StageBError):
                stage_b.preflight(p, self.origin, environ=self.env,
                                  approved_requests=self.scope_of(p))
        self.assertEqual(seen, [])

    # ---- 目录证据（PROOF P2）----
    def test_S17_missing_catalog_evidence_blocks(self):
        msg = self.gate_error(self._no_catalog_plan())
        self.assertIn("catalog.present", msg)

    def test_S18_tampered_catalog_raw_blocks(self):
        # 只要原始字节被换过，声明的 sha256 就对不上 —— 派生失败。
        p = self.plan()
        p["model"]["confirmation"]["evidence_file"] = str(
            write_catalog(self.tmp / "catalog_tampered",
                          declared_sha="1" * 64))
        msg = self.gate_error(p)
        self.assertIn("raw_sha256_matches_declared", msg)

    def test_S19_catalog_without_the_model_blocks(self):
        p = self.plan()
        p["model"]["confirmation"]["evidence_file"] = str(
            write_catalog(self.tmp / "catalog_other",
                          raw=catalog_raw(model_id="some/Other-Model")))
        msg = self.gate_error(p)
        self.assertIn("model_id_listed", msg)

    def test_S1A_catalog_pricing_mismatch_blocks(self):
        p = self.plan()
        p["model"]["confirmation"]["evidence_file"] = str(
            write_catalog(self.tmp / "catalog_price",
                          raw=catalog_raw(pricing={"prompt": "0.0000005",
                                                   "completion": "0.0000009"})))
        msg = self.gate_error(p)
        self.assertIn("pricing_input_matches_plan", msg)

    def test_S1B_catalog_http_error_blocks(self):
        p = self.plan()
        p["model"]["confirmation"]["evidence_file"] = str(
            write_catalog(self.tmp / "catalog_500", status=500,
                          raw=b'{"error":"internal"}'))
        msg = self.gate_error(p)
        self.assertIn("http_status_200", msg)

    def test_S1C_declared_ready_true_but_derived_false_blocks(self):
        # 这一条就是"不能只依赖人工修改布尔标记"的直接证明：
        # ready 写 true、其他照旧空着 —— 派生结果仍是未就绪，必须拒绝。
        p = copy.deepcopy(stage_b.load_plan())
        p["execution_gate"]["ready"] = True
        p["execution_gate"]["blocking"] = []
        msg = self.gate_error(p)
        self.assertIn("execution_gate.ready", msg)

    def test_S1D_declared_ready_false_while_derived_true_blocks(self):
        # 反向也拒绝：能跑不等于可以跑，必须先把声明改成一致。
        p = self.plan()
        p["execution_gate"]["ready"] = False
        p["execution_gate"]["blocking"] = ["还没批"]
        msg = self.gate_error(p)
        self.assertIn("execution_gate.ready", msg)

    def test_S1E_declared_flags_cannot_override_derivation(self):
        # 目录证据不支持时，把 verified_against_catalog / state 都写成"已确认"也没用。
        p = self.plan()
        p["model"]["confirmation"]["evidence_file"] = str(
            write_catalog(self.tmp / "catalog_other2",
                          raw=catalog_raw(model_id="some/Other-Model")))
        p["model"]["pricing"]["verified_against_catalog"] = True
        p["model"]["model_id_verification"]["state"] = "VERIFIED"
        msg = self.gate_error(p)
        self.assertIn("model.identity", msg)
        self.assertIn("model.pricing", msg)

    def test_S1F_price_normalization_both_notations_agree(self):
        # 6e-8（每 token）与 0.06（每 1M）必须被认为是同一个价。
        notations = ({"prompt": "0.00000006", "completion": "0.00000024"},
                     {"prompt": 0.06, "completion": 0.24})
        want = catalog_mod.expected_request_of(stage_b.load_plan())
        for i, notation in enumerate(notations):
            with self.subTest(notation=notation):
                path = write_catalog(self.tmp / ("cat_norm_%d" % i),
                                     raw=catalog_raw(pricing=notation))
                res = catalog_mod.verify(path, MODEL_ID,
                                         {"input": 0.06, "output": 0.24},
                                         expected_request=want)
                self.assertTrue(res["ok"], res["failed"])
                self.assertAlmostEqual(
                    res["pricing_observed"]["input_per_1m_usd"], 0.06, places=12)

    # ---- 目录来源对应（本轮新增）----
    def _plan_with_catalog(self, name, **kw):
        p = self.plan()
        p["model"]["confirmation"]["evidence_file"] = str(
            write_catalog(self.tmp / name, **kw))
        return p

    def test_S1G_catalog_from_another_origin_blocks(self):
        # 内容完全正确，但这份目录是从别的端点查来的 —— 不能当成本次查询的结果。
        p = self._plan_with_catalog("cat_src_origin",
                                    source={"origin": "https://other.invalid:443",
                                            "url": "https://other.invalid:443/v1/models?verbose=true"})
        msg = self.gate_error(p)
        self.assertIn("catalog.request_source", msg)
        self.assertIn("endpoint_origin_matches_plan", msg)

    def test_S1H_catalog_with_wrong_method_path_or_query_blocks(self):
        cases = {
            "method": {"method": "POST"},
            "path": {"path": "/v1/models"},
            "query": {"query": "verbose=false"},
        }
        for name, override in cases.items():
            with self.subTest(field=name):
                p = self._plan_with_catalog("cat_src_%s" % name, source=override)
                msg = self.gate_error(p)
                self.assertIn("catalog.request_source", msg)

    def test_S1I_catalog_url_rewritten_but_hash_stale_blocks(self):
        # 改了 URL 却保留旧 URL 的摘要：两条来源检查都要失败。
        want_url = catalog_mod.expected_request_of(stage_b.load_plan())["url"]
        p = self._plan_with_catalog(
            "cat_src_url",
            source={"url": want_url + "&x=1"},
            url_sha256=hashlib.sha256(want_url.encode("utf-8")).hexdigest())
        ev = json.loads(Path(p["model"]["confirmation"]["evidence_file"])
                        .read_text(encoding="utf-8"))
        self.assertNotEqual(ev["request_url_sha256"],
                            hashlib.sha256(ev["request_url"].encode()).hexdigest(),
                            "夹具必须真的造出 URL 与摘要不一致的状态")
        msg = self.gate_error(p)
        self.assertIn("request_url_sha256_matches", msg)
        self.assertIn("request_url_matches_plan", msg)

    def test_S1J_verify_without_expected_request_is_not_ok(self):
        # 不给期望请求 = 无从核对来源，必须判未通过（而不是默默跳过）。
        path = write_catalog(self.tmp / "cat_noexpect")
        res = catalog_mod.verify(path, MODEL_ID, {"input": 0.06, "output": 0.24})
        self.assertFalse(res["ok"])
        self.assertIn("request_expected_provided", res["failed"])

    def test_S1K_gate_records_which_receipt_was_consumed(self):
        p = self.plan()
        got = stage_b.preflight(p, self.origin, environ=self.env,
                                approved_requests=self.scope_of(p))
        cat = got["gate"]["catalog"]
        # 摘要必须等于磁盘上那份 evidence 的真实字节摘要
        on_disk = Path(p["model"]["confirmation"]["evidence_file"]).read_bytes()
        self.assertEqual(cat["evidence_sha256"],
                         hashlib.sha256(on_disk).hexdigest())
        self.assertEqual(cat["request_recorded"]["method"], "GET")
        self.assertEqual(cat["request_expected"]["origin"], self.origin)


class TestPricingEvidenceTier(Base):
    """定价来源分档的准入条件（S70–S74）。

    降级档 `declared_from_official_page` 存在的理由是**端点目录不发布价格**。
    这个前提必须由目录证据证明，不能由计划自述，否则会出现一个真实缺口：
    目录给了价格但与计划冲突时，三项定价检查同样失败，于是「冲突」会被
    当成「目录没价」静默放行 —— 而冲突本该是停止条件。

    这一组的存在理由是：真实正例（DeepSeek）跑通之后，该分支从未被负例打中过；
    原 81 + 27 项回归全部走 catalog_entry 档，不能替代新增分支的验证。
    """

    def _declared(self, evidence_file):
        """把计划改成降级档并指向给定目录证据（其它字段保持与派生结果一致）。"""
        return self.plan(**{
            "model.pricing.evidence_class": "declared_from_official_page",
            "model.pricing.source":
                "https://api-docs.deepseek.com/zh-cn/quick_start/pricing",
            "model.pricing.declared_at": "2026-10-29T13:05:00",
            "model.pricing.verified_against_catalog": False,
            "model.pricing.machine_verified": False,
            "model.confirmation.evidence_file": str(evidence_file),
        })

    def _preflight(self, plan):
        return stage_b.preflight(plan, self.origin, environ=self.env,
                                approved_requests=self.scope_of(plan))

    def test_S70_declared_tier_accepted_when_catalog_truly_has_no_price(self):
        # 正例：目录条目存在但无 pricing —— 唯一合法的降级场景。
        ev = write_catalog(self.tmp / "nopricing", raw=catalog_raw_no_pricing())
        plan = self._declared(ev)
        g = self._preflight(plan)
        self.assertTrue(g["gate"]["checks"]["model.pricing_catalog_absence"],
                        "目录确实无价时，降级档的前提应成立")
        # 降级档永远不得产出"已核验"这个结论
        self.assertFalse(g["pricing"]["machine_verified"])
        self.assertFalse(g["pricing"]["verified_against_catalog"])
        self.assertEqual(g["pricing"]["evidence_class"], "declared_from_official_page")

    def test_S71_declared_tier_rejected_when_catalog_price_conflicts(self):
        # 关键负例：目录**有**价格且与计划不一致。旧实现会当成"目录没价"放行。
        ev = write_catalog(
            self.tmp / "conflict",
            raw=catalog_raw(pricing={"prompt": "0.00000009",
                                     "completion": "0.00000036"}))
        plan = self._declared(ev)
        with self.assertRaises(stage_b.StageBError) as cm:
            self._preflight(plan)
        msg = str(cm.exception)
        self.assertIn("完全不发布价格", msg,
                      "冲突必须被识别为「目录有价」，而不是「目录没价」：%s" % msg)

    def test_S72_declared_tier_rejected_when_catalog_price_matches(self):
        # 目录有价且一致：应走 catalog_entry 档享受机器核验，而不是自称抄录值。
        plan = self._declared(self.cat)
        with self.assertRaises(stage_b.StageBError) as cm:
            self._preflight(plan)
        self.assertIn("完全不发布价格", str(cm.exception))

    def test_S73_partial_catalog_pricing_is_not_treated_as_absence(self):
        # 只给了输入价：也算"有价"，不得走降级档（否则等于绕开一半比对）。
        raw = json.dumps({
            "object": "list",
            "data": [{"id": MODEL_ID, "pricing": {"prompt": "0.00000006"}}],
        }, ensure_ascii=False).encode("utf-8")
        ev = write_catalog(self.tmp / "partial", raw=raw)
        plan = self._declared(ev)
        with self.assertRaises(stage_b.StageBError) as cm:
            self._preflight(plan)
        self.assertIn("完全不发布价格", str(cm.exception))

    def test_S74_catalog_entry_tier_is_not_relaxed_by_the_fix(self):
        # 反向守门：修降级档不能顺手放松原档位。目录缺价时 catalog_entry 必须失败。
        ev = write_catalog(self.tmp / "nopricing2", raw=catalog_raw_no_pricing())
        plan = self.plan()
        plan["model"]["confirmation"]["evidence_file"] = str(ev)
        with self.assertRaises(stage_b.StageBError) as cm:
            self._preflight(plan)
        self.assertIn("目录定价与计划定价不一致", str(cm.exception))


class TestPlanBinding(Base):
    """summary 必须绑定"本次实际读入的那一版计划字节"（S75–S76）。

    背景：计划在同一批里被改过执行范围，事后只有最后一版留在磁盘上，
    于是三批证据都无法回答"当时用的哪一版"。绑定计划字节是唯一的补救路径，
    且必须由**文件字节**算，不能拿内存 dict 反推。
    """

    def _run_ok(self, plan):
        def fake_run(intent, prov, **kw):
            req = next(r for r in plan["requests"] if r["intent_text"] == intent)
            exp = req["expected"]
            if not exp.get("kernel_invoked"):
                return ok_evidence(model_decision=exp["model_decision_in"][0],
                                   sid=None, invoked=False, exit_code=None,
                                   kind=None, value=None,
                                   outcome="LEGAL_TERMINAL_%s"
                                           % exp["model_decision_in"][0])
            kind, _, value = exp["kernel_kind_outcome"].partition(" / ")
            return ok_evidence(sid=exp["scenario_id"],
                               exit_code=exp["kernel_exit"], kind=kind, value=value)
        return fake_run

    def test_S75_summary_binds_plan_file_bytes(self):
        plan = self.plan(scope=["R1"])
        ppath = self.tmp / "plan_snapshot.json"
        ppath.write_bytes(json.dumps(plan, ensure_ascii=False).encode("utf-8"))
        want = hashlib.sha256(ppath.read_bytes()).hexdigest()
        summary = self._run(plan, patch_run=self._run_ok(plan), plan_path=ppath)
        pb = summary["plan_binding"]
        self.assertEqual(pb["state"], "BOUND_TO_FILE_BYTES_SAME_SOURCE")
        self.assertTrue(pb["same_source"])
        self.assertEqual(pb["plan_sha256"], want)
        self.assertEqual(pb["plan_bytes"], ppath.stat().st_size)
        self.assertEqual(pb["plan_path"], str(ppath))

    def test_S76_unbound_plan_is_declared_not_guessed(self):
        # 不给路径时不得假装绑定：宁可写 NOT_BOUND，也不能编一个哈希出来。
        plan = self.plan(scope=["R1"])
        summary = self._run(plan, patch_run=self._run_ok(plan))
        pb = summary["plan_binding"]
        self.assertEqual(pb["state"], "NOT_BOUND")
        self.assertFalse(pb["same_source"])
        self.assertIsNone(pb["plan_sha256"])
        self.assertIsNone(pb["plan_bytes"])

    def test_S77_memory_plan_differs_from_file_is_rejected(self):
        # PROOF：给了路径时不得"哈希一份、跑另一份"。
        # 文件写 R1，内存改宽成 R1+R2 —— 旧实现照样会写 BOUND_TO_FILE_BYTES 并跑 R2。
        plan = self.plan(scope=["R1"])
        ppath = self.tmp / "plan_snapshot.json"
        ppath.write_bytes(json.dumps(plan, ensure_ascii=False).encode("utf-8"))
        tampered = copy.deepcopy(plan)
        tampered["execution_scope"]["approved_request_ids"] = ["R1", "R2"]
        tampered["execution_scope"]["approved_count"] = 2
        with self.assertRaises(stage_b.StageBError) as ctx:
            self._run(tampered, patch_run=self._run_ok(tampered),
                      plan_path=ppath, approved=["R1", "R2"])
        msg = str(ctx.exception)
        self.assertIn("同源性校验失败", msg)
        self.assertIn("sha256=", msg)
        # 拒绝必须发生在建证据目录之前：不可留下半个运行根。
        self.assertFalse((self.tmp / "ev").exists())

    def test_S78_file_with_invalid_json_is_rejected(self):
        # 字节哈希算得出来、对象解析不出来时，不能"先跑再说"。
        plan = self.plan(scope=["R1"])
        ppath = self.tmp / "plan_broken.json"
        ppath.write_bytes(b'{"schema": "H56_STAGE_B_PLAN_V1",')
        with self.assertRaises(stage_b.StageBError):
            self._run(plan, patch_run=self._run_ok(plan), plan_path=ppath)

    def test_S79_canonical_file_yields_identical_two_hashes(self):
        # 规范形写盘时，内存计划与文件字节的哈希必须相等 —— 证明同源比对不是
        # 因为空白/键序差异而假阴，且重新解析确实回到同一份内容。
        plan = self.plan(scope=["R1"])
        ppath = self.tmp / "plan_canonical.json"
        ppath.write_bytes(stage_b._canonical_plan_json(plan))
        summary = self._run(plan, patch_run=self._run_ok(plan), plan_path=ppath)
        pb = summary["plan_binding"]
        self.assertTrue(pb["same_source"])
        self.assertEqual(pb["memory_plan_sha256"], pb["plan_sha256"])


class TestExecutionScope(Base):
    """执行范围：本轮获准哪些请求，就只能跑哪些请求。

    这一组的存在理由很具体：上一版计划里只有一条授权（R1），但驱动遍历的是
    全部 7 条。R1 成功之后会继续 R2 —— 授权边界没有落到代码。
    """

    def _fake_run_ok(self, plan, seen=None):
        def fake_run(intent, prov, **kw):
            if seen is not None:
                seen.append(kw.get("correlation_id"))
            req = next(r for r in plan["requests"]
                       if r["intent_text"] == intent)
            exp = req["expected"]
            if not exp.get("kernel_invoked"):
                return ok_evidence(model_decision=exp["model_decision_in"][0],
                                   sid=None, invoked=False, exit_code=None,
                                   kind=None, value=None,
                                   outcome="LEGAL_TERMINAL_%s"
                                           % exp["model_decision_in"][0])
            kind, _, value = exp["kernel_kind_outcome"].partition(" / ")
            return ok_evidence(sid=exp["scenario_id"],
                               exit_code=exp["kernel_exit"], kind=kind, value=value)
        return fake_run

    def test_S41_real_plan_declares_only_r1(self):
        # 计划文件里的范围就是 R1。这条同时防止测试夹具把宽范围写回真实计划。
        plan = stage_b.load_plan()
        self.assertEqual(plan["execution_scope"]["approved_request_ids"], ["R1"])

    def test_S42_r1_only_runs_r1_and_never_reaches_r2(self):
        # PROOF：R1 成功之后不得进入 R2。
        plan = self.plan(scope=["R1"])
        seen = []
        summary = self._run(plan, patch_run=self._fake_run_ok(plan, seen))

        self.assertEqual(seen, ["R1"], "只应发出 R1；出现 R2 说明范围没生效")
        self.assertEqual(summary["executed_requests"], 1)
        sc = summary["execution_scope"]
        self.assertEqual(sc["approved_request_ids"], ["R1"])
        self.assertEqual(sc["executed_request_ids"], ["R1"])
        self.assertEqual(sc["not_in_scope"], ["R2", "R3", "R4", "R5", "R6", "R7"])
        self.assertEqual(sc["not_reached_in_scope"], [])
        self.assertFalse(sc["scope_is_full_plan"])
        # 跑完范围不算"出事"：termination 是 SCOPE_COMPLETE，不是失败
        self.assertEqual(summary["termination"]["kind"], "SCOPE_COMPLETE")
        self.assertFalse(summary["stopped"])
        self.assertIsNone(summary["stop_reason"])
        # 未获准的请求既没有结果，也没有证据目录
        self.assertEqual([r["request_id"] for r in summary["results"]], ["R1"])
        self.assertFalse((self.tmp / "ev" / "R2").exists())
        # 字段集本身要被钉住：三个数分开是**结构保证**，不是文档承诺。
        # 少一个字段就会让读者把"1 条通过"读成"7 条通过"。
        self.assertEqual(summary["schema"], stage_b.SUMMARY_SCHEMA)
        for key in ("planned_requests", "executed_requests", "termination",
                    "stopped", "stop_reason", "execution_scope", "gate", "budget"):
            self.assertIn(key, summary, "summary 缺字段 %r" % key)
        for key in ("approved_request_ids", "approved_count", "executed_request_ids",
                    "not_in_scope", "not_reached_in_scope", "scope_is_full_plan"):
            self.assertIn(key, sc, "execution_scope 缺字段 %r" % key)

    def test_S42b_scope_denies_before_constructing_provider(self):
        # 范围外的请求连 provider 都不构造：网络层一次都不该被摸到。
        plan = self.plan(scope=["R1"])
        posted = []
        with mock.patch.object(provider_mod, "_post",
                               side_effect=lambda *a, **k: posted.append(a)):
            # 用真实 run.py；R1 会真的走到 _post，但 _post 被拦住后 R1 必然失败，
            # 于是循环在 R1 结束 —— 无论 R1 成败，R2 都不该出现。
            summary = stage_b.execute(plan, self.tmp / "ev",
                                      python=sys.executable, environ=self.env,
                                      verbose=False, approved_origin=self.origin,
                                      approved_requests=["R1"])
        self.assertEqual(len(posted), 1, "只允许 R1 触碰网络层")
        self.assertEqual([r["request_id"] for r in summary["results"]], ["R1"])

    def test_S43_full_scope_still_works(self):
        # 范围给全 7 条时，行为与上一轮一致（不是把功能删掉，而是加了参数）。
        plan = self.plan()
        seen = []
        summary = self._run(plan, patch_run=self._fake_run_ok(plan, seen))
        self.assertEqual(seen, ALL_IDS)
        self.assertTrue(summary["execution_scope"]["scope_is_full_plan"])
        self.assertEqual(summary["execution_scope"]["not_in_scope"], [])
        self.assertEqual(summary["termination"]["kind"], "SCOPE_COMPLETE")
        # 闸门项数钉死：README 的清单说 21 项，就必须真的是 21 项。
        # 加减闸门却没同步文档，这条会先红。
        self.assertEqual(len(summary["gate"]["checks"]), 21,
                         "闸门项数与 README 清单不一致：改闸门必须同步改文档")
        self.assertIn("scope.matches_cli", summary["gate"]["checks"])
        self.assertIn("catalog.request_source", summary["gate"]["checks"])

    def test_S44_scope_must_match_cli_exactly(self):
        plan = self.plan(scope=["R1"])
        for bad in (["R1", "R2"], ["R2", "R1"], ["R2"], []):
            with self.subTest(cli=bad):
                seen = []
                with mock.patch.object(provider_mod, "_post",
                                       side_effect=lambda *a, **k: seen.append(a)):
                    with self.assertRaises(stage_b.StageBError) as cm:
                        stage_b.execute(plan, self.tmp / ("ev_%d" % len(bad)),
                                        environ=self.env, verbose=False,
                                        approved_origin=self.origin,
                                        approved_requests=bad)
                self.assertIn("scope.matches_cli", str(cm.exception))
                self.assertEqual(seen, [])

    def test_S45_cli_scope_is_required(self):
        plan = self.plan(scope=["R1"])
        with self.assertRaises(stage_b.StageBError) as cm:
            stage_b.preflight(plan, self.origin, environ=self.env)
        self.assertIn("scope.matches_cli", str(cm.exception))

    def test_S46_scope_is_checked_statically(self):
        base = self.plan()
        cases = {
            "空列表": [],
            "不存在的 id": ["R1", "R9"],
            "顺序与计划不一致": ["R2", "R1"],
            "重复": ["R1", "R1"],
            "超过额度": ALL_IDS + ["R1"],
        }
        for name, ids in cases.items():
            with self.subTest(case=name):
                p = copy.deepcopy(base)
                p["execution_scope"]["approved_request_ids"] = ids
                self.assertTrue(
                    any("execution_scope" in i
                        for i in stage_b.validate_plan(p)),
                    "%s 未被 validate_plan 发现（%s）"
                    % (name, stage_b.validate_plan(p)))

    def test_S47_scope_failure_does_not_create_evidence_dir(self):
        plan = self.plan(scope=["R1"])
        with self.assertRaises(stage_b.StageBError):
            stage_b.execute(plan, self.tmp / "ev_scope",
                            environ=self.env, verbose=False,
                            approved_origin=self.origin,
                            approved_requests=["R1", "R2"])
        self.assertFalse((self.tmp / "ev_scope").exists())


class TestBudgetGuard(unittest.TestCase):
    """预算：发送前预留、响应后核对。三个口径分开记账。"""

    def setUp(self):
        self.plan = granted_plan(None)
        self.guard = stage_b.BudgetGuard(self.plan)
        self.req = self.plan["requests"][0]

    def test_S50_request_count_cap_is_enforced(self):
        # PROOF P3（请求数）：额度用尽后不再允许发。
        for _ in range(7):
            self.assertTrue(self.guard.precheck(self.req)["allowed"])
        d = self.guard.precheck(self.req)
        self.assertFalse(d["allowed"])
        self.assertIn("请求数已达上限", "；".join(d["reasons"]))

    def test_S51_reserve_exceeding_budget_blocks_before_sending(self):
        # PROOF P3（费用）：把上限压到低于"7 次顶格"，第 2 次就必须发不出去。
        plan = copy.deepcopy(self.plan)
        plan["budget"]["max_total_usd"] = 0.0003  # 单次顶格 0.000216
        g = stage_b.BudgetGuard(plan)
        self.assertTrue(g.precheck(self.req)["allowed"])
        g.settle(self.req, {"prompt_tokens": 2000, "completion_tokens": 400})
        d = g.precheck(plan["requests"][1])
        self.assertFalse(d["allowed"])
        self.assertIn("预留最坏费用", "；".join(d["reasons"]))
        self.assertFalse(d["checks"]["reserve_within_budget"])

    def test_S52_token_caps_must_match_declared_budget(self):
        bad = copy.deepcopy(self.req)
        bad["max_output_tokens"] = 4000
        d = self.guard.precheck(bad)
        self.assertFalse(d["allowed"])
        self.assertFalse(d["checks"]["request_token_caps"])

    def test_S53_missing_usage_is_charged_conservatively_and_halts(self):
        # PROOF P3（usage 缺失）：不得用较低估算冒充真实费用。
        row = self.guard.settle(self.req, {"prompt_tokens": None,
                                          "completion_tokens": None})
        self.assertEqual(row["cost_source"],
                         "conservative_worst_case_declared_caps")
        self.assertFalse(row["cost_confirmable"])
        self.assertAlmostEqual(row["cost_usd"],
                               self.guard.worst_case_usd(self.req), places=10)
        self.assertGreater(row["cost_usd"],
                           self.req["budget_usd_estimate"],
                           "缺失 usage 时必须按顶格计入，不能比预估还低")
        self.assertIsNotNone(self.guard.halt)
        d = self.guard.precheck(self.plan["requests"][1])
        self.assertFalse(d["allowed"], "费用无法确认后，后续调用必须被挡住")
        self.assertIn("费用无法确认", "；".join(d["reasons"]))

    def test_S53b_usage_that_is_not_an_int_is_not_trusted(self):
        for bad in ({"prompt_tokens": "1100", "completion_tokens": 60},
                    {"prompt_tokens": 1100.0, "completion_tokens": 60},
                    {"prompt_tokens": True, "completion_tokens": 60},
                    {}, None):
            with self.subTest(usage=bad):
                g = stage_b.BudgetGuard(self.plan)
                row = g.settle(self.req, bad)
                self.assertEqual(row["cost_source"],
                                 "conservative_worst_case_declared_caps")

    def test_S53c_negative_usage_is_rejected_not_subtracted(self):
        # 负 token 会让 cost 变成负值，从而把累计花费"抹平"、绕过上限。
        # 只排除字符串/浮点/布尔是不够的 —— 这里补非负条件。
        for bad in ({"prompt_tokens": -1, "completion_tokens": 60},
                    {"prompt_tokens": 1100, "completion_tokens": -60},
                    {"prompt_tokens": -5000, "completion_tokens": -5000}):
            with self.subTest(usage=bad):
                g = stage_b.BudgetGuard(self.plan)
                row = g.settle(self.req, bad)
                self.assertFalse(row["cost_confirmable"], "负数不得被当成确认值")
                self.assertEqual(row["cost_source"],
                                 "conservative_worst_case_declared_caps")
                self.assertGreater(row["cost_usd"], 0,
                                   "费用必须是正的：负 token 不得把花费算成负数")
                self.assertIsNotNone(g.halt)
                self.assertFalse(
                    g.precheck(self.plan["requests"][1])["allowed"],
                    "费用无法确认后，后续调用必须被挡住")
                # 硬边界：无论 usage 多离谱，累计花费都不会变成负数
                self.assertGreaterEqual(g.spent, 0)

    def test_S54_real_usage_settles_exactly(self):
        row = self.guard.settle(self.req, {"prompt_tokens": 1100,
                                          "completion_tokens": 60})
        self.assertEqual(row["cost_source"], "usage")
        self.assertAlmostEqual(row["cost_usd"], 1100 / 1e6 * 0.06 + 60 / 1e6 * 0.24,
                               places=10)
        self.assertIsNone(self.guard.halt)

    def test_S55_actual_tokens_over_declared_caps_halts(self):
        row = self.guard.settle(self.req, {"prompt_tokens": 5000,
                                          "completion_tokens": 60})
        self.assertTrue(row["over_declared_caps"])
        self.assertIsNotNone(self.guard.halt)
        self.assertFalse(self.guard.precheck(self.plan["requests"][1])["allowed"])

    def test_S56_cost_of_keeps_the_same_two_sources(self):
        # 兼容入口必须与 BudgetGuard 用同一套口径，不能各算各的。
        cost, source = stage_b.cost_of({"prompt_tokens": 1100,
                                        "completion_tokens": 60},
                                       self.plan["model"]["pricing"], self.req)
        self.assertEqual(source, "usage")
        self.assertAlmostEqual(cost, 1100 / 1e6 * 0.06 + 60 / 1e6 * 0.24, places=10)
        cost2, source2 = stage_b.cost_of({}, self.plan["model"]["pricing"], self.req)
        self.assertEqual(source2, "conservative_worst_case_declared_caps")
        self.assertAlmostEqual(cost2, self.guard.worst_case_usd(self.req), places=10)


class TestStopBehaviour(Base):
    """停止行为：不多发、不重试、剩余额度留在账上。"""

    def _evidence_for(self, plan, intent, **kw):
        """按计划里该请求的 expected 段造一份"通得过"的证据。"""
        req = next((r for r in plan["requests"] if r["intent_text"] == intent), None)
        if req is None:
            raise AssertionError("计划里没有这条意图：%r" % intent[:20])
        exp = req["expected"]
        if not exp.get("kernel_invoked"):
            return ok_evidence(model_decision=exp["model_decision_in"][0], sid=None,
                               invoked=False, exit_code=None, kind=None, value=None,
                               outcome="LEGAL_TERMINAL_%s"
                                       % exp["model_decision_in"][0], **kw)
        kind, _, value = exp["kernel_kind_outcome"].partition(" / ")
        return ok_evidence(sid=exp["scenario_id"], exit_code=exp["kernel_exit"],
                           kind=kind, value=value, **kw)

    def test_S30_stops_after_first_rejection_and_sends_exactly_one(self):
        calls = []

        def bad_post(url, data, headers, timeout):
            calls.append(url)
            # 合法 JSON 但不是约定的 5 键结构 -> validate 判 SCHEMA_VIOLATION
            return 200, envelope('{"decision":"MAYBE"}'), {}

        summary = self._run(self.plan(), post=bad_post)

        self.assertEqual(len(calls), 1, "失败后不得再发第二个请求")
        self.assertTrue(summary["stopped"])
        self.assertEqual(summary["executed_requests"], 1)
        self.assertEqual(summary["not_executed"], ["R2", "R3", "R4", "R5", "R6", "R7"])
        self.assertFalse(summary["retry_attempted"])
        self.assertIn("adapter_decision", summary["stop_reason"])

    def test_S31_all_seven_run_when_every_gate_passes(self):
        plan = self.plan()
        seen = []

        def fake_run(intent, prov, **kw):
            seen.append((intent, kw))
            return self._evidence_for(plan, intent)

        summary = self._run(plan, patch_run=fake_run)

        self.assertEqual(len(seen), 7)
        self.assertEqual(summary["executed_requests"], 7)
        self.assertEqual(summary["not_executed"], [])
        self.assertFalse(summary["stopped"])
        expected = round(7 * (1100 / 1e6 * 0.06 + 60 / 1e6 * 0.24), 10)
        self.assertAlmostEqual(summary["spent_usd"], expected, places=9)
        self.assertLess(summary["spent_usd"], 0.05)
        self.assertEqual(summary["budget"]["cost_source_values"], ["usage"])
        self.assertTrue(summary["gate"]["ready_derived"])

    def test_S32_domain_out_control_is_not_allowed_to_select(self):
        plan = self.plan()

        def fake_run(intent, prov, **kw):
            if kw.get("suppress_kernel_if_select"):
                # R7 被强行映射成登记场景 -> 必须判失败
                return ok_evidence(sid="S-C01")
            return self._evidence_for(plan, intent)

        summary = self._run(plan, patch_run=fake_run)
        self.assertEqual(summary["executed_requests"], 7)
        self.assertTrue(summary["stopped"])
        self.assertIn("model_decision_in", summary["stop_reason"])

    def test_S33_evidence_dir_must_be_fresh(self):
        p = self.plan()
        (self.tmp / "ev").mkdir(parents=True)
        with self.assertRaises(stage_b.StageBError):
            stage_b.execute(p, self.tmp / "ev", environ=self.env,
                            verbose=False, approved_origin=self.origin,
                            approved_requests=self.scope_of(p))

    def test_S34_no_retry_branch_exists_in_source(self):
        src = Path(stage_b.__file__).read_text(encoding="utf-8")
        for forbidden in ("while True", "for attempt in", "max_retries", "backoff"):
            self.assertNotIn(forbidden, src,
                             "驱动里出现了重试语义：%s" % forbidden)

    def test_S35_mock_provider_cannot_pass_the_judge(self):
        # 验收目标第 2 条的结构性保证：把 A2 的 FixedMockProvider 拿到这里跑，
        # judge 必须判失败，而不是因为"结果字段看着对"就放过。
        plan = self.plan()
        req = plan["requests"][0]
        ev = self._evidence_for(plan, req["intent_text"])
        ev["call"]["provider_impl"]["impl"] = (
            "model_ingress_v1.tests.a2_integration.FixedMockProvider")
        ok, _checks, bad = stage_b.judge(req, ev)
        self.assertFalse(ok)
        self.assertIn("provider_is_not_mock", bad)

    def test_S36_execute_enforces_the_gate_itself(self):
        # PROOF P1：绕开 main() 直接调 execute()，闸门照样生效、零请求。
        seen = []
        real = stage_b.load_plan()
        with mock.patch.object(provider_mod, "_post",
                               side_effect=lambda *a, **k: seen.append(a)):
            with self.assertRaises(stage_b.StageBError) as cm:
                stage_b.execute(real, self.tmp / "ev_gate",
                                environ=self.env, verbose=False,
                                approved_origin=self.origin,
                                approved_requests=self.scope_of(real))
        self.assertEqual(seen, [])
        self.assertIn("authorization.state", str(cm.exception))
        self.assertFalse((self.tmp / "ev_gate").exists(),
                         "闸门拒绝时不得留下证据目录（更不得留下字节）")

    def test_S37_r7_is_wired_with_forbidden_contract(self):
        # PROOF P4（接线）：FORBIDDEN 必须真的传到 run()，不是写在计划里好看。
        plan = self.plan()
        seen = {}

        def fake_run(intent, prov, **kw):
            rid = kw.get("correlation_id")
            seen[rid] = (kw.get("suppress_kernel_if_select"),
                         kw.get("evidence_dir"))
            return self._evidence_for(plan, intent)

        self._run(plan, patch_run=fake_run)
        self.assertIs(seen["R7"][0], True, "R7 必须是 suppress=True")
        for rid in ("R1", "R2", "R3", "R4", "R5", "R6"):
            self.assertIs(seen[rid][0], False, "%s 不得被 suppress" % rid)
        self.assertEqual(sorted(seen), ["R1", "R2", "R3", "R4", "R5", "R6", "R7"])
        self.assertTrue(str(seen["R7"][1]).endswith("R7"),
                        "每条请求的证据目录必须按 request_id 分开")

    def test_S38_r7_select_never_reaches_the_kernel(self):
        # PROOF P4（真实路径）：走真实 run.py，模型硬要选 S-C01，
        # 必须在 spawn 之前就停，并记为「真实模型错误」而不是「零调用成功」。
        plan = self.plan()
        spawned = []

        def spy_spawn(cmd, **kw):
            spawned.append(cmd)
            raise AssertionError("合同禁止碰核心，却启动了内核：%r" % (cmd,))

        def fake_run(intent, prov, **kw):
            if kw.get("suppress_kernel_if_select"):
                return _REAL_RUN(
                    intent, _SelectProvider(selection("S-C01")),
                    evidence_dir=Path(kw["evidence_dir"]), spawn=spy_spawn,
                    python=sys.executable,
                    correlation_id=kw["correlation_id"],
                    suppress_kernel_if_select=True)
            return self._evidence_for(plan, intent)

        summary = self._run(plan, patch_run=fake_run)
        self.assertEqual(spawned, [], "内核一次都不许启动")
        self.assertTrue(summary["stopped"])
        r7 = summary["results"][-1]
        self.assertEqual(r7["request_id"], "R7")
        self.assertEqual(r7["adapter_outcome"],
                         "MODEL_ERROR_SELECTED_WHERE_FORBIDDEN")
        self.assertIs(r7["kernel_invoked"], False)
        self.assertIn("no_overshoot", r7["failed_checks"])
        self.assertNotIn("no_kernel_launched", r7["failed_checks"],
                         "合同守住了：内核确实一次没启动")

    def test_S39_budget_halt_stops_the_remaining_requests(self):
        # PROOF P3（执行层）：第 1 条的 usage 不可用 -> 后续一律不发。
        plan = self.plan()
        sent = []

        def fake_run(intent, prov, **kw):
            sent.append(kw.get("correlation_id"))
            return self._evidence_for(plan, intent,
                                      usage={"prompt_tokens": None,
                                             "completion_tokens": None})

        summary = self._run(plan, patch_run=fake_run)
        self.assertEqual(sent, ["R1"], "费用无法确认后不得再发")
        self.assertTrue(summary["stopped"])
        self.assertIn("费用无法确认", summary["stop_reason"])
        self.assertEqual(summary["budget"]["unconfirmed_cost_requests"], ["R1"])
        self.assertEqual(summary["not_executed"],
                         ["R2", "R3", "R4", "R5", "R6", "R7"])


class TestCredentialIsolation(unittest.TestCase):
    """凭据不进内核子进程。重点：变量名可切之后，名单追不上名字，必须传参。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="h56_cred_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_S40_nebius_key_is_stripped_from_kernel_env(self):
        from model_ingress_v1 import run as run_mod
        env, removed = run_mod._kernel_env({
            "PATH": "/x",
            stage_b.KEY_ENV: "secret-value",
            "H56_MODEL_API_KEY": "secret2",
        })
        self.assertNotIn(stage_b.KEY_ENV, env, "NEBIUS_API_KEY 不得继承给内核")
        self.assertNotIn("H56_MODEL_API_KEY", env)
        self.assertEqual(env["PATH"], "/x")
        self.assertIn(stage_b.KEY_ENV, removed)
        self.assertNotIn("secret-value", json.dumps(removed),
                         "只记变量名，不记值")

    def test_S57_custom_slot_name_is_stripped_only_when_handed_over(self):
        # 使用不符合通用凭据后缀的名字，仍证明显式槽位参数承担实际清理。
        from model_ingress_v1 import run as run_mod
        environ = {"PATH": "/x", "CUSTOM_PROVIDER_AUTH": "synthetic-must-not-leak"}
        env_default, removed_default = run_mod._kernel_env(environ)
        self.assertIn("CUSTOM_PROVIDER_AUTH", env_default,
                      "不传名字时不剔除：证明参数是承重的，不是装饰")
        self.assertNotIn("CUSTOM_PROVIDER_AUTH", removed_default)

        env, removed = run_mod._kernel_env(environ,
                                           extra_names=("CUSTOM_PROVIDER_AUTH",))
        self.assertNotIn("CUSTOM_PROVIDER_AUTH", env, "传了名字就必须剔除")
        self.assertIn("CUSTOM_PROVIDER_AUTH", removed)
        self.assertNotIn("synthetic-must-not-leak", json.dumps(removed),
                         "只记变量名，不记值")

    def test_S60_custom_slot_is_absent_from_the_real_kernel_env(self):
        # 走真实 run()：合法 SELECT -> spawn，核对**真正交给子进程**的 env 对象。
        from model_ingress_v1 import run as run_mod
        passed = {}

        def spy_spawn(cmd, **kw):
            passed["env"] = kw.get("env")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with mock.patch.dict(os.environ,
                             {"NVIDIA_API_KEY": "nvapi-must-not-leak"}):
            ev = run_mod.run("随便一句话", _SelectProvider(selection("S-C01")),
                             evidence_dir=self.tmp / "ev", spawn=spy_spawn,
                             python=sys.executable, timeout=30,
                             key_env="NVIDIA_API_KEY")

        self.assertTrue(ev["kernel"]["invoked"], "SELECT 必须真的走到 spawn")
        self.assertIsNotNone(passed.get("env"), "必须显式传 env，不依赖默认继承")
        self.assertNotIn("NVIDIA_API_KEY", passed["env"],
                         "自定义槽位名不得出现在内核子进程环境里")
        san = ev["kernel"]["env_sanitized"]
        self.assertIn("NVIDIA_API_KEY", san["removed_names"])
        self.assertEqual(san["key_env_targeted"], "NVIDIA_API_KEY")
        self.assertFalse(san["values_recorded"])
        self.assertNotIn("nvapi-must-not-leak",
                         json.dumps(ev, ensure_ascii=False),
                         "证据全文不得出现密钥值")


class TestProductSpawnEnv(unittest.TestCase):
    """产品侧四个子进程入口的环境净化。

    `run.py::_kernel_env()` 只覆盖 Adapter → CLI 一条链。产品自身还有四个出口：
    UI 启动 demo、demo 跑候选计算、demo 探测解释器、demo 只读复演。它们此前都不传
    `env=`，等于把父进程的密钥原样交给那些一个字节都不需要它的进程。
    """

    _PRODUCT = Path(__file__).absolute().parents[2]
    _FIXTURE = {
        "PATH": "/bin:/usr/bin",
        "SYSTEMROOT": "C:\\Windows",
        "TEMP": "/tmp",
        "H56_MODEL_API_KEY": "h56-secret-must-not-leak",
        "NEBIUS_API_KEY": "nebius-secret-must-not-leak",
        "NVIDIA_API_KEY": "nvapi-secret-must-not-leak",
        # 真实存在但不符合「_KEY 结尾」的命名形态：
        "DASHSCOPE_APIKEY": "dashscope-secret-must-not-leak",
        "SILICONFLOW_APIKEY": "siliconflow-secret-must-not-leak",
        "MY_PASSWORD_HASH": "pwhash-secret-must-not-leak",
        "PG_PASSWD": "passwd-secret-must-not-leak",
        # 反例：名字里含 KEY 片段但不是凭据，后缀规则不得误删。
        "MONKEY_PATH": "/do/not/remove",
        "ACCESS_KEYBOARD": "keep-me-too",
        "UNRELATED_SETTING": "keep-me",
    }

    def _load(self, relpath, name):
        import importlib.util
        spec = importlib.util.spec_from_file_location(name, str(self._PRODUCT / relpath))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_S61_demo_clean_env_removes_keys_and_keeps_the_rest(self):
        demo = self._load("demo.py", "h56_demo_s61")
        env = demo._clean_env(dict(self._FIXTURE))
        for name in ("H56_MODEL_API_KEY", "NEBIUS_API_KEY", "NVIDIA_API_KEY",
                     "DASHSCOPE_APIKEY", "SILICONFLOW_APIKEY",
                     "MY_PASSWORD_HASH", "PG_PASSWD"):
            self.assertNotIn(name, env, "%s 不得进入子进程环境" % name)
        for name in ("PATH", "SYSTEMROOT", "TEMP", "UNRELATED_SETTING",
                     "MONKEY_PATH", "ACCESS_KEYBOARD"):
            self.assertEqual(env[name], self._FIXTURE[name],
                             "%s 必须原样继承 —— 净化不是最小白名单环境，也不能误删" % name)
        body = json.dumps(env, ensure_ascii=False)
        self.assertNotIn("must-not-leak", body, "返回值里不得出现任何密钥值")

    def test_S62_ui_clean_env_matches_demo(self):
        demo = self._load("demo.py", "h56_demo_s62")
        serve = self._load("ui/serve.py", "h56_serve_s62")
        self.assertEqual(demo.ENV_PREFIX, serve.ENV_PREFIX)
        self.assertEqual(sorted(demo.ENV_EXTRA_REMOVE), sorted(serve.ENV_EXTRA_REMOVE),
                         "两处静态名单必须一致，否则同一份规则有两个版本")
        self.assertEqual(demo._clean_env(dict(self._FIXTURE)),
                         serve._clean_env(dict(self._FIXTURE)),
                         "同一 fixture 下两份实现必须得到同一环境")

    def test_S63_static_lists_agree_with_the_dynamic_mechanism(self):
        # 防漂移：demo/UI 的静态名单，喂给 run 的动态机制必须得到同一结果。
        # 任一方向漂移（多删、少删）都会在这里断。
        from model_ingress_v1 import run as run_mod
        demo = self._load("demo.py", "h56_demo_s63")
        self.assertEqual(demo.ENV_PREFIX, run_mod.ENV_PREFIX,
                         "前缀常量必须与净化链同源")
        kept_by_run, removed_by_run = run_mod._kernel_env(
            dict(self._FIXTURE), extra_names=demo.ENV_EXTRA_REMOVE)
        self.assertEqual(sorted(removed_by_run),
                         ["DASHSCOPE_APIKEY", "H56_MODEL_API_KEY", "MY_PASSWORD_HASH",
                          "NEBIUS_API_KEY", "NVIDIA_API_KEY", "PG_PASSWD",
                          "SILICONFLOW_APIKEY"],
                         "静态实现与动态机制删掉的键集必须逐键相同（含新增命名形态）")
        self.assertEqual(demo._clean_env(dict(self._FIXTURE)), kept_by_run,
                         "静态实现与动态机制的结果必须逐键相同")

    def test_S64_every_product_spawn_passes_env_explicitly(self):
        # 只断言"不含密钥"会漏掉最可能的实现错误：根本没传 env（= 完整继承）。
        # 这里逐个枚举 product 侧全部 subprocess 调用点，要求都带 env=_clean_env()。
        import ast
        for relpath in ("demo.py", "ui/serve.py"):
            tree = ast.parse((self._PRODUCT / relpath).read_text(encoding="utf-8"))
            calls = [n for n in ast.walk(tree)
                     if isinstance(n, ast.Call)
                     and isinstance(n.func, ast.Attribute)
                     and isinstance(n.func.value, ast.Name)
                     and n.func.value.id == "subprocess"]
            self.assertTrue(calls, "%s 里应当有 subprocess 调用点" % relpath)
            for call in calls:
                kw = {k.arg: k.value for k in call.keywords}
                self.assertIn("env", kw,
                              "%s:%d 未传 env —— 等于完整继承父进程环境"
                              % (relpath, call.lineno))
                self.assertIsInstance(kw["env"], ast.Call,
                                      "%s:%d 的 env 不是一次调用" % (relpath, call.lineno))
                self.assertEqual(kw["env"].func.id, "_clean_env",
                                 "%s:%d 的 env 不是 _clean_env()"
                                 % (relpath, call.lineno))

    def test_S65_version_probe_receives_the_cleaned_env(self):
        demo = self._load("demo.py", "h56_demo_s65")
        seen = {}

        def fake_run(cmd, **kw):
            seen.update(kw)
            return SimpleNamespace(stdout="3.9.13\n", stderr="", returncode=0)

        with mock.patch.dict(os.environ, dict(self._FIXTURE)):
            with mock.patch.object(demo.subprocess, "run", fake_run):
                self.assertEqual(demo.ver(sys.executable), "3.9.13")

        self.assertIn("env", seen, "版本探测必须显式传 env")
        self.assertIsNotNone(seen["env"])
        for name in ("H56_MODEL_API_KEY", "NEBIUS_API_KEY", "NVIDIA_API_KEY"):
            self.assertNotIn(name, seen["env"])

    def test_S66_ui_demo_spawn_receives_the_cleaned_env(self):
        serve = self._load("ui/serve.py", "h56_serve_s66")
        seen = {}

        def fake_popen(cmd, **kw):
            seen["cmd"] = cmd
            seen.update(kw)
            return SimpleNamespace(stdout=iter([]), returncode=0, wait=lambda: 0)

        with mock.patch.dict(os.environ, dict(self._FIXTURE)):
            with mock.patch.object(serve.subprocess, "Popen", fake_popen):
                serve._run_demo("rid", Path(tempfile.gettempdir()) / "h56_s66",
                                Path(tempfile.gettempdir()) / "h56_s66" / "report.json",
                                None)

        self.assertIn("env", seen, "UI 启动 demo 必须显式传 env")
        self.assertIsNotNone(seen["env"], "env=None 等于继承，等于没做")
        for name in ("H56_MODEL_API_KEY", "NEBIUS_API_KEY", "NVIDIA_API_KEY"):
            self.assertNotIn(name, seen["env"])
        self.assertNotIn("must-not-leak", json.dumps(seen["env"], ensure_ascii=False))


class TestKeyEnvWiring(Base):
    """阶段 B 把「本次选中的槽位名」交给净化链，而不是让它随环境继承。"""

    def test_S58_execute_hands_the_custom_slot_name_to_run(self):
        plan = self.plan(scope=["R1"])
        saw = {}

        def fake_run(intent, prov, **kw):
            saw[kw.get("correlation_id")] = kw.get("key_env")
            return ok_evidence(sid="S-C01")

        self._run(plan, patch_run=fake_run,
                  environ={"NEBIUS_API_KEY": "k-offline",
                           "NVIDIA_API_KEY": "k-nv"},
                  key_env="NVIDIA_API_KEY")
        self.assertEqual(saw, {"R1": "NVIDIA_API_KEY"},
                         "execute 必须把 --key-env 选中的名字传下去")

    def test_S59_default_slot_name_is_also_handed_over(self):
        # 默认路径同样显式传名字：不是「碰巧在静态名单里」才算安全。
        plan = self.plan(scope=["R1"])
        saw = {}

        def fake_run(intent, prov, **kw):
            saw[kw.get("correlation_id")] = kw.get("key_env")
            return ok_evidence(sid="S-C01")

        self._run(plan, patch_run=fake_run, environ=self.env)
        self.assertEqual(saw, {"R1": stage_b.KEY_ENV})


class TestCredentialSuffixIsolation(unittest.TestCase):
    def test_direct_entry_helpers_remove_other_provider_credentials(self):
        import demo
        from ui import serve
        from model_ingress_v1 import run as run_mod
        names = ("DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ZAI_API_KEY", "BAIDU_API_KEY",
                 "NVIDIA_API_KEY", "CUSTOM_PROVIDER_KEY", "AWS_ACCESS_KEY_ID",
                 "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET", "lowercase_api_key")
        fixture = {name: "SYNTHETIC-ONLY" for name in names}
        fixture.update(PATH="/keep", SYSTEMROOT="C:\\Windows", TEMP="/keep-temp",
                       UNRELATED_SETTING="keep")
        results = [demo._clean_env(fixture), serve._clean_env(fixture),
                   run_mod._kernel_env(fixture)[0]]
        for result in results:
            self.assertFalse(set(names) & set(result))
            self.assertEqual(result, {k: fixture[k] for k in
                             ("PATH", "SYSTEMROOT", "TEMP", "UNRELATED_SETTING")})

    def test_real_child_receives_no_fixture_credentials(self):
        import demo
        from ui import serve
        from model_ingress_v1 import run as run_mod
        import subprocess
        names = ("DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ZAI_API_KEY", "BAIDU_API_KEY")
        fixture = dict(os.environ)
        fixture.update({name: "SYNTHETIC-ONLY" for name in names})
        code = "import os,json;print(json.dumps([k for k in %r if k in os.environ]))" % (names,)
        for env in (demo._clean_env(fixture), serve._clean_env(fixture),
                    run_mod._kernel_env(fixture)[0]):
            child = subprocess.run([sys.executable, "-I", "-B", "-S", "-c", code],
                                   env=env, capture_output=True, text=True)
            self.assertEqual(child.returncode, 0)
            self.assertEqual(json.loads(child.stdout), [])


class TestEvidencePersistence(Base):
    """走真实 HttpProvider（只把 _post 换成固定字节），核对请求体/错误体确实落盘。

    A2 用的是 FixedMockProvider，它不产生请求体，因此 A2 证据里
    request_body 恒为 None —— 那是诚实的，但也意味着"请求体留痕"这条
    必须另有用例覆盖。这几条就是补这个洞。
    """

    def _prov(self, **kw):
        return HttpProvider(STUB_URL, MODEL_ID, "k-offline",
                            allowed_origins={STUB_ORIGIN}, **kw)

    def test_S26_request_body_is_written_and_hash_recomputable(self):
        # PROOF P6：请求字节落盘 -> 哈希可由磁盘重算 -> 与响应的 sha256 同链。
        from model_ingress_v1 import run as run_mod
        content = ('{"decision":"NOT_APPLICABLE","scenario_id":null,'
                   '"clarification_question":null,"reason":"no match",'
                   '"confidence":0.5}')
        with mock.patch.object(provider_mod, "_post",
                               return_value=(200, envelope(content), {})):
            prov = self._prov(enable_thinking=False)
            ev = run_mod.run("随便一句话", prov, evidence_dir=self.tmp / "R",
                             python=sys.executable, correlation_id="R7")

        self.assertEqual(ev["adapter"]["decision"], "ACCEPTED")
        self.assertEqual(ev["adapter"]["model_decision"], "NOT_APPLICABLE")
        self.assertFalse(ev["kernel"]["invoked"], "非 SELECT 不得碰内核")
        self.assertEqual(ev["correlation_id"], "R7")
        self.assertEqual(ev["adapter"]["outcome"], "LEGAL_TERMINAL_NOT_APPLICABLE")

        body_file = self.tmp / "R" / run_mod.REQUEST_BODY_FILE
        self.assertTrue(body_file.exists(), "请求体必须落盘，否则无法核对模型看到什么")
        disks = body_file.read_bytes()
        self.assertEqual(hashlib.sha256(disks).hexdigest(),
                         ev["request_body"]["sha256"])
        self.assertEqual(ev["request_body"]["sha256"],
                         ev["call"]["request_body_sha256"])
        resp_file = self.tmp / "R" / run_mod.RAW_BODY_FILE
        self.assertEqual(hashlib.sha256(resp_file.read_bytes()).hexdigest(),
                         ev["linkage"]["model_response_sha256"])

        sent = json.loads(disks.decode("utf-8"))
        self.assertEqual(sent["chat_template_kwargs"], {"enable_thinking": False})
        self.assertEqual(sent["max_tokens"], 400)
        self.assertEqual(sent["temperature"], 0)
        self.assertEqual(sent["model"], MODEL_ID)
        self.assertNotIn("Bearer", disks.decode("utf-8"),
                         "请求体不得携带鉴权头")
        self.assertTrue(ev["call"]["thinking"]["requested"])
        self.assertEqual(ev["call"]["thinking"]["support"],
                         "unverified_until_first_real_response")

    def test_S27_http_error_body_is_written_and_no_cli_is_spawned(self):
        # PROOF P5：400 也留请求体 + 原始错误体 + 状态码，且不调 CLI。
        from model_ingress_v1 import run as run_mod
        err = b'{"error":{"message":"unsupported parameter: chat_template_kwargs"}}'
        seen = []

        def spy_spawn(cmd, **kw):
            seen.append(cmd)

        with mock.patch.object(provider_mod, "_post",
                               return_value=(400, err, {})):
            prov = self._prov(enable_thinking=False)
            ev = run_mod.run("随便一句话", prov, evidence_dir=self.tmp / "E",
                             spawn=spy_spawn, python=sys.executable,
                             correlation_id="R1")

        self.assertEqual(ev["adapter"]["decision"], "REJECTED")
        self.assertEqual(ev["adapter"]["outcome"], "REJECTED_BY_TRANSPORT")
        self.assertEqual(ev["adapter"]["code"], "MODEL_TRANSPORT_FAILED")
        self.assertEqual(ev["adapter"]["attempts"], 1, "不得重试")
        self.assertEqual(seen, [], "传输失败后不得调用 CLI")
        err_file = self.tmp / "E" / run_mod.ERROR_BODY_FILE
        self.assertTrue(err_file.exists(), "参数被拒时的响应体必须保留")
        self.assertEqual(hashlib.sha256(err_file.read_bytes()).hexdigest(),
                         ev["raw_error_body"]["sha256"])
        self.assertEqual(ev["raw_error_body"]["http_status"], 400)

        # PROOF P5 的关键：失败那次也留了**实际发出的请求体**与关联标识
        body_file = self.tmp / "E" / run_mod.REQUEST_BODY_FILE
        self.assertTrue(body_file.exists(), "失败请求同样必须留请求体")
        body = body_file.read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         ev["request_body"]["sha256"])
        self.assertEqual(ev["request_body"]["sha256"],
                         ev["call"]["request_body_sha256"])
        self.assertEqual(ev["call"]["correlation_id"], "R1")
        self.assertEqual(ev["call"]["http_status"], 400)
        self.assertEqual(ev["call"]["model_id"], MODEL_ID)
        self.assertNotIn("Bearer", body.decode("utf-8"))
        self.assertNotIn("k-offline", body.decode("utf-8"))

    def test_S27b_timeout_keeps_request_body_even_without_response(self):
        # 超时没有响应体，但请求体必须有：否则无法证明超时那次发了什么。
        from model_ingress_v1 import run as run_mod
        import socket

        def boom(url, data, headers, timeout):
            raise socket.timeout("read timed out")

        with mock.patch.object(provider_mod, "_post", boom):
            prov = self._prov(enable_thinking=False)
            ev = run_mod.run("随便一句话", prov, evidence_dir=self.tmp / "T",
                             python=sys.executable, correlation_id="R2")

        self.assertEqual(ev["adapter"]["code"], "MODEL_TRANSPORT_FAILED")
        self.assertEqual(ev["call"]["transport_error"], "timeout")
        self.assertIsNone(ev["call"]["http_status"])
        self.assertTrue((self.tmp / "T" / run_mod.REQUEST_BODY_FILE).exists())
        self.assertEqual(ev["raw_error_body"]["sha256"], None)
        self.assertIn("没有响应体", ev["raw_error_body"]["note"])


class TestCatalogFetch(Base):
    """目录查询的取数通路：单次 GET、原始字节落盘、凭据不入库。"""

    def test_S2D_fetch_then_verify_with_plan_expectation_round_trips(self):
        # 闭环：fetch 产出的证据，必须能被 verify 用**计划派生**的期望请求认定合格。
        # 这一条防的是"fetch 发的 URL 与 verify 期望的 URL 不是同一个"——
        # 两边各自成立但彼此对不上，是最容易埋进去的一类错。
        # 模型 id 与价格也一律从计划派生，不写死离线夹具值：否则这条闭环只证明了
        # "夹具与夹具自洽"，换一份计划就失效。
        plan = stage_b.load_plan()
        want = catalog_mod.expected_request_of(plan)
        self.assertEqual(want["url"],
                         catalog_mod.catalog_url(plan["model"]["endpoint"]["base_url"],
                                                 plan["model"]["confirmation"]["query"]))
        mid = plan["model"]["model_id_expected"]
        pr = plan["model"]["pricing"]
        self.assertEqual(pr["unit"], "per 1M tokens", "计划价格口径变了，本用例的换算需同步")
        per_token = {"prompt": str(Decimal(str(pr["input"])) / Decimal(1000000)),
                     "completion": str(Decimal(str(pr["output"])) / Decimal(1000000))}
        with mock.patch.object(provider_mod, "_get_once",
                               return_value=(200, catalog_raw(model_id=mid,
                                                              pricing=per_token), {})):
            catalog_mod.fetch(plan["model"]["endpoint"]["base_url"], "k",
                              {plan["model"]["endpoint"]["origin"]},
                              self.tmp / "cat_round")
        res = catalog_mod.verify(self.tmp / "cat_round" / catalog_mod.EVIDENCE_FILE,
                                 mid, pr, expected_request=want)
        self.assertTrue(res["ok"], res["failed"])
        self.assertEqual(res["request_recorded"]["url"], want["url"])

    def test_S28_single_get_and_raw_bytes_preserved(self):
        # PROOF P6（目录侧）：响应字节可独立核验，哈希由磁盘重算。
        raw = catalog_raw(extra_ids=("meta/Llama-3-8B",))
        seen = []

        def fake_get(url, headers, timeout=30):
            seen.append((url, dict(headers)))
            return 200, raw, {}

        with mock.patch.object(provider_mod, "_get_once", fake_get):
            ev = catalog_mod.fetch(STUB_URL, "k-secret", {STUB_ORIGIN},
                                   self.tmp / "cat")

        self.assertEqual(len(seen), 1, "目录查询只允许一次")
        self.assertEqual(seen[0][0], STUB_URL + "/models?verbose=true")
        self.assertEqual(seen[0][1]["Authorization"], "Bearer k-secret")
        self.assertEqual(ev["model_count"], 2)
        self.assertEqual(ev["raw_bytes"], len(raw))
        d = self.tmp / "cat"
        self.assertEqual(hashlib.sha256((d / catalog_mod.RAW_FILE).read_bytes())
                         .hexdigest(), ev["raw_sha256"])
        text = (d / catalog_mod.EVIDENCE_FILE).read_text(encoding="utf-8")
        self.assertNotIn("k-secret", text, "凭据不得进入证据")
        self.assertNotIn("Bearer", text)
        self.assertIn("k-secret", json.dumps(seen[0][1]), "但请求头里必须真的带了")

    def test_S29_http_error_still_preserves_raw(self):
        # 目录查失败也有取证价值：状态码 + 原始错误体。
        with mock.patch.object(provider_mod, "_get_once",
                               return_value=(401, b'{"error":"bad key"}', {})):
            ev = catalog_mod.fetch(STUB_URL, "k", {STUB_ORIGIN},
                                   self.tmp / "cat401")
        self.assertEqual(ev["http_status"], 401)
        self.assertEqual((self.tmp / "cat401" / catalog_mod.RAW_FILE).read_bytes(),
                         b'{"error":"bad key"}')
        res = catalog_mod.verify(self.tmp / "cat401" / catalog_mod.EVIDENCE_FILE,
                                 MODEL_ID, {"input": 0.06, "output": 0.24})
        self.assertFalse(res["ok"])
        self.assertIn("http_status_200", res["failed"])

    def test_S2A_unapproved_origin_refuses_before_any_request(self):
        seen = []
        with mock.patch.object(provider_mod, "_get_once",
                               side_effect=lambda *a, **k: seen.append(a)):
            with self.assertRaises(catalog_mod.CatalogError):
                catalog_mod.fetch(STUB_URL, "k", set(), self.tmp / "cat_x")
        self.assertEqual(seen, [])

    def test_S2B_existing_evidence_dir_is_never_reused(self):
        (self.tmp / "cat_dup").mkdir()
        with mock.patch.object(provider_mod, "_get_once",
                               return_value=(200, catalog_raw(), {})):
            with self.assertRaises(catalog_mod.CatalogError):
                catalog_mod.fetch(STUB_URL, "k", {STUB_ORIGIN}, self.tmp / "cat_dup")

    def test_S2C_catalog_cli_refuses_without_execute(self):
        self.assertEqual(catalog_mod.main([]), 3)
        self.assertEqual(
            catalog_mod.main(["--execute", "--approve-origin", STUB_ORIGIN]), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
