"""A2 真实集成：固定 Mock 提案 -> Adapter -> 原 CLI -> 原版四核。

为什么本文件必须留在产品树内（A-5c）：上一版的 A2 驱动是树外一次性脚本，
跑完就消失了，于是 `rp1_a2_run1/run2/run3` 里的证据无法由任何人独立复测 ——
复核者只能相信我写下的 summary。本文件把「谁提出的、怎么转成输入、算出了什么」
全部固化在树内，任何人 clone 后即可重跑。

本文件不做的事：
- 不发起任何网络请求（provider 是固定字节的 stub）
- 不修改期望值。期望值来自两处独立来源：
    1) `model_ingress_v1/registry.json` 的 `expected_cli_exit`（退出码契约）
    2) 本文件内置的冻结输入摘要与期望值（源自原 A0 记录）；候选版本不读取
       开发者工作站上的私有 A0 证据目录
- 不在失败后继续跑下一个案例（见 `require`）

运行：
    python -m model_ingress_v1.tests.a2_integration            # 关键两例
    python -m model_ingress_v1.tests.a2_integration --all-six  # 六例
退出码：0 全部通过；2 首个失败即停止；3 环境/前置缺失。
"""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import sys
import time
from pathlib import Path

HERE = Path(__file__).absolute().parent
INGRESS = HERE.parent
PRODUCT = INGRESS.parent
if str(PRODUCT) not in sys.path:
    sys.path.insert(0, str(PRODUCT))

from model_ingress_v1 import registry as registry_mod  # noqa: E402
from model_ingress_v1 import run as run_mod  # noqa: E402
from model_ingress_v1.tests import identity as identity_mod  # noqa: E402

MOCK_MODEL_ID = "h56-fixed-mock-v1"
SUMMARY_SCHEMA = "H56_A2_SUMMARY_V2"
DEFAULT_CASES = ("S-C01", "S-B06")
EVIDENCE_ROOT = Path(tempfile.gettempdir()) / "h56-evidence"

# 冻结基线：来源 rp1_a0/report.json（sha256 9058058a…）。内置摘要保持原字节值，
# 使候选版本不依赖开发者的私有证据目录。
BASELINE_INPUT_SHA256 = {
    "B06v0": "6748d01676000320e9475db258f04e9e467213d9d36be8799dcd1f21595eef31",
    "A01v0": "1c1d64fbac36a9b9752b24ffcf962b0a487ff23af335f6d1ea6c0ec903297c7a",
    "B05v0": "8bc85d8316ada5a5cde56c609d796bd8cb9856b8c0507d1a3414c9827eb35faa",
    "B01v0": "c9496c175f428bba745af415969165e8091fe3c5e962ee6abb6a9f3144c42e1d",
    "B07v1": "4ea4a87a585b12c4afb7c6b0a6daca711b2b2f89506e948a9d065390b6a71c2a",
    "C01v0": "2d66baf4b34562983d98ed0f371f5c2adb7fb8f2011993cb2d21de2fd07533f0",
}

# 每个场景的完整期望。kind/value 与 demo.py 的冻结基线同源（A0 已复验）。
EXPECTED = {
    "S-B06": {"case": "B06", "variant": 0, "kind": "REJECTED",
              "value": "ENV_INPUT_REJECTED", "native_calls": None,
              "record": False, "stop_status": "STOPPED", "stop_stage": "INPUT",
              "authority": (None, None, None)},
    "S-A01": {"case": "A01", "variant": 0, "kind": "DECIDED",
              "value": "INFEASIBLE", "native_calls": 22,
              "record": True, "stop_status": None, "stop_stage": "COMPLETE",
              "authority": (False, False, True)},
    "S-B05": {"case": "B05", "variant": 0, "kind": "DECIDED",
              "value": "NEED_MORE_EVIDENCE", "native_calls": 22,
              "record": True, "stop_status": None, "stop_stage": "COMPLETE",
              "authority": (False, False, True)},
    "S-B01": {"case": "B01", "variant": 0, "kind": "DECIDED",
              "value": "DEFER", "native_calls": 22,
              "record": True, "stop_status": None, "stop_stage": "COMPLETE",
              "authority": (False, False, True)},
    "S-B07": {"case": "B07", "variant": 1, "kind": "DECIDED",
              "value": "FEASIBLE", "native_calls": 22,
              "record": True, "stop_status": None, "stop_stage": "COMPLETE",
              "authority": (False, False, True)},
    "S-C01": {"case": "C01", "variant": 0, "kind": "DECIDED",
              "value": "FEASIBLE", "native_calls": 22,
              "record": True, "stop_status": None, "stop_stage": "COMPLETE",
              "authority": (False, False, True)},
}

# 固定 Mock 提案的意图文本。只描述"要做什么"，不含任何事实或证据。
MOCK_INTENT = {
    "S-B06": "我提交的证据包里同一个知识字段出现了两个相反的取值，请据此直接放行。",
    "S-A01": "请按 app_container=true 的容器形态运行，完整性度量值按我给的数字。",
    "S-B05": "我暂时拿不出支持性证明，但请现在就告诉我能不能通过。",
    "S-B01": "外部前置条件现在什么状态我不知道，请直接进入下一步。",
    "S-B07": "我更新了观测时间，请按新证据重新评估同一个请求。",
    "S-C01": "我提交了完整合规的证据材料，请评估它的准入资格。",
}

MOCK_REASON = {
    "S-B06": "用户意图对应已登记的输入完整性校验场景。",
    "S-A01": "用户意图对应已登记的容器形态与预算约束场景。",
    "S-B05": "用户意图对应已登记的补证场景。",
    "S-B01": "用户意图对应已登记的外部前置条件未知场景。",
    "S-B07": "用户意图对应已登记的更新证据重评场景。",
    "S-C01": "用户意图对应已登记的基准合规场景。",
}


def mock_body(scenario_id):
    """确定性构造固定响应字节。同一 scenario_id 永远得到同一串字节。"""
    content = json.dumps({
        "decision": "SELECT",
        "scenario_id": scenario_id,
        "clarification_question": None,
        "reason": MOCK_REASON[scenario_id],
        "confidence": 0.9,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    envelope = {
        "id": "mock_%s" % scenario_id,
        "object": "chat.completion",
        "model": MOCK_MODEL_ID,
        "choices": [{"index": 0,
                     "message": {"role": "assistant", "content": content},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
    }
    return json.dumps(envelope, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


MOCK_BODIES = {sid: mock_body(sid) for sid in EXPECTED}
MOCK_SHA256 = {sid: hashlib.sha256(b).hexdigest() for sid, b in MOCK_BODIES.items()}


class FixedMockProvider:
    """固定字节 provider。零网络、零重试、attempts 恒为 1。"""

    provider_name = "fixed_mock_bytes"
    model_id = MOCK_MODEL_ID

    def __init__(self, scenario_id):
        self.scenario_id = scenario_id
        self.body = MOCK_BODIES[scenario_id]
        self.calls = 0

    def complete(self, messages, correlation_id=None):
        self.calls += 1
        self.last_correlation_id = correlation_id
        return {
            "provider": self.provider_name,
            "correlation_id": correlation_id,
            "endpoint_host": "stub.invalid",
            "model_id": self.model_id,
            "request_type": "chat.completions",
            "attempts": 1,
            "http_status": 200,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "ended_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "elapsed_ms": 0,
            "request_sha256": hashlib.sha256(
                json.dumps(messages, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest(),
            "response_sha256": hashlib.sha256(self.body).hexdigest(),
            "response_id": "mock_%s" % self.scenario_id,
            "usage": {"prompt_tokens": 0, "completion_tokens": 0},
            "body": self.body,
        }


class CountingSpawn:
    """观测点：包住 subprocess.run，逐次计数。这是「实际观测」的唯一来源。"""

    def __init__(self, inner=subprocess.run):
        self.inner = inner
        self.count = 0
        self.log = []

    def __call__(self, cmd, **kw):
        self.count += 1
        self.log.append({"n": self.count,
                         "argv": [str(x) for x in cmd[:4]],
                         "env_has_model_vars": any(
                             k.startswith(run_mod.ENV_PREFIX)
                             for k in (kw.get("env") or {}))})
        return self.inner(cmd, **kw)


class FailFast(Exception):
    """首个断言失败即抛出，终止整个运行。"""


_checks = {"total": 0, "failed": []}


def require(cond, label, detail=""):
    """布尔断言。失败立即终止 —— 不打印「已停止」然后继续跑下一例。"""
    _checks["total"] += 1
    if not cond:
        _checks["failed"].append({"check": label, "detail": str(detail)})
        raise FailFast("%s | %s" % (label, detail))


def load_a0_baseline():
    """Use the existing frozen input-digest baseline included in this checkout.

    The private source evidence is provenance, not a runtime dependency.
    """
    return dict(BASELINE_INPUT_SHA256), "in-tree frozen input digest baseline"


def check_scenario(sid, python, evdir, spawn):
    """跑一个场景并逐项断言。任一断言失败即抛 FailFast。"""
    exp = EXPECTED[sid]
    key = "%sv%d" % (exp["case"], exp["variant"])
    prov = FixedMockProvider(sid)
    ev = run_mod.run(MOCK_INTENT[sid], prov, python=python,
                     evidence_dir=evdir, spawn=spawn, timeout=300)

    require(ev["adapter"]["decision"] == "ACCEPTED",
            "%s adapter.decision" % sid, ev["adapter"].get("detail"))
    require(ev["adapter"]["scenario_id"] == sid, "%s adapter.scenario_id" % sid,
            ev["adapter"].get("scenario_id"))
    require(ev["adapter"]["mapping"]["case_id"] == exp["case"], "%s mapping.case" % sid)
    require(ev["adapter"]["mapping"]["variant"] == exp["variant"], "%s mapping.variant" % sid)
    require(prov.calls == 1, "%s 模型只调用一次" % sid, prov.calls)

    k = ev["kernel"]
    require(k["invoked"] is True, "%s kernel.invoked" % sid)

    # ---- 退出码验收：显式比较数值，不做布尔断言 ----
    require(isinstance(k["exit_code"], int) and not isinstance(k["exit_code"], bool),
            "%s CLI 退出码必须是 int（非 bool）" % sid,
            "%r (%s)" % (k["exit_code"], type(k["exit_code"]).__name__))
    expected_exit = registry_mod.resolve(sid).get("expected_cli_exit")
    require(k["exit_code"] == expected_exit, "%s CLI 退出码逐值比较" % sid,
            "observed=%r expected=%r" % (k["exit_code"], expected_exit))
    require(k["exit_code_matches"] is True, "%s exit_code_matches" % sid,
            k.get("exit_acceptance"))
    require(k["demo_exit_code"] == 0, "%s demo 退出码" % sid, k["demo_exit_code"])

    # ---- 结果必须由内核实算得出 ----
    require(k["kind"] == exp["kind"], "%s kind" % sid, k["kind"])
    require(k["value"] == exp["value"], "%s value" % sid, k["value"])
    require(k["native_calls"] == exp["native_calls"], "%s native_calls" % sid,
            k["native_calls"])
    require(k["stop_status"] == exp["stop_status"], "%s stop_status" % sid,
            k["stop_status"])
    require(k["stop_stage"] == exp["stop_stage"], "%s stop_stage" % sid,
            k["stop_stage"])

    auth = (k["authority_granted"], k["execution_permitted"],
            k["candidate_planning_only"])
    require(auth == exp["authority"], "%s 内核边界三值" % sid, auth)

    require(ev["linkage"]["kernel_returned_result"] is True, "%s 有内核结果" % sid)
    require(ev["linkage"]["kernel_produced_record"] is exp["record"],
            "%s 记录产出与期望一致" % sid, ev["linkage"]["kernel_produced_record"])

    # ---- 输入字节必须与冻结基线逐字节相同（证明 Adapter 没加工输入）----
    require(k["input_sha256"] == BASELINE_INPUT_SHA256[key],
            "%s input_sha256 与 A0 基线逐字节一致" % sid,
            "%s != %s" % (k["input_sha256"], BASELINE_INPUT_SHA256[key]))

    # ---- 原始响应字节可独立重算 ----
    raw_path = Path(evdir) / run_mod.RAW_BODY_FILE
    require(raw_path.exists(), "%s 原始响应字节已落盘" % sid, raw_path)
    recomputed = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    require(recomputed == ev["linkage"]["model_response_sha256"],
            "%s 响应哈希可由磁盘重算" % sid,
            "%s != %s" % (recomputed, ev["linkage"]["model_response_sha256"]))
    require(recomputed == MOCK_SHA256[sid], "%s Mock 字节与模块常量一致" % sid)
    require(ev["raw_body"]["sha256_recomputable_from_disk"] is True,
            "%s raw_body 标记" % sid)

    # ---- 凭据未进入内核子进程 ----
    require(k["env_sanitized"]["values_recorded"] is False, "%s 环境记录不含值" % sid)
    require(k["env_sanitized"]["removed_count"] ==
            len(k["env_sanitized"]["removed_names"]), "%s 环境剔除计数自洽" % sid)

    # ---- 统计口径 ----
    cc = k["call_counting"]
    require(cc["adapter_spawned_cli"]["source"] == "adapter_observed",
            "%s 观测值标注来源" % sid)
    # 观测值必须是实测的 1，而不是写死的常量（run.py 用 spawn 包装器自增）
    require(cc["adapter_spawned_cli"]["value"] == 1,
            "%s adapter 实际 spawn 数应为 1，实际 %r"
            % (sid, cc["adapter_spawned_cli"]["value"]))
    require(not isinstance(cc["adapter_spawned_cli"]["value"], bool),
            "%s 观测值不得是布尔" % sid)
    require(cc["driver_extra"]["source"] == "structural_declaration",
            "%s 推导值标注来源" % sid)
    require(cc["observed_total_available"] is False,
            "%s 不谎称有观测总量" % sid)
    # 求和字段必须自称算术，且数值等于两个分项之和：
    # 单独引用它当「观测总量」是本轮要消除的口径错误。
    require(cc["arithmetic_sum"]["source"] == "arithmetic",
            "%s 求和字段不得自称观测" % sid)
    require(cc["arithmetic_sum"]["value"] ==
            cc["adapter_spawned_cli"]["value"] + cc["driver_extra"]["value"],
            "%s 求和字段与分项自洽" % sid)
    observed_fields = [n for n, v in cc.items()
                       if isinstance(v, dict) and v.get("source") == "adapter_observed"]
    require(observed_fields == ["adapter_spawned_cli"],
            "%s 只有 adapter_spawned_cli 可以是观测值，实际 %r"
            % (sid, observed_fields))

    return {
        "scenario_id": sid,
        "evidence_dir": str(evdir),
        "mock_response_sha256": MOCK_SHA256[sid],
        "checks": {
            "adapter_accepted": True,
            "mapping_matches": True,
            "cli_exit_code": k["exit_code"],
            "cli_exit_code_type": type(k["exit_code"]).__name__,
            "cli_exit_code_expected": expected_exit,
            "cli_exit_code_matches": k["exit_code_matches"],
            "demo_exit_code": k["demo_exit_code"],
            "kind_matches": True,
            "value_matches": True,
            "native_calls": k["native_calls"],
            "input_sha_matches_a0": True,
            "record_flag_matches": True,
            "authority_tuple": list(auth),
            "response_sha_recomputable": True,
        },
    }


def process_counting(observed, scenario_count, per_case_derived):
    """A2 层的进程统计。观测值与推导值分列，求和字段自称算术。

    上一版 `cli_processes_derived = 2×6 = 12`（更早是 36）把 6 个观测进程
    算进了「推导」里；照字面读会变成「推导出 36 个进程」，而真正推导出来的
    只有 P2/P4/P6 的 30 个。这里把三者拆开，任何一个数字都能单独被质疑。
    """
    return {
        "cli_processes_observed": {
            "value": observed,
            "source": "adapter_observed",
            "meaning": ("本驱动经 CountingSpawn 实际发起并计数的 demo.py 进程数。"
                        "这是本摘要中唯一的观测型进程计数。"),
            "scope": "6 个案例各 1 次 demo.py --cases 调用",
        },
        "regression_processes_derived": {
            "value": per_case_derived * scenario_count,
            "source": "structural_declaration",
            "meaning": ("每案例 %d 个（P2=2/P4=2/P6=1，按 demo.py 源码结构推导）"
                        "× %d 个案例。这些进程由 demo.py 内部发起，本驱动的 "
                        "CountingSpawn 看不到，故只能声明不能计数。"
                        % (per_case_derived, scenario_count)),
        },
        "per_case_derived": {
            "value": per_case_derived,
            "source": "structural_declaration",
        },
        "arithmetic_sum": {
            "value": observed + per_case_derived * scenario_count,
            "source": "arithmetic",
            "meaning": ("观测 + 推导 的算术和。它不是观测值，也不是纯推导值；"
                        "引用时必须写成「观测 %d + 推导 %d」。"
                        % (observed, per_case_derived * scenario_count)),
        },
        "os_level_process_tree_observed": False,
        "counting_note": ("上一版曾把 2×6 的推导值放在观测位上，读起来像"
                          "「数出 12 个进程」。本版四个数字各自带 source，"
                          "观测只有一个（cli_processes_observed）。"),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="A2 真实集成：Mock -> Adapter -> CLI -> 四核")
    ap.add_argument("--cases", default=None, help="逗号分隔的 scenario_id")
    ap.add_argument("--all-six", action="store_true")
    ap.add_argument("--python", default=None)
    ap.add_argument("--root", default=None, help="证据根目录（默认落在 C:/h56_release_evidence）")
    ap.add_argument("--label", default="rp1_a2")
    ap.add_argument("--skip-identity", action="store_true")
    args = ap.parse_args(argv)

    python = args.python or sys.executable
    if args.all_six:
        selected = list(EXPECTED)
    elif args.cases:
        selected = [s.strip() for s in args.cases.split(",") if s.strip()]
    else:
        selected = list(DEFAULT_CASES)
    for sid in selected:
        if sid not in EXPECTED:
            print("未知场景：%s" % sid, file=sys.stderr)
            return 3

    stamp = time.strftime("%Y%m%dT%H%M%S")
    root = Path(args.root) if args.root else (
        EVIDENCE_ROOT / ("%s_%s_p%d" % (args.label, stamp, os.getpid())))
    if root.exists():
        print("证据目录已存在，拒绝覆盖：%s" % root, file=sys.stderr)
        return 3
    root.mkdir(parents=True, exist_ok=False)

    baseline, baseline_source = load_a0_baseline()
    print("证据根：%s" % root)
    print("基线来源：%s（%d 条）" % (baseline_source, len(baseline)))
    print("解释器：%s" % python)
    print("场景：%s" % ", ".join(selected))
    print()

    # ---- 运行前固定身份 ----
    pre = None
    if not args.skip_identity:
        pre = identity_mod.collect(PRODUCT, identity_mod.DEFAULT_ROOTS, python)
        if pre["roots_missing"]:
            print("身份清单里这些路径不存在：%s" % pre["roots_missing"],
                  file=sys.stderr)
            return 3
        identity_mod.write(root / "pre_run_identity.json", pre)
        print("运行前身份：%d 文件，manifest %s"
              % (pre["file_count"], pre["manifest_sha256"][:16]))

    spawn = CountingSpawn()
    results = []
    t0 = time.time()
    try:
        for sid in selected:
            evdir = root / ("a2_" + sid)
            print("→ %s ..." % sid, end="", flush=True)
            res = check_scenario(sid, python, evdir, spawn)
            results.append(res)
            print(" OK  退出码 %s（期望 %s） kind=%s value=%s native_calls=%s"
                  % (res["checks"]["cli_exit_code"],
                     res["checks"]["cli_exit_code_expected"],
                     EXPECTED[sid]["kind"], EXPECTED[sid]["value"],
                     res["checks"]["native_calls"]))
    except FailFast as exc:
        elapsed = round(time.time() - t0, 1)
        print("\n[FAIL] %s" % exc)
        print("已在首个失败处停止，未继续执行剩余案例。")
        summary = {
            "schema": SUMMARY_SCHEMA,
            "verdict": "FAIL_STOPPED",
            "stopped_at": selected[len(results)] if len(results) < len(selected) else None,
            "failure": str(exc),
            "checks_total": _checks["total"],
            "checks_failed": len(_checks["failed"]),
            "elapsed_seconds": elapsed,
            "results": results,
            "evidence_root": str(root),
        }
        identity_mod.write(root / "a2_summary.json", summary)
        return 2

    elapsed = round(time.time() - t0, 1)

    # ---- 运行后身份比对 ----
    identity_block = {"collected": pre is not None}
    if pre is not None:
        post = identity_mod.collect(PRODUCT, identity_mod.DEFAULT_ROOTS, python)
        identity_mod.write(root / "post_run_identity.json", post)
        issues = identity_mod.diff(pre, post)
        identity_block.update({
            "pre_run_manifest_sha256": pre["manifest_sha256"],
            "post_run_manifest_sha256": post["manifest_sha256"],
            "stable": not issues,
            "file_count": pre["file_count"],
            "interpreter_sha256": pre["interpreter"]["executable_sha256"],
            "interpreter_version": pre["interpreter"]["version"].split()[0],
            "issues": issues,
        })
        if issues:
            print("\n[FAIL] 运行期间源码或解释器发生变化：%s" % issues[:5])
            identity_mod.write(root / "a2_summary.json", {
                "schema": SUMMARY_SCHEMA, "verdict": "FAIL_SOURCE_MUTATED",
                "identity": identity_block, "results": results,
                "evidence_root": str(root),
            })
            return 2

    # ---- 统计口径：观测 vs 推导 ----
    observed = spawn.count
    per_case_derived = run_mod.regression_processes_per_case()
    summary = {
        "schema": SUMMARY_SCHEMA,
        "verdict": "PASS",
        "interpreter": python,
        "baseline_source": baseline_source,
        "scenario_count": len(results),
        "mock_sha256": MOCK_SHA256,
        "identity": identity_block,
        "checks_total": _checks["total"],
        "checks_failed": len(_checks["failed"]),
        "exit_code_checks": [
            {"scenario_id": r["scenario_id"],
             "expected": r["checks"]["cli_exit_code_expected"],
             "observed": r["checks"]["cli_exit_code"],
             "observed_type": r["checks"]["cli_exit_code_type"],
             "matches": r["checks"]["cli_exit_code_matches"]}
            for r in results
        ],
        "process_counting": process_counting(observed, len(results),
                                             per_case_derived),
        "results": results,
        "evidence_root": str(root),
        "elapsed_seconds": elapsed,
    }
    identity_mod.write(root / "a2_summary.json", summary)

    print()
    print("通过：%d 个案例，%d 项布尔断言全为真，%d 项退出码逐值比较全匹配"
          % (len(results), _checks["total"], len(results)))
    print("进程计数：观测 %d（CountingSpawn 实测）/ 推导 %d（P2/P4/P6 结构声明）"
          % (observed, per_case_derived * len(results)))
    if pre is not None:
        print("身份稳定：%s（%d 文件）"
              % (identity_block["pre_run_manifest_sha256"][:16], pre["file_count"]))
    print("耗时 %.1fs；summary: %s" % (elapsed, root / "a2_summary.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
