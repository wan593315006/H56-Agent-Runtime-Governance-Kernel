#!/usr/bin/env python3
"""h56mu 离线资格评估 —— 一键演示与自检

用法：
    python demo.py                                 # 演示主线：6 个真实案例（快）
    python demo.py --all                           # 全部 31 个案件 / 56 个变体
    python demo.py --compare-python <python.exe>   # 加做跨版本字节一致性
    python demo.py --emit-baseline                 # 输出冻结基线字面量
    python demo.py --all --work-dir <新目录> --json <新目录>/report.json
                                                   # 结构化结果（ui/serve.py 用它驱动页面）

它做什么：
    以「外部操作者」身份驱动 offline_qualification_v1/cli.py（隔离模式 -I -B -S）。
    通过输入/来源门禁并产生记录的变体会真实执行 K0→K1→C1→C2 原生计算；
    拒绝路径在写记录前停止。脚本检查 7 条性质：
      1. 每个变体的结局（判定 / 拒绝码）与冻结基线一致
      2. 同输入重复提交 → 判定与 semantic_sha256 完全相同（幂等）
       3. 提供第二解释器时，跨 Python 版本的 semantic_sha256 逐字节相同
      4. 补证后独立重评可挂父引用，且生成新评估（不是覆盖）
       5. B01→C01 补证链上的已封存记录在后续运行中字节不变
      6. view 复演不重算原生内核（只读复演）
      7. 授权边界不被越过（authority_granted / execution_permitted 恒 False）

关于「拒绝」：A/B/R/X 组里相当一部分案件的正确结局就是被拒绝
（证据不合规、策略拒斥、越权请求等）。本脚本把它们记为 REJECTED 与原因码，
不视为失败。只有「既没有记录也没有原因码」才算失败。

运行目录必须位于产品根之外，否则 cli.py 会以 RUN_ROOT_OVERLAP 拒绝执行。

本脚本不做的事：不发布、不联网、不写凭据、不修改任何已封存证据。
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

PRODUCT = Path(__file__).absolute().parent
sys.path.insert(0, str(PRODUCT))

from offline_qualification_v1.tests.test_evidence import (  # noqa: E402
    case_envelope, evidence_bytes, metadata)

CASES_FILE = PRODUCT / "offline_qualification_v1" / "fixtures" / "cases.json"
MANIFEST = PRODUCT / "offline_qualification_v1" / "SOURCE_MANIFEST.json"
ASSETS_MANIFEST = PRODUCT / "offline_qualification_v1" / "assets" / "manifest.json"
CLI = PRODUCT / "offline_qualification_v1" / "cli.py"

# ── 子进程环境净化 ───────────────────────────────────────────────────────────
# 规则与 model_ingress_v1/run.py::_kernel_env 同源：前缀 + 静态名单。
# 此处**自包含实现**，不 import 适配层 —— 产品核心演示不应依赖 model_ingress_v1，
# 否则公开候选里缺少该包时 `python demo.py` 直接无法启动（假依赖）。
# 防漂移由 test_stage_b.S61–S63 的等价性用例承担，不靠 import 关系承担。
#
# 净化的含义只有一个：**从既有环境里移除密钥类变量**，其余原样继承。
# 不能改成"最小白名单环境" —— 子进程带 -I -B -S，仍需要 SYSTEMROOT / PATH / TEMP，
# 白名单式环境在 Windows 上会直接失败。
ENV_PREFIX = "H56_MODEL_"
ENV_EXTRA_REMOVE = ("NEBIUS_API_KEY", "NVIDIA_API_KEY")


def _clean_env(environ=None):
    """返回一份剔除了密钥类变量的环境副本。不修改入参，不记录任何值。"""
    env = dict(os.environ if environ is None else environ)
    drop = [k for k in env if k.startswith(ENV_PREFIX) or k in ENV_EXTRA_REMOVE]
    for k in drop:
        env.pop(k, None)
    return env


# 演示主线：6 个案例，输入证据字节互不相同，覆盖「拒绝 / 不可行 / 未知 / 延后 / 放行」。
# 刻意不含 R01v0、C05v1、X01v0 等「变体键未被消费、证据字节与 C01v0 完全相同」的行——
# 那些行保留在 --all 的回归基线里，但不作为演示覆盖计入。
MAIN = [("B06", 0), ("A01", 0), ("B05", 0), ("B01", 0), ("B07", 1), ("C01", 0)]

EXPECTED = {
    "A01v0": ("DECIDED", "INFEASIBLE"),
    "A02v0": ("DECIDED", "INFEASIBLE"),
    "A03v0": ("DECIDED", "INFEASIBLE"),
    "A04v0": ("DECIDED", "INFEASIBLE"),
    "A05v0": ("REJECTED", "ENV_TASK_SCOPE_MISMATCH"),
    "A06v0": ("REJECTED", "ENV_TASK_SCOPE_MISMATCH"),
    "A07v0": ("DECIDED", "FEASIBLE"),
    "A08v0": ("DECIDED", "FEASIBLE"),
    "B01v0": ("DECIDED", "DEFER"),
    "B02v0": ("DECIDED", "DEFER"),
    "B03v0": ("DECIDED", "DEFER"),
    "B04v0": ("REJECTED", "ENV_TIME_INVALID_OR_FUTURE"),
    "B04v1": ("REJECTED", "ENV_TIME_INVALID_OR_FUTURE"),
    "B04v2": ("REJECTED", "ENV_TIME_INVALID_OR_FUTURE"),
    "B05v0": ("DECIDED", "NEED_MORE_EVIDENCE"),
    "B06v0": ("REJECTED", "ENV_INPUT_REJECTED"),
    "B06v1": ("REJECTED", "ENV_INPUT_REJECTED"),
    "B07v0": ("DECIDED", "DEFER"),
    "B07v1": ("DECIDED", "FEASIBLE"),
    "B08v0": ("REJECTED", "ENV_EVIDENCE_CONFLICT"),
    "B08v1": ("REJECTED", "ENV_EVIDENCE_CONFLICT"),
    "B08v2": ("REJECTED", "ENV_EVIDENCE_CONFLICT"),
    "B09v0": ("REJECTED", "ENV_SOURCE_OR_VERSION_MISMATCH"),
    "B09v1": ("DECIDED", "FEASIBLE"),
    "B10v0": ("DECIDED", "INFEASIBLE"),
    "C01v0": ("DECIDED", "FEASIBLE"),
    "C04v0": ("DECIDED", "FEASIBLE"),
    "C05v0": ("DECIDED", "FEASIBLE"),
    "C05v1": ("DECIDED", "FEASIBLE"),
    "C05v2": ("DECIDED", "FEASIBLE"),
    "C06v0": ("REJECTED", "ENV_INPUT_REJECTED"),
    "C06v1": ("REJECTED", "ENV_INPUT_REJECTED"),
    "C06v2": ("REJECTED", "ENV_INPUT_REJECTED"),
    "C06v3": ("DECIDED", "FEASIBLE"),
    "C06v4": ("DECIDED", "FEASIBLE"),
    "C06v5": ("DECIDED", "FEASIBLE"),
    "R01v0": ("DECIDED", "FEASIBLE"),
    "R02v0": ("DECIDED", "FEASIBLE"),
    "R03v0": ("DECIDED", "FEASIBLE"),
    "R03v1": ("DECIDED", "FEASIBLE"),
    "R03v2": ("DECIDED", "FEASIBLE"),
    "R04v0": ("DECIDED", "FEASIBLE"),
    "R04v1": ("DECIDED", "FEASIBLE"),
    "R04v2": ("DECIDED", "FEASIBLE"),
    "X01v0": ("DECIDED", "FEASIBLE"),
    "X01v1": ("DECIDED", "FEASIBLE"),
    "X01v2": ("DECIDED", "FEASIBLE"),
    "X02v0": ("DECIDED", "FEASIBLE"),
    "X02v1": ("DECIDED", "FEASIBLE"),
    "X02v2": ("DECIDED", "FEASIBLE"),
    "X03v0": ("DECIDED", "FEASIBLE"),
    "X03v1": ("DECIDED", "FEASIBLE"),
    "X03v2": ("DECIDED", "FEASIBLE"),
    "X03v3": ("DECIDED", "FEASIBLE"),
    "X04v0": ("DECIDED", "FEASIBLE"),
    "X05v0": ("DECIDED", "FEASIBLE"),
}


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def is_within(path, root):
    """Return whether path resolves under root; never rely on string prefixes."""
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False


def create_owned_workdir(requested):
    """Validate before creation; never delete a caller-provided directory."""
    work = (Path(requested) if requested else
            Path(tempfile.gettempdir()) / f"h56-demo-{uuid.uuid4().hex}")
    try:
        resolved = work.resolve()
    except OSError as exc:
        raise ValueError(f"无法解析运行目录：{work}") from exc
    if is_within(resolved, PRODUCT):
        raise ValueError(f"运行目录不能位于产品根内：{resolved}")
    if resolved.exists():
        raise ValueError(f"运行目录必须是尚不存在的独占目录：{resolved}")
    try:
        resolved.mkdir(parents=True, exist_ok=False)
        owner = uuid.uuid4().hex
        marker = resolved / ".h56-demo-owner"
        marker.write_text(owner, encoding="ascii")
        return resolved, marker, owner
    except OSError as exc:
        raise ValueError(f"无法创建独占运行目录：{resolved}") from exc


def cleanup_owned_workdir(work, marker, owner):
    """Only remove the directory created by this invocation and still owned by it."""
    try:
        if is_within(work, PRODUCT) or not marker.is_file():
            return False
        if marker.read_text(encoding="ascii") != owner:
            return False
        shutil.rmtree(work)
        return True
    except OSError:
        return False


def validate_report_path(requested, work):
    """Accept only a new report path inside the owned run directory."""
    if requested is None:
        return None
    report_path = Path(requested).resolve()
    if not is_within(report_path, work) or report_path == Path(work).resolve():
        raise ValueError(f"结果文件必须位于本次运行目录内：{report_path}")
    if report_path.exists():
        raise ValueError(f"结果文件不得预先存在：{report_path}")
    return report_path


def load_pairs(use_all, cases=None):
    if cases:
        # 受控场景入口：只接受 model_ingress_v1/registry.json 中已登记的 id。
        # 惰性导入 —— 删掉 model_ingress_v1/ 后，默认模式与 --all 完全不受影响。
        from model_ingress_v1 import registry
        return [registry.resolve_pair(cid) for cid in cases]
    if not use_all:
        return MAIN
    cases_data = json.loads(CASES_FILE.read_text(encoding="utf-8"))["cases"]
    out = []
    for c in cases_data:
        for i in range(len(c.get("variants") or [{}])):
            out.append((c["id"], i))
    return out


def describe_variant(case_id, variant):
    """把该变体相对基准信封的真实改动翻译成一句话，供人工核对「确实施加了操作」。"""
    data = json.loads(CASES_FILE.read_text(encoding="utf-8"))
    selected = next(c for c in data["cases"] if c["id"] == case_id)["variants"][variant]
    parts = []
    for field in selected.get("remove", []):
        parts.append(f"移除字段 {field}")
    for field, value in sorted(selected.get("fields", {}).items()):
        parts.append(f"{field} = {json.dumps(value, ensure_ascii=False)}")
    for field in selected.get("unknown", []):
        parts.append(f"{field} 标记为 UNKNOWN")
    for field, stamp in sorted(selected.get("observed_at", {}).items()):
        parts.append(f"{field}.observed_at = {stamp}")
    for field, level in sorted(selected.get("coverage", {}).items()):
        parts.append(f"{field}.coverage = {level}")
    for field, patch in sorted(selected.get("knowledge_value", {}).items()):
        parts.append(f"{field} 知识态改写为 {json.dumps(patch, ensure_ascii=False)}")
    if selected.get("conflicting_field"):
        parts.append("追加一条取值相反的重复证据项（冲突）")
    elif selected.get("duplicate_field"):
        parts.append("追加一条同名字段证据项（重复）")
    if selected.get("duplicate_id"):
        parts.append("令两个证据项复用同一 evidence_id")
    if selected.get("strict_type_field"):
        parts.append(f"{selected['strict_type_field']} 置为非法类型 "
                     f"{json.dumps(selected.get('invalid_value'), ensure_ascii=False)}")
    if selected.get("envelope"):
        parts.append("信封顶层字段改写 " + json.dumps(selected["envelope"], ensure_ascii=False))
    return "；".join(parts) if parts else "无改动（基准信封）"


def run_case(python, root, session, case_id, variant, request_id, parent_ref=None):
    """在同一 root / session 下写输入并调用真实 CLI，返回 (退出码, payload)。"""
    (root / "in").mkdir(parents=True, exist_ok=True)
    (root / "out").mkdir(parents=True, exist_ok=True)
    envelope = case_envelope(case_id, variant)
    raw_evidence = evidence_bytes(envelope)
    request = metadata(envelope, request_id)
    request["source_manifest_sha256"] = sha256(MANIFEST.read_bytes())
    request["asset_manifest_sha256"] = sha256(ASSETS_MANIFEST.read_bytes())
    request["raw_evidence_sha256"] = sha256(raw_evidence)
    if parent_ref is not None:
        request["parent_decision_ref"] = parent_ref
    (root / "in" / "evidence.json").write_bytes(raw_evidence)
    (root / "in" / "request.json").write_bytes(
        json.dumps(request, sort_keys=True, separators=(",", ":")).encode())

    binding = dict(
        schema="H56_OFFLINE_OPERATION_BINDING_V1", operation="evaluate",
        input_root=str(root / "in"), output_root=str(root / "out"), session=session,
        request_sha256=sha256((root / "in" / "request.json").read_bytes()),
        evidence_sha256=sha256(raw_evidence),
        source_manifest_sha256=request["source_manifest_sha256"],
        asset_manifest_sha256=request["asset_manifest_sha256"], reference=None)
    path = root / "binding.json"
    path.write_bytes(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode())

    proc = subprocess.run(
        [python, "-I", "-B", "-S", "-X", "utf8", str(CLI), "evaluate",
         "--binding", str(path), "--binding-sha256", sha256(path.read_bytes())],
        env=_clean_env(), capture_output=True, text=True, cwd=str(root), timeout=300)
    if not proc.stdout.strip():
        return proc.returncode, {"status": "NO_OUTPUT", "stderr": proc.stderr[-400:]}
    return proc.returncode, json.loads(proc.stdout.strip())


def outcome(payload):
    """归约为 (类别, 值)。类别 ∈ DECIDED / REJECTED。"""
    if "record" in payload:
        projection = payload["record"].get("c2_projection")
        return "DECIDED", (projection["decision"] if projection else "NO_PROJECTION")
    return "REJECTED", payload.get("reason") or payload.get("status") or "UNKNOWN"


def native_calls(payload):
    return (payload.get("record") or {}).get("source_validation", {}).get("recorded_native_calls")


def artifact_index(session_dir, work):
    """列出一次评估落盘的全部证据文件（相对路径 + 字节数 + sha256），供 UI 展示证据链。"""
    out = []
    if not session_dir.exists():
        return out
    for path in sorted(session_dir.rglob("*")):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        out.append({
            "rel": path.relative_to(work).as_posix(),
            "bytes": len(raw),
            "sha256": sha256(raw),
        })
    return out


def sealed_files(session_dir):
    """已封存证据：artifacts/ 与 claims/ 下的 JSON。events.jsonl 是追加日志，不在不可变断言范围内。"""
    files = {}
    for sub in ("artifacts", "claims"):
        directory = session_dir / sub
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.json")):
            files[f"{sub}/{path.name}"] = path.read_bytes()
    return files


def ver(python):
    try:
        out = subprocess.run([python, "-c", "import sys;print('%d.%d.%d' % sys.version_info[:3])"],
                             env=_clean_env(), capture_output=True, text=True, timeout=30)
        return out.stdout.strip()
    except Exception:
        return "?"


def main():
    ap = argparse.ArgumentParser(description="h56 离线资格评估一键演示")
    ap.add_argument("--all", action="store_true", help="跑全部 31 案件 / 56 变体")
    ap.add_argument("--python", default=sys.executable, help="主解释器")
    ap.add_argument("--compare-python", default=None, help="跨版本比对的第二个解释器")
    ap.add_argument("--work-dir", default=None,
                    help="尚不存在、位于产品根之外的独占运行目录")
    ap.add_argument("--emit-baseline", action="store_true", help="打印冻结基线字面量")
    ap.add_argument("--keep", action="store_true", help="保留运行目录")
    ap.add_argument("--json", default=None, metavar="PATH",
                    help="把结构化结果写入运行目录内的 PATH（每完成一个变体刷新一次）")
    ap.add_argument("--cases", default=None, metavar="ID",
                    help="只跑 model_ingress_v1/registry.json 中已登记的场景 id"
                         "（逗号分隔可多个）")
    args = ap.parse_args()

    scenarios = None
    if args.cases:
        wanted = [s.strip() for s in args.cases.split(",") if s.strip()]
        try:
            scenarios = load_pairs(False, wanted)
        except Exception as exc:
            print(f"场景解析失败（未创建运行目录）：{exc}")
            return 2

    try:
        work, owner_marker, owner = create_owned_workdir(args.work_dir)
    except ValueError as exc:
        print(exc)
        return 2

    python = args.python
    pairs = scenarios if scenarios is not None else load_pairs(args.all)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    print("=" * 78)
    print("h56 离线资格评估 · 一键演示")
    print("=" * 78)
    print(f"产品根    : {PRODUCT}")
    print(f"解释器    : {python}  (Python {ver(python)})")
    print(f"运行目录  : {work}")
    print(f"案件      : {len(pairs)} 个变体"
          + ("（受控场景入口，来自 model_ingress_v1 登记表）" if args.cases
             else ("（全量回归基线）" if args.all
                   else "（演示主线，--all 跑全量）")))
    print(f"清单成员  : {len(manifest['runtime_required'])} 条 runtime_required")
    print()

    props = []

    def prop(pid, name, status, detail=""):
        props.append({"id": pid, "name": name, "status": status, "detail": detail})

    report = {
        "schema": "H56_DEMO_REPORT_V1",
        "mode": "scenario" if args.cases else ("all" if args.all else "main"),
        "product_root": str(PRODUCT),
        "work_dir": str(work),
        "interpreter": {"path": python, "version": ver(python)},
        "manifest_members": len(manifest["runtime_required"]),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status": "RUNNING",
        "progress": {"done": 0, "total": len(pairs)},
        "rows": [],
        "properties": props,
        "counts": {},
        "compare_interpreter": None,
    }
    try:
        json_path = validate_report_path(args.json, work)
    except ValueError as exc:
        print(exc)
        cleanup_owned_workdir(work, owner_marker, owner)
        return 2
    if json_path is not None:
        json_path.parent.mkdir(parents=True, exist_ok=True)

    def flush_report():
        if json_path is None:
            return
        tmp = json_path.with_name(json_path.name + ".tmp")
        tmp.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        tmp.replace(json_path)

    started = time.time()
    broken = []
    for case_id, variant in pairs:
        root = work / f"{case_id}_v{variant}" / "op"
        session = f"oq_{case_id}_{variant}"
        code, payload = run_case(python, root, session, case_id, variant, "r1")
        kind, value = outcome(payload)
        if kind == "REJECTED" and value in ("UNKNOWN", "NO_OUTPUT"):
            broken.append(f"{case_id}v{variant} 既无记录也无原因码")
        record = payload.get("record") or {}
        projection = record.get("c2_projection") or {}
        key = f"{case_id}v{variant}"
        baseline = EXPECTED.get(key)
        input_sha = sha256(evidence_bytes(case_envelope(case_id, variant)))
        report["rows"].append({
            "key": key, "case": case_id, "variant": variant, "session": session,
            "input_sha256": input_sha,
            "variant_note": describe_variant(case_id, variant),
            "exit": code, "kind": kind, "value": value,
            "expected": list(baseline) if baseline else None,
            "match": ([kind, value] == list(baseline)) if baseline else None,
            "stop_status": payload.get("status"),
            "stop_stage": payload.get("stage") or record.get("stage"),
            "native_calls": native_calls(payload),
            "semantic_sha256": record.get("semantic_sha256"),
            "decision_id": record.get("decision_id"),
            "assessment_id": record.get("assessment_id"),
            "decision": projection.get("decision"),
            "reason_codes": record.get("reason_codes") or [],
            "parent_decision_ref": record.get("parent_decision_ref"),
            "authority_granted": projection.get("authority_granted"),
            "execution_permitted": projection.get("execution_permitted"),
            "candidate_planning_only": projection.get("candidate_planning_only"),
            "evidence": artifact_index(root / "out" / session, work),
        })
        report["progress"]["done"] = len(report["rows"])
        flush_report()
    elapsed = time.time() - started

    print(f"{'案件':<7}{'变体':<5}{'退出':<5}{'类别':<10}{'判定 / 拒绝码':<36}{'原生调用':<9}semantic_sha256")
    print("-" * 78)
    for row in report["rows"]:
        print(f"{row['case']:<7}{row['variant']:<5}{str(row['exit']):<5}{row['kind']:<10}"
              f"{str(row['value']):<36}{str(row['native_calls']):<9}"
              f"{str(row['semantic_sha256'])[:18]}")
    print("-" * 78)
    decided = sum(1 for r in report["rows"] if r["kind"] == "DECIDED")
    print(f"{len(report['rows'])} 个变体：DECIDED {decided} / "
          f"REJECTED {len(report['rows']) - decided}，耗时 {elapsed:.1f}s")

    decisions, reasons = {}, {}
    for row in report["rows"]:
        bucket = decisions if row["kind"] == "DECIDED" else reasons
        bucket[row["value"]] = bucket.get(row["value"], 0) + 1
    report["counts"] = {
        "variants": len(report["rows"]),
        "decided": decided,
        "rejected": len(report["rows"]) - decided,
        "decisions": decisions,
        "reason_codes": reasons,
        "elapsed_seconds": round(elapsed, 1),
    }

    # 有效覆盖：按输入证据字节聚类。仅统计每组的代表行，避免把同一字节串的重复跑动
    # 计成多项独立能力。
    groups = {}
    for row in report["rows"]:
        groups.setdefault(row["input_sha256"], []).append(row)
    distinct_decisions, distinct_reasons = {}, {}
    for rows in groups.values():
        rep = rows[0]
        bucket = distinct_decisions if rep["kind"] == "DECIDED" else distinct_reasons
        bucket[rep["value"]] = bucket.get(rep["value"], 0) + 1
    report["coverage"] = {
        "rows": len(report["rows"]),
        "distinct_inputs": len(groups),
        "duplicate_rows": len(report["rows"]) - len(groups),
        "distinct_decisions": distinct_decisions,
        "distinct_reasons": distinct_reasons,
    }

    print(f"有效覆盖：{len(report['rows'])} 行中，输入证据字节互不相同的有 "
          f"{len(groups)} 条，其余 {len(report['rows']) - len(groups)} 行与其中某一条逐字节相同")
    print("  真实判定分布：" + "、".join(
        f"{k} {v}" for k, v in sorted(distinct_decisions.items())))
    if distinct_reasons:
        print("  真实拒斥分布：" + "、".join(
            f"{k} {v}" for k, v in sorted(distinct_reasons.items())))
    if not args.all:
        print()
        print("场景明细 —— 输入是真实构造的，判定由四核计算得出：" if args.cases
              else "演示主线 —— 每行输入都是真实构造的，且互不相同：")
        for row in report["rows"]:
            print(f"  {row['key']:<6} {row['kind']:<9}{row['value']:<26}"
                  f"输入 {row['input_sha256'][:12]}  {row['variant_note']}")
    print()

    if args.emit_baseline:
        print("EXPECTED = {")
        for row in report["rows"]:
            print(f'    "{row["key"]}": ("{row["kind"]}", "{row["value"]}"),')
        print("}")
        print()
        return 0

    failures = list(broken)

    if EXPECTED:
        mismatch = [(r["key"], tuple(r["expected"]), (r["kind"], r["value"]))
                    for r in report["rows"]
                    if r["expected"] and tuple(r["expected"]) != (r["kind"], r["value"])]
        print(f"[1] 结局与冻结基线一致        {'PASS' if not mismatch else 'FAIL'}"
              f"  {len(report['rows']) - len(mismatch)}/{len(report['rows'])}")
        for m in mismatch[:3]:
            print(f"      {m[0]}：基线 {m[1]} → 现在 {m[2]}")
        prop(1, "结局与冻结基线一致", "PASS" if not mismatch else "FAIL",
             f"{len(report['rows']) - len(mismatch)}/{len(report['rows'])} 变体与冻结基线一致")
        if mismatch:
            failures.append("结局与基线不一致")
    else:
        print("[1] 结局与冻结基线一致        未设定基线（记录模式，用 --emit-baseline 生成）")
        prop(1, "结局与冻结基线一致", "SKIP", "未设定基线")

    idem_root = work / "idem" / "op"
    _, first = run_case(python, idem_root, "oq_idem", "C01", 0, "same_req")
    _, again = run_case(python, idem_root, "oq_idem", "C01", 0, "same_req")
    r1 = first.get("record") or {}
    r2 = again.get("record") or {}
    same_sem = bool(r1) and r1.get("semantic_sha256") == r2.get("semantic_sha256")
    same_dec = bool(r1) and r1.get("decision_id") == r2.get("decision_id")
    print(f"[2] 同输入重复提交幂等        {'PASS' if same_sem and same_dec else 'FAIL'}"
          f"  semantic_sha256={'相同' if same_sem else '不同'} "
          f"decision_id={'相同' if same_dec else '不同'}")
    prop(2, "同输入重复提交幂等", "PASS" if same_sem and same_dec else "FAIL",
         f"semantic_sha256={'相同' if same_sem else '不同'}，"
         f"decision_id={'相同' if same_dec else '不同'}")
    if not (same_sem and same_dec):
        failures.append("幂等失败")

    if args.compare_python:
        _, other = run_case(args.compare_python, work / "crossver" / "op", "oq_cross",
                            "C01", 0, "same_req")
        sem_other = (other.get("record") or {}).get("semantic_sha256")
        cross = sem_other is not None and sem_other == r1.get("semantic_sha256")
        print(f"[3] 跨 Python 版本字节一致    {'PASS' if cross else 'FAIL'}"
              f"  {ver(python)} vs {ver(args.compare_python)}")
        report["compare_interpreter"] = {
            "path": args.compare_python, "version": ver(args.compare_python)}
        prop(3, "跨 Python 版本字节一致", "PASS" if cross else "FAIL",
             f"semantic_sha256 在 {ver(python)} 与 {ver(args.compare_python)} 之间"
             f"{'逐字节相同' if cross else '不同'}")
        if not cross:
            failures.append("跨版本 semantic_sha256 不一致")
    else:
        print("[3] 跨 Python 版本字节一致    跳过（未提供 --compare-python）")
        prop(3, "跨 Python 版本字节一致", "SKIP", "未提供 --compare-python")

    root = work / "chain" / "op"
    _, base = run_case(python, root, "oq_chain", "B01", 0, "parent_req")
    base_record = base.get("record") or {}
    before = sealed_files(root / "out" / "oq_chain")

    from offline_qualification_v1.records import RecordStore
    store = RecordStore(root / "out", "oq_chain", create=False)
    parent = store.reference(store._events()[0])
    _, child = run_case(python, root, "oq_chain", "C01", 0, "child_req", parent_ref=parent)
    child_record = child.get("record") or {}
    has_parent = bool(child_record.get("parent_decision_ref"))
    new_assessment = bool(child_record) and \
        child_record.get("assessment_id") != base_record.get("assessment_id")
    child_decision = (child_record.get("c2_projection") or {}).get("decision")
    print(f"[4] 补证后独立重评挂父引用    {'PASS' if has_parent and new_assessment else 'FAIL'}"
          f"  父引用={'SET' if has_parent else 'NONE'} 新评估={new_assessment} 子判定={child_decision}")
    prop(4, "补证后独立重评挂父引用", "PASS" if has_parent and new_assessment else "FAIL",
         f"父引用={'SET' if has_parent else 'NONE'}，新评估={new_assessment}，子判定={child_decision}")
    if not (has_parent and new_assessment):
        failures.append("父引用未生效")

    after = sealed_files(root / "out" / "oq_chain")
    unchanged = bool(before) and all(before[k] == after.get(k) for k in before)
    print(f"[5] 已封存记录字节不变        {'PASS' if unchanged else 'FAIL'}"
          f"  {len(before)} 个产物文件逐一比对")
    prop(5, "已封存记录字节不变", "PASS" if unchanged else "FAIL",
         f"{len(before)} 个已封存文件（artifacts/claims）在后续评估后逐字节不变")
    if not unchanged:
        failures.append("历史记录被改写")

    view_binding = dict(
        schema="H56_OFFLINE_OPERATION_BINDING_V1", operation="view",
        input_root=str(root / "in"), output_root=str(root / "out"), session="oq_chain",
        request_sha256=sha256((root / "in" / "request.json").read_bytes()),
        evidence_sha256="0" * 64,
        source_manifest_sha256=sha256(MANIFEST.read_bytes()),
        asset_manifest_sha256=sha256(ASSETS_MANIFEST.read_bytes()), reference=parent)
    view_path = work / "chain" / "view.json"
    view_path.write_bytes(json.dumps(view_binding, sort_keys=True, separators=(",", ":")).encode())
    proc = subprocess.run(
        [python, "-I", "-B", "-S", "-X", "utf8", str(CLI), "view",
         "--binding", str(view_path), "--binding-sha256", sha256(view_path.read_bytes())],
        env=_clean_env(), capture_output=True, text=True, cwd=str(work / "chain"), timeout=300)
    replay = json.loads(proc.stdout.strip()) if proc.stdout.strip() else {}
    ok_replay = (proc.returncode == 0 and replay.get("integrity_checked") is True
                 and replay.get("native_recomputed") is False)
    print(f"[6] view 只读复演不重算内核   {'PASS' if ok_replay else 'FAIL'}"
          f"  integrity_checked={replay.get('integrity_checked')} "
          f"native_recomputed={replay.get('native_recomputed')}")
    prop(6, "view 只读复演不重算内核", "PASS" if ok_replay else "FAIL",
         f"integrity_checked={replay.get('integrity_checked')}，"
         f"native_recomputed={replay.get('native_recomputed')}")
    if not ok_replay:
        failures.append("只读复演失败")

    p = r1.get("c2_projection") or {}
    ok_boundary = (p.get("authority_granted") is False and p.get("execution_permitted") is False
                   and p.get("candidate_planning_only") is True)
    print(f"[7] 授权边界未被越过          {'PASS' if ok_boundary else 'FAIL'}"
          f"  authority_granted={p.get('authority_granted')} "
          f"execution_permitted={p.get('execution_permitted')} "
          f"candidate_planning_only={p.get('candidate_planning_only')}")
    prop(7, "授权边界未被越过", "PASS" if ok_boundary else "FAIL",
         f"authority_granted={p.get('authority_granted')}，"
         f"execution_permitted={p.get('execution_permitted')}，"
         f"candidate_planning_only={p.get('candidate_planning_only')}")
    if not ok_boundary:
        failures.append("授权边界被越过")

    skipped = [p for p in props if p["status"] == "SKIP"]
    report["result"] = ("FAIL" if failures else
                        "PASS_WITH_SKIPS" if skipped else "PASS")
    report["failures"] = failures
    report["status"] = "DONE" if not failures else "FAILED"
    report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    report["progress"]["done"] = len(report["rows"])
    flush_report()

    print()
    if failures:
        print(f"结果：FAIL —— {len(failures)} 项未通过")
        for f in failures[:10]:
            print("   -", f)
    elif skipped:
        print(f"结果：PASS_WITH_SKIPS —— {len(props) - len(skipped)} 项通过，"
              f"{len(skipped)} 项跳过")
    else:
        print("结果：PASS —— 7 项性质全部成立")
    print(f"运行产物：{work}" + ("（保留）" if args.keep else "（已清理，--keep 可保留）"))
    print("=" * 78)
    if not args.keep:
        removed = cleanup_owned_workdir(work, owner_marker, owner)
        if not removed:
            print(f"运行目录未清理（所有权校验未通过）：{work}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
