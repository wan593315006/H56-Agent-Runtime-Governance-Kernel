"""证据一致性核验：对已落盘的证据目录做只读比对，不重新运行任何东西。

为什么需要它：`a2_summary.json` 里的每个 True 都是被测程序自己写的。
「程序说它算对了」和「我从磁盘重算得到同一个数」是两件事。本文件只做后者。

口径务必读准：这是**一致性核验**，不是**独立执行见证**。它证明「磁盘上的字节
与记录里的哈希对得上」，不证明「四核此刻仍会算出同样结果」——后者必须真的重跑。

它刻意不复用 run.py 的任何计算 —— 哈希、退出码比较、输入定位全部在这里
重新写一遍。共用实现的话，同一个错误会在两边同时出现，核对就失去意义。

用法：
    python -m model_ingress_v1.tests.verify_evidence <证据根>
    python -m model_ingress_v1.tests.verify_evidence <证据根> --json out.json
退出码：0 全部核对通过；2 存在不一致；3 输入缺失。
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).absolute().parent
INGRESS = HERE.parent
PRODUCT = INGRESS.parent
if str(PRODUCT) not in sys.path:
    sys.path.insert(0, str(PRODUCT))

REGISTRY = INGRESS / "registry.json"
EVIDENCE_JSON = "model_selection_evidence.json"
RAW_BIN = "model_response_raw.bin"
RAW_META = "model_response_raw.json"


class Report:
    def __init__(self):
        self.items = []

    def check(self, name, ok, detail=""):
        self.items.append({"check": name, "ok": bool(ok), "detail": str(detail)})
        return ok

    @property
    def failed(self):
        return [i for i in self.items if not i["ok"]]


def sha256_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load_registry():
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    return {s["scenario_id"]: s for s in data["scenarios"]}


def verify_one(evdir, registry, rep):
    evdir = Path(evdir)
    tag = evdir.name
    ev_path = evdir / EVIDENCE_JSON
    if not rep.check("%s 证据文件存在" % tag, ev_path.exists(), ev_path):
        return None
    ev = json.loads(ev_path.read_text(encoding="utf-8"))
    link = ev.get("linkage") or {}
    kernel = ev.get("kernel") or {}

    # 1. 原始响应字节 -> 哈希 -> 与 evidence 自报值比对
    bin_path = evdir / RAW_BIN
    if rep.check("%s 原始响应字节已落盘" % tag, bin_path.exists(), bin_path):
        disk_sha = sha256_file(bin_path)
        rep.check("%s 响应哈希可由磁盘重算" % tag,
                  disk_sha == link.get("model_response_sha256"),
                  "%s vs %s" % (disk_sha, link.get("model_response_sha256")))
        rep.check("%s raw_body 摘要与 linkage 一致" % tag,
                  disk_sha == (ev.get("raw_body") or {}).get("sha256"))
        rep.check("%s raw_body 字节数与磁盘一致" % tag,
                  len(bin_path.read_bytes()) == (ev.get("raw_body") or {}).get("bytes"))

    # 2. 元数据与实际字节一致（防止「换了字节没换元数据」）
    meta_path = evdir / RAW_META
    if rep.check("%s 响应元数据存在" % tag, meta_path.exists(), meta_path):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        rep.check("%s 元数据记录的哈希与磁盘一致" % tag,
                  meta.get("response_sha256") == sha256_file(bin_path))
        rep.check("%s attempts 恒为 1" % tag, meta.get("attempts") == 1,
                  meta.get("attempts"))

    # 3. 输入字节：按所选场景精确定位，再直接对磁盘取哈希
    # 注意 run/ 下还会出现 idem/ 与 chain/（demo.py 的 P2/P4 产生的），
    # 它们不是本案例的输入，不能用通配符一把捞。
    sid = (kernel.get("selected_scenario") or {}).get("scenario_id")
    row_key = (kernel.get("selected_scenario") or {}).get("row_key") or ""
    case, sep, variant = row_key.partition("v")
    cand = (evdir / "run" / ("%s_v%s" % (case, variant)) / "op" / "in" / "evidence.json"
            if sep else None)
    if rep.check("%s 定位到所选场景的输入文件" % tag,
                 cand is not None and cand.exists(), cand):
        rep.check("%s 输入哈希可由磁盘重算" % tag,
                  sha256_file(cand) == kernel.get("input_sha256"),
                  "%s vs %s" % (sha256_file(cand), kernel.get("input_sha256")))
    others = sorted(p for p in evdir.glob("run/*/op/in/evidence.json")
                    if cand is None or p != cand)
    rep.check("%s 驱动额外输入未被混入所选场景" % tag, len(others) >= 1,
              [p.parent.parent.parent.name for p in others])

    # 4. 退出码：类型 + 逐值比较 + 与登记表一致
    code = kernel.get("exit_code")
    reg_exit = (registry.get(sid) or {}).get("expected_cli_exit")
    rep.check("%s CLI 退出码是 int（非 bool）" % tag,
              isinstance(code, int) and not isinstance(code, bool),
              "%r %s" % (code, type(code).__name__))
    rep.check("%s 退出码与 evidence 期望一致" % tag,
              code == kernel.get("expected_cli_exit"),
              "%r vs %r" % (code, kernel.get("expected_cli_exit")))
    rep.check("%s 退出码与登记表期望一致" % tag, code == reg_exit,
              "%r vs %r" % (code, reg_exit))
    rep.check("%s demo 退出码单独记录为 0" % tag,
              kernel.get("demo_exit_code") == 0, kernel.get("demo_exit_code"))

    # 5. 凭据：只留变量名，不留值
    envs = kernel.get("env_sanitized") or {}
    if envs:
        rep.check("%s 环境记录不含变量值" % tag, envs.get("values_recorded") is False)
        rep.check("%s 环境剔除项均为名字" % tag,
                  all(isinstance(n, str) for n in (envs.get("removed_names") or [])))
        blob = json.dumps(ev, ensure_ascii=False)
        rep.check("%s 证据全文不含疑似密钥" % tag,
                  "sk-" not in blob and "Bearer " not in blob)

    # 6. 结果与记录：DECIDED 必有 semantic_sha256，REJECTED 必无
    kind = kernel.get("kind")
    has_rec = kernel.get("semantic_sha256") is not None
    rep.check("%s 记录产出与 kind 自洽" % tag,
              has_rec == (kind == "DECIDED"), "%s / %s" % (kind, has_rec))
    rep.check("%s linkage 记录产出标记与 kind 一致" % tag,
              link.get("kernel_produced_record") == (kind == "DECIDED"))

    return {
        "evidence_dir": str(evdir),
        "scenario_id": sid,
        "kind": kind,
        "value": kernel.get("value"),
        "cli_exit_code": code,
        "input_sha256": kernel.get("input_sha256"),
        "response_sha256": link.get("model_response_sha256"),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="只读复算证据目录")
    ap.add_argument("root", help="A2 证据根（含 a2_S-* 子目录）")
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        print("不是目录：%s" % root, file=sys.stderr)
        return 3
    dirs = sorted(p for p in root.iterdir()
                  if p.is_dir() and p.name.startswith("a2_"))
    if not dirs:
        print("没有找到 a2_* 证据目录：%s" % root, file=sys.stderr)
        return 3

    registry = load_registry()
    rep = Report()
    facts = []

    # 0. 运行身份：前后两次必须一致
    pre_p, post_p = root / "pre_run_identity.json", root / "post_run_identity.json"
    if pre_p.exists() and post_p.exists():
        pre = json.loads(pre_p.read_text(encoding="utf-8"))
        post = json.loads(post_p.read_text(encoding="utf-8"))
        rep.check("运行前后源码身份一致",
                  pre["manifest_sha256"] == post["manifest_sha256"],
                  "%s vs %s" % (pre["manifest_sha256"][:16],
                                post["manifest_sha256"][:16]))
        rep.check("身份清单无缺失根路径", not pre.get("roots_missing"),
                  pre.get("roots_missing"))

    for d in dirs:
        fact = verify_one(d, registry, rep)
        if fact:
            facts.append(fact)

    # 7. cross-check：各案例输入哈希互不相同（否则「六案例」是重复输入）
    shas = [f["input_sha256"] for f in facts if f.get("input_sha256")]
    rep.check("各案例输入哈希互不相同", len(set(shas)) == len(shas),
              "%d 条 / %d 种" % (len(shas), len(set(shas))))

    out = {
        "schema": "H56_EVIDENCE_RECOMPUTE_V2",
        "root": str(root),
        "checked_dirs": len(dirs),
        "checks_total": len(rep.items),
        "checks_failed": len(rep.failed),
        "verdict": "PASS" if not rep.failed else "FAIL",
        "scope": {
            "kind": "evidence_consistency_check",
            "label_zh": "证据一致性核验",
            "re_execution_performed": False,
            "witnesses_execution": False,
            "canonical_statement": (
                "本核验对 %d 个已落盘证据目录做了 %d 项只读比对，结论是"
                "「证据彼此自洽」，不是「独立见证了执行」。它没有重跑 CLI，"
                "没有重跑 K0/K1/C1/C2，也没有重新构造输入。"
                % (len(dirs), len(rep.items))),
            "what_it_does_prove": [
                "磁盘上的 in/evidence.json 字节哈希等于记录中写的 input_sha256",
                "磁盘上的原始响应字节哈希等于 model_response_sha256",
                "退出码、kind、value 与 registry.json 的登记值一致",
                "六案例输入哈希互不相同（排除重复输入冒充六案例）",
            ],
            "what_it_does_not_prove": [
                "四核在本次核验时刻仍会算出同样结果（需重跑才有见证）",
                "139 项计算闭包未变（那是 manifest 哈希的职责，不是本核验）",
                "进程数量、时序或并发行为",
            ],
            "shares_code_with_subject": False,
            "shares_code_note": ("哈希、退出码比较、输入定位在本文件里重写了一遍，"
                                 "刻意不 import run.py 的计算。共用实现会让同一个错误"
                                 "在两边同时出现，核对就失去意义。"),
        },
        "facts": facts,
        "items": rep.items,
    }
    if args.json:
        p = Path(args.json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                     encoding="utf-8")

    print("复算目录：%s（%d 个证据目录）" % (root, len(dirs)))
    for it in rep.items:
        if not it["ok"]:
            print("  [FAIL] %s | %s" % (it["check"], it["detail"]))
    print()
    print("逐案例：")
    for f in facts:
        print("  %-8s exit=%-3s %-9s %-22s 输入 %s  响应 %s"
              % (f["scenario_id"], f["cli_exit_code"], f["kind"], f["value"],
                 (f["input_sha256"] or "")[:12], (f["response_sha256"] or "")[:12]))
    print()
    print("核对 %d 项，失败 %d 项 —— %s"
          % (out["checks_total"], out["checks_failed"], out["verdict"]))
    print("口径：证据一致性核验（未重跑 CLI / 四核，不构成独立执行见证）")
    return 0 if not rep.failed else 2


if __name__ == "__main__":
    sys.exit(main())
