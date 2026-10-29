"""运行身份固定：源码、测试输入、解释器。

目的只有一个：让「这次测试跑的是哪一份代码」不再依赖 mtime 或记忆。

背景（A2 run1/run2 的教训）：当时 `model_ingress_v1/` 是 untracked，两次运行
之间改过源码却没有任何记录，事后只能靠文件时间反推「这是两棵树」。
本模块把该隐患变成可检测项：运行前后各采一次身份，不一致即报警。

采集范围：产品树内全部 .py / .json / .md 等文本产物，**排除**
__pycache__、*.pyc、.git、out、work、evidence。缓存文件必须排除，
否则「编译缓存是否命中」会被误当成「源码是否变化」。
"""

import hashlib
import json
import os
import platform
import sys
from pathlib import Path

EXCLUDE_DIR_NAMES = {
    "__pycache__", ".git", ".hg", ".svn", "out", "work", "evidence",
    "node_modules", ".pytest_cache", ".mypy_cache",
}
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".pyd", ".log", ".tmp"}

# 纯文档后缀。这些文件进身份清单（用来看「树里有什么」），
# 但不进代码身份（证据绑定用它），因此改 README 不需要重跑案例。
DOC_SUFFIXES = (".md", ".markdown", ".rst", ".txt")

MANIFEST_SCHEMA = "H56_RUN_IDENTITY_V2"


def _iter_files(root):
    root = Path(root)
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in EXCLUDE_DIR_NAMES for part in p.parts):
            continue
        if p.suffix.lower() in EXCLUDE_SUFFIXES:
            continue
        yield p


class IdentityPathCollision(Exception):
    """两个不同文件映射到同一个身份路径。宁可直接失败，也不静默覆盖。"""


def canonical_path(product_root, path):
    """把任意路径规范成「相对产品根」的 POSIX 路径。

    这是本模块唯一的路径口径。修复前的实现按「相对各自 root」计算，
    于是 `model_ingress_v1/tests/x.py` 与 `offline_qualification_v1/tests/x.py`
    都会得到 `tests/x.py`；`runtime_*/SOURCE_MANIFEST.json` 等同名文件更是
    一个路径压住四个文件。相对产品根之后，路径与磁盘位置一一对应，
    碰撞在构造上不可能发生。
    """
    product = Path(os.path.normpath(os.path.abspath(str(product_root))))
    target = Path(os.path.normpath(os.path.abspath(str(path))))
    try:
        return target.relative_to(product).as_posix()
    except ValueError:
        # root 在产品树之外：保留绝对路径，不做任何猜测性裁剪。
        return "external:" + target.as_posix()


def file_entries(product_root, roots):
    """返回 [{path, bytes, sha256}]，path 一律相对产品根（唯一口径）。

    同一个物理文件被重叠的 root 重复扫到时按规范路径去重（记入
    `overlaps` 供调用方知情）；不同文件若落到同一路径则抛
    IdentityPathCollision —— 不以字典覆盖掩盖差异。
    """
    product = Path(os.path.normpath(os.path.abspath(str(product_root))))
    out = []
    by_path = {}
    overlaps = []
    for root in roots:
        root_p = product / root
        if not root_p.exists():
            continue
        for f in _iter_files(root_p):
            rel = canonical_path(product, f)
            if rel in by_path:
                prev = by_path[rel]
                if prev == str(f):
                    overlaps.append({"path": rel, "root": str(root),
                                     "why": "重叠 root 重复扫到同一文件"})
                    continue
                raise IdentityPathCollision(
                    "%s 同时指向 %s 与 %s" % (rel, prev, f))
            by_path[rel] = str(f)
            try:
                raw = f.read_bytes()
            except OSError as exc:
                out.append({"path": rel, "error": type(exc).__name__})
                continue
            out.append({
                "path": rel,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
    out.sort(key=lambda e: e.get("path", ""))
    return out, overlaps


def manifest_sha256(entries):
    """对 (path, sha256) 序列取合成摘要。文件顺序固定，故可复算。"""
    h = hashlib.sha256()
    for e in entries:
        h.update(("%s\0%s\n" % (e.get("path", ""), e.get("sha256", ""))).encode("utf-8"))
    return h.hexdigest()


def code_entries(entries):
    """剔除纯文档后的成员。README 等 .md 变更不应改变代码身份。

    证据绑定的应该是「会执行的东西」，而不是「会被人读的东西」。
    """
    return [e for e in entries
            if not e.get("path", "").lower().endswith(DOC_SUFFIXES)]


def duplicate_paths(entries):
    """返回重复的 path 列表（空列表 = 每个成员身份唯一）。"""
    seen = {}
    dup = []
    for e in entries:
        p = e.get("path", "")
        if p in seen and p not in dup:
            dup.append(p)
        seen[p] = True
    return dup


def interpreter_identity(python=None):
    """解释器身份。exe 本身也取哈希，避免「同版本不同二进制」。"""
    exe = Path(python or sys.executable).absolute()
    info = {
        "executable": str(exe),
        "version": sys.version,
        "version_info": list(sys.version_info[:3]),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
    }
    try:
        raw = exe.read_bytes()
        info["executable_sha256"] = hashlib.sha256(raw).hexdigest()
        info["executable_bytes"] = len(raw)
    except OSError as exc:
        info["executable_sha256"] = None
        info["executable_error"] = type(exc).__name__
    return info


def collect(product_root, roots, python=None):
    """采一份完整身份。roots 为相对 product_root 的路径列表。

    路径不存在不会被静默跳过：缺失的 root 会进 `roots_missing`，由调用方断言。
    静默跳过会让「身份清单少了一半」看起来和「代码没变」一模一样。

    成员身份唯一性在此强制：一旦出现重复 path 直接抛 IdentityPathCollision，
    不会靠 dict 后写覆盖先写把差异吞掉。
    """
    product = Path(product_root).absolute()
    abs_roots = [product / r for r in roots]
    missing = [r for r, p in zip(roots, abs_roots) if not p.exists()]
    entries, overlaps = file_entries(product, roots)
    dup = duplicate_paths(entries)
    if dup:
        raise IdentityPathCollision("身份清单出现重复路径：%r" % (dup[:5],))
    code = code_entries(entries)
    return {
        "schema": MANIFEST_SCHEMA,
        "product_root": str(product),
        "roots": list(roots),
        "roots_missing": missing,
        "excluded_dir_names": sorted(EXCLUDE_DIR_NAMES),
        "excluded_suffixes": sorted(EXCLUDE_SUFFIXES),
        "doc_suffixes": list(DOC_SUFFIXES),
        "overlapping_root_hits": overlaps,
        "file_count": len(entries),
        "file_bytes_total": sum(e.get("bytes", 0) for e in entries),
        "path_duplicates": dup,
        "unique_path_count": len({e.get("path") for e in entries}),
        "manifest_sha256": manifest_sha256(entries),
        "code_file_count": len(code),
        "code_manifest_sha256": manifest_sha256(code),
        "code_identity_note": (
            "代码身份剔除 %s；证据绑定用 code_manifest_sha256，"
            "因此纯文档变更（如 README）不改变代码身份，也不需要重跑案例。"
            % (", ".join(DOC_SUFFIXES),)),
        "files": entries,
        "interpreter": interpreter_identity(python),
    }


DEFAULT_ROOTS = (
    "model_ingress_v1",
    "offline_qualification_v1",
    "runtime_binding_v1_20261024",
    "runtime_windows",
    "ui",
    "demo.py",
    "run_tests.py",
    "README.md",
    "DEMO_GUIDE.md",
    "ARCHITECTURE.md",
    "RECOVERY_GUIDE.md",
)


def diff(before, after):
    """比较两次采集。返回差异清单（空列表 = 一致）。

    修复前的实现把成员塞进 {path: sha256}，重名时后写覆盖先写：
    `runtime_support_v1_20261024/SOURCE_MANIFEST.json` 一变，
    若排序在其后的同名成员没变，差异就会被吞掉。
    现在先各自检查重复，再把多重集当作多重集来比。
    """
    issues = []
    for side, snap in (("before", before), ("after", after)):
        for p in duplicate_paths(snap.get("files", [])):
            issues.append({"path": p, "issue": "duplicate_path_in_" + side,
                           "detail": "同一身份路径对应多个文件，差异比对不可信"})
    b = {}
    a = {}
    for e in before.get("files", []):
        b.setdefault(e.get("path"), []).append(e.get("sha256"))
    for e in after.get("files", []):
        a.setdefault(e.get("path"), []).append(e.get("sha256"))
    for p in sorted(set(b) | set(a)):
        if sorted(b.get(p, [])) != sorted(a.get(p, [])):
            issues.append({"path": p,
                           "before": b.get(p),
                           "after": a.get(p)})
    if before.get("code_manifest_sha256") != after.get("code_manifest_sha256"):
        issues.append({"path": "<code_manifest>",
                       "before": before.get("code_manifest_sha256"),
                       "after": after.get("code_manifest_sha256"),
                       "detail": "代码身份变化（已排除纯文档），证据需要重取"})
    if before["interpreter"]["executable_sha256"] != \
            after["interpreter"]["executable_sha256"]:
        issues.append({"path": "<interpreter>",
                       "before": before["interpreter"]["executable_sha256"],
                       "after": after["interpreter"]["executable_sha256"]})
    return issues


def write(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    tmp.replace(p)
    return p
