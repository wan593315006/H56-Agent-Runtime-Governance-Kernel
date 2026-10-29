"""已登记场景表：加载、自校验、解析。

这是外围 Adapter 与产品之间唯一允许的「场景」边界。模型看不到本文件以外
的任何东西；本文件也不含事实、证据或状态字段，只含标识与一句话意图描述。

自校验是硬前置：任何一条 scenario 的 case_id / variant 若在
offline_qualification_v1/fixtures/cases.json 中不存在，加载即失败
（REGISTRY_INTEGRITY_FAILED），不进入后续任何步骤。
"""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).absolute().parent
PRODUCT = HERE.parent
REGISTRY_PATH = HERE / "registry.json"
CASES_FILE = PRODUCT / "offline_qualification_v1" / "fixtures" / "cases.json"

SCHEMA = "H56_MODEL_INGRESS_REGISTRY_V1"
REQUIRED_KEYS = {"scenario_id", "case_id", "variant", "registered_outcome",
                 "expected_cli_exit", "intent_hint", "note"}
EXPECTED_COUNT = 6

# 进入模型上下文的键：只有这两个。其余键（含 expected_cli_exit 与
# registered_outcome）永远不得出现在 prompt 里，由 test_ingress 的负例守着。
MODEL_VISIBLE_KEYS = ("scenario_id", "intent_hint")


class RegistryError(Exception):
    """REGISTRY_INTEGRITY_FAILED —— 加载期失败，不是运行期拒绝。"""

    code = "REGISTRY_INTEGRITY_FAILED"

    def __init__(self, detail):
        super().__init__(f"{self.code}: {detail}")
        self.detail = detail


def _case_index():
    """从 cases.json 取 {case_id: 变体数}。这是唯一的事实来源。"""
    try:
        data = json.loads(CASES_FILE.read_text(encoding="utf-8"))
        cases = data["cases"]
    except Exception as exc:  # 缺文件、坏 JSON 都算登记表不自洽
        raise RegistryError(f"无法读取 cases.json：{type(exc).__name__}")
    return {c["id"]: len(c.get("variants") or [{}]) for c in cases}


def registry_sha256(path=None):
    p = Path(path) if path else REGISTRY_PATH
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load(path=None):
    """加载并自校验，返回 scenario 列表（保持文件顺序）。"""
    p = Path(path) if path else REGISTRY_PATH
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RegistryError(f"无法读取 registry：{type(exc).__name__}")
    if not isinstance(raw, dict):
        raise RegistryError("registry 顶层不是对象")
    if raw.get("schema") != SCHEMA:
        raise RegistryError(f"schema 不符：{raw.get('schema')!r}")
    scenarios = raw.get("scenarios")
    if not isinstance(scenarios, list):
        raise RegistryError("scenarios 不是数组")
    if len(scenarios) != EXPECTED_COUNT:
        raise RegistryError(f"场景数应为 {EXPECTED_COUNT}，实际 {len(scenarios)}")

    index = _case_index()
    seen = set()
    for i, s in enumerate(scenarios):
        if not isinstance(s, dict):
            raise RegistryError(f"第 {i} 条不是对象")
        if set(s.keys()) != REQUIRED_KEYS:
            raise RegistryError(
                f"第 {i} 条键集不符：{sorted(s.keys())}")
        sid = s["scenario_id"]
        if not isinstance(sid, str) or not sid.startswith("S-"):
            raise RegistryError(f"第 {i} 条 scenario_id 非法：{sid!r}")
        if sid in seen:
            raise RegistryError(f"scenario_id 重复：{sid}")
        seen.add(sid)
        cid, var = s["case_id"], s["variant"]
        if cid not in index:
            raise RegistryError(f"{sid} 的 case_id 不存在于 cases.json：{cid!r}")
        if not isinstance(var, int) or isinstance(var, bool):
            raise RegistryError(f"{sid} 的 variant 不是整数：{var!r}")
        if not 0 <= var < index[cid]:
            raise RegistryError(
                f"{sid} 的 variant 越界：{cid} 只有 {index[cid]} 个变体")
        for k in ("registered_outcome", "intent_hint", "note"):
            if not isinstance(s[k], str) or not s[k].strip():
                raise RegistryError(f"{sid} 的 {k} 必须是非空字符串")
        exp = s["expected_cli_exit"]
        if not isinstance(exp, int) or isinstance(exp, bool):
            raise RegistryError(f"{sid} 的 expected_cli_exit 不是整数：{exp!r}")
    return scenarios


def ids(path=None):
    return {s["scenario_id"] for s in load(path)}


def resolve(scenario_id, path=None):
    """scenario_id -> 完整登记记录。未登记抛 RegistryError。"""
    for s in load(path):
        if s["scenario_id"] == scenario_id:
            return dict(s)
    raise RegistryError(f"未登记的场景：{scenario_id!r}")


def resolve_pair(scenario_id, path=None):
    """scenario_id -> (case_id, variant)，供 demo.py --cases 使用。"""
    s = resolve(scenario_id, path)
    return s["case_id"], s["variant"]
