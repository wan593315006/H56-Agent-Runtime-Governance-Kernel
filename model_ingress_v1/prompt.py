"""构造模型请求。

约束（施工合同 2.2）：本文件产出的 messages 只含
  1. 六条 scenario_id + 一句话意图描述；
  2. 用户意图原文；
  3. 输出格式要求。
**不含**任何事实、证据、状态、判定结果或 registered_outcome。

这不是风格问题：模型一旦看到上述任一字段，它就可能「生成」而不是「选择」，
而这条路线的全部价值在于模型只能挑一个已登记的场景编号。
"""

SCHEMA_HINT = """你必须只输出一个 JSON 对象，且恰好包含下列 5 个键，不得多也不得少：

{
  "decision": "SELECT" | "NOT_APPLICABLE" | "NEED_CLARIFICATION",
  "scenario_id": "<六条之一，或 null>",
  "clarification_question": "<10-300 字的问题，或 null>",
  "reason": "<不超过 500 字的自然语言说明>",
  "confidence": <0.0 到 1.0 之间的浮点数>
}

跨字段规则（违反即被拒绝）：
- decision = "SELECT"            → scenario_id 必须是下面六条之一；clarification_question 必须为 null
- decision = "NOT_APPLICABLE"    → scenario_id 与 clarification_question 都必须为 null
- decision = "NEED_CLARIFICATION"→ scenario_id 必须为 null；clarification_question 必须是 10-300 字

不要输出任何其他内容，不要用代码块包裹，不要解释你的格式。
你不得声明、暗示或建议任何执行授权、批准或权限；你只做场景匹配。"""


def build_system(scenarios):
    """scenarios: registry.load() 的返回值。只读取 id 与 intent_hint。"""
    lines = [
        "你是场景匹配器，不是决策者。",
        "",
        "下面是一个离线资格评估引擎已登记的场景清单。你的唯一任务是：",
        "判断用户意图是否对应其中某一个场景，并回答该场景的编号。",
        "",
        "你必须遵守：",
        "1. 不得把任何用户意图强行映射成某个场景；不匹配就回答 NOT_APPLICABLE。",
        "2. 信息不足以判断时，回答 NEED_CLARIFICATION 并给出一个具体问题。",
        "3. 你不知道也不得推断任何事实、证据、状态或最终的资格结论——",
        "   最终判定由确定性内核在收到场景编号后独立计算，与你无关。",
        "4. 你不得授予授权、不得声明执行许可、不得建议放行。",
        "",
        "已登记场景：",
    ]
    for s in scenarios:
        lines.append(f'- {s["scenario_id"]}：{s["intent_hint"]}')
    lines.append("")
    lines.append(SCHEMA_HINT)
    return "\n".join(lines)


def build_user(intent):
    """intent 是用户原始意图的自由文本，原样放入，不做任何改写或结构化。"""
    return f"用户意图如下（原始文本）：\n\n{intent}"


def build(intent, scenarios):
    """返回 OpenAI 兼容的 messages 数组。"""
    if not isinstance(intent, str) or not intent.strip():
        raise ValueError("用户意图不能为空")
    return [
        {"role": "system", "content": build_system(scenarios)},
        {"role": "user", "content": build_user(intent)},
    ]
