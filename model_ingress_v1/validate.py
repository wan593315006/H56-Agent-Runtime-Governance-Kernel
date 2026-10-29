"""严格校验模型响应。禁止重试、禁止改写、禁止 fallback。

设计原则：
1. 失败关闭 —— 任何无法确证合法的输入一律拒绝，不尝试「修复」。
2. 顺序固定 —— 检查顺序是本文件的一部分契约，测试按此顺序断言。
3. 不产出事实上游 —— 本文件只判断「这个响应是否合规」，不对资格作任何推断。

检查顺序（顺序即契约）：
    1. 响应体长度              > 8192 B          -> MODEL_RESPONSE_TOO_LONG
    2. 外层 JSON               解析失败/非对象     -> MODEL_RESPONSE_MALFORMED
                               同层重复键         -> MODEL_RESPONSE_DUPLICATE_KEY
    3. 响应 model 身份          != 请求 model     -> MODEL_IDENTITY_UNPINNED
    4. choices[0].message.content                -> MODEL_RESPONSE_SCHEMA_VIOLATION
    5. content JSON            解析失败/非对象     -> MODEL_RESPONSE_MALFORMED
                               同层重复键         -> MODEL_RESPONSE_DUPLICATE_KEY
    6. 键集                     != 恰好 5 键      -> MODEL_RESPONSE_SCHEMA_VIOLATION
    7. 字段类型                                   -> MODEL_RESPONSE_SCHEMA_VIOLATION
    8. reason 长度              > 500 字          -> MODEL_RESPONSE_TOO_LONG
    9. 越权表述                                   -> MODEL_CLAIMED_AUTHORITY
   10. decision 取值不在三态内                     -> MODEL_RESPONSE_SCHEMA_VIOLATION
   11. 跨字段约束                                 -> MODEL_SELECTION_FIELD_CONFLICT
                                                  / MODEL_SELECTION_OUT_OF_REGISTRY

越权检查放在跨字段约束之前，是因为它是安全事件，应优先于业务层拒绝被记录。

为什么拒绝重复键：`json.loads` 的默认行为是「后者覆盖前者」，同一层出现两次
`"decision"` 时，校验器看到的与任何独立复核者肉眼看到的可能不是同一个值 ——
`{"decision":"SELECT", "decision":"NOT_APPLICABLE"}` 在默认解析下等于 NOT_APPLICABLE，
而在只读第一处的实现下等于 SELECT。这种歧义不能带进资格判定，故一律失败关闭。
检测覆盖所有嵌套层级，不只是顶层与 content。
"""

import json

MAX_BODY_BYTES = 8192
MAX_REASON_CHARS = 500
MIN_QUESTION_CHARS = 10
MAX_QUESTION_CHARS = 300

REQUIRED_KEYS = {"decision", "scenario_id", "clarification_question",
                 "reason", "confidence"}
DECISIONS = {"SELECT", "NOT_APPLICABLE", "NEED_CLARIFICATION"}

# 刻意只收窄到「声明式」越权短语，而不是裸词 authority / execute。
# 裸词会把「我不能授予授权」这类否认句也判成越权；但那仍然会被拒，
# 因为下面这些模式本身也是宽口径的失败关闭策略 —— 见 README「已知严格点」。
AUTHORITY_PATTERNS = (
    "execution_permitted",
    "authority_granted",
    "permission granted",
    "grant authority",
    "granted authority",
    "grant permission",
    "access granted",
    "granted access",
    "approved for execution",
    "authorized to execute",
    "you are authorized",
    "权限已授予",
    "已授予执行权限",
    "已授予授权",
    "授予执行许可",
    "授权已生效",
    "允许执行该操作",
    "批准执行该操作",
)


class Verdict(dict):
    """既是 dict（便于落盘）又带属性访问（便于测试）。"""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class DuplicateKeyError(ValueError):
    """同一 JSON 对象层级内出现两个相同键。"""

    def __init__(self, keys, depth_hint=""):
        self.keys = sorted(set(keys))
        super().__init__("同层重复键 %s%s" % (self.keys, depth_hint))


def _no_duplicate_keys(pairs):
    """`json.loads` 的 object_pairs_hook：同层出现重复键即失败关闭。

    返回普通 dict 以保持与默认解析结果同型；一旦发现重复，抛 DuplicateKeyError，
    让调用方按自己的顺序契约转成拒绝码。
    """
    seen = set()
    dup = []
    out = {}
    for k, v in pairs:
        if k in seen:
            dup.append(k)
        else:
            seen.add(k)
        out[k] = v
    if dup:
        raise DuplicateKeyError(dup)
    return out


def _accepted(**kw):
    base = {
        "decision": "ACCEPTED",
        "code": None,
        "model_decision": None,
        "scenario_id": None,
        "clarification_question": None,
        "reason": None,
        "confidence": None,
        "authority_pattern": None,
        "detail": "",
        "checks_passed": [],
    }
    base.update(kw)
    return Verdict(base)


def _rejected(code, detail, passed):
    return Verdict({
        "decision": "REJECTED",
        "code": code,
        "model_decision": None,
        "scenario_id": None,
        "clarification_question": None,
        "reason": None,
        "confidence": None,
        "authority_pattern": None,
        "detail": detail,
        "checks_passed": list(passed),
    })


def _content_of(body_obj):
    """取 choices[0].message.content。任何形状异常都返回 None。"""
    try:
        choices = body_obj["choices"]
        if not isinstance(choices, list) or not choices:
            return None
        msg = choices[0]["message"]
        if not isinstance(msg, dict):
            return None
        content = msg.get("content")
        return content if isinstance(content, str) else None
    except (KeyError, TypeError, IndexError):
        return None


def validate_response(raw_body, expected_model_id, registry_ids):
    """raw_body: bytes（原始响应体）。registry_ids: set of scenario_id。"""
    passed = []

    # 1. 长度
    if not isinstance(raw_body, (bytes, bytearray)):
        return _rejected("MODEL_RESPONSE_MALFORMED", "响应体不是字节", passed)
    if len(raw_body) > MAX_BODY_BYTES:
        return _rejected("MODEL_RESPONSE_TOO_LONG",
                         f"响应体 {len(raw_body)} B > {MAX_BODY_BYTES} B", passed)
    passed.append("body_length")

    # 2. 外层 JSON（含全层级重复键检测）
    try:
        body = json.loads(raw_body.decode("utf-8"),
                          object_pairs_hook=_no_duplicate_keys)
    except DuplicateKeyError as exc:
        return _rejected("MODEL_RESPONSE_DUPLICATE_KEY",
                         "响应体 %s" % exc, passed)
    except Exception:
        return _rejected("MODEL_RESPONSE_MALFORMED", "响应体不是合法 JSON", passed)
    if not isinstance(body, dict):
        return _rejected("MODEL_RESPONSE_MALFORMED", "响应体顶层不是对象", passed)
    passed.append("body_json")

    # 3. 模型身份
    if body.get("model") != expected_model_id:
        return _rejected(
            "MODEL_IDENTITY_UNPINNED",
            f"响应 model={body.get('model')!r} 不等于请求 model={expected_model_id!r}",
            passed)
    passed.append("model_identity")

    # 4. content 存在
    content = _content_of(body)
    if content is None:
        return _rejected("MODEL_RESPONSE_SCHEMA_VIOLATION",
                         "choices[0].message.content 缺失或不是字符串", passed)
    passed.append("content_present")

    # 5. content JSON（含全层级重复键检测）
    try:
        obj = json.loads(content, object_pairs_hook=_no_duplicate_keys)
    except DuplicateKeyError as exc:
        return _rejected("MODEL_RESPONSE_DUPLICATE_KEY",
                         "content %s" % exc, passed)
    except Exception:
        return _rejected("MODEL_RESPONSE_MALFORMED",
                         "content 不是合法 JSON（可能被代码块包裹或含多余文本）",
                         passed)
    if not isinstance(obj, dict):
        return _rejected("MODEL_RESPONSE_MALFORMED", "content 顶层不是对象", passed)
    passed.append("content_json")

    # 6. 键集
    keys = set(obj.keys())
    if keys != REQUIRED_KEYS:
        missing = sorted(REQUIRED_KEYS - keys)
        extra = sorted(keys - REQUIRED_KEYS)
        return _rejected("MODEL_RESPONSE_SCHEMA_VIOLATION",
                         f"键集不符：缺 {missing}，多 {extra}", passed)
    passed.append("key_set")

    # 7. 字段类型（bool 不是 float，int 也不是 float —— 见 README 已知严格点）
    decision = obj["decision"]
    scenario_id = obj["scenario_id"]
    question = obj["clarification_question"]
    reason = obj["reason"]
    confidence = obj["confidence"]

    if not isinstance(decision, str):
        return _rejected("MODEL_RESPONSE_SCHEMA_VIOLATION",
                         "decision 不是字符串", passed)
    if scenario_id is not None and not isinstance(scenario_id, str):
        return _rejected("MODEL_RESPONSE_SCHEMA_VIOLATION",
                         "scenario_id 既不是字符串也不是 null", passed)
    if question is not None and not isinstance(question, str):
        return _rejected("MODEL_RESPONSE_SCHEMA_VIOLATION",
                         "clarification_question 既不是字符串也不是 null", passed)
    if not isinstance(reason, str):
        return _rejected("MODEL_RESPONSE_SCHEMA_VIOLATION",
                         "reason 不是字符串", passed)
    if isinstance(confidence, bool) or not isinstance(confidence, float):
        return _rejected("MODEL_RESPONSE_SCHEMA_VIOLATION",
                         f"confidence 类型为 {type(confidence).__name__}，必须是 float",
                         passed)
    if not 0.0 <= confidence <= 1.0:
        return _rejected("MODEL_RESPONSE_SCHEMA_VIOLATION",
                         f"confidence={confidence} 不在 [0,1]", passed)
    passed.append("field_types")

    # 8. reason 长度
    if len(reason) > MAX_REASON_CHARS:
        return _rejected("MODEL_RESPONSE_TOO_LONG",
                         f"reason {len(reason)} 字 > {MAX_REASON_CHARS}", passed)
    passed.append("reason_length")

    # 9. 越权表述（扫 content 全文，不只看 reason）
    low = content.lower()
    for pat in AUTHORITY_PATTERNS:
        if pat.lower() in low:
            v = _rejected("MODEL_CLAIMED_AUTHORITY",
                          f"响应含越权表述：{pat!r}", passed)
            v["authority_pattern"] = pat
            return v
    passed.append("no_authority_claim")

    # 10. decision 取值
    if decision not in DECISIONS:
        return _rejected("MODEL_RESPONSE_SCHEMA_VIOLATION",
                         f"decision={decision!r} 不在 {sorted(DECISIONS)}", passed)
    passed.append("decision_enum")

    # 11. 跨字段约束
    if decision == "SELECT":
        if scenario_id is None:
            return _rejected("MODEL_SELECTION_FIELD_CONFLICT",
                             "SELECT 但 scenario_id 为 null", passed)
        if scenario_id not in registry_ids:
            return _rejected("MODEL_SELECTION_OUT_OF_REGISTRY",
                             f"scenario_id={scenario_id!r} 不在已登记 6 条内",
                             passed)
        if question is not None:
            return _rejected("MODEL_SELECTION_FIELD_CONFLICT",
                             "SELECT 但 clarification_question 非 null", passed)
    elif decision == "NOT_APPLICABLE":
        if scenario_id is not None:
            return _rejected("MODEL_SELECTION_FIELD_CONFLICT",
                             "NOT_APPLICABLE 但 scenario_id 非 null", passed)
        if question is not None:
            return _rejected("MODEL_SELECTION_FIELD_CONFLICT",
                             "NOT_APPLICABLE 但 clarification_question 非 null",
                             passed)
    else:  # NEED_CLARIFICATION
        if scenario_id is not None:
            return _rejected("MODEL_SELECTION_FIELD_CONFLICT",
                             "NEED_CLARIFICATION 但 scenario_id 非 null", passed)
        if question is None:
            return _rejected("MODEL_SELECTION_FIELD_CONFLICT",
                             "NEED_CLARIFICATION 但 clarification_question 为 null",
                             passed)
        if not MIN_QUESTION_CHARS <= len(question) <= MAX_QUESTION_CHARS:
            return _rejected(
                "MODEL_SELECTION_FIELD_CONFLICT",
                f"clarification_question {len(question)} 字，须在 "
                f"{MIN_QUESTION_CHARS}-{MAX_QUESTION_CHARS} 之间", passed)
    passed.append("cross_field")

    return _accepted(model_decision=decision, scenario_id=scenario_id,
                     clarification_question=question, reason=reason,
                     confidence=confidence, detail="全部 11 项检查通过",
                     checks_passed=passed)
