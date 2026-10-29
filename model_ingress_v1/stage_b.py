"""阶段 B 执行驱动：按 stage_b_plan.json 逐请求执行，逐请求设闸。

它存在的唯一理由是机械地保证四件人手做不到的事：

1. 不多发。请求数、输入输出上限、总费用上限都由计划文件固定；驱动只按计划
   逐条发，发完即止。没有重试分支，`retry` 字段恒为 0。
2. 不停错地方。任何一个请求触发停止条件就整体停下，剩余额度留在账上，
   不会被自动用于"再试一次"或"换个参数试试"。
3. 不误发。闸门不是读几个非空字符串，而是**读证据文件重新算**：
   - 授权：state / granted_by / granted_at / ruling_sha256 逐项核；
   - 模型身份：从目录原始字节里找 id，不是看 model_id_confirmed 有没有字；
   - 价格：从目录条目重新解析并与计划比对，不是看一个布尔标记；
   - 预算：发送前按声明的上限**预留最坏费用**，预留后超预算就不发；
   - `execution_gate.ready` 是**声明值**，必须与派生值一致，否则拒绝运行。
4. 不假装记账。响应里 usage 缺失或不是整数时，按声明的上限顶格计入，
   并**停止后续需要额外确认的调用**——绝不用较低的估算冒充真实费用。

本模块不构造请求体、不解析响应、不做任何判定 —— 那些分别属于 provider.py、
validate.py、run.py。这里只有顺序、闸门和记账。
"""

import hashlib
import json
import os
import sys
import time
from pathlib import Path

try:  # 作为包导入
    from . import catalog as catalog_mod
    from . import run as run_mod
    from .provider import (HttpProvider, ProviderConfigError, THINKING_STYLES,
                           THINKING_STYLE_CHAT_TEMPLATE)
except ImportError:  # 直接运行
    sys.path.insert(0, str(Path(__file__).absolute().parent.parent))
    from model_ingress_v1 import catalog as catalog_mod
    from model_ingress_v1 import run as run_mod
    from model_ingress_v1.provider import (HttpProvider, ProviderConfigError,
                                           THINKING_STYLES,
                                           THINKING_STYLE_CHAT_TEMPLATE)

PLAN_PATH = Path(__file__).absolute().parent / "stage_b_plan.json"
SUMMARY_SCHEMA = "H56_STAGE_B_RUN_SUMMARY_V3"
SUMMARY_FILE = "stage_b_summary.json"
KEY_ENV = "NEBIUS_API_KEY"

# 定价证据的两种来源。这个字段存在的理由很具体：有些端点的 /models 根本不发布价格
# （DeepSeek 只给 id / context_window / 能力），于是"从目录重算定价"这条路在那里
# 物理上不存在。既不允许多报（假装核验过），也不允许因此就不写价格（预算与账本
# 都要用），所以把来源**显式分档**，并强制降级档位不得声称机器核验。
PRICING_EVIDENCE_CATALOG = "catalog_entry"
PRICING_EVIDENCE_DECLARED = "declared_from_official_page"
PRICING_EVIDENCE_CLASSES = (PRICING_EVIDENCE_CATALOG, PRICING_EVIDENCE_DECLARED)

# 目录核验里"只跟定价有关"的三项。声明定价来自官方页面时，这三项允许失败，
# 其余任何失败都不允许 —— 也就是"放开的是定价口径，不是目录本身"。
PRICING_ONLY_CHECKS = frozenset({
    "catalog_pricing_present",
    "pricing_input_matches_plan",
    "pricing_output_matches_plan",
})

# 请求合同：本条请求允许/禁止启动内核。
CONTRACT_REQUIRED = "REQUIRED"
CONTRACT_FORBIDDEN = "FORBIDDEN"

# run.py 写进证据的三个 outcome 值，驱动据此判「模型是否越界」。
OUTCOME_SELECTED_WHERE_FORBIDDEN = "MODEL_ERROR_SELECTED_WHERE_FORBIDDEN"


class StageBError(Exception):
    """执行前的拒绝。不是运行期拒绝码，不进拒绝码表。"""


def load_plan(path=None):
    p = Path(path) if path else PLAN_PATH
    return json.loads(p.read_text(encoding="utf-8"))


def _canonical_plan_json(obj):
    """计划对象的规范形字节：用于判断「内存里的 dict」与「文件字节」是否同一份内容。

    只做**内容**层面的等价判定：排序键、去空白、固定分隔符。它不能替代文件字节
    哈希 —— 哈希证明"读的是哪份字节"，规范形证明"跑的对象是不是那份字节解析出来的"。
    两者都要，缺一不可。
    """
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _iso_seconds_ok(value):
    """granted_at 必须能被解析；随手写的字符串不算时间。"""
    if not isinstance(value, str) or len(value) < 19:
        return False
    try:
        time.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
        return True
    except ValueError:
        return False


def _normalize_ids(value):
    """把命令行给的请求集合归一成列表。接受 list 或 "R1,R2" 字符串。

    不排序、不去重：顺序与重复都要如实反映输入，否则"与计划逐字一致"这句
    比对就失真了（R2,R1 与 R1,R2 必须被当成不同输入）。
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [s.strip() for s in value.split(",") if s.strip()]
    return [str(v).strip() for v in value if str(v).strip()]


# ---------------------------------------------------------------- 静态校验
def validate_plan(plan):
    """对计划文件做纯静态核对。返回问题清单（空 = 通过）。

    这些检查不花一分钱，也不碰网络；把能在这里发现的错误留到发请求时发现，
    就是把预算当调试工具用。
    """
    issues = []
    reqs = plan.get("requests") or []
    if plan.get("schema") != "H56_STAGE_B_PLAN_V1":
        issues.append("schema 不是 H56_STAGE_B_PLAN_V1")

    pricing = (plan.get("model") or {}).get("pricing") or {}
    pin = pricing.get("input")
    pout = pricing.get("output")
    for name, val in (("input", pin), ("output", pout)):
        if not isinstance(val, (int, float)) or isinstance(val, bool) or val <= 0:
            issues.append("pricing.%s 必须是正数，实际 %r" % (name, val))
            pin = pout = None
            break

    # 定价来源分档必须是两种之一；降级档位的三个条件是硬性的：
    # 写明来源、写明抄录时点、且**不得**声称经目录核验或机器核验。
    pclass = pricing.get("evidence_class") or PRICING_EVIDENCE_CATALOG
    if pclass not in PRICING_EVIDENCE_CLASSES:
        issues.append("pricing.evidence_class 必须是 %s，实际 %r"
                      % (list(PRICING_EVIDENCE_CLASSES), pclass))
    elif pclass == PRICING_EVIDENCE_DECLARED:
        if not (isinstance(pricing.get("source"), str)
                and pricing["source"].strip()):
            issues.append("降级档定价必须写明 source（官方定价页 URL 与抓取时点）")
        if not _iso_seconds_ok(pricing.get("declared_at")):
            issues.append("降级档定价必须写明 declared_at（ISO 秒级时间），实际 %r"
                          % (pricing.get("declared_at"),))
        if pricing.get("verified_against_catalog") is not False:
            issues.append("降级档定价的 verified_against_catalog 必须显式为 false —— "
                          "端点目录不发布价格时，不得声称经目录核验")
        if pricing.get("machine_verified") is not False:
            issues.append("降级档定价的 machine_verified 必须显式为 false")

    # 推理开关的形态：不认得就不发请求，不做"换个端点试试"。
    params_decl = plan.get("params") or {}
    style = params_decl.get("thinking_style") or THINKING_STYLE_CHAT_TEMPLATE
    if style not in THINKING_STYLES:
        issues.append("params.thinking_style 必须是 %s，实际 %r"
                      % (list(THINKING_STYLES), style))
    declared_param = params_decl.get("thinking_param")
    if declared_param is not None and declared_param not in (
            "chat_template_kwargs.enable_thinking", "thinking.type"):
        issues.append("params.thinking_param 只接受两种已知写法，实际 %r"
                      % (declared_param,))

    budget = plan.get("budget") or {}
    if budget.get("max_inference_requests") != len(reqs):
        issues.append("budget.max_inference_requests=%r 与实际请求数 %d 不一致"
                      % (budget.get("max_inference_requests"), len(reqs)))
    if len(reqs) != 7:
        issues.append("计划必须是 7 条推理请求，实际 %d" % len(reqs))

    max_in = budget.get("max_input_tokens_per_request")
    max_out = budget.get("max_output_tokens_per_request")

    seen, contracts = [], {}
    for r in reqs:
        rid = r.get("request_id")
        if not rid:
            issues.append("存在缺少 request_id 的条目")
            continue
        if r.get("retry") != 0:
            issues.append("%s 的 retry 必须为 0" % rid)
        if not r.get("stop_conditions"):
            issues.append("%s 没有停止条件" % rid)
        if not r.get("purpose"):
            issues.append("%s 没有测试目的" % rid)
        if r.get("max_input_tokens") != max_in:
            issues.append("%s 的输入上限与预算不一致" % rid)
        if r.get("max_output_tokens") != max_out:
            issues.append("%s 的输出上限与预算不一致" % rid)

        contract = r.get("kernel_contract")
        contracts[rid] = contract
        if contract not in (CONTRACT_REQUIRED, CONTRACT_FORBIDDEN):
            issues.append("%s 的 kernel_contract 必须是 %s / %s，实际 %r"
                          % (rid, CONTRACT_REQUIRED, CONTRACT_FORBIDDEN, contract))
        elif (contract == CONTRACT_FORBIDDEN) != (r.get("scenario_id") is None):
            issues.append("%s 的 kernel_contract 与 scenario_id 是否为空不一致："
                          "域外对照必须 FORBIDDEN，其余必须 REQUIRED" % rid)

        text = r.get("intent_text") or ""
        if _sha256_text(text) != r.get("intent_sha256"):
            issues.append("%s 的 intent_sha256 与实际文本不符" % rid)
        if r.get("scenario_id"):
            seen.append(r["scenario_id"])
        est = r.get("estimated_input_tokens_upper")
        if isinstance(est, int) and est > r.get("max_input_tokens", 0):
            issues.append("%s 的输入上界估计 %d 已超过上限" % (rid, est))

        # 逐条预算必须是算出来的，不是手写的：用该条自己的输入上界估计与输出
        # 上限重算一遍，对不上就报错。这样"改了 token 估计忘了改钱"必然暴露。
        if pin is not None and isinstance(est, int):
            recomputed = round(est / 1e6 * pin + (max_out or 0) / 1e6 * pout, 10)
            declared = r.get("budget_usd_estimate") or 0
            if abs(recomputed - declared) > 1e-9:
                issues.append("%s 的 budget_usd_estimate %.10f 与重算值 %.10f 不符"
                              % (rid, declared, recomputed))

    if len(seen) != len(set(seen)):
        issues.append("同一场景被登记了多次：%s" % seen)
    if len(seen) != 6:
        issues.append("必须覆盖 6 个登记场景各一次，实际覆盖 %d 条" % len(seen))
    forbidden = [k for k, v in contracts.items() if v == CONTRACT_FORBIDDEN]
    if len(forbidden) != 1:
        issues.append("必须恰有 1 条 FORBIDDEN（域外对照），实际 %s" % forbidden)

    # ---- 执行范围：本轮获准执行哪几条 ----
    # 计划永远保留全部 7 条（完整性），但**执行范围**是它自己的一个字段。
    # 不加这一段，就会出现"只批了 R1，驱动却把七条都跑了"——那是授权边界没落到代码。
    scope = plan.get("execution_scope") or {}
    scope_ids = scope.get("approved_request_ids")
    all_ids = [r.get("request_id") for r in reqs if r.get("request_id")]
    if not isinstance(scope_ids, list) or not scope_ids:
        issues.append("execution_scope.approved_request_ids 必须是非空列表"
                      "（本轮获准执行的请求；不写等于没批）")
    else:
        unknown = [i for i in scope_ids if i not in all_ids]
        if unknown:
            issues.append("execution_scope 含计划里不存在的 request_id：%s" % unknown)
        if len(scope_ids) != len(set(scope_ids)):
            issues.append("execution_scope 有重复 request_id：%s" % scope_ids)
        pos = [all_ids.index(i) for i in scope_ids if i in all_ids]
        if pos != sorted(pos):
            issues.append("execution_scope 的顺序与计划顺序不一致：%s" % scope_ids)
        if isinstance(budget.get("max_inference_requests"), int) and \
                len(scope_ids) > budget["max_inference_requests"]:
            issues.append("execution_scope 有 %d 条，超过请求额度 %d"
                          % (len(scope_ids), budget["max_inference_requests"]))

    total = sum(r.get("budget_usd_estimate") or 0 for r in reqs)
    if total > budget.get("max_total_usd", 0):
        issues.append("预估总费用 %.6f 超过上限 %.6f"
                      % (total, budget.get("max_total_usd", 0)))

    # 下面三个字段缺失时必须报错，不能像早前那样 `if declared is not None` 静默跳过：
    # 字段一改名，检查就变成永不触发的死代码，看起来还在，实际什么都没查。
    declared = budget.get("estimated_usd_at_expected_prompt")
    if declared is None:
        issues.append("预算缺少 estimated_usd_at_expected_prompt")
    elif abs(declared - total) > 1e-9:
        issues.append("计划声明的预估总额与逐条之和不等：%s vs %.6f"
                      % (declared, total))

    caps = budget.get("worst_case_usd_at_declared_caps")
    if caps is None:
        issues.append("预算缺少 worst_case_usd_at_declared_caps")
    else:
        if caps <= total:
            issues.append("最坏值 %.6f 不大于预估 %.6f：两个口径被混用了"
                          % (caps, total))
        if caps > budget.get("max_total_usd", 0):
            issues.append("最坏值 %.6f 已超过预算上限" % caps)

    # 目录证据的取用方式必须写在计划里，否则"目录查过没有"只能靠嘴说。
    conf = (plan.get("model") or {}).get("confirmation") or {}
    if "evidence_file" not in conf:
        issues.append("model.confirmation 缺少 evidence_file 字段")
    if conf.get("max_queries") != budget.get("max_catalog_queries"):
        issues.append("confirmation.max_queries 与 budget.max_catalog_queries 不一致")
    ver = (plan.get("model") or {}).get("model_id_verification") or {}
    if ver.get("state") not in ("UNVERIFIED", "VERIFIED"):
        issues.append("model.model_id_verification.state 必须是 UNVERIFIED / VERIFIED")
    return issues


# ---------------------------------------------------------------- 预算
class BudgetGuard:
    """发送前预留、响应后结算。所有判断都在这里，执行循环不自己算钱。

    三个数字口径必须分开：
      reserve  —— 发送前按**声明上限**顶格预留（2000 输入 + 400 输出）
      cost     —— 响应后按 usage 结算
      unconfirmed —— usage 不可用时的保守计入（等于 reserve），并置 halt
    """

    def __init__(self, plan):
        b = plan["budget"]
        self.max_requests = b["max_inference_requests"]
        self.max_in = b["max_input_tokens_per_request"]
        self.max_out = b["max_output_tokens_per_request"]
        self.max_usd = b["max_total_usd"]
        self.pricing = plan["model"]["pricing"]
        # 键名沿用 *_usd（历史命名），真实单位由计划声明 —— 打印与提示都带上它。
        self.currency = self.pricing.get("currency") or "USD"
        self.sent = 0
        self.spent = 0.0
        self.ledger = []
        self.unconfirmed = []
        self.halt = None

    # -- 算术 --
    def worst_case_usd(self, request):
        return round(
            (self.max_in or 0) / 1e6 * self.pricing["input"]
            + (self.max_out or 0) / 1e6 * self.pricing["output"], 10)

    def cost_of_usage(self, usage):
        """usage 必须是**非负整数**。字符串/浮点/布尔都不算确认；
        负数同样不算 —— 负 token 会让费用变成负值，从而绕过累计上限。"""
        pt = (usage or {}).get("prompt_tokens")
        ct = (usage or {}).get("completion_tokens")
        ok = (isinstance(pt, int) and not isinstance(pt, bool) and pt >= 0
              and isinstance(ct, int) and not isinstance(ct, bool) and ct >= 0)
        if not ok:
            return None, None, None
        cost = round(pt / 1e6 * self.pricing["input"]
                     + ct / 1e6 * self.pricing["output"], 10)
        return cost, pt, ct

    # -- 发送前 --
    def precheck(self, request):
        """返回是否允许发送。**允许即消耗一个请求额度**（先记账再发，宁可少发）。"""
        rid = request.get("request_id")
        reserve = self.worst_case_usd(request)
        checks = {
            "not_halted": self.halt is None,
            "no_unconfirmed_cost": not self.unconfirmed,
            "request_count": self.sent < self.max_requests,
            "request_token_caps": (request.get("max_input_tokens") == self.max_in
                                   and request.get("max_output_tokens") == self.max_out),
            "estimate_within_caps": (
                isinstance(request.get("estimated_input_tokens_upper"), int)
                and request["estimated_input_tokens_upper"] <= self.max_in),
            "reserve_within_budget": (self.spent + reserve) <= self.max_usd,
        }
        reasons = []
        if not checks["not_halted"]:
            reasons.append("已停止：%s" % self.halt)
        if not checks["no_unconfirmed_cost"]:
            reasons.append("前序请求费用无法确认（%s），后续调用需额外确认"
                           % ", ".join(self.unconfirmed))
        if not checks["request_count"]:
            reasons.append("请求数已达上限 %d" % self.max_requests)
        if not checks["request_token_caps"]:
            reasons.append("本条请求的 token 上限与预算声明不一致")
        if not checks["estimate_within_caps"]:
            reasons.append("输入上界估计超过声明的输入上限")
        if not checks["reserve_within_budget"]:
            reasons.append("预留最坏费用 %.6f %s 后累计 %.6f %s 将超过上限 %.6f %s"
                           % (reserve, self.currency, self.spent + reserve,
                              self.currency, self.max_usd, self.currency))
        allowed = not reasons
        if allowed:
            self.sent += 1
        decision = {
            "request_id": rid,
            "allowed": allowed,
            "reasons": reasons,
            "checks": checks,
            "reserve_usd": reserve,
            "spent_before_usd": round(self.spent, 10),
            "remaining_usd_before": round(self.max_usd - self.spent, 10),
            "sent_before": self.sent - (1 if allowed else 0),
            "rule": ("发送前按声明的 token 上限预留最坏费用；预留后仍须 <= 上限，"
                     "否则不发。额度不是用来试的资源。"),
        }
        return decision

    # -- 响应后 --
    def settle(self, request, usage):
        rid = request.get("request_id")
        reserve = self.worst_case_usd(request)
        cost, pt, ct = self.cost_of_usage(usage)
        confirmable = cost is not None
        if not confirmable:
            # 关键：不拿"按预估 prompt 长度"的低值冒充真实费用。
            cost = reserve
            source = "conservative_worst_case_declared_caps"
            self.unconfirmed.append(rid)
            self.halt = ("费用无法确认（usage 缺失或非整数），已按顶格计入 %.6f %s"
                         % (reserve, self.currency))
        else:
            source = "usage"
        over_caps = []
        if confirmable:
            if pt > self.max_in:
                over_caps.append("prompt_tokens %d > 声明上限 %d" % (pt, self.max_in))
            if ct > self.max_out:
                over_caps.append("completion_tokens %d > 声明上限 %d" % (ct, self.max_out))
            if over_caps:
                self.halt = "实际 token 超出声明上限：%s" % "；".join(over_caps)
        self.spent = round(self.spent + cost, 10)
        row = {
            "request_id": rid,
            "cost_usd": cost,
            "cost_source": source,
            "cost_confirmable": confirmable,
            "prompt_tokens": pt,
            "completion_tokens": ct,
            "reserve_usd": reserve,
            "over_declared_caps": over_caps,
            "spent_after_usd": self.spent,
            "within_budget": self.spent <= self.max_usd,
        }
        self.ledger.append(row)
        return row

    def report(self):
        return {
            "max_inference_requests": self.max_requests,
            "sent": self.sent,
            "spent_usd": self.spent,
            "budget_usd": self.max_usd,
            "remaining_usd": round(self.max_usd - self.spent, 10),
            "unconfirmed_cost_requests": list(self.unconfirmed),
            "halt_reason": self.halt,
            "ledger": list(self.ledger),
            "cost_source_values": sorted({r["cost_source"] for r in self.ledger}),
            "note": ("cost_source=usage 表示按响应里的真实 usage 结算；"
                     "conservative_worst_case_declared_caps 表示 usage 不可用，"
                     "按声明上限顶格计入——这两个数不能混着引用。"),
        }


def cost_of(usage, pricing, request):
    """把一次调用的 usage 折算成美元。usage 缺失时按声明上限顶格兜底。

    保留这个函数是为了让"折算规则"只有一个实现（BudgetGuard 复用同一算法），
    但对外口径以 BudgetGuard.settle 的 cost_source 为准。
    """
    guard = BudgetGuard({"budget": {"max_inference_requests": 1,
                                    "max_input_tokens_per_request":
                                        request.get("max_input_tokens"),
                                    "max_output_tokens_per_request":
                                        request.get("max_output_tokens"),
                                    "max_total_usd": 0},
                         "model": {"pricing": pricing}})
    cost, _pt, _ct = guard.cost_of_usage(usage)
    if cost is not None:
        return cost, "usage"
    return guard.worst_case_usd(request), "conservative_worst_case_declared_caps"


# ---------------------------------------------------------------- 判定
def judge(request, ev):
    """按计划的 expected 段逐项核对。返回 (ok, checks, reasons)。

    「分别评价」在这里落地：模型有没有选对（scenario_id / model_decision）、
    有没有越界（outcome / no_overshoot）、内核有没有真算（kernel_*）、
    这条请求的合同有没有被守住（no_kernel_launched），每条都是独立的检查项，
    不合成一个"整体通过"。
    """
    exp = request.get("expected") or {}
    call = ev.get("call") or {}
    ad = ev.get("adapter") or {}
    k = ev.get("kernel") or {}
    checks = []

    def add(name, ok, detail=None):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    add("http_status", call.get("http_status") == exp.get("http_status"),
        call.get("http_status"))
    add("adapter_decision", ad.get("decision") == exp.get("adapter_decision"),
        ad.get("decision"))

    # 验收目标第 2 条（"响应来自本次实际调用，而不是 Mock"）的结构性检查：
    # 若有人把 A2 的 FixedMockProvider 拿到这里跑，impl 里会带 mock，直接判失败。
    impl = (call.get("provider_impl") or {}).get("impl") or ""
    add("provider_is_not_mock", "mock" not in impl.lower(), impl or "(未记录)")
    add("attempts_is_one", call.get("attempts") == 1, call.get("attempts"))

    if "model_decision_in" in exp:
        add("model_decision_in", ad.get("model_decision") in exp["model_decision_in"],
            ad.get("model_decision"))
    else:
        add("model_decision", ad.get("model_decision") == exp.get("model_decision"),
            ad.get("model_decision"))
        add("scenario_id", ad.get("scenario_id") == exp.get("scenario_id"),
            ad.get("scenario_id"))

    if exp.get("scenario_id_null") is True:
        add("scenario_id_null", ad.get("scenario_id") is None, ad.get("scenario_id"))

    # 请求合同：FORBIDDEN 的请求，内核一次都不许启动。
    # 这里不跟 invoked 混在一起判 —— 「内核没启动」与「模型没越界」是两件事：
    # 前者是合同守住了，后者是模型表现对。合成一条就会掩盖"模型错了但被拦下"。
    contract = request.get("kernel_contract")
    add("kernel_contract_declared",
        contract in (CONTRACT_REQUIRED, CONTRACT_FORBIDDEN), contract)
    if contract == CONTRACT_FORBIDDEN:
        add("no_kernel_launched", k.get("invoked") is not True, k.get("invoked"))
        add("no_overshoot",
            ad.get("outcome") != OUTCOME_SELECTED_WHERE_FORBIDDEN
            and ad.get("model_decision") != "SELECT",
            ad.get("outcome"))

    add("kernel_invoked", bool(k.get("invoked")) == bool(exp.get("kernel_invoked")),
        k.get("invoked"))

    if exp.get("kernel_invoked"):
        add("kernel_exit", k.get("exit_code") == exp.get("kernel_exit"),
            k.get("exit_code"))
        want = "%s / %s" % ((k.get("kind") or ""), (k.get("value") or ""))
        add("kernel_outcome", want.strip(" /") == exp.get("kernel_kind_outcome"), want)

    bad = [c["check"] for c in checks if not c["ok"]]
    return (not bad), checks, bad


# ---------------------------------------------------------------- 执行前闸门
def preflight(plan, approved_origin, environ=None, catalog_evidence=None,
              approved_requests=None, key_env=None):
    """统一执行闸门。返回 dict；任何一项不满足即抛 StageBError（附全部阻断项）。

    与上一版的关键差别：这里**不再**采信计划文件里的布尔标记。
    `execution_gate.ready` / `verified_against_catalog` /
    `model_id_verification.state` 都是**声明值**，必须与派生值一致；
    派生值只能由「读目录原始字节 + 重算哈希 + 重新解析」得出。

    本轮新增两项：
    - `scope.*`：本轮获准执行的请求集合必须写在计划里，且与命令行逐字一致。
      「只批了 R1」这件事从此是**参数**，不是执行者的记性。
    - `catalog.*`：目录证据必须能对应到"这一次、这个端点、这个方法"的 GET
      （origin / method / path / query / 完整 URL），不能只是"内容碰巧对得上"。
    """
    env = os.environ if environ is None else environ
    # 密钥**变量名**可切，密钥值不可切。切换变量名只影响「去哪个环境槽位取」，
    # 不改变「必须有值」这条：空槽位照样阻断。默认仍取 NEBIUS_API_KEY，
    # 所以正式链路的行为与本次改动前逐字节一致。
    env_name = (key_env or KEY_ENV).strip() or KEY_ENV
    blocking = []
    checks = {}

    def gate(name, ok, reason=None):
        checks[name] = bool(ok)
        if not ok:
            blocking.append("%s：%s" % (name, reason or "不满足"))
        return bool(ok)

    # 1. 计划静态一致性
    issues = validate_plan(plan)
    gate("plan.static", not issues, "；".join(issues) if issues else None)

    # 2. 授权：四个字段逐项核，缺一不可
    auth = plan.get("authorization") or {}
    ruling = auth.get("ruling_text")
    auth_ok = gate(
        "authorization.state", auth.get("state") == "GRANTED",
        "state 为 %r，必须有具名裁决放行" % (auth.get("state"),))
    auth_ok &= gate(
        "authorization.granted_by",
        isinstance(auth.get("granted_by"), str) and bool(auth["granted_by"].strip()),
        "granted_by 为空：没有具名裁决人")
    auth_ok &= gate(
        "authorization.granted_at", _iso_seconds_ok(auth.get("granted_at")),
        "granted_at 缺失或不是 ISO 时间：%r" % (auth.get("granted_at"),))
    auth_ok &= gate(
        "authorization.ruling_sha256",
        isinstance(ruling, str) and len(ruling) > 0
        and _sha256_text(ruling) == auth.get("ruling_sha256"),
        "ruling_sha256 与 ruling_text 不符或缺失：裁决原文未绑定")

    # 3. 模型目录证据：从原始字节重新算，不看派生字段
    model = plan.get("model") or {}
    conf = model.get("confirmation") or {}
    pricing = model.get("pricing") or {}
    pclass = pricing.get("evidence_class") or PRICING_EVIDENCE_CATALOG
    # 只有"端点目录不发布定价"这一条分支才允许这三项失败；其余失败照常阻断。
    allowed_failed = (PRICING_ONLY_CHECKS if pclass == PRICING_EVIDENCE_DECLARED
                      else frozenset())
    expected_id = model.get("model_id_expected")
    ev_path = catalog_evidence or conf.get("evidence_file")
    expected_req = catalog_mod.expected_request_of(plan)
    if not ev_path:
        cat = {"ok": False, "failed": ["evidence_file_not_declared"],
               "checks": [], "model_id_verified": None, "pricing_observed": None,
               "evidence_sha256_recomputed": None, "request_recorded": None}
        gate("catalog.present", False,
             "未声明目录证据文件：model.confirmation.evidence_file 为空，"
             "说明目录查询尚未执行")
    else:
        p = Path(ev_path)
        if not p.is_absolute():
            p = Path(PLAN_PATH).parent / p
        cat = catalog_mod.verify(p, expected_id or "", model.get("pricing") or {},
                                 expected_request=expected_req)
        gate("catalog.present", True)
        hard_failed = [f for f in (cat.get("failed") or [])
                       if f not in allowed_failed]
        gate("catalog.evidence_valid", not hard_failed,
             "目录证据核验未通过：%s" % ", ".join(hard_failed))
        # 来源对应单独列一项：内容对得上但来源不是这次获准的 GET，也算未通过。
        src_failed = [c["check"] for c in cat.get("checks", [])
                      if c["check"].startswith(("request_", "endpoint_origin"))
                      and not c["ok"]]
        gate("catalog.request_source", not src_failed,
             "目录证据的来源与本次获准的 GET 不对应：%s" % src_failed)
    derived_model_id = cat.get("model_id_verified")

    # 4. 模型身份：名称必须与目录里的 id 逐字相同
    confirmed = model.get("model_id_confirmed")
    id_ok = gate(
        "model.identity", bool(derived_model_id) and confirmed == derived_model_id,
        "model_id_confirmed=%r 与目录中实测 id=%r 不一致（或目录无此模型）"
        % (confirmed, derived_model_id))
    declared_state = (model.get("model_id_verification") or {}).get("state")
    derived_state = "VERIFIED" if id_ok else "UNVERIFIED"
    gate("model.verification_state", declared_state == derived_state,
         "计划声明 %r，按目录证据派生为 %r —— 声明值不得覆盖派生值"
         % (declared_state, derived_state))

    # 5. 价格：来源分档。
    #
    #    catalog_entry           —— 从目录条目重新解析后与计划比对（原行为，未变）
    #    declared_from_official_page —— 端点目录不发布定价时的显式降级档。
    #      这一档**不产生**"已核验"这个结论：它只要求来源、抄录时点齐全，并且
    #      必须把 verified_against_catalog 与 machine_verified 都写成 false。
    #      下游 summary 会带 cost_evidence_class=declared_price_unverified，
    #      因此这个数不会被当成实测账单引用。
    #
    #    降级档的**准入条件**是"目录确实没有价格"，而这个条件必须由证据证明。
    #    早前只按"失败项 ⊆ 三项定价检查"放行，有一个真实缺口：目录**有价但与
    #    计划冲突**时，那三项同样会失败，于是"价格冲突"会被当成"目录没价"
    #    静默放过。所以下面改成看观测值本身 —— 只要目录条目给出任一价格，
    #    就不允许走降级档（有价就该走 catalog_entry 档，冲突就该停）。
    if pclass == PRICING_EVIDENCE_CATALOG:
        derived_pricing_ok = bool(
            cat.get("ok")
            and not (PRICING_ONLY_CHECKS & set(cat.get("failed") or [])))
        gate("model.pricing", derived_pricing_ok,
             "目录定价与计划定价不一致或目录证据不可用：%s"
             % (cat.get("pricing_observed") or "无观测值"))
        gate("model.pricing_declared_flag",
             bool(pricing.get("verified_against_catalog")) == derived_pricing_ok,
             "pricing.verified_against_catalog=%r 与派生结果 %r 不一致"
             % (pricing.get("verified_against_catalog"), derived_pricing_ok))
    else:
        # 前提一：目录里确实查到了这个模型（否则"没有价格"只是"没有条目"）。
        # 前提二：该条目**完全不发布价格** —— input 与 output 都不能有观测值。
        # 两个前提缺一，降级档就不成立；这不是"少报"，是把分支的适用条件钉死。
        observed = cat.get("pricing_observed")
        observed = observed if isinstance(observed, dict) else {}
        cat_in = observed.get("input_per_1m_usd")
        cat_out = observed.get("output_per_1m_usd")
        absence_ok = gate(
            "model.pricing_catalog_absence",
            cat.get("model_id_verified") == confirmed
            and confirmed is not None
            and cat_in is None and cat_out is None,
            "降级档要求目录中该模型条目**完全不发布价格**；实测 "
            "model_id_verified=%r input_per_1m=%r output_per_1m=%r。"
            "目录给了价格就必须走 catalog_entry 档：一致则照常核验通过，"
            "冲突则必须停止 —— 不得借降级档把冲突改写成「目录没价」。"
            % (cat.get("model_id_verified"), cat_in, cat_out))
        declared_ok = bool(
            absence_ok
            and isinstance(pricing.get("source"), str) and pricing["source"].strip()
            and _iso_seconds_ok(pricing.get("declared_at"))
            and pricing.get("verified_against_catalog") is False
            and pricing.get("machine_verified") is False)
        gate("model.pricing", declared_ok,
             "降级档定价声明不完整：需要 source / declared_at(ISO) / "
             "verified_against_catalog=false / machine_verified=false")
        gate("model.pricing_declared_flag", declared_ok,
             "降级档不允许出现任何声称已核验的定价字段")
        derived_pricing_ok = False

    # 6. 端点：命令行必须逐字给出计划里的 origin
    want = (model.get("endpoint") or {}).get("origin")
    if not approved_origin:
        gate("endpoint.approved", False, "命令行未给出 --approve-origin")
    else:
        gate("endpoint.approved", bool(want) and approved_origin.strip() == want,
             "--approve-origin %r 与计划中的 %r 不一致"
             % (approved_origin.strip(), want))

    # 7. 凭据：只看有没有，绝不记录值
    gate("credential.present", bool(env.get(env_name)),
         "环境变量 %s 未配置（值不入库、不入日志）" % env_name)

    # 7.5 执行范围：本轮获准执行哪几条。这是"只批 R1 就跑 R1"的落地点。
    scope_ids = (plan.get("execution_scope") or {}).get("approved_request_ids") or []
    cli_ids = _normalize_ids(approved_requests)
    gate("scope.declared", isinstance(scope_ids, list) and bool(scope_ids),
         "计划未声明 execution_scope.approved_request_ids")
    gate("scope.matches_cli", bool(cli_ids) and cli_ids == list(scope_ids),
         "命令行 --approved-requests %r 与计划 execution_scope %r 不一致"
         % (cli_ids, list(scope_ids)))

    # 8. 预算：静态口径先卡住，运行期由 BudgetGuard 逐条预留
    b = plan.get("budget") or {}
    guard = BudgetGuard(plan)
    gate("budget.caps", guard.worst_case_usd({"max_input_tokens": guard.max_in,
                                              "max_output_tokens": guard.max_out})
         <= guard.max_usd,
         "顶格最坏费用已超过 max_total_usd")
    gate("budget.request_count", b.get("max_inference_requests") == len(plan["requests"]),
         "请求额度与请求条数不一致")
    gate("budget.covers_scope",
         isinstance(b.get("max_inference_requests"), int)
         and len(scope_ids) <= b["max_inference_requests"],
         "执行范围有 %d 条，超过请求额度 %r"
         % (len(scope_ids), b.get("max_inference_requests")))

    # 9. 声明值必须与派生值一致 —— 这一条把 execution_gate.ready 变成被消费的字段
    derived_ready = not blocking
    declared_ready = plan.get("execution_gate", {}).get("ready")
    declared_blocking = plan.get("execution_gate", {}).get("blocking") or []
    gate("execution_gate.ready", declared_ready == derived_ready,
         "计划声明 ready=%r，按实际预检派生为 %r。声明与派生不一致时必须拒绝，"
         "不允许把 ready 手改成 true 再试。" % (declared_ready, derived_ready))
    gate("execution_gate.blocking",
         (len(declared_blocking) > 0) == (not derived_ready),
         "blocking 列表（%d 项）与派生结果的就绪状态不一致" % len(declared_blocking))

    if blocking:
        raise StageBError("；".join(blocking))
    return {
        "origin": want,
        "model_id": derived_model_id,
        "request_count": len(plan["requests"]),
        "pricing": {
            "evidence_class": pclass,
            # 只有"目录条目重算并与计划一致"这一档，才允许对外说定价经机器核验。
            "machine_verified": bool(pclass == PRICING_EVIDENCE_CATALOG
                                     and derived_pricing_ok),
            "verified_against_catalog": bool(
                pclass == PRICING_EVIDENCE_CATALOG and derived_pricing_ok),
        },
        "scope": {
            "approved_request_ids": list(scope_ids),
            "planned_request_ids": [r["request_id"] for r in plan["requests"]],
            "source": (plan.get("execution_scope") or {}).get("source"),
        },
        "gate": {
            "ready_derived": True,
            "ready_declared": declared_ready,
            "checks": checks,
            "scope": {
                "approved_request_ids": list(scope_ids),
                "matches_cli": True,
                "cli_echo": "由 --approved-requests 逐字给出并与计划一致",
            },
            "catalog": {
                "evidence_file": cat.get("evidence_file"),
                # 把"本次消费的是哪一份回执"钉在结果里：摘要变了，说明换了证据。
                "evidence_sha256": cat.get("evidence_sha256_recomputed"),
                "http_status": cat.get("http_status"),
                "retrieved_at": cat.get("retrieved_at"),
                "raw_sha256_recomputed": cat.get("raw_sha256_recomputed"),
                "model_id_verified": derived_model_id,
                "pricing_observed": cat.get("pricing_observed"),
                "request_expected": cat.get("request_expected"),
                "request_recorded": cat.get("request_recorded"),
                "source": ("catalog.verify（从原始字节重新解析 + 与计划端点逐字比对来源）"),
            },
        },
    }


# ---------------------------------------------------------------- 主流程
def execute(plan, root, python=None, spawn=None, environ=None, verbose=True,
            approved_origin=None, catalog_evidence=None, approved_requests=None,
            key_env=None, plan_path=None):
    """按**执行范围**顺序执行。任一条触发停止条件即整体停止，剩余请求不执行。

    两条纪律在这里落地：

    1. 闸门在**本函数内**运行，不是只在命令行里运行：任何调用方绕开 main()
       直接调 execute()，闸门照样生效。
    2. 循环只遍历 `execution_scope.approved_request_ids`。范围外的请求
       **不构造 provider、不发一个字节**，只记入 `not_in_scope`。
       所以"只批了 R1"时，R1 成功后不存在"继续 R2"这条路径。

    `plan_path` 用于把「本次执行到底读的是哪一版计划」写进 summary。
    不给就记 NOT_BOUND —— 宁可承认没绑定，也不拿内存里的 dict 反推一个哈希：
    plan 在同一批里被改过范围时，事后无法分辨每条证据出自哪一版。

    **同源强制**：给了 `plan_path` 时，本函数不再信任传入的 `plan` 对象。
    它读文件字节 → 算 sha256 → 用**同一份字节**重新解析出计划对象 →
    与传入对象做规范形比对。三者任一不合即拒绝执行（fail-closed）。
    之后全部下游逻辑（闸门、预算、请求循环）都只用**重新解析出的那个对象**，
    因此「哈希覆盖的字节」与「实际执行的内容」是同一份，不是两次独立读取。
    """
    memory_plan_sha256 = hashlib.sha256(
        _canonical_plan_json(plan)).hexdigest()
    plan_binding = {
        "plan_path": None,
        "plan_sha256": None,
        "plan_bytes": None,
        "memory_plan_sha256": memory_plan_sha256,
        "same_source": False,
        "state": "NOT_BOUND",
        "rule": ("给了 plan_path 时必须：读文件字节 → sha256 → 由同一份字节重新解析 "
                 "→ 与传入对象比对规范形。三者一致才记 "
                 "BOUND_TO_FILE_BYTES_SAME_SOURCE；不一致直接拒绝执行。"
                 "NOT_BOUND 表示未提供路径，该 summary 不得被用来指代任何一版计划文件。"),
        "limit": ("本字段证明「执行内容 = 被哈希的字节」，不证明该字节来自某个具名裁决；"
                  "授权来源仍看 authorization 段与 ruling_sha256。"),
    }
    if plan_path:
        pb = Path(plan_path)
        try:
            praw = pb.read_bytes()
        except OSError as exc:
            raise StageBError("计划文件不可读，拒绝在无身份的情况下执行：%s" % exc)
        file_sha = hashlib.sha256(praw).hexdigest()
        try:
            parsed = json.loads(praw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise StageBError(
                "计划文件不是合法 UTF-8 JSON（sha256=%s，%d 字节），拒绝执行：%s"
                % (file_sha, len(praw), exc))
        file_canon = _canonical_plan_json(parsed)
        mem_canon = _canonical_plan_json(plan)
        if file_canon != mem_canon:
            raise StageBError(
                "计划同源性校验失败，拒绝执行：传入的内存计划与计划文件字节不是同一份内容。"
                "文件 %s（sha256=%s，%d 字节，规范形 sha256=%s）≠ 内存计划（规范形 sha256=%s）。"
                "执行的对象必须是由被哈希的那份字节解析出来的计划。"
                % (str(pb.absolute()), file_sha, len(praw),
                   hashlib.sha256(file_canon).hexdigest(),
                   hashlib.sha256(mem_canon).hexdigest()))
        # 关键一行：下游一律使用由被哈希字节重新解析出的对象。
        plan = parsed
        plan_binding.update({
            "plan_path": str(pb.absolute()),
            "plan_sha256": file_sha,
            "plan_bytes": len(praw),
            "memory_plan_sha256": hashlib.sha256(mem_canon).hexdigest(),
            "same_source": True,
            "state": "BOUND_TO_FILE_BYTES_SAME_SOURCE",
        })
    gate = preflight(plan, approved_origin, environ=environ,
                     catalog_evidence=catalog_evidence,
                     approved_requests=approved_requests, key_env=key_env)
    # 与 preflight 取同一个槽位，避免「闸门检查 A 变量、发请求用 B 变量」这种
    # 闸门看起来通过而实际用了另一把钥匙的情形。
    env = os.environ if environ is None else environ
    env_name = (key_env or KEY_ENV).strip() or KEY_ENV

    root = Path(root)
    if root.exists():
        raise StageBError("证据目录已存在，拒绝覆盖：%s" % root)
    root.mkdir(parents=True, exist_ok=False)

    model = plan["model"]
    endpoint = model["endpoint"]
    params = plan.get("params") or {}
    # 账本里键名是 *_usd（历史命名），真实单位由计划声明；打印时必须带上。
    cost_unit = (plan.get("budget") or {}).get("currency") or "USD"
    guard = BudgetGuard(plan)

    scope_ids = list(gate["scope"]["approved_request_ids"])
    scope_set = set(scope_ids)
    in_scope = [r for r in plan["requests"] if r["request_id"] in scope_set]
    out_of_scope = [r["request_id"] for r in plan["requests"]
                    if r["request_id"] not in scope_set]

    results = []
    termination = {"kind": "SCOPE_COMPLETE", "reason": None}

    for req in in_scope:
        rid = req["request_id"]

        # 发送前：额度、token 上限、剩余预算。这里拒绝就不构造 provider，也不发任何字节。
        decision = guard.precheck(req)
        if not decision["allowed"]:
            termination = {"kind": "BUDGET_PRECHECK_DENIED",
                           "reason": "%s 未发送：%s" % (rid, "；".join(decision["reasons"]))}
            break

        ev_dir = root / rid
        prov = HttpProvider(
            endpoint["base_url"], model["model_id_confirmed"],
            (os.environ if environ is None else environ)[env_name],
            max_tokens=req["max_output_tokens"],
            allowed_origins={endpoint["origin"]},
            enable_thinking=params.get("enable_thinking"),
            # 推理开关的形态由计划声明；未声明时走 chat_template_kwargs，
            # 与改动前逐字节一致（Nebius 正式链路的请求体不变）。
            thinking_style=(params.get("thinking_style")
                            or THINKING_STYLE_CHAT_TEMPLATE),
        )
        t0 = time.time()
        ev = run_mod.run(req["intent_text"], prov, python=python,
                         evidence_dir=ev_dir, spawn=spawn,
                         correlation_id=rid,
                         # 把「本次实际使用的密钥变量名」交给净化链：否则用
                         # --key-env NVIDIA_API_KEY 时，这把钥匙会随环境继承
                         # 进 demo.py 及它派生的每个进程。名字由本函数已解析
                         # 过一次（env_name），与取值的槽位是同一个。
                         key_env=env_name,
                         suppress_kernel_if_select=(
                             req.get("kernel_contract") == CONTRACT_FORBIDDEN))
        elapsed = round(time.time() - t0, 2)

        ok, checks, bad = judge(req, ev)
        settled = guard.settle(req, (ev.get("call") or {}).get("usage"))
        cost, cost_source = settled["cost_usd"], settled["cost_source"]

        results.append({
            "request_id": rid,
            "scenario_id": req.get("scenario_id"),
            "kernel_contract": req.get("kernel_contract"),
            "purpose": req.get("purpose"),
            "intent_sha256": req.get("intent_sha256"),
            "evidence_dir": str(ev_dir),
            "http_status": (ev.get("call") or {}).get("http_status"),
            "adapter_decision": (ev.get("adapter") or {}).get("decision"),
            "adapter_code": (ev.get("adapter") or {}).get("code"),
            "adapter_outcome": (ev.get("adapter") or {}).get("outcome"),
            "model_decision": (ev.get("adapter") or {}).get("model_decision"),
            "kernel_invoked": (ev.get("kernel") or {}).get("invoked"),
            "kernel_exit": (ev.get("kernel") or {}).get("exit_code"),
            "kernel_kind": (ev.get("kernel") or {}).get("kind"),
            "kernel_value": (ev.get("kernel") or {}).get("value"),
            "cost_usd": cost,
            "cost_source": cost_source,
            "cost_confirmable": settled["cost_confirmable"],
            "over_declared_caps": settled["over_declared_caps"],
            "budget_precheck": decision,
            "checks": checks,
            "failed_checks": bad,
            "ok": ok,
            "elapsed_seconds": elapsed,
        })
        if verbose:
            # 单位显式打出来：history 上这条曾写成 cost=$…，而实际单位可能是 CNY。
            # 旧回执不追改，新回执一律带单位。
            print("[%s] %s ok=%s http=%s decision=%s outcome=%s exit=%s cost=%.6f %s(%s)"
                  % (rid, req.get("scenario_id") or "OUT", ok,
                     results[-1]["http_status"], results[-1]["adapter_decision"],
                     results[-1]["adapter_outcome"],
                     results[-1]["kernel_exit"], cost, cost_unit, cost_source),
                  file=sys.stderr)

        if not ok:
            termination = {"kind": "REQUEST_FAILED",
                           "reason": "%s 未通过：%s" % (rid, ", ".join(bad))}
            break
        if guard.spent > guard.max_usd:
            termination = {"kind": "BUDGET_EXCEEDED",
                           "reason": "累计费用 %.6f %s 已超过上限 %.2f %s"
                                     % (guard.spent, cost_unit,
                                        guard.max_usd, cost_unit)}
            break
        if guard.halt:
            # usage 不可用 / 实际 token 超声明上限：本条结果保留，后续一律不发。
            termination = {"kind": "COST_UNCONFIRMED",
                           "reason": "停止后续调用：%s" % guard.halt}
            break

    executed_ids = [r["request_id"] for r in results]
    not_reached_in_scope = [i for i in scope_ids if i not in executed_ids]
    summary = {
        "schema": SUMMARY_SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "plan_binding": plan_binding,
        "plan_schema": plan.get("schema"),
        "model_id": model.get("model_id_confirmed"),
        "endpoint_origin": endpoint.get("origin"),
        "params": params,
        "pricing": gate.get("pricing"),
        # 费用口径：键名里的 *_usd 是历史命名，单位以 cost_unit 为准。
        # cost_evidence_class 只有两个值，引用时必须一起带上：
        #   catalog_verified_price     —— 定价从目录条目重算并与计划一致
        #   declared_price_unverified  —— 端点目录不发布定价，价格是官方页抄录值
        "cost_unit": (plan.get("budget") or {}).get("currency") or "USD",
        "cost_evidence_class": (
            "catalog_verified_price"
            if (gate.get("pricing") or {}).get("machine_verified")
            else "declared_price_unverified"),
        "cost_unit_note": ("budget.*_usd 与 ledger.cost_usd 沿用旧键名，实际单位见 "
                           "cost_unit；cost_evidence_class=declared_price_unverified "
                           "时，该金额是「用量 × 抄录单价」的估算，不是账单实测值。"),
        "gate": gate["gate"],
        "planned_requests": len(plan["requests"]),
        # 三个数必须分开：计划几条、本轮获准几条、实际执行几条。
        # 只写一个 executed 会把"只跑了 1 条"读成"7 条都跑了"。
        "execution_scope": {
            "approved_request_ids": scope_ids,
            "approved_count": len(scope_ids),
            "executed_request_ids": executed_ids,
            "not_reached_in_scope": not_reached_in_scope,
            "not_in_scope": out_of_scope,
            "scope_is_full_plan": set(scope_ids) == {r["request_id"]
                                                     for r in plan["requests"]},
            "complete_means": ("scope 内全部执行且通过即结束。"
                              "not_in_scope 的请求本轮未获准，不代表它们会通过，"
                              "也不代表它们会失败。"),
            "source": (plan.get("execution_scope") or {}).get("source"),
        },
        "executed_requests": len(results),
        "not_executed": [r["request_id"] for r in plan["requests"]
                         if r["request_id"] not in executed_ids],
        "termination": termination,
        # 兼容字段：stopped 只表示"出事了"。正常跑完 scope 不算 stopped，
        # 哪怕 scope 只有 1 条、计划有 7 条。
        "stopped": termination["kind"] != "SCOPE_COMPLETE",
        "stop_reason": termination["reason"],
        "budget": guard.report(),
        "spent_usd": guard.spent,
        "budget_usd": guard.max_usd,
        "retry_attempted": False,
        "results": results,
        "evidence_root": str(root),
    }
    (root / SUMMARY_FILE).write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return summary


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--execute" not in argv:
        print("拒绝：未提供 --execute。本驱动不接受交互式确认，"
              "运行前必须有具名裁决。", file=sys.stderr)
        return 3
    argv.remove("--execute")

    approve_origin = ""
    root = None
    python = None
    plan_path = None
    catalog_evidence = None
    approved_requests = None
    key_env = None
    while argv:
        a = argv.pop(0)
        if a == "--approve-origin" and argv:
            approve_origin = argv.pop(0)
        elif a == "--root" and argv:
            root = Path(argv.pop(0))
        elif a == "--python" and argv:
            python = argv.pop(0)
        elif a == "--plan" and argv:
            plan_path = Path(argv.pop(0))
        elif a == "--catalog-evidence" and argv:
            catalog_evidence = argv.pop(0)
        elif a == "--key-env" and argv:
            # 只换**变量名**，不换「必须有值」这条。默认仍 NEBIUS_API_KEY。
            # 用途：在非正式通道上指向别的环境槽位；正式链路不传即行为不变。
            key_env = argv.pop(0)
        elif a == "--approved-requests" and argv:
            # 本轮获准执行的请求，逗号分隔，例如 "R1"。
            # 必须与计划 execution_scope 逐字一致：两处独立给出，任一处被改都会暴露。
            approved_requests = argv.pop(0)
        else:
            print("未知参数：%r" % a, file=sys.stderr)
            return 3

    plan = load_plan(plan_path)
    root = root or (Path("C:/h56_release_evidence")
                    / ("stage_b_%s_p%d" % (time.strftime("%Y%m%dT%H%M%S"),
                                           os.getpid())))
    try:
        summary = execute(plan, root, python=python, approved_origin=approve_origin,
                          catalog_evidence=catalog_evidence,
                          approved_requests=approved_requests, key_env=key_env,
                          plan_path=plan_path or PLAN_PATH)
    except (StageBError, ProviderConfigError) as exc:
        print("执行前拒绝：%s" % exc, file=sys.stderr)
        return 4

    scope = summary["execution_scope"]
    if summary["termination"]["kind"] == "SCOPE_COMPLETE":
        verdict = "范围内全部通过"
    else:
        verdict = "%s：%s" % (summary["termination"]["kind"], summary["stop_reason"])
    print("\n范围 %s（%d/%d 条获准）：执行 %d 条，花费 %.6f %s（%s），%s"
          % ("→".join(scope["approved_request_ids"]),
             scope["approved_count"], summary["planned_requests"],
             summary["executed_requests"], summary["spent_usd"],
             summary.get("cost_unit"), summary.get("cost_evidence_class"), verdict),
          file=sys.stderr)
    if scope["not_in_scope"]:
        print("本轮未获准（未执行、未构造 provider、未发字节）：%s"
              % ", ".join(scope["not_in_scope"]), file=sys.stderr)
    print("证据：%s" % root, file=sys.stderr)
    return 0 if summary["termination"]["kind"] == "SCOPE_COMPLETE" else 2


if __name__ == "__main__":
    sys.exit(main())
