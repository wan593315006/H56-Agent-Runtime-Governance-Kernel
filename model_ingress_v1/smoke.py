"""非证据通道：用任意 OpenAI 兼容端点验证 prompt → provider → validate 三段。

**这不是证据链的一部分。** 它不写 `stage_b_summary.json`、不调内核、不产生
可用于 DEL-11 / R1 / D4 的任何证据。它的唯一用途是：在正式授权下来之前，用
真实响应把三件只能靠真实响应才能确认的事确认掉——

  1. 提示词能否把模型引导到**恰好 5 个键**的合规 JSON（格式服从性）；
  2. 响应的字段名与结构（`choices[0].message.content`、`usage` 的键名）；
  3. 网络与鉴权路径是否通（HTTP 状态、错误体形状）。

它推进到哪一步、没推进到哪一步（这两句必须一起读）：
  - **已覆盖**：提示词 → Provider → 响应校验。三段复用的是正式链路
    同一份实现（`prompt` / `provider.HttpProvider` / `validate`）。
  - **未覆盖**：模型提案没有进入 Adapter 的登记表解析与内核启动，因此
    本轮取得的是**调试准备成果**，没有为「真实模型 ↔ 原四核协同」增加任何
    运行证据。要走完那一段，只能靠正式阶段 B（`stage_b --execute`），它带
    统一闸门、预算守卫、执行范围与证据绑定，需另行裁决。

「同一份实现」≠「同一次请求」：正式阶段 B 从计划逐请求传入
`max_output_tokens` 与 `params.enable_thinking`，本通道也按同一来源取值
（见 `request_config`），但闸门/预算/证据层不在，且 smoke 的调用上下文固定为
单条 R1 意图。所以 smoke 通过**不能**推出正式请求必过——正式请求仍需验证。

用法（密钥只从环境变量取，不进命令行、不进证据）：

    python -m model_ingress_v1.smoke --execute \
        --origin https://integrate.api.nvidia.com:443 \
        --base-url https://integrate.api.nvidia.com/v1 \
        --model-id <该端点上的模型 id> \
        --key-env NVIDIA_API_KEY \
        --root C:/h56_release_evidence/smoke_<stamp>

正式端点就绪后换成：

    --origin https://api.tokenfactory.nebius.com:443 \
    --base-url https://api.tokenfactory.nebius.com/v1 \
    --model-id nvidia/Nemotron-3.5-Lightning --key-env NEBIUS_API_KEY

退出码：0 = 调用成功且校验通过；2 = 调用成功但校验未通过（有原始响应可查）；
3 = 参数问题；4 = 未获得执行开关 / 端点未显式批准 / 密钥缺失 / 目录已存在。
"""

import hashlib
import json
import os
import sys
import time
from pathlib import Path

from . import prompt as prompt_mod
from . import provider as provider_mod
from . import registry as registry_mod
from . import stage_b as stage_b_mod
from . import validate as validate_mod

SMOKE_SCHEMA = "H56_SMOKE_NON_EVIDENCE_V1"
CHAIN_MARK = "NOT_EVIDENCE_CHAIN"

# 与正式阶段 B 的差别，逐条列出来而不是笼统说「没有闸门」。
# 请求侧配置（enable_thinking / max_tokens）已对齐，所以差别只在这些治理层。
REQUEST_RESIDUAL_DIFFS = (
    "无统一闸门 stage_b.preflight",
    "无预算守卫 BudgetGuard",
    "无执行范围校验 execution_scope",
    "无证据绑定（不写 summary、不受裁决约束）",
    "模型提案不进入 Adapter/内核：不产生四核记录，也不构成模型↔OS 协同证据",
)

META_FILE = "smoke_meta.json"
REQUEST_FILE = "request_body.json"
RAW_FILE = "response_raw.bin"
VERDICT_FILE = "verdict.json"


def _write_json(path, obj):
    Path(path).write_text(
        json.dumps(obj, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def run_smoke(base_url, model_id, api_key, origin, root, intent,
              key_env=None, env_name=None, timeout=None,
              enable_thinking=None, max_tokens=None, config_source=None):
    """发一次 chat completion 并校验。任何路径都留证据（失败也留）。

    enable_thinking / max_tokens 必须由调用方按**正式阶段 B 的同一来源**
    （计划 `params.enable_thinking` 与 R1 的 `max_output_tokens`）传入。
    早前版本不传 enable_thinking，于是请求体比正式请求少一个
    `chat_template_kwargs` 键：复用了实现，但请求配置并不相同，通过结果
    不能推出正式请求也会通过。现在把这层差别写进 `request_config`。
    """
    env_label = env_name or (key_env or stage_b_mod.KEY_ENV)
    out = Path(root)
    if out.exists():
        raise RuntimeError("证据目录已存在，拒绝覆盖：%s" % out)

    scenarios = registry_mod.load()
    registry_ids = registry_mod.ids()
    messages = prompt_mod.build(intent, scenarios)
    messages_sha = hashlib.sha256(
        json.dumps(messages, ensure_ascii=False).encode("utf-8")).hexdigest()

    kw = {}
    if timeout is not None:
        kw["timeout"] = timeout
    if max_tokens is not None:
        kw["max_tokens"] = max_tokens
    prov = provider_mod.HttpProvider(
        base_url, model_id, api_key,
        allowed_origins={provider_mod.origin_of(origin)},
        enable_thinking=enable_thinking, **kw)

    out.mkdir(parents=True, exist_ok=False)
    cfg = config_source or {}
    meta = {
        "schema": SMOKE_SCHEMA,
        "chain_mark": CHAIN_MARK,
        "statement": ("本目录是调试通道的产物，不属于证据链，不得用于任何"
                      "授权、合规或参赛材料。唯一用途是确认提示词/协议/鉴权三段是否可用。"),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "endpoint": {
            "base_url": prov.base_url,
            "origin": prov._origin,
            "path": prov.path(),
            "model_id": prov.model_id,
            "max_tokens": prov.max_tokens,
            "attempts": prov.attempts,
            "redirects_followed": 0,
            "approved_origin_explicit": True,
        },
        "credential": {
            "env_var_name": env_label,
            "recorded": False,
            "note": "只记变量名，不记值，也不记长度。",
        },
        "prompt": {
            "messages_count": len(messages),
            "messages_sha256": messages_sha,
            "intent_sha256": hashlib.sha256(
                intent.encode("utf-8")).hexdigest(),
            "intent_chars": len(intent),
        },
        # 请求侧配置：与正式阶段 B 是否一致，写清楚，不靠读者比对代码。
        "request_config": {
            "enable_thinking": prov.enable_thinking,
            "thinking_param": prov.thinking_block(),
            "max_tokens": prov.max_tokens,
            "temperature": 0,
            "stream": False,
            "source": cfg.get("source") or "caller_supplied",
            "stage_b_reference": cfg.get("stage_b_reference"),
            "matches_stage_b": cfg.get("matches_stage_b"),
            "matches_rule": ("enable_thinking 与 max_tokens 逐项等于计划"
                             "params.enable_thinking 与 R1.max_output_tokens。"
                             "None 表示调用方未提供计划参照，本轮无法比较。"),
            "residual_differences_vs_stage_b": list(REQUEST_RESIDUAL_DIFFS),
        },
        "kernel": {
            "invoked": False,
            "why": ("调试通道不调内核：它没有把模型提案交给登记表解析，也没有执行范围/"
                    "预算/证据绑定，直接 spawn 只会得到一条无法归属到 DEL-11 链路的进程记录。"
                    "这不等于「调核心会产生假记录」——正式方案本来就是「模型选冻结场景，"
                    "原四核真算」，合成输入与真实计算可以同时成立；只是那一步必须走阶段 B。"),
        },
        "credential_value_written": False,
    }

    call = None
    err = None
    raw = b""
    req_body = b""
    t0 = time.time()
    try:
        call = prov.complete(messages)
        # Call["body"] 装的是**响应原始字节**（不是解析后的对象），
        # 与 run.py 里 validate_response(call["body"], ...) 的用法一致。
        raw = call.get("body") or b""
        req_body = call.get("request_body") or b""
        meta["http_status"] = call.get("http_status")
    except provider_mod.ProviderError as exc:
        err = exc
        raw = getattr(exc, "raw", b"") or b""
        req_body = getattr(exc, "request_body", b"") or b""
        meta["http_status"] = getattr(exc, "http_status", None)
    elapsed = round(time.time() - t0, 2)

    if req_body:
        (out / REQUEST_FILE).write_bytes(req_body)
    if raw:
        (out / RAW_FILE).write_bytes(raw)

    meta["elapsed_s"] = elapsed
    meta["request_body"] = {
        "file": REQUEST_FILE if req_body else None,
        "bytes": len(req_body),
        "sha256": hashlib.sha256(req_body).hexdigest() if req_body else None,
    }
    meta["response_raw"] = {
        "file": RAW_FILE if raw else None,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
    }

    if err is not None:
        meta["outcome"] = "TRANSPORT_FAILED"
        meta["error"] = {"type": type(err).__name__, "detail": str(err)[:500],
                         "http_status": getattr(err, "http_status", None)}
        _write_json(out / META_FILE, meta)
        return {"ok": False, "exit": 4, "outcome": "TRANSPORT_FAILED",
                "meta": meta}

    usage = call.get("usage")
    meta["usage"] = usage
    meta["usage_field_present"] = isinstance(usage, dict) and all(
        isinstance(usage.get(k), int) for k in ("prompt_tokens", "completion_tokens"))
    if isinstance(usage, dict):
        meta["usage_keys"] = sorted(usage.keys())

    # 构造初期的失败（超时/HTTP 非 200）已在上面的 except 里返回，所以这里
    # body 一定是 200 的字节；解析失败由 validate 判 MALFORMED。
    verdict = validate_mod.validate_response(raw, prov.model_id, registry_ids)
    _write_json(out / VERDICT_FILE, dict(verdict))

    meta["validate"] = {
        "decision": verdict["decision"],
        "code": verdict["code"],
        "scenario_id": verdict["scenario_id"],
        "model_decision": verdict["model_decision"],
        "checks_passed": verdict["checks_passed"],
        "reason_chars": len(verdict.get("reason") or ""),
    }
    meta["outcome"] = ("CALL_OK_VALIDATED"
                       if verdict.get("decision") == "ACCEPTED"
                       else "CALL_OK_REJECTED")
    meta["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    _write_json(out / META_FILE, meta)

    accepted = verdict.get("decision") == "ACCEPTED"
    return {"ok": accepted,
            "exit": 0 if accepted else 2,
            "outcome": meta["outcome"], "meta": meta, "verdict": dict(verdict)}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--execute" not in argv:
        print("拒绝：未提供 --execute。本通道会发真实请求，不接受顺手执行。",
              file=sys.stderr)
        return 3
    argv.remove("--execute")

    origin = base_url = model_id = root = intent = key_env = None
    plan_path = None
    timeout = None
    while argv:
        a = argv.pop(0)
        if a == "--origin" and argv:
            origin = argv.pop(0)
        elif a == "--base-url" and argv:
            base_url = argv.pop(0)
        elif a == "--model-id" and argv:
            model_id = argv.pop(0)
        elif a == "--key-env" and argv:
            key_env = argv.pop(0)
        elif a == "--root" and argv:
            root = argv.pop(0)
        elif a == "--intent" and argv:
            intent = argv.pop(0)
        elif a == "--intent-file" and argv:
            intent = Path(argv.pop(0)).read_text(encoding="utf-8")
        elif a == "--plan" and argv:
            plan_path = Path(argv.pop(0))
        elif a == "--timeout" and argv:
            timeout = float(argv.pop(0))
        else:
            print("未知参数：%r" % a, file=sys.stderr)
            return 3

    missing = [n for n, v in (("--origin", origin), ("--base-url", base_url),
                              ("--model-id", model_id), ("--root", root))
               if not v]
    if missing:
        print("拒绝：缺少 %s" % ", ".join(missing), file=sys.stderr)
        return 3

    # 端点必须显式点名：与正式链路同一口径——没有默认批准任何主机。
    if provider_mod.origin_of(base_url) != provider_mod.origin_of(origin):
        print("拒绝：--origin %r 与 --base-url 的实际源 %r 不一致"
              % (origin, provider_mod.origin_of(base_url)), file=sys.stderr)
        return 4

    plan = stage_b_mod.load_plan(plan_path)
    params = plan.get("params") or {}
    r1 = None
    for req in plan.get("requests") or []:
        if req.get("request_id") == "R1":
            r1 = req
            break

    if not intent:
        intent = (r1 or {}).get("intent_text")
        if not intent:
            print("拒绝：未给 --intent，且计划里没有 R1 的 intent_text 可借用",
                  file=sys.stderr)
            return 3

    # 请求侧配置与正式阶段 B 同源取：params.enable_thinking + R1.max_output_tokens。
    # 早前版本不传 enable_thinking，发出去的请求体比正式请求少一个
    # chat_template_kwargs 键 —— 复用了实现，却不是同一次请求。
    enable_thinking = params.get("enable_thinking")
    # 阶段 B 对每条请求直接下标 req["max_output_tokens"]（缺失即 KeyError），
    # 所以这里也按该键取；取不到才回退，并因此判为「与阶段 B 不一致」。
    r1_max = (r1 or {}).get("max_output_tokens")
    max_tokens = r1_max
    stage_b_would_send = {
        "enable_thinking": params.get("enable_thinking"),
        "max_tokens": r1_max,
    }
    if max_tokens is None:
        max_tokens = params.get("max_tokens")
    resolved_max = (max_tokens if max_tokens is not None
                    else provider_mod.DEFAULT_MAX_TOKENS)
    stage_b_reference = {
        "enable_thinking": stage_b_would_send["enable_thinking"],
        "max_tokens": stage_b_would_send["max_tokens"],
        "source": {
            "enable_thinking": "plan.params.enable_thinking",
            "max_tokens": ("plan.requests[R1].max_output_tokens" if r1_max
                           else "回退：计划未给 R1.max_output_tokens"),
        },
        "plan_path": str(plan_path or stage_b_mod.PLAN_PATH),
    }
    # 逐项比较本通道将要发送的值与阶段 B 对 R1 会发送的值。
    # 这是结构比较（同源推导），不是「两次真实请求互相比对」。
    matches_stage_b = (enable_thinking == stage_b_would_send["enable_thinking"]
                       and resolved_max == stage_b_would_send["max_tokens"])

    env_name = (key_env or stage_b_mod.KEY_ENV).strip() or stage_b_mod.KEY_ENV
    key = os.environ.get(env_name)
    if not key:
        print("拒绝：环境变量 %s 未配置（值不入库、不入日志）" % env_name,
              file=sys.stderr)
        return 4

    try:
        res = run_smoke(base_url, model_id, key, origin, root, intent,
                        key_env=key_env, env_name=env_name, timeout=timeout,
                        enable_thinking=enable_thinking,
                        max_tokens=max_tokens,
                        config_source={
                            "source": "plan:params.enable_thinking + R1.max_output_tokens",
                            "stage_b_reference": stage_b_reference,
                            "matches_stage_b": matches_stage_b,
                        })
    except RuntimeError as exc:
        print("拒绝：%s" % exc, file=sys.stderr)
        return 4

    m = res["meta"]
    print("outcome     : %s" % res["outcome"])
    print("http_status : %s" % m.get("http_status"))
    print("elapsed     : %ss" % m["elapsed_s"])
    print("model_id    : %s" % m["endpoint"]["model_id"])
    print("origin      : %s" % m["endpoint"]["origin"])
    rc = m.get("request_config") or {}
    print("req_config  : enable_thinking=%s max_tokens=%s matches_stage_b=%s"
          % (rc.get("enable_thinking"), rc.get("max_tokens"),
             rc.get("matches_stage_b")))
    print("usage       : %s" % json.dumps(m.get("usage"), ensure_ascii=False))
    if "validate" in m:
        print("decision    : %s / code %s / scenario %s"
              % (m["validate"]["decision"], m["validate"]["code"],
                 m["validate"]["scenario_id"]))
    print("evidence    : %s  (%s)" % (root, CHAIN_MARK))
    return res["exit"]


if __name__ == "__main__":
    sys.exit(main())
