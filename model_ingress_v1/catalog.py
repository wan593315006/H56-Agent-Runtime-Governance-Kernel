"""模型目录：一次 GET，把「我看过目录」这件事固化成可核验的本地证据。

两个动作严格分开，因为它们的授权不同：

    fetch()  —— 真的发一次 GET（需要联网裁决，且只做一次）
    verify() —— 只读本地证据文件，重算哈希、从原始字节重新解析（不联网）

为什么 fetch 不顺手把结果写回计划文件：那样「模型身份已确认」就变成程序自己
签的字，又回到「人工改布尔标记」的老路。这里的规矩相反 ——

    fetch 只产出证据；
    「VERIFIED」由预检代码**读证据**算出来；
    计划文件里的 state 只是被比对的声明值，不一致就拒绝运行。

目录响应对本仓库不是秘密（公开的模型列表），对凭据是 —— 所以 raw 原样落盘，
但 evidence 里只记 `credential_recorded: false`，并且 verify 会主动检查
落盘字节里不含 `Bearer `。
"""

import hashlib
import json
import sys
import time
from pathlib import Path

try:  # 作为包导入
    from . import provider as provider_mod
except ImportError:  # 直接运行
    sys.path.insert(0, str(Path(__file__).absolute().parent.parent))
    from model_ingress_v1 import provider as provider_mod

CATALOG_SCHEMA = "H56_MODEL_CATALOG_EVIDENCE_V1"
RAW_FILE = "catalog_models_raw.json"
EVIDENCE_FILE = "catalog_evidence.json"
CATALOG_PATH = "/models"
DEFAULT_QUERY = "verbose=true"
KEY_ENV = "NEBIUS_API_KEY"

# 目录定价的两种写法：有的端点给「每 token」，有的给「每 1M token」。
# 6e-8 与 0.06 描述的是同一件事，不归一化就没法比。
PRICE_AS_TOKEN_CEILING = 1e-3
PRICE_REL_TOLERANCE = 1e-6


class CatalogError(Exception):
    """目录查询的部署期/执行期错误。不是推理拒绝码，不进拒绝码表。"""


def catalog_url(base_url, query=DEFAULT_QUERY):
    return base_url.rstrip("/") + CATALOG_PATH + ("?" + query if query else "")


def expected_request_of(plan):
    """由计划派生「本次获准的那次 GET 长什么样」。

    派生而不是手写：origin / 路径 / 查询参数三处只要有一处被改动，
    比对就会失败 —— 这正是"来源对应"要拦的东西。
    """
    model = (plan or {}).get("model") or {}
    endpoint = model.get("endpoint") or {}
    conf = model.get("confirmation") or {}
    query = conf.get("query", DEFAULT_QUERY)
    base_url = endpoint.get("base_url") or ""
    path = endpoint.get("catalog_path") or CATALOG_PATH
    origin = endpoint.get("origin")
    url = base_url.rstrip("/") + path + ("?" + query if query else "") if base_url else None
    return {"origin": origin, "method": "GET", "path": path,
            "query": query, "url": url}


def request_url_matches(recorded_url, expected):
    """记录的 URL 与计划派生的 URL 是否对应。逐字比较，不做规范化。"""
    if not expected or not expected.get("url"):
        return None  # 计划里没有可比的基线 -> 调用方应按"未提供期望"处理
    return recorded_url == expected["url"]


def normalize_price(value):
    """把目录里的一个价格归一到「USD / 1M tokens」。

    返回 (per_1m_usd, rule)；无法解析时返回 (None, None)。
    归一化规则必须写进证据，否则「0.06 与 6e-8 相等」这件事会变成读代码才知道的暗知识。
    """
    if isinstance(value, bool) or value is None:
        return None, None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None, None
    if v <= 0:
        return None, None
    if v <= PRICE_AS_TOKEN_CEILING:
        return v * 1e6, "value<=1e-3，按 per-token 归一为 per-1M"
    return v, "value>1e-3，本身就是 per-1M"


def _price_fields(entry):
    """从目录条目里取 (input_per_1m, output_per_1m, raw_block)。"""
    pricing = entry.get("pricing") if isinstance(entry, dict) else None
    if not isinstance(pricing, dict):
        return None, None, None
    raw_in = pricing.get("prompt", pricing.get("input"))
    raw_out = pricing.get("completion", pricing.get("output"))
    pin, rule_in = normalize_price(raw_in)
    pout, rule_out = normalize_price(raw_out)
    return pin, pout, {
        "raw_prompt": raw_in, "raw_completion": raw_out,
        "input_per_1m_usd": pin, "output_per_1m_usd": pout,
        "input_normalization": rule_in, "output_normalization": rule_out,
    }


def _model_entries(raw):
    """从原始字节重新解析出模型条目。绝不读 evidence 里的派生字段。"""
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise CatalogError("目录响应顶层不是对象")
    models = data.get("data")
    if not isinstance(models, list):
        raise CatalogError("目录响应缺少 data 数组")
    return [m for m in models if isinstance(m, dict)]


# ---------------------------------------------------------------- 一次 GET
def fetch(base_url, api_key, allowed_origins, evidence_dir,
          timeout=provider_mod.DEFAULT_TIMEOUT, query=DEFAULT_QUERY,
          key_env=None):
    """发且只发一次 GET，把原始字节与证据写进新建目录。目录已存在即拒绝。"""
    env_name = (key_env or KEY_ENV).strip() or KEY_ENV
    if not api_key:
        raise CatalogError("缺少 API key（%s）" % env_name)
    origin = provider_mod.origin_of(base_url)
    if origin not in frozenset(allowed_origins):
        raise CatalogError("端点 %s 不在批准清单内" % origin)
    url = catalog_url(base_url, query)
    if provider_mod.origin_of(url) != origin:
        raise CatalogError("endpoint_drift：%s != %s"
                           % (provider_mod.origin_of(url), origin))

    out = Path(evidence_dir)
    if out.exists():
        raise CatalogError("证据目录已存在，拒绝覆盖：%s" % out)

    headers = {"Accept": "application/json",
               "Authorization": "Bearer %s" % api_key}
    started = time.strftime("%Y-%m-%dT%H:%M:%S")
    t0 = time.time()
    try:
        status, raw, _headers = provider_mod._get_once(url, headers, timeout)
    except provider_mod.ProviderError as exc:
        raise CatalogError("目录查询失败：%s" % exc.detail)
    elapsed_ms = int((time.time() - t0) * 1000)
    retrieved_at = time.strftime("%Y-%m-%dT%H:%M:%S")

    out.mkdir(parents=True, exist_ok=False)
    (out / RAW_FILE).write_bytes(raw)

    ids, entries, parse_error = [], {}, None
    try:
        for m in _model_entries(raw):
            mid = m.get("id")
            if not isinstance(mid, str):
                continue
            ids.append(mid)
            pin, pout, price_block = _price_fields(m)
            entries[mid] = {
                "id": mid,
                "context_length": m.get("context_length"),
                "supported_features": m.get("supported_features"),
                "pricing": price_block,
                "input_per_1m_usd": pin,
                "output_per_1m_usd": pout,
            }
    except Exception as exc:  # 解析失败照样落证据：失败也有取证价值
        parse_error = "%s: %s" % (type(exc).__name__, exc)

    ev = {
        "schema": CATALOG_SCHEMA,
        "retrieved_at": retrieved_at,
        "started_at": started,
        "elapsed_ms": elapsed_ms,
        "endpoint_origin": origin,
        "request_method": "GET",
        "request_path": CATALOG_PATH,
        "request_query": query,
        # 完整 URL 留档（只含 origin + 路径 + 非敏感查询参数，不含任何凭据），
        # 以及它的摘要。有了它，"这次查的是不是计划里那个端点"才可被程序比对，
        # 而不是靠读 fetch() 的代码推断。
        "request_url": url,
        "request_url_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
        "http_status": status,
        "attempts": 1,
        "redirects_followed": 0,
        "credential_recorded": False,
        "credential_env_var_name": env_name,
        "raw_file": RAW_FILE,
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_truncated": len(raw) > provider_mod.MAX_CATALOG_BYTES,
        "model_count": len(ids),
        "model_ids": sorted(ids),
        "models": entries,
        "parse_error": parse_error,
        "note": ("本文件是一次真实 GET 的结果记录。这里没有、也不得出现任何凭据；"
                 "raw 文件是端点返回的原始字节，其 sha256 可由磁盘独立重算。"
                 "本文件不构成任何授权：模型身份是否确认，由 stage_b.preflight "
                 "读本文件后计算，不采信任何手工写入的布尔值。"),
    }
    (out / EVIDENCE_FILE).write_text(
        json.dumps(ev, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return ev


# ---------------------------------------------------------------- 只读核验
def verify(evidence_path, model_id_expected, pricing, expected_request=None,
           tolerance=PRICE_REL_TOLERANCE):
    """只读核验目录证据。返回 dict；ok=False 时 failed 列出具体项。

    关键点：所有事实都从 **raw 原始字节**重新解析，不读 evidence.json 里的
    派生字段（model_ids / models / input_per_1m_usd …）。派生字段只是方便人看，
    一旦与 raw 不一致，raw 说话。

    `expected_request` 是「本次获准的那次 GET」的期望形态（由
    `expected_request_of(plan)` 派生）。给了它，就额外核对
    origin / method / path / query / 完整 URL 五项来源对应 ——
    否则一份"从别处查来的目录"只要内容对得上，也会被当成这次查询的结果。
    """
    checks = []

    def add(name, ok, detail=None):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    res = {
        "evidence_file": str(evidence_path),
        "model_id_expected": model_id_expected,
        "model_id_verified": None,
        "pricing_observed": None,
        "pricing_declared": {"input": (pricing or {}).get("input"),
                             "output": (pricing or {}).get("output")},
        "http_status": None,
        "retrieved_at": None,
        "raw_sha256_recomputed": None,
        "evidence_sha256_recomputed": None,
        "request_recorded": None,
        "request_expected": expected_request,
        "checks": checks,
    }

    def done():
        res["failed"] = [c["check"] for c in checks if not c["ok"]]
        res["ok"] = not res["failed"]
        return res

    p = Path(evidence_path)
    add("evidence_file_exists", p.exists(), str(p))
    add("model_id_expected_present", isinstance(model_id_expected, str)
        and bool(model_id_expected), model_id_expected)
    if not p.exists() or not isinstance(model_id_expected, str) or not model_id_expected:
        return done()

    ev_bytes = p.read_bytes()
    res["evidence_sha256_recomputed"] = hashlib.sha256(ev_bytes).hexdigest()
    try:
        ev = json.loads(ev_bytes.decode("utf-8"))
    except Exception as exc:
        add("evidence_parses", False, "%s: %s" % (type(exc).__name__, exc))
        return done()
    add("evidence_parses", True)
    add("schema", ev.get("schema") == CATALOG_SCHEMA, ev.get("schema"))
    res["http_status"] = ev.get("http_status")
    res["retrieved_at"] = ev.get("retrieved_at")

    # -- 来源对应：这份证据是不是"这一次、这个端点、这个方法"的结果 --
    recorded = {
        "origin": ev.get("endpoint_origin"),
        "method": ev.get("request_method"),
        "path": ev.get("request_path"),
        "query": ev.get("request_query"),
        "url": ev.get("request_url"),
        "url_sha256": ev.get("request_url_sha256"),
    }
    res["request_recorded"] = recorded
    want = expected_request or {}
    if not want.get("url"):
        add("request_expected_provided", False,
            "未提供期望请求：无法核对来源，等于不核")
    else:
        add("request_expected_provided", True, want.get("url"))
        add("endpoint_origin_matches_plan", recorded["origin"] == want.get("origin"),
            "%r vs %r" % (recorded["origin"], want.get("origin")))
        add("request_method_matches_plan", recorded["method"] == want.get("method"),
            "%r vs %r" % (recorded["method"], want.get("method")))
        add("request_path_matches_plan", recorded["path"] == want.get("path"),
            "%r vs %r" % (recorded["path"], want.get("path")))
        add("request_query_matches_plan", recorded["query"] == want.get("query"),
            "%r vs %r" % (recorded["query"], want.get("query")))
        add("request_url_matches_plan", recorded["url"] == want.get("url"),
            "%r vs %r" % (recorded["url"], want.get("url")))
        add("request_url_sha256_matches",
            isinstance(recorded["url"], str)
            and recorded["url_sha256"] == hashlib.sha256(
                recorded["url"].encode("utf-8")).hexdigest(),
            recorded["url_sha256"])

    rawp = p.parent / str(ev.get("raw_file") or "")
    add("raw_file_declared", bool(ev.get("raw_file")), ev.get("raw_file"))
    add("raw_file_exists", bool(ev.get("raw_file")) and rawp.exists(), str(rawp))
    if not (ev.get("raw_file") and rawp.exists()):
        return done()
    raw = rawp.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    res["raw_sha256_recomputed"] = sha
    add("raw_sha256_matches_declared", sha == ev.get("raw_sha256"),
        "%s vs %s" % (sha[:16], str(ev.get("raw_sha256"))[:16]))
    add("raw_bytes_match_declared", len(raw) == ev.get("raw_bytes"),
        "%d vs %s" % (len(raw), ev.get("raw_bytes")))
    add("raw_not_truncated", len(raw) <= provider_mod.MAX_CATALOG_BYTES,
        "%d bytes" % len(raw))
    add("http_status_200", ev.get("http_status") == 200, ev.get("http_status"))
    add("redirects_not_followed", ev.get("redirects_followed") in (0, None),
        ev.get("redirects_followed"))
    add("attempts_is_one", ev.get("attempts") in (1, None), ev.get("attempts"))
    add("credential_absent_from_raw", b"Bearer " not in raw and b"NEBIUS_API_KEY" not in raw)
    add("credential_not_recorded", ev.get("credential_recorded") is False,
        ev.get("credential_recorded"))

    try:
        entries = _model_entries(raw)
    except Exception as exc:
        add("raw_parses_as_model_list", False, "%s: %s" % (type(exc).__name__, exc))
        return done()
    add("raw_parses_as_model_list", True)

    ids = [m.get("id") for m in entries if isinstance(m.get("id"), str)]
    add("model_id_listed", model_id_expected in ids,
        "%s（目录共 %d 个模型）" % (model_id_expected, len(ids)))
    entry = next((m for m in entries if m.get("id") == model_id_expected), None)
    res["model_id_verified"] = entry.get("id") if entry else None
    if entry is None:
        return done()

    pin, pout, block = _price_fields(entry)
    res["pricing_observed"] = block
    want_in = (pricing or {}).get("input")
    want_out = (pricing or {}).get("output")
    add("catalog_pricing_present", pin is not None and pout is not None, block)

    def close(observed, declared):
        if observed is None or not isinstance(declared, (int, float)):
            return False
        return abs(observed - declared) <= max(abs(declared), 1e-12) * tolerance

    add("pricing_input_matches_plan", close(pin, want_in),
        "%s vs %s" % (pin, want_in))
    add("pricing_output_matches_plan", close(pout, want_out),
        "%s vs %s" % (pout, want_out))
    return done()


# ---------------------------------------------------------------- 命令行
def main(argv=None):
    """一次具名目录查询的执行入口。

        python -m model_ingress_v1.catalog --execute \
            --approve-origin https://api.tokenfactory.nebius.com:443 \
            --root C:/h56_release_evidence/d4_catalog_<stamp>

    没有 --execute 一律拒绝：本程序不接受「顺手跑一下」。
    """
    import os

    argv = list(sys.argv[1:] if argv is None else argv)
    if "--execute" not in argv:
        print("拒绝：未提供 --execute。目录查询需要具名裁决，不接受顺手执行。",
              file=sys.stderr)
        return 3
    argv.remove("--execute")

    approve_origin, root, plan_path, key_env = "", None, None, None
    while argv:
        a = argv.pop(0)
        if a == "--approve-origin" and argv:
            approve_origin = argv.pop(0)
        elif a == "--root" and argv:
            root = Path(argv.pop(0))
        elif a == "--plan" and argv:
            plan_path = Path(argv.pop(0))
        elif a == "--key-env" and argv:
            # 只换**变量名**。默认 NEBIUS_API_KEY，正式链路不传即行为不变。
            key_env = argv.pop(0)
        else:
            print("未知参数：%r" % a, file=sys.stderr)
            return 3

    try:
        from . import stage_b as stage_b_mod
    except ImportError:
        from model_ingress_v1 import stage_b as stage_b_mod
    plan = stage_b_mod.load_plan(plan_path)
    model = plan.get("model") or {}
    endpoint = model.get("endpoint") or {}
    want = endpoint.get("origin")
    if not approve_origin:
        print("拒绝：未提供 --approve-origin", file=sys.stderr)
        return 4
    if approve_origin.strip() != want:
        print("拒绝：--approve-origin %r 与计划中的 %r 不一致"
              % (approve_origin.strip(), want), file=sys.stderr)
        return 4
    env_name = (key_env or KEY_ENV).strip() or KEY_ENV
    key = os.environ.get(env_name)
    if not key:
        print("拒绝：环境变量 %s 未配置（值不入库、不入日志）" % env_name,
              file=sys.stderr)
        return 4

    root = root or (Path("C:/h56_release_evidence")
                    / ("d4_catalog_%s_p%d" % (time.strftime("%Y%m%dT%H%M%S"),
                                              os.getpid())))
    try:
        ev = fetch(endpoint["base_url"], key, {want}, root,
                   query=plan["model"]["confirmation"].get("query", DEFAULT_QUERY),
                   key_env=env_name)
    except CatalogError as exc:
        print("目录查询失败：%s" % exc, file=sys.stderr)
        return 4

    print("HTTP %s，%d 个模型，原始 %d 字节"
          % (ev["http_status"], ev["model_count"], ev["raw_bytes"]), file=sys.stderr)
    res = verify(Path(root) / EVIDENCE_FILE,
                 model.get("model_id_expected") or "", model.get("pricing") or {},
                 expected_request=expected_request_of(plan))
    if res["ok"]:
        print("核验通过：目录列出 %s，定价与计划一致，来源与计划端点对应。"
              % res["model_id_verified"], file=sys.stderr)
    else:
        print("核验未通过：%s" % ", ".join(res["failed"]), file=sys.stderr)
    print("证据：%s" % root, file=sys.stderr)
    return 0 if ev["http_status"] == 200 and res["ok"] else 5


if __name__ == "__main__":
    sys.exit(main())
