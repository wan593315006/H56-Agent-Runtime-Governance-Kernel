"""模型调用的唯一出口。标准库 urllib，单次 POST，绝不重试。

硬约束：
- attempts 恒为 1。没有退避、没有第二次、没有 fallback provider。
- 配置全部来自环境变量，不从文件读、不从命令行参数读、不落盘。
- 异常只暴露「类型 + HTTP 状态码」，不回显请求头、不回显 URL 的查询段。
- 本模块不含任何资格判断逻辑，只搬运字节。

端点固定（fail-closed）：
- 构造期即把 base_url 归约为 `scheme://host:port` 并冻结，之后不可改。
- host 必须落在批准清单内。清单为空 = 尚未裁决任何端点 = 任何构造都失败，
  因此默认行为是「一个请求也发不出去」，而不是「默认允许」。
- 重定向一律拒绝。HTTPRedirectHandler 被替换为抛错实现，301/302/303/307/308
  都会在发出第二个请求之前失败 —— 这是为了避免 Authorization 头被带到
  未批准的主机上。发送后还会复核最终地址的 origin 仍与冻结值一致。

阶段 A 不触发本模块的网络路径：测试把 `_post` 整体替换为固定响应。
"""

import hashlib
import json
import os
import socket
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ENV_BASE_URL = "H56_MODEL_BASE_URL"
ENV_MODEL_ID = "H56_MODEL_ID"
ENV_API_KEY = "H56_MODEL_API_KEY"

DEFAULT_MAX_TOKENS = 400
DEFAULT_TIMEOUT = 30
MAX_RESPONSE_BYTES = 8192  # 与 validate.MAX_BODY_BYTES 一致
# 目录查询（GET /models）的响应远大于一次 chat.completion：模型列表带 verbose 时
# 轻松过百 KB。这个上限只作用于目录查询，不改变推理响应的 8192 字节上限 ——
# 把推理响应也放宽会稀释 validate 的体积防线.
MAX_CATALOG_BYTES = 1 << 20

# 推理模式开关（阶段 B 具名范围）。
#
# 为什么需要它：Nemotron 3 默认开启 reasoning，推理文本走 message.reasoning_content，
# 而 content 只放最终答案。在 max_tokens=400 的预算下，若推理占满配额，content 会是
# 空串 —— 那会被 validate 判成 MODEL_RESPONSE_SCHEMA_VIOLATION，看起来像"模型不听话"，
# 实际是我们没关推理。这是请求侧问题，不该由校验侧放宽来解决。
#
# 为什么默认不发送：默认发出去会让阶段 A 已落盘证据的请求体字节无法复现。
# None = 不发送该键（与阶段 A 完全一致的请求体）；False = 发送并关闭推理。
#
# 支持性未经本仓库验证：据公开资料 Nebius 通过 extra_body 转发该组参数，
# 但那是第三方记录，不是官方文档承诺。故此处如实标注 support=unverified，
# 由第一次真实响应确认；不支持时保留响应并停止，不得自动改用别的参数或模型。
THINKING_PARAM_NAME = "chat_template_kwargs.enable_thinking"
THINKING_SUPPORT = "unverified_until_first_real_response"

# 推理开关的**形态**。同一个语义在不同端点上写法不同，所以形态必须显式声明，
# 不能靠"换个 base_url 就假定兼容"。
#
#   chat_template_kwargs —— NIM / vLLM 系：{"chat_template_kwargs": {"enable_thinking": bool}}
#   thinking_object      —— DeepSeek 系：   {"thinking": {"type": "enabled"|"disabled"}}
#
# 默认值保持 chat_template_kwargs，因此未声明本字段的既有调用方，请求体与改动前
# 逐字节一致（阶段 A 已落盘证据仍可复现）。未知取值一律 ProviderConfigError，
# 不做"猜一个试试"。
THINKING_STYLE_CHAT_TEMPLATE = "chat_template_kwargs"
THINKING_STYLE_THINKING_OBJECT = "thinking_object"
THINKING_STYLES = (THINKING_STYLE_CHAT_TEMPLATE, THINKING_STYLE_THINKING_OBJECT)
THINKING_PARAM_NAMES = {
    THINKING_STYLE_CHAT_TEMPLATE: THINKING_PARAM_NAME,
    THINKING_STYLE_THINKING_OBJECT: "thinking.type",
}

# 批准端点清单。元素是完整 origin（`scheme://host:port`），不是裸主机名：
# 只批主机名会让「同主机不同端口」「http 换成 https」都变成合法变更，那不叫固定。
# 阶段 B 裁决前保持为空：不批准任何端点，任何构造都失败关闭。
# 测试通过 allowed_origins= 显式批准，元素由 origin_of() 生成。
ALLOWED_ORIGINS = frozenset()


class ProviderConfigError(Exception):
    """部署期错误：凭据或端点未配置。不是运行期拒绝码，不进拒绝码表。"""


class ProviderError(Exception):
    """运行期传输失败 -> MODEL_TRANSPORT_FAILED。

    无论成功还是失败，调用方都必须能拿到**实际发出的请求体**。理由很直接：
    失败请求最需要取证——参数被拒时，你要能证明"我发的就是这个"，而不是事后
    从代码里推断"应该发的是这个"。所以请求字节与关联标识挂在异常上一起带走。
    """

    code = "MODEL_TRANSPORT_FAILED"

    def __init__(self, detail, http_status=None, raw=b"", request_body=b"",
                 origin=None, correlation_id=None, attempts=1):
        super().__init__(f"{self.code}: {detail}")
        self.detail = detail
        self.http_status = http_status
        self.attempts = attempts
        # 端点返回的响应体/错误体。参数被拒（400）时，这是唯一能说明"为什么"的材料。
        self.raw = raw or b""
        # 实际发出的请求体（不含鉴权头，故可原样落盘）。
        self.request_body = request_body or b""
        self.request_body_sha256 = (
            hashlib.sha256(self.request_body).hexdigest() if self.request_body else None)
        self.origin = origin
        self.correlation_id = correlation_id


class Call(dict):
    """一次调用的脱敏记录。可直接写进 evidence 的 call 段。"""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class RedirectRefused(ProviderError):
    """跳转被拒绝。与普通传输失败区分：这是安全事件，不是网络抖动。"""

    def __init__(self, detail, http_status=None):
        super().__init__("redirect_refused: " + detail, http_status=http_status)


def origin_of(url):
    """把 URL 归约为 `scheme://host:port`。scheme 非 http(s)、无 host 一律拒绝。"""
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        raise ProviderConfigError("URL 端口非法，拒绝解析")
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        raise ProviderConfigError("URL 缺少 http(s) scheme 或主机名")
    if port is None:
        port = 443 if scheme == "https" else 80
    return "%s://%s:%d" % (scheme, host, port)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """任何 3xx 都在发出第二个请求之前失败，Authorization 头不会被带出去。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RedirectRefused("%d -> %s" % (code, origin_of(newurl)), http_status=code)


def _opener():
    return urllib.request.build_opener(_NoRedirect())


def _request(method, url, data, headers, timeout, max_bytes=MAX_RESPONSE_BYTES):
    """唯一发出网络请求的地方。测试整体替换 `_post` / `_get_once` 即可断网。

    4xx/5xx 不在此处抛异常，而是照常返回状态码与响应体：错误响应体的内容
    （例如"不支持的参数 chat_template_kwargs"）是判断参数是否被接受的唯一依据，
    在传输层丢掉它就等于把"为什么失败"删掉。

    POST（推理）与 GET（目录）共用本函数，是为了让"重定向一律拒绝""最终地址
    不得跨源"这两条防线只有一个实现点：多写一份 GET 通路，就多一个可能漏掉
    跨源检查的地方。
    """
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _opener().open(req, timeout=timeout) as resp:  # noqa: S310
            # 纵深防御：即使 handler 被替换或绕过，最终地址也不得跨源。
            final = resp.geturl()
            if origin_of(final) != origin_of(url):
                raise RedirectRefused(
                    "响应最终地址跨源 %s -> %s" % (origin_of(url), origin_of(final)))
            return resp.status, resp.read(max_bytes + 1), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.read(max_bytes + 1), dict(exc.headers)


def _post(url, data, headers, timeout):
    return _request("POST", url, data, headers, timeout)


def _get_once(url, headers, timeout=DEFAULT_TIMEOUT):
    """目录查询用：单次 GET，不重试、不跳转、不解释。只搬运字节。"""
    return _request("GET", url, None, headers, timeout,
                    max_bytes=MAX_CATALOG_BYTES)



def endpoint_host(base_url):
    """只保留主机名，不保留 scheme/path/查询段。"""
    rest = base_url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("?", 1)[0]


def _canonical_request_sha256(path, payload):
    """对去掉鉴权头的规范化请求取摘要：方法 + 路径 + 排序后的 body。"""
    canon = json.dumps(
        {"method": "POST", "path": path, "body": payload},
        sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


class HttpProvider:
    """OpenAI 兼容的 chat.completions 客户端。"""

    provider_name = "openai_compatible_chat_completions"

    def __init__(self, base_url, model_id, api_key,
                 max_tokens=DEFAULT_MAX_TOKENS, timeout=DEFAULT_TIMEOUT,
                 allowed_origins=None, enable_thinking=None,
                 thinking_style=THINKING_STYLE_CHAT_TEMPLATE):
        for name, val in (("base_url", base_url), ("model_id", model_id),
                          ("api_key", api_key)):
            if not val:
                raise ProviderConfigError("%s 未配置" % name)
        # 类型必须严格：字符串 "false" 是真值，一旦漏进来就会把"关推理"静默变成"开推理"。
        if enable_thinking is not None and not isinstance(enable_thinking, bool):
            raise ProviderConfigError(
                "enable_thinking 只接受 True / False / None，收到 %r"
                % (enable_thinking,))
        if thinking_style not in THINKING_STYLES:
            raise ProviderConfigError(
                "thinking_style 只接受 %s，收到 %r —— 不认得形态就不发请求"
                % (list(THINKING_STYLES), thinking_style))
        self.base_url = base_url.rstrip("/")
        self.model_id = model_id
        self._api_key = api_key
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.enable_thinking = enable_thinking
        self.thinking_style = thinking_style
        self.attempts = 1

        # 端点固定：构造期一次算定，之后不可变。
        self._origin = origin_of(self.base_url)
        origins = ALLOWED_ORIGINS if allowed_origins is None else frozenset(
            allowed_origins)
        if self._origin not in origins:
            raise ProviderConfigError(
                "端点 %s 不在批准清单内；批准清单为空表示尚未裁决任何端点"
                % self._origin)
        self._allowed_origins = origins

    @classmethod
    def from_env(cls, environ=None, **kw):
        env = os.environ if environ is None else environ
        missing = [k for k in (ENV_BASE_URL, ENV_MODEL_ID, ENV_API_KEY)
                   if not env.get(k)]
        if missing:
            raise ProviderConfigError(f"缺少环境变量：{missing}")
        return cls(env[ENV_BASE_URL], env[ENV_MODEL_ID], env[ENV_API_KEY], **kw)

    # -- 请求构造 --
    def payload(self, messages):
        body = {
            "model": self.model_id,
            "messages": messages,
            "temperature": 0,
            "max_tokens": self.max_tokens,
            "stream": False,
        }
        # 只有显式要求时才多这一个键。None 时请求体与阶段 A 逐字节一致，
        # 因此"加了开关"不会让旧证据失去可复现性。
        if self.enable_thinking is not None:
            if self.thinking_style == THINKING_STYLE_THINKING_OBJECT:
                body["thinking"] = {
                    "type": "enabled" if self.enable_thinking else "disabled"}
            else:
                body["chat_template_kwargs"] = {
                    "enable_thinking": self.enable_thinking}
        return body

    def thinking_block(self):
        """把"推理开关到底发了什么"写成可核对的字段，而不是靠读代码推断。"""
        if self.enable_thinking is None:
            return {
                "requested": False,
                "param": None,
                "value": None,
                "style": self.thinking_style,
                "sent_in_request": False,
                "support": "not_probed",
                "note": "未请求关闭推理；请求体不含推理开关键。",
            }
        if self.thinking_style == THINKING_STYLE_THINKING_OBJECT:
            param = THINKING_PARAM_NAMES[THINKING_STYLE_THINKING_OBJECT]
        else:
            param = THINKING_PARAM_NAMES[THINKING_STYLE_CHAT_TEMPLATE]
        return {
            "requested": True,
            "param": param,
            "value": self.enable_thinking,
            "style": self.thinking_style,
            "sent_in_request": True,
            "support": THINKING_SUPPORT,
            "note": ("该参数是否被端点接受，只能由第一次真实响应的 HTTP 状态码判定；"
                     "本字段在发送前恒为 unverified。参数被拒时不得自动改参数或换模型。"),
        }

    def path(self):
        return "/chat/completions"

    def complete(self, messages, correlation_id=None):
        """单次调用。任何异常 -> ProviderError（带着请求字节），不重试。

        correlation_id 由调用方给（阶段 B 用 "R1".."R7"），用于把
        「模型响应 / 真实 CLI 输入 / 四核记录」三件事串起来。不传则为 None，
        阶段 A 的调用点因此行为不变。
        """
        payload = self.payload(messages)
        # req_body 是发出去的字节；raw 是收回来的字节。两者分开命名，
        # 免得再出现"这个 body 是谁的 body"这类只能靠猜的字段。
        req_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        url = self.base_url + self.path()

        def fail(detail, http_status=None, raw=b""):
            """所有失败路径的唯一出口：一定带上请求字节、源、关联标识。"""
            raise ProviderError(detail, http_status=http_status, raw=raw,
                                request_body=req_body, origin=self._origin,
                                correlation_id=correlation_id,
                                attempts=self.attempts)

        # 发送前复核：请求地址必须仍落在构造期冻结的源上。
        if origin_of(url) != self._origin:
            fail("endpoint_drift: %s != %s" % (origin_of(url), self._origin))
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer %s" % self._api_key,
        }
        started = time.strftime("%Y-%m-%dT%H:%M:%S")
        t0 = time.time()
        try:
            status, raw, resp_headers = _post(url, req_body, headers, self.timeout)
        except ProviderError as exc:
            # RedirectRefused 属于安全事件：保留原始 detail，同时补上请求字节。
            exc.request_body = req_body
            exc.request_body_sha256 = hashlib.sha256(req_body).hexdigest()
            exc.origin = self._origin
            exc.correlation_id = correlation_id
            raise
        except urllib.error.HTTPError as exc:
            # 只留状态码与响应体，不回显响应头
            try:
                err_raw = exc.read(MAX_RESPONSE_BYTES + 1)
            except Exception:
                err_raw = b""
            fail("HTTPError %s" % exc.code, http_status=exc.code, raw=err_raw)
        except (socket.timeout, TimeoutError):
            # 超时没有响应体，但请求体必须有——否则无法证明超时的那次发了什么。
            fail("timeout")
        except urllib.error.URLError as exc:
            fail("URLError %s" % type(exc.reason).__name__)
        except Exception as exc:
            fail("%s" % type(exc).__name__)
        ended = time.strftime("%Y-%m-%dT%H:%M:%S")
        elapsed_ms = int((time.time() - t0) * 1000)

        if status != 200:
            # 保留响应体：参数被拒时，这是唯一能说明原因的材料。
            fail("HTTP %s" % status, http_status=status, raw=raw)

        response_sha = hashlib.sha256(raw).hexdigest()
        meta = {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
            if isinstance(parsed, dict):
                meta["response_id"] = parsed.get("id")
                usage = parsed.get("usage")
                if isinstance(usage, dict):
                    meta["usage"] = {
                        "prompt_tokens": usage.get("prompt_tokens"),
                        "completion_tokens": usage.get("completion_tokens"),
                    }
                # 只记结构与规模，不记推理文本本身：原始字节已在 raw 里完整留档，
                # 再抄一份进 evidence 只会让证据变长而不变强。
                choices = parsed.get("choices")
                if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                    choice = choices[0]
                    meta["finish_reason"] = choice.get("finish_reason")
                    msg = choice.get("message")
                    if isinstance(msg, dict):
                        meta["content_chars"] = len(msg.get("content") or "")
                        for key in ("reasoning_content", "reasoning"):
                            val = msg.get(key)
                            if isinstance(val, str):
                                meta["reasoning_field"] = key
                                meta["reasoning_chars"] = len(val)
                                break
        except Exception:
            pass  # 解析失败留给 validate 判 MALFORMED

        return Call({
            "provider": self.provider_name,
            "correlation_id": correlation_id,
            "endpoint_host": endpoint_host(self.base_url),
            "approved_origin": self._origin,
            "endpoint_origin_pinned": True,
            "redirects_followed": 0,
            "model_id": self.model_id,
            "request_type": "chat.completions",
            "attempts": self.attempts,
            "http_status": status,
            "started_at": started,
            "ended_at": ended,
            "elapsed_ms": elapsed_ms,
            "request_sha256": _canonical_request_sha256(self.path(), payload),
            "request_body_bytes": len(req_body),
            "request_body_sha256": hashlib.sha256(req_body).hexdigest(),
            "request_params": {
                "temperature": payload.get("temperature"),
                "max_tokens": payload.get("max_tokens"),
                "stream": payload.get("stream"),
                "top_level_keys": sorted(payload.keys()),
            },
            "thinking": self.thinking_block(),
            "response_sha256": response_sha,
            "response_id": meta.get("response_id"),
            "finish_reason": meta.get("finish_reason"),
            "content_chars": meta.get("content_chars"),
            "reasoning_field": meta.get("reasoning_field"),
            "reasoning_chars": meta.get("reasoning_chars"),
            "usage": meta.get("usage") or {"prompt_tokens": None,
                                           "completion_tokens": None},
            "body": raw,
            "request_body": req_body,
        })
