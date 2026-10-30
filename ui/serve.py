#!/usr/bin/env python3
"""h56 本地演示服务 —— 单页 UI + 零依赖本地 HTTP。

它只做三件事：
  1. 把 ui/index.html 发给本机浏览器；
  2. 收到 POST /api/run 时，用**独立进程真实执行** demo.py --all（不是回放、不是预置动画）；
  3. 把 demo.py 的结构化输出（--json，每完成一个变体刷新一次）与 stdout 转发给页面。

它不做的事：不联网、不监听 0.0.0.0、不写凭据、不修改任何已封存证据、不发布任何东西。

用法：
    python ui/serve.py                              # http://127.0.0.1:8765
    python ui/serve.py --port 9000
    python ui/serve.py --compare-python <python.exe>  # 加做跨版本字节一致性（性质 3）

注意：解释器就是本进程的 sys.executable。想切版本，用另一个 Python 启动本脚本。
"""
import argparse
import hashlib
import json
import mimetypes
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from pathlib import PurePosixPath
from urllib.parse import urlparse, parse_qs

UI_DIR = Path(__file__).absolute().parent
PRODUCT = UI_DIR.parent
DEMO = PRODUCT / "demo.py"
INDEX = UI_DIR / "index.html"
RUN_TOKEN = secrets.token_urlsafe(32)

# ── 子进程环境净化 ───────────────────────────────────────────────────────────
# 与 demo.py / model_ingress_v1.run 同一规则：前缀 + 静态名单。此处自包含实现，
# 理由与 demo.py 相同 —— 不把 UI 的启动条件绑到任何适配层上。
# 不是"最小白名单环境"：demo.py 的子进程仍需要 SYSTEMROOT / PATH / TEMP。
# 等价性由 model_ingress_v1/tests/test_stage_b.py 的 S61–S63 断言。
ENV_PREFIX = "H56_MODEL_"
ENV_EXTRA_REMOVE = ("NEBIUS_API_KEY", "NVIDIA_API_KEY")
# 后缀表只做「名称尾部」精确匹配，不做子串匹配 —— 子串匹配会误删 MONKEY_PATH
# 这类正常变量，而误删环境变量比少删一个更隐蔽。
#   _APIKEY / _APITOKEN ：无下划线分隔的厂商写法（DASHSCOPE_APIKEY、SILICONFLOW_APIKEY）
#   _PASSWORD_HASH / _PASSWD ：口令派生值同样是凭据（MY_PASSWORD_HASH）
ENV_CREDENTIAL_SUFFIXES = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD",
                           "_CREDENTIAL", "_CREDENTIALS", "_ACCESS_KEY_ID",
                           "_APIKEY", "_APITOKEN", "_PASSWORD_HASH", "_PASSWD")


def _clean_env(environ=None):
    """返回一份剔除了密钥类变量的环境副本。不修改入参，不记录任何值。"""
    env = dict(os.environ if environ is None else environ)
    drop = [k for k in env if k.upper().startswith(ENV_PREFIX)
            or k.upper() in ENV_EXTRA_REMOVE
            or k.upper().endswith(ENV_CREDENTIAL_SUFFIXES)]
    for k in drop:
        env.pop(k, None)
    return env


STATE_LOCK = threading.Lock()
STATE = {
    "status": "idle",          # idle | running | done | failed
    "started_at": None,
    "finished_at": None,
    "report_path": None,
    "work_dir": None,
    "run_id": None,
    "interpreter": None,
    "compare_python": None,
    "log": [],
    "error": None,
}


def _log(line):
    with STATE_LOCK:
        STATE["log"].append(line.rstrip())
        del STATE["log"][:-400]


def _run_demo(run_id, work_dir, report_path, compare_python):
    python = sys.executable
    cmd = [python, "-I", "-B", "-S", "-X", "utf8", str(DEMO),
           "--all", "--keep", "--work-dir", str(work_dir), "--json", str(report_path)]
    if compare_python:
        cmd += ["--compare-python", compare_python]
    _log(f"$ {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, cwd=str(PRODUCT), env=_clean_env(),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace", bufsize=1)
        for line in proc.stdout:
            _log(line)
        proc.wait()
        with STATE_LOCK:
            STATE["status"] = "done" if proc.returncode == 0 else "failed"
            STATE["finished_at"] = time.time()
            if proc.returncode != 0:
                STATE["error"] = f"demo.py 退出码 {proc.returncode}"
    except Exception as exc:                       # noqa: BLE001 - 失败必须显式暴露
        _log(f"!! 启动失败：{exc}")
        with STATE_LOCK:
            STATE["status"] = "failed"
            STATE["finished_at"] = time.time()
            STATE["error"] = str(exc)


def start_run():
    with STATE_LOCK:
        if STATE["status"] == "running":
            return False, "已有一次运行在进行"
        stamp = time.strftime("%Y%m%d_%H%M%S")
        base = Path(tempfile.gettempdir()) / "h56-ui" / f"{stamp}_{secrets.token_hex(8)}"
        if base.exists():
            return False, "独占运行目录已存在"
        state = {
            "status": "running", "started_at": time.time(), "finished_at": None,
            "report_path": str(base / "report.json"), "work_dir": str(base),
            "run_id": stamp, "interpreter": sys.executable,
            "compare_python": STATE["compare_python"], "log": [], "error": None,
        }
        STATE.update(state)
    thread = threading.Thread(target=_run_demo, args=(
        stamp, base, base / "report.json", STATE["compare_python"]), daemon=True)
    thread.start()
    return True, stamp


def read_report():
    path = STATE.get("report_path")
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def is_within(path, root):
    """Return whether path resolves under root; never rely on string prefixes."""
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False


def registered_evidence(root, report):
    """Map only report-registered, contained evidence files to their identities."""
    allowed = {}
    for row in (report or {}).get("rows") or []:
        for item in row.get("evidence") or []:
            rel = item.get("rel")
            if (not isinstance(rel, str) or not isinstance(item.get("bytes"), int)
                    or not isinstance(item.get("sha256"), str) or "\\" in rel):
                continue
            rel_path = PurePosixPath(rel)
            if rel_path.is_absolute() or ".." in rel_path.parts:
                continue
            target = (Path(root) / Path(*rel_path.parts)).resolve()
            if not is_within(target, root):
                continue
            allowed[target] = {"bytes": item["bytes"], "sha256": item["sha256"]}
    return allowed


def read_registered_evidence(root, report, rel):
    """Read exactly one registered evidence file and verify its recorded identity."""
    if not isinstance(rel, str) or "\\" in rel:
        raise ValueError("EVIDENCE_PATH_OUTSIDE_RUN")
    rel_path = PurePosixPath(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise ValueError("EVIDENCE_PATH_OUTSIDE_RUN")
    target = (Path(root) / Path(*rel_path.parts)).resolve()
    expected = registered_evidence(root, report).get(target)
    if not is_within(target, root) or expected is None or not target.is_file():
        raise ValueError("EVIDENCE_NOT_REGISTERED")
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise ValueError("EVIDENCE_READ_FAILED") from exc
    if len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
        raise ValueError("EVIDENCE_IDENTITY_MISMATCH")
    return target, raw


def is_valid_run_request_body(body):
    """The HTTP endpoint accepts no per-request execution configuration."""
    return body == {}


def is_valid_run_token(provided_token):
    return isinstance(provided_token, str) and secrets.compare_digest(provided_token, RUN_TOKEN)


# 只接受本机回环的三种主机名写法，且**逐个精确匹配**。
# DNS rebinding 要求 Host 是攻击者可控的域名，而这三种名字既无法注册，
# 也不会成为外站页面的 Host，所以精确放行它们是安全的；反过来，
# 绝不能退化成后缀/包含匹配 —— 那样 127.0.0.1.evil.example 会被放过。
LOOPBACK_HOSTNAMES = ("127.0.0.1", "localhost", "[::1]")


def is_allowed_run_origin(origin, port):
    """Only the page served by this loopback listener may initiate a run."""
    if not isinstance(origin, str):
        return False
    allowed = {f"http://{name}:{port}".lower() for name in LOOPBACK_HOSTNAMES}
    if port == 80:
        allowed |= {f"http://{name}".lower() for name in LOOPBACK_HOSTNAMES}
    return origin.strip().lower() in allowed


def is_allowed_host(host, port):
    """Reject foreign Host headers on every route, including page bootstrap."""
    if not isinstance(host, str):
        return False
    host = host.strip().lower()
    for name in LOOPBACK_HOSTNAMES:
        if host == f"{name}:{port}" or (port == 80 and host == name):
            return True
    return False


class Handler(BaseHTTPRequestHandler):
    server_version = "h56-demo"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):       # 静音默认访问日志
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # 单页 + 本地服务，禁止任何外部资源
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _check_local_request(self):
        port = self.server.server_port
        if not is_allowed_host(self.headers.get("Host", ""), port):
            self._json({"error": "请求主机不属于本次本地服务"}, 403)
            return False
        origin = self.headers.get("Origin")
        if origin is not None and not is_allowed_run_origin(origin, port):
            self._json({"error": "请求来源不属于本次本地服务"}, 403)
            return False
        if self.headers.get("Sec-Fetch-Site", "") == "cross-site":
            self._json({"error": "不接受跨站读取请求"}, 403)
            return False
        return True

    def do_GET(self):
        if not self._check_local_request():
            return
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/") and not is_valid_run_token(
                self.headers.get("X-H56-Run-Token", "")):
            return self._json({"error": "缺少或无效的本次服务令牌"}, 403)

        if path in ("/", "/index.html"):
            if not INDEX.exists():
                return self._send(500, "index.html 缺失", "text/plain; charset=utf-8")
            ctype = "text/html; charset=utf-8"
            html = INDEX.read_text(encoding="utf-8").replace("__H56_RUN_TOKEN__", RUN_TOKEN)
            return self._send(200, html, ctype)

        if path == "/api/state":
            report = read_report()
            with STATE_LOCK:
                payload = {
                    "status": STATE["status"],
                    "started_at": STATE["started_at"],
                    "finished_at": STATE["finished_at"],
                    "run_id": STATE["run_id"],
                    "work_dir": STATE["work_dir"],
                    "interpreter": STATE["interpreter"],
                    "compare_python": STATE["compare_python"],
                    "error": STATE["error"],
                    "elapsed": (round((STATE["finished_at"] or time.time())
                                      - STATE["started_at"], 1)
                                if STATE["started_at"] else 0),
                    "log": STATE["log"][-40:],
                }
            payload["report"] = report
            return self._json(payload)

        if path == "/api/evidence":
            query = parse_qs(parsed.query)
            rel = (query.get("rel") or [""])[0]
            work = STATE.get("work_dir")
            if not rel:
                return self._json({"error": "缺少 rel 参数"}, 400)
            if not work:
                return self._json({"error": "尚无运行产物，请先跑一次演示"}, 404)
            root = Path(work).resolve()
            try:
                target, raw = read_registered_evidence(root, read_report(), rel)
            except ValueError as exc:
                code = 409 if str(exc) == "EVIDENCE_IDENTITY_MISMATCH" else 403
                return self._json({"error": str(exc)}, code)
            ctype = mimetypes.guess_type(target.name)[0] or "text/plain"
            if target.suffix in (".json", ".jsonl", ".txt"):
                ctype = "application/json; charset=utf-8"
            return self._send(200, raw, ctype)

        if path == "/api/health":
            return self._json({"ok": True, "product": str(PRODUCT),
                               "demo": DEMO.exists(), "index": INDEX.exists()})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._check_local_request():
            return
        parsed = urlparse(self.path)
        if parsed.path != "/api/run":
            return self._json({"error": "not found"}, 404)
        if not is_allowed_run_origin(self.headers.get("Origin", ""), self.server.server_port):
            return self._json({"error": "请求来源不属于本次本地服务"}, 403)
        provided_token = self.headers.get("X-H56-Run-Token", "")
        if not is_valid_run_token(provided_token):
            return self._json({"error": "缺少或无效的本次服务令牌"}, 403)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._json({"error": "无效的 Content-Length"}, 400)
        if length < 0 or length > 1024:
            return self._json({"error": "请求体超出限制"}, 413)
        body = {}
        if length:
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            except ValueError:
                return self._json({"error": "请求体必须是空 JSON 对象"}, 400)
        if not is_valid_run_request_body(body):
            return self._json({"error": "运行配置只允许在服务启动时指定"}, 400)
        ok, detail = start_run()
        return self._json({"started": ok, "detail": detail}, 202 if ok else 409)


def main():
    ap = argparse.ArgumentParser(description="h56 本地演示服务")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--compare-python", default=None,
                    help="用于性质 3 的第二个解释器完整路径")
    ap.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = ap.parse_args()

    if not DEMO.exists():
        print(f"找不到 demo.py：{DEMO}")
        return 2

    with STATE_LOCK:
        STATE["compare_python"] = args.compare_python

    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        print(f"端口 {args.port} 无法监听：{exc}")
        return 2
    server.daemon_threads = True
    url = f"http://127.0.0.1:{args.port}/"
    print("=" * 66)
    print("h56 离线资格评估 · 本地演示服务")
    print("=" * 66)
    print(f"产品根   : {PRODUCT}")
    print(f"解释器   : {sys.executable}")
    print(f"地址     : {url}")
    print(f"跨版本   : {args.compare_python or '未提供（性质 3 将显示 SKIP）'}")
    print("停止     : Ctrl+C")
    print("=" * 66)
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
