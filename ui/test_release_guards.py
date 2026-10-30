"""Pure regression checks for demo/UI release guards; no product evaluation runs."""
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import demo
from ui import serve


class DemoWorkdirGuardTests(unittest.TestCase):
    def test_existing_directory_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / "existing"
            existing.mkdir()
            sentinel = existing / "sentinel.txt"
            sentinel.write_text("preserve", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "尚不存在"):
                demo.create_owned_workdir(existing)

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

    def test_product_root_is_rejected_before_creation(self):
        candidate = demo.PRODUCT / ".release-guard-must-not-exist"
        self.assertFalse(candidate.exists())
        with self.assertRaisesRegex(ValueError, "产品根内"):
            demo.create_owned_workdir(candidate)
        self.assertFalse(candidate.exists())

    def test_only_owned_directory_is_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            work, marker, owner = demo.create_owned_workdir(Path(tmp) / "owned")
            self.assertTrue(marker.is_file())
            self.assertTrue(demo.cleanup_owned_workdir(work, marker, owner))
            self.assertFalse(work.exists())

    def test_missing_or_mismatched_owner_marker_preserves_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing, marker, owner = demo.create_owned_workdir(Path(tmp) / "missing-marker")
            marker.unlink()
            self.assertFalse(demo.cleanup_owned_workdir(missing, marker, owner))
            self.assertTrue(missing.is_dir())

            mismatched, marker, owner = demo.create_owned_workdir(Path(tmp) / "wrong-marker")
            marker.write_text("different-owner", encoding="ascii")
            self.assertFalse(demo.cleanup_owned_workdir(mismatched, marker, owner))
            self.assertTrue(mismatched.is_dir())

    def test_report_path_must_stay_inside_new_workdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            work.mkdir()
            with self.assertRaisesRegex(ValueError, "运行目录内"):
                demo.validate_report_path(Path(tmp) / "outside.json", work)
            self.assertFalse((Path(tmp) / "outside.json").exists())
            inside = demo.validate_report_path(work / "report.json", work)
            self.assertEqual(inside, (work / "report.json").resolve())


class ServeGuardTests(unittest.TestCase):
    def test_only_registered_contained_evidence_is_eligible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            evidence = root / "C01_v0" / "op" / "out" / "oq_C01_0" / "artifacts" / "record.json"
            evidence.parent.mkdir(parents=True)
            raw = b'{"record":"fixture"}'
            evidence.write_bytes(raw)
            rel = evidence.relative_to(root).as_posix()
            report = {"rows": [{"evidence": [{
                "rel": rel, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            }]}]}

            target, observed = serve.read_registered_evidence(root, report, rel)
            self.assertEqual(target, evidence.resolve())
            self.assertEqual(observed, raw)
            self.assertFalse(serve.is_within(Path(tmp) / "run-sibling" / "secret.json", root))

            bad_report = {"rows": [{"evidence": [{
                "rel": "../run-sibling/secret.json", "bytes": 1, "sha256": "0" * 64,
            }]}]}
            with self.assertRaisesRegex(ValueError, "EVIDENCE_PATH_OUTSIDE_RUN"):
                serve.read_registered_evidence(root, bad_report, "../run-sibling/secret.json")

    def test_tampered_registered_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            evidence = root / "artifacts" / "record.json"
            evidence.parent.mkdir(parents=True)
            original = b'{"record":"original"}'
            evidence.write_bytes(original)
            rel = evidence.relative_to(root).as_posix()
            report = {"rows": [{"evidence": [{
                "rel": rel, "bytes": len(original), "sha256": hashlib.sha256(original).hexdigest(),
            }]}]}
            evidence.write_bytes(b'{"record":"tampered"}')

            with self.assertRaisesRegex(ValueError, "EVIDENCE_IDENTITY_MISMATCH"):
                serve.read_registered_evidence(root, report, rel)

            evidence.write_bytes(b'{"record":"short"}')
            with self.assertRaisesRegex(ValueError, "EVIDENCE_IDENTITY_MISMATCH"):
                serve.read_registered_evidence(root, report, rel)

    def test_run_endpoint_has_no_request_config_surface(self):
        self.assertTrue(serve.is_valid_run_request_body({}))
        self.assertFalse(serve.is_valid_run_request_body({"compare_python": r"C:\\untrusted.exe"}))
        self.assertFalse(serve.is_valid_run_request_body(["not-an-object"]))
        self.assertTrue(serve.is_valid_run_token(serve.RUN_TOKEN))
        self.assertFalse(serve.is_valid_run_token("wrong-token"))
        # 回环三写法都放行（手输 localhost 的用户此前会 403），但必须逐个精确匹配。
        for ok_origin in ("http://127.0.0.1:8765", "http://localhost:8765", "http://[::1]:8765"):
            self.assertTrue(serve.is_allowed_run_origin(ok_origin, 8765), ok_origin)
        for bad_origin in ("https://untrusted.example",
                           "https://localhost:8765",              # 本服务只讲 http
                           "http://localhost:8766",               # 端口不符
                           "http://127.0.0.1.evil.example:8765",  # 后缀伪装
                           "http://localhost@evil.example:8765",  # userinfo 伪装
                           "http://localhost.evil.example:8765"):
            self.assertFalse(serve.is_allowed_run_origin(bad_origin, 8765), bad_origin)

        for ok_host in ("127.0.0.1:8765", "localhost:8765", "LOCALHOST:8765", "[::1]:8765"):
            self.assertTrue(serve.is_allowed_host(ok_host, 8765), ok_host)
        for bad_host in ("foreign.example.invalid", "127.0.0.1:8766",
                         "127.0.0.1.evil.example:8765", "localhost.evil.example:8765",
                         "", None, "127.0.0.1:8765.example"):
            self.assertFalse(serve.is_allowed_host(bad_host, 8765), bad_host)

    def test_handler_rejections_do_not_start_demo(self):
        def handler_for(origin, token, body):
            handler = serve.Handler.__new__(serve.Handler)
            handler.path = "/api/run"
            handler.headers = {
                "Host": "127.0.0.1:8765",
                "Origin": origin,
                "X-H56-Run-Token": token,
                "Content-Length": str(len(body)),
            }
            handler.rfile = io.BytesIO(body)
            handler.server = SimpleNamespace(server_port=8765)
            replies = []
            handler._json = lambda payload, code=200: replies.append((code, payload))
            return handler, replies

        rejected = [
            ("https://untrusted.example", serve.RUN_TOKEN, b"{}", 403),
            ("http://127.0.0.1:8765", "wrong-token", b"{}", 403),
            ("http://127.0.0.1:8765", serve.RUN_TOKEN,
             json.dumps({"compare_python": r"C:\\untrusted.exe"}).encode("utf-8"), 400),
        ]
        for origin, token, body, expected_status in rejected:
            with self.subTest(status=expected_status, body=body), patch.object(serve, "start_run") as start:
                handler, replies = handler_for(origin, token, body)
                handler.do_POST()
                start.assert_not_called()
                self.assertEqual(replies[0][0], expected_status)

        with patch.object(serve, "start_run", return_value=(True, "fixture-run")) as start:
            handler, replies = handler_for("http://127.0.0.1:8765", serve.RUN_TOKEN, b"{}")
            handler.do_POST()
            start.assert_called_once_with()
            self.assertEqual(replies[0], (202, {"started": True, "detail": "fixture-run"}))

    def test_get_routes_reject_foreign_host_and_origin(self):
        for path in ("/", "/api/health", "/api/state", "/api/evidence?rel=x"):
            for extra in ({"Host": "foreign.example.invalid"},
                          {"Origin": "https://foreign.example.invalid"},
                          {"Sec-Fetch-Site": "cross-site"}):
                with self.subTest(path=path, headers=extra):
                    handler = serve.Handler.__new__(serve.Handler)
                    handler.path = path
                    handler.headers = {"Host": "127.0.0.1:8765",
                                       "X-H56-Run-Token": serve.RUN_TOKEN, **extra}
                    handler.server = SimpleNamespace(server_port=8765)
                    replies = []
                    handler._json = lambda payload, code=200: replies.append((code, payload))
                    handler.do_GET()
                    self.assertEqual(replies[0][0], 403)

    def test_loopback_aliases_reach_the_page(self):
        # 反面用例（外站 Host 一律 403）之外，必须有正面用例：手输 localhost 的用户
        # 也要能拿到首页，且首页里嵌的是本次进程的令牌，不是上一轮的。
        for host in ("127.0.0.1:8765", "localhost:8765", "[::1]:8765"):
            with self.subTest(host=host):
                handler = serve.Handler.__new__(serve.Handler)
                handler.path = "/"
                handler.headers = {"Host": host}
                handler.server = SimpleNamespace(server_port=8765)
                replies = []
                handler._send = lambda code, body, ctype=None: replies.append((code, body))
                handler.do_GET()
                self.assertEqual(replies[0][0], 200)
                self.assertIn(serve.RUN_TOKEN, replies[0][1])

    def test_api_reads_require_the_current_token(self):
        for path in ("/api/health", "/api/state", "/api/evidence?rel=x"):
            handler = serve.Handler.__new__(serve.Handler)
            handler.path = path
            handler.headers = {"Host": "127.0.0.1:8765"}
            handler.server = SimpleNamespace(server_port=8765)
            replies = []
            handler._json = lambda payload, code=200: replies.append((code, payload))
            handler.do_GET()
            self.assertEqual(replies[0][0], 403)

        handler.path = "/api/health"
        handler.headers["X-H56-Run-Token"] = serve.RUN_TOKEN
        replies.clear()
        handler.do_GET()
        self.assertEqual(replies[0][0], 200)


if __name__ == "__main__":
    unittest.main()
