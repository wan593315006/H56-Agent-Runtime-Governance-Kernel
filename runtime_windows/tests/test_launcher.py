"""C1 pure contract/result/AST checks, never a native launcher experiment.

All paths, hashes, SID and PID values are labelled synthetic fixture data.
No backend construction, child entry, collector, ctypes or WinDLL call occurs.
"""

import ast
import builtins
import copy
import importlib
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(ROOT))
ORIGINAL_IMPORT = builtins.__import__
BLOCKED_IMPORTS = []


def deny_native(name, *args, **kwargs):
    if name == 'ctypes' or name.startswith('ctypes.'):
        BLOCKED_IMPORTS.append(name)
        raise AssertionError('C1 pure tests cannot import ctypes')
    return ORIGINAL_IMPORT(name, *args, **kwargs)


builtins.__import__ = deny_native
try:
    contract = importlib.import_module('runtime_windows.launch_contract')
    launcher = importlib.import_module('runtime_windows.launcher')
    backend_source = importlib.import_module('runtime_windows.win32_backend')
    probe = importlib.import_module('runtime_windows.kernel_probe')
    from runtime_windows.errors import PreparationError
finally:
    builtins.__import__ = ORIGINAL_IMPORT


def request():
    return {
        'schema': contract.SCHEMA, 'mode': 'OBSERVATION_ONLY', 'run_id': 'pure_fixture_only',
        'source_identity': {
            'product_manifest_sha256': 'a' * 64, 'runtime_manifest_sha256': 'b' * 64,
            'source_files': {path: 'c' * 64 for path in contract.SOURCE_FILES},
        },
        'runtime': {'python_executable': 'C:\\fixture_runtime\\python.exe',
                    'python_sha256': 'd' * 64, 'version': '3.13.12', 'arch': 'WINDOWS_X64',
                    'closure_sha256': 'e' * 64},
        'profile': {'name': 'h56.pure.fixture',
                    'sid': 'S-1-15-2-101-202-303-404-505-606-707',
                    'storage_root': 'C:\\fixture_profile\\storage',
                    'provisioning_receipt_sha256': 'f' * 64},
        'paths': {'product_root': 'C:\\fixture_product', 'runtime_root': 'C:\\fixture_runtime',
                  'scratch_root': 'C:\\fixture_scratch', 'evidence_root': 'C:\\fixture_evidence'},
        'environment': {'SYSTEMROOT': 'C:\\Windows', 'WINDIR': 'C:\\Windows',
                        'TEMP': 'C:\\fixture_scratch', 'TMP': 'C:\\fixture_scratch',
                        'H56_RUN_ID': 'pure_fixture_only'},
        'observation_policy': {'schema': probe.POLICY_SCHEMA,
            'appcontainer_sid': 'S-1-15-2-101-202-303-404-505-606-707',
            'capabilities': [], 'token_has_restrictions': False, 'elevation_type': 1,
            'active_process_limit': 4, 'process_memory_limit_bytes': 536870912,
            'job_memory_limit_bytes': 536870912, 'cpu_rate_hundredths': 1000},
        'limits': {'startup_ms': 10000, 'total_ms': 30000, 'cleanup_ms': 5000,
                   'stdout_bytes': 1048576, 'stderr_bytes': 65536, 'control_bytes': 65536},
        'release_binding': {key: '1' * 64 for key in (
            'external_decision_sha256', 'source_scope_sha256',
            'resource_binding_sha256', 'preflight_receipt_sha256')},
    }


def child_result(plan):
    policy = plan.decoded()['observation_policy']
    return {'schema': contract.CHILD_RESULT_SCHEMA, 'request_sha256': plan.sha256,
        'run_id': plan.decoded()['run_id'], 'pid': 1234,
        'environment_sha256': contract.digest(contract.build_environment(plan)),
        'observation': {'schema': probe.OBSERVATION_SCHEMA,
            'scope': 'CURRENT_PROCESS_AND_IMMEDIATE_JOB_ONLY', 'query_complete': True,
            'collection_error': None, 'token': {'primary_token_type': 1,
                'thread_impersonation_present': False, 'is_appcontainer': True,
                'appcontainer_sid': policy['appcontainer_sid'], 'capabilities': [],
                'has_restrictions': False, 'elevated': False, 'elevation_type': 1},
            'job': {'in_job': True, 'scope': 'IMMEDIATE_JOB_ONLY',
                'limit_flags': probe.REQUIRED_JOB_FLAGS, 'active_process_limit': 4,
                'process_memory_limit_bytes': 536870912, 'job_memory_limit_bytes': 536870912,
                'cpu_control_flags': 5, 'cpu_rate_hundredths': 1000}}}


class PureLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        builtins.__import__ = deny_native

    @classmethod
    def tearDownClass(cls):
        builtins.__import__ = ORIGINAL_IMPORT

    def invalid(self, data):
        with self.assertRaises(PreparationError):
            contract.validate_launch_request(data)

    def test_import_is_lazy_and_no_backend_or_core_instantiated(self):
        self.assertEqual([], BLOCKED_IMPORTS)
        for module in (contract, launcher, backend_source):
            self.assertNotIn('ctypes', module.__dict__)
        self.assertEqual([], backend_source._QUARANTINED_NATIVE_OPERATIONS)

    def test_plan_is_immutable_and_is_not_an_approval(self):
        data = request()
        plan = contract.validate_launch_request(data)
        old = plan.sha256
        data['run_id'] = 'changed'
        decoded = plan.decoded()
        decoded['run_id'] = 'changed'
        self.assertEqual(old, plan.sha256)
        self.assertEqual('pure_fixture_only', plan.decoded()['run_id'])
        with self.assertRaises(AttributeError):
            plan._raw = b'fake'
        for anchor in (None, {'approved': True}, {'hash': plan.sha256}):
            with self.assertRaisesRegex(PreparationError, 'TRUSTED_EXTERNAL'):
                launcher.run_observer(request(), anchor)

    def test_json_authority_flag_or_untrusted_object_does_not_release(self):
        for authority in ({'approved': True}, object(), lambda: True):
            with self.assertRaisesRegex(PreparationError, 'TRUSTED_EXTERNAL'):
                launcher.run_observer(request(), 'synthetic_anchor', authority=authority)

    def test_bool_authority_bridge_result_rejected_before_native(self):
        class BadAuthority(contract.ObservationAuthority):
            def authorize(self, plan, release_anchor):
                return True

            def verify_preprovisioned_resources(self, plan):
                raise AssertionError('must not get past invalid authorize response')

        with self.assertRaisesRegex(PreparationError, 'AUTHORITY_BRIDGE_RESULT_INVALID'):
            launcher.run_observer(request(), 'synthetic_anchor', authority=BadAuthority())

    def test_missing_top_or_resource_binding_rejected(self):
        for key in request():
            data = request()
            del data[key]
            self.invalid(data)
        for section, field in (('profile', 'sid'), ('runtime', 'closure_sha256'),
                               ('release_binding', 'preflight_receipt_sha256')):
            data = request()
            data[section][field] = None
            self.invalid(data)

    def test_extra_fields_and_candidate_execution_mode_rejected(self):
        for key in ('action', 'argv', 'approved', 'candidate'):
            data = request()
            data[key] = True
            self.invalid(data)
        for mode in ('CANDIDATE_COMPUTE', 'EXECUTE', None, True):
            data = request()
            data['mode'] = mode
            self.invalid(data)

    def test_environment_exact_names_not_subset(self):
        for key in contract.REQUEST_ENV_KEYS:
            data = request()
            del data['environment'][key]
            self.invalid(data)
        for key in ('PATH', 'USERPROFILE', 'APPDATA', 'COMSPEC', 'DEEPSEEK_API_KEY', 'systemroot'):
            data = request()
            data['environment'][key] = 'fixture'
            self.invalid(data)
        data = request()
        data['environment']['H56_REQUEST_SHA256'] = 'a' * 64
        self.invalid(data)

    def test_environment_values_and_derived_hash(self):
        for key in contract.REQUEST_ENV_KEYS:
            data = request()
            data['environment'][key] = 'wrong'
            self.invalid(data)
        plan = contract.validate_launch_request(request())
        env = contract.build_environment(plan)
        self.assertEqual(contract.CHILD_ENV_KEYS, set(env))
        self.assertEqual(plan.sha256, env['H56_REQUEST_SHA256'])
        block = contract.environment_block(plan)
        self.assertTrue(block.endswith('\0\0'))
        self.assertEqual(6, len(block[:-2].split('\0')))

    def test_paths_deny_unc_traversal_devices_ads_and_controls(self):
        bad = ['\\\\server\\share', 'relative', 'C:\\a\\..\\b', 'C:\\a\\.\\b',
               'C:\\a:stream', 'C:\\CON.txt', 'C:\\LPT1', 'C:\\a\\',
               'C:\\a.', 'C:\\a ', 'C:\\a?b', 'C:\\a\x00b', 'C:\\a\nb',
               'C:/slash/path', 'C:\\a"b', None]
        for value in bad:
            data = request()
            data['paths']['evidence_root'] = value
            self.invalid(data)

    def test_root_overlaps_and_python_escape_rejected(self):
        cases = [('scratch_root', 'C:\\fixture_product'),
                 ('evidence_root', 'C:\\fixture_scratch'),
                 ('scratch_root', 'C:\\fixture_runtime')]
        for key, value in cases:
            data = request()
            data['paths'][key] = value
            self.invalid(data)
        data = request()
        data['runtime']['python_executable'] = 'C:\\other_project\\python.exe'
        self.invalid(data)
        data = request()
        data['profile']['storage_root'] = 'C:\\fixture_product\\profile'
        self.invalid(data)

    def test_job_caps_profile_mismatch_and_limits_are_strict(self):
        data = request()
        data['profile']['sid'] = 'S-1-15-2-999'
        self.invalid(data)
        data = request()
        data['observation_policy']['capabilities'] = [{'sid': 'S-1-15-3-1', 'attributes': 4}]
        self.invalid(data)
        for key in request()['limits']:
            for value in (0, -1, True, None, '1000', 1 << 64):
                data = request()
                data['limits'][key] = value
                self.invalid(data)
        data = request()
        data['limits']['startup_ms'] = 30000
        data['limits']['total_ms'] = 10000
        self.invalid(data)

    def test_source_closure_must_be_exact_and_nonplaceholder(self):
        for key in contract.SOURCE_FILES:
            data = request()
            del data['source_identity']['source_files'][key]
            self.invalid(data)
        data = request()
        data['source_identity']['source_files']['runtime_windows/launcher.py'] = '0' * 64
        self.invalid(data)
        data = request()
        data['source_identity']['source_files']['../other/secret'] = 'a' * 64
        self.invalid(data)

    def test_fixed_command_has_no_domain_action_or_shell(self):
        plan = contract.validate_launch_request(request())
        argv = contract.command_arguments(plan)
        self.assertEqual(('-I', '-B', '-S', '-X', 'utf8', '-c'), argv[1:7])
        self.assertIn('child_main()', argv[-1])
        self.assertNotIn('candidate', argv[-1])
        self.assertNotIn('subprocess', argv[-1])
        self.assertTrue(contract.command_line(plan).startswith('"C:\\fixture_runtime\\python.exe"'))
        self.assertEqual('"a\\\\\\"b"', contract.quote_argument('a\\"b'))

    def test_duplicate_and_nonfinite_request_json_rejected(self):
        with self.assertRaises(PreparationError):
            contract.parse_request(b'{"schema":"x","schema":"y"}')
        with self.assertRaises(PreparationError):
            contract.parse_request(b'{"value":NaN}')
        with self.assertRaises(PreparationError):
            contract.parse_request(b'x' * 32769)

    def test_frame_exact_byte_length_budget_and_duplicate_rejection(self):
        raw = contract.encode_frame({'utf8': '测试'}, 1024)
        self.assertEqual({'utf8': '测试'}, contract.decode_frame(raw, 1024))
        for invalid in (b'', raw[:-1], raw + b'X', b'\xff' * 4, bytearray(raw)):
            with self.assertRaises(PreparationError):
                contract.decode_frame(invalid, 1024)
        with self.assertRaises(PreparationError):
            contract.encode_frame({'data': 'a' * 1024}, 100)
        duplicate = b'{"x":1,"x":2}'
        with self.assertRaises(PreparationError):
            contract.decode_frame(len(duplicate).to_bytes(4, 'little') + duplicate, 1024)

    def test_fake_matching_child_result_never_proves_isolation(self):
        plan = contract.validate_launch_request(request())
        raw = contract.encode_frame(child_result(plan), 65536)
        result = launcher.check_child_result(plan, raw, 1234)
        self.assertEqual('OBSERVED_MATCH_NEGATIVE_TESTS_PENDING', result['status'])
        self.assertFalse(result['runtime_authorized'])
        self.assertFalse(result['isolation_verified'])
        self.assertEqual({'NOT_RUN'}, set(result['required_runtime_checks'].values()))

    def test_capture_retains_bounded_raw_prefix_on_first_excess(self):
        capture = contract.BoundedCapture(5, 3)
        self.assertTrue(capture.accept('stdout', b'abcd'))
        self.assertFalse(capture.accept('stdout', b'EFGH'))
        self.assertTrue(capture.accept('stderr', b'err'))
        snapshot = capture.snapshot()
        self.assertEqual(b'abcdE', snapshot['raw_stdout'])
        self.assertEqual(b'err', snapshot['raw_stderr'])
        self.assertEqual({'stdout': 8, 'stderr': 3}, snapshot['observed_output_bytes'])
        self.assertEqual({'stdout': True, 'stderr': False}, snapshot['capture_prefix_truncated'])
        with self.assertRaises(PreparationError):
            capture.accept('stdout', b'x')
        self.assertEqual(snapshot, capture.snapshot())

    def test_capture_is_bytes_not_lines_and_rejects_unbounded_chunks(self):
        capture = contract.BoundedCapture(5, 3)
        self.assertTrue(capture.accept('stdout', b'abc'))
        self.assertTrue(capture.accept('stdout', b'\0\xff'))
        self.assertEqual(b'abc\0\xff', capture.snapshot()['raw_stdout'])
        for role, block in (('stdin', b'x'), ('stdout', 'text'), ('stderr', b'x' * 4097)):
            with self.assertRaises(PreparationError):
                capture.accept(role, block)
        for a, b in ((True, 3), (5, 0), (1 << 64, 3)):
            with self.assertRaises(PreparationError):
                contract.BoundedCapture(a, b)

    def test_failure_capture_and_cleanup_do_not_override_stop_source_contract(self):
        source = (ROOT / 'runtime_windows' / 'launcher.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        function = next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == 'run_observer')
        block = next(x for x in function.body if isinstance(x, ast.Try))
        finally_source = '\n'.join(source.splitlines()[block.finalbody[0].lineno - 1:])
        self.assertGreaterEqual(finally_source.count('backend.snapshot()'), 2)
        for node in ast.walk(ast.Module(body=block.finalbody, type_ignores=[])):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                        self.assertNotEqual('stop_reason', target.slice.value)

    def test_child_result_identity_type_extra_output_and_drift_rejected(self):
        plan = contract.validate_launch_request(request())
        for key, bad in (('pid', True), ('pid', 5678), ('run_id', 'other'),
                         ('request_sha256', 'f' * 64), ('environment_sha256', 'f' * 64)):
            result = child_result(plan)
            result[key] = bad
            with self.assertRaises(PreparationError):
                launcher.check_child_result(plan, contract.encode_frame(result, 65536), 1234)
        raw = contract.encode_frame(child_result(plan), 65536)
        with self.assertRaises(PreparationError):
            launcher.check_child_result(plan, raw + b'extra', 1234)
        result = child_result(plan)
        result['observation']['job']['cpu_control_flags'] = 3
        self.assertEqual('NOT_VERIFIED', launcher.check_child_result(
            plan, contract.encode_frame(result, 65536), 1234)['status'])

    def test_native_source_has_only_local_owned_creation_and_no_profile_api(self):
        raw = (ROOT / 'runtime_windows' / 'win32_backend.py').read_text(encoding='utf-8')
        tree = ast.parse(raw)
        self.assertNotIn('CreateAppContainerProfile', raw)
        self.assertNotIn('DeleteAppContainerProfile', raw)
        self.assertNotIn('OpenProcess(', raw)
        self.assertNotIn('OpenJobObject', raw)
        self.assertIn('0x0002000D', raw)  # Atomic JOB_LIST, not post-resume attach.
        self.assertIn('0x00020002', raw)  # Exact HANDLE_LIST.
        self.assertIn('0x00020009', raw)  # SECURITY_CAPABILITIES.
        self.assertIn('0x0002000E', raw)  # Child process restriction.
        job_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Subscript):
                if isinstance(node.func.slice, ast.Constant) and node.func.slice.value == 'CreateJobObjectW':
                    job_calls.append(node)
        self.assertEqual(1, len(job_calls))
        self.assertTrue(all(isinstance(x, ast.Constant) and x.value is None for x in job_calls[0].args))

    def test_top_level_declarations_have_no_native_construction(self):
        for relative in ('launch_contract.py', 'launcher.py', 'win32_backend.py'):
            tree = ast.parse((ROOT / 'runtime_windows' / relative).read_text(encoding='utf-8'))
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
                    continue
                for nested in ast.walk(node):
                    if isinstance(nested, ast.Call):
                        self.assertIsInstance(nested.func, (ast.Name, ast.Attribute))
                        name = nested.func.id if isinstance(nested.func, ast.Name) else nested.func.attr
                        self.assertIn(name, ('frozenset', 'compile', 'object'))


if __name__ == '__main__':
    try:
        unittest.main(verbosity=2)
    finally:
        builtins.__import__ = ORIGINAL_IMPORT
