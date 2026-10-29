"""Pure-data preparation tests. No collector, ctypes or Win32 API is run.

All SID and observation values below are synthetic fixtures, not resource
bindings or evidence that an AppContainer/Job exists on the test host.
"""

import ast
import builtins
import copy
import importlib
import pathlib
import sys
import unittest


PRODUCT_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PRODUCT_ROOT))
_original_import = builtins.__import__
_blocked_imports = []


def _deny_ctypes(name, *args, **kwargs):
    if name == 'ctypes' or name.startswith('ctypes.'):
        _blocked_imports.append(name)
        raise AssertionError('Pure tests must not import ctypes')
    return _original_import(name, *args, **kwargs)


builtins.__import__ = _deny_ctypes
try:
    probe = importlib.import_module('runtime_windows.kernel_probe')
    from runtime_windows.errors import PreparationError
finally:
    builtins.__import__ = _original_import


def policy():
    return {
        'schema': probe.POLICY_SCHEMA,
        'appcontainer_sid': 'S-1-15-2-101-202-303-404-505-606-707',
        'capabilities': [],
        'token_has_restrictions': False,
        'elevation_type': 1,
        'active_process_limit': 4,
        'process_memory_limit_bytes': 536870912,
        'job_memory_limit_bytes': 536870912,
        'cpu_rate_hundredths': 1000,
    }


def observation():
    expected = policy()
    return {
        'schema': probe.OBSERVATION_SCHEMA,
        'scope': 'CURRENT_PROCESS_AND_IMMEDIATE_JOB_ONLY',
        'query_complete': True,
        'collection_error': None,
        'token': {
            'primary_token_type': 1, 'thread_impersonation_present': False,
            'is_appcontainer': True,
            'appcontainer_sid': expected['appcontainer_sid'],
            'capabilities': [], 'has_restrictions': False,
            'elevated': False, 'elevation_type': 1,
        },
        'job': {
            'in_job': True, 'scope': 'IMMEDIATE_JOB_ONLY',
            'limit_flags': probe.REQUIRED_JOB_FLAGS,
            'active_process_limit': 4,
            'process_memory_limit_bytes': 536870912,
            'job_memory_limit_bytes': 536870912,
            'cpu_control_flags': 5, 'cpu_rate_hundredths': 1000,
        },
    }


class PureObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        builtins.__import__ = _deny_ctypes

    @classmethod
    def tearDownClass(cls):
        builtins.__import__ = _original_import

    def reject(self, data, reason=None, expected=None):
        result = probe.evaluate_observation(expected or policy(), data)
        self.assertEqual('NOT_VERIFIED', result['status'])
        self.assertFalse(result['runtime_authorized'])
        self.assertFalse(result['isolation_verified'])
        if reason:
            self.assertIn(reason, result['reasons'])

    def test_import_and_all_pure_tests_never_import_ctypes(self):
        self.assertEqual([], _blocked_imports)
        self.assertNotIn('ctypes', probe.__dict__)
        self.assertNotIn('os', probe.__dict__)

    def test_matching_fixture_only_pending_and_never_authorizes(self):
        data = observation()
        before = copy.deepcopy(data)
        result = probe.evaluate_observation(policy(), data)
        self.assertEqual('OBSERVED_MATCH_NEGATIVE_TESTS_PENDING', result['status'])
        self.assertFalse(result['runtime_authorized'])
        self.assertFalse(result['isolation_verified'])
        self.assertEqual('NOT_COMPUTED', result['candidate_qualification'])
        self.assertEqual({'NOT_RUN'}, set(result['required_runtime_checks'].values()))
        self.assertEqual(before, data)

    def test_unbound_real_resource_is_not_a_policy(self):
        expected = policy()
        expected['appcontainer_sid'] = None
        self.reject(observation(), 'APPCONTAINER_IDENTITY_UNBOUND_OR_INVALID', expected)

    def test_missing_and_extra_policy_fields(self):
        for key in policy():
            expected = policy()
            del expected[key]
            self.reject(observation(), 'POLICY_FIELDS_INVALID', expected)
        expected = policy()
        expected['approved'] = True
        self.reject(observation(), 'POLICY_FIELDS_INVALID', expected)

    def test_policy_ranges_and_bool_int_confusion(self):
        for key in ('active_process_limit', 'process_memory_limit_bytes',
                    'job_memory_limit_bytes', 'cpu_rate_hundredths', 'elevation_type'):
            for value in (True, False, 0, -1, None, '4', 1.0, 1 << 64):
                expected = policy()
                expected[key] = value
                self.reject(observation(), expected=expected)

    def test_invalid_restrictions_expectation(self):
        for value in (0, 1, None, 'false'):
            expected = policy()
            expected['token_has_restrictions'] = value
            self.reject(observation(), 'TOKEN_RESTRICTIONS_EXPECTATION_INVALID', expected)

    def test_appcontainer_restrictions_are_not_implicitly_assumed_true(self):
        expected, data = policy(), observation()
        expected['token_has_restrictions'] = True
        self.reject(data, 'TOKEN_RESTRICTIONS_MISMATCH', expected)
        data['token']['has_restrictions'] = True
        self.assertEqual('OBSERVED_MATCH_NEGATIVE_TESTS_PENDING',
                         probe.evaluate_observation(expected, data)['status'])

    def test_policy_inconsistent_memory_and_elevation(self):
        expected = policy()
        expected['process_memory_limit_bytes'] += 1
        self.reject(observation(), 'POLICY_MEMORY_LIMITS_INCONSISTENT', expected)
        expected = policy()
        expected['elevation_type'] = 2
        self.reject(observation(), 'ELEVATION_EXPECTATION_INVALID', expected)

    def test_missing_extra_or_wrong_observation_shape(self):
        for key in observation():
            data = observation()
            del data[key]
            self.reject(data, 'OBSERVATION_FIELDS_INVALID')
        data = observation()
        data['runtime_authorized'] = True
        self.reject(data, 'OBSERVATION_FIELDS_INVALID')
        for data in (None, [], 1, True):
            self.reject(data, 'OBSERVATION_FIELDS_INVALID')

    def test_scope_schema_and_completeness(self):
        for key, value, reason in (
            ('scope', 'ALL_PROCESS_SCAN', 'OBSERVATION_SCOPE_INVALID'),
            ('schema', 'unknown', 'OBSERVATION_SCHEMA_INVALID'),
            ('query_complete', 1, 'OBSERVATION_INCOMPLETE'),
            ('query_complete', None, 'OBSERVATION_INCOMPLETE'),
            ('collection_error', 'ACCESS_DENIED', 'OBSERVATION_INCOMPLETE'),
        ):
            data = observation()
            data[key] = value
            self.reject(data, reason)

    def test_each_token_field_required(self):
        for key in observation()['token']:
            data = observation()
            del data['token'][key]
            self.reject(data, 'TOKEN_OBSERVATION_INCOMPLETE')

    def test_token_not_appcontainer_elevated_impersonated_or_unknown(self):
        cases = (
            ('primary_token_type', True, 'PRIMARY_TOKEN_NOT_PROVED'),
            ('primary_token_type', 2, 'PRIMARY_TOKEN_NOT_PROVED'),
            ('thread_impersonation_present', True, 'THREAD_TOKEN_AMBIGUOUS'),
            ('thread_impersonation_present', None, 'THREAD_TOKEN_AMBIGUOUS'),
            ('is_appcontainer', False, 'APPCONTAINER_NOT_PROVED'),
            ('is_appcontainer', 1, 'APPCONTAINER_NOT_PROVED'),
            ('elevated', True, 'ELEVATED_OR_UNKNOWN_TOKEN'),
            ('elevated', 0, 'ELEVATED_OR_UNKNOWN_TOKEN'),
            ('has_restrictions', 0, 'TOKEN_RESTRICTIONS_MISMATCH'),
            ('elevation_type', True, 'TOKEN_ELEVATION_TYPE_MISMATCH'),
        )
        for key, value, reason in cases:
            data = observation()
            data['token'][key] = value
            self.reject(data, reason)

    def test_sid_mismatch_and_noncanonical_sid(self):
        for value in ('S-1-15-2-999', 'S-1-015-2-1', 'S-1-15-3-1',
                      'S-1-15-2-4294967296', None, [], 'S-1-15-2-１'):
            data = observation()
            data['token']['appcontainer_sid'] = value
            self.reject(data, 'APPCONTAINER_IDENTITY_MISMATCH')

    def test_capabilities_must_be_observed_and_exact_including_attributes(self):
        for value in (None, {}, [{'sid': 'S-1-15-3-1', 'attributes': 4}],
                      [{'sid': 'S-1-15-3-1', 'attributes': True}],
                      [{'sid': 'S-1-15-3-1', 'attributes': 4}] * 65):
            data = observation()
            data['token']['capabilities'] = value
            self.reject(data)
        expected, data = policy(), observation()
        expected['capabilities'] = [{'sid': 'S-1-15-3-1', 'attributes': 4}]
        data['token']['capabilities'] = [{'sid': 'S-1-15-3-1', 'attributes': 2}]
        self.reject(data, 'CAPABILITIES_MISMATCH', expected)

    def test_capability_order_is_not_identity_and_duplicates_are_invalid(self):
        caps = [{'sid': 'S-1-15-3-1', 'attributes': 4},
                {'sid': 'S-1-15-3-2', 'attributes': 4}]
        expected, data = policy(), observation()
        expected['capabilities'], data['token']['capabilities'] = caps, list(reversed(caps))
        self.assertEqual('OBSERVED_MATCH_NEGATIVE_TESTS_PENDING',
                         probe.evaluate_observation(expected, data)['status'])
        expected['capabilities'] = caps + [caps[0]]
        self.reject(data, 'POLICY_CAPABILITIES_INVALID', expected)

    def test_each_job_field_required(self):
        for key in observation()['job']:
            data = observation()
            del data['job'][key]
            self.reject(data, 'JOB_OBSERVATION_INCOMPLETE')

    def test_no_job_or_scope_unknown_is_not_matching(self):
        for value in (False, None, 1):
            data = observation()
            data['job']['in_job'] = value
            self.reject(data, 'CURRENT_JOB_NOT_PROVED')
        data = observation()
        data['job']['scope'] = 'PARENT_JOB_ASSUMED'
        self.reject(data, 'JOB_SCOPE_INVALID')

    def test_each_job_enforcement_flag_must_be_enabled(self):
        for bit in (0x8, 0x100, 0x200, 0x2000):
            data = observation()
            data['job']['limit_flags'] &= ~bit
            self.reject(data, 'JOB_ENFORCEMENT_FLAGS_MISMATCH')
        for bit in (0x800, 0x1000, 0x40000000):
            data = observation()
            data['job']['limit_flags'] |= bit
            self.reject(data, 'JOB_ENFORCEMENT_FLAGS_MISMATCH')
        for value in (True, -1, None, 1 << 32):
            data = observation()
            data['job']['limit_flags'] = value
            self.reject(data, 'JOB_LIMIT_FLAGS_INVALID')

    def test_cpu_value_without_exact_hard_cap_mode_not_accepted(self):
        for value in (0, 1, 2, 3, 4, 7, 0x11, 0x15, True, None):
            data = observation()
            data['job']['cpu_control_flags'] = value
            self.reject(data, 'CPU_HARD_CAP_MODE_NOT_PROVED')

    def test_each_limit_exact_type_and_value(self):
        for name in ('active_process_limit', 'process_memory_limit_bytes',
                     'job_memory_limit_bytes', 'cpu_rate_hundredths'):
            for value in (None, True, '4', 4.0, 0, 1 << 64):
                data = observation()
                data['job'][name] = value
                self.reject(data, 'JOB_LIMIT_MISMATCH:' + name)

    def test_sid_decoder_length_revision_and_endianness(self):
        raw = bytes((1, 2, 0, 0, 0, 0, 0, 15)) + (2).to_bytes(4, 'little') + (101).to_bytes(4, 'little')
        self.assertEqual('S-1-15-2-101', probe._decode_sid_bytes(raw))
        for invalid in (b'', b'\x01' * 7, bytes((2, 1)) + b'\0' * 10,
                        bytes((1, 16)) + b'\0' * 70, raw + b'\0', bytearray(raw)):
            with self.assertRaises(PreparationError):
                probe._decode_sid_bytes(invalid)

    def test_static_collector_query_only_apis_and_no_arbitrary_pid_or_job(self):
        tree = ast.parse((PRODUCT_ROOT / 'runtime_windows' / 'kernel_probe.py').read_text(encoding='utf-8'))
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        self.assertEqual(['policy'], [x.arg for x in functions['collect_current_process_observation'].args.args])
        bound_api_names = set()
        for node in ast.walk(functions['_bind_windows_api']):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'bind':
                bound_api_names.add(node.args[1].value)
        self.assertEqual({
            'GetCurrentProcess', 'GetCurrentThread', 'OpenProcessToken',
            'OpenThreadToken', 'GetTokenInformation', 'IsProcessInJob',
            'QueryInformationJobObject', 'CloseHandle',
        }, bound_api_names)
        for node in ast.walk(functions['collect_current_process_observation']):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Subscript):
                key = node.func.slice
                if isinstance(key, ast.Constant) and key.value == 'job_info':
                    self.assertIsNone(node.args[0].value)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(x.name for x in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module)
        self.assertNotIn('subprocess', imports)
        self.assertNotIn('socket', imports)

    def test_static_no_top_level_os_or_ctypes_or_collector_invocation(self):
        tree = ast.parse((PRODUCT_ROOT / 'runtime_windows' / 'kernel_probe.py').read_text(encoding='utf-8'))
        allowed_calls = {'frozenset'}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ImportFrom)):
                continue
            for item in ast.walk(node):
                if isinstance(item, ast.Import):
                    self.fail('Top-level import is not permitted')
                if isinstance(item, ast.Call):
                    self.assertIsInstance(item.func, ast.Name)
                    self.assertIn(item.func.id, allowed_calls)


if __name__ == '__main__':
    try:
        unittest.main(verbosity=2)
    finally:
        builtins.__import__ = _original_import
