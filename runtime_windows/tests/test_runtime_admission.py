"""New perimeter pure validation only; no runtime admission or native loading."""
import ast
import builtins
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

PRODUCT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(PRODUCT))
_original_import = builtins.__import__


def _import_guard(name, *args, **kwargs):
    if name == 'ctypes' or name.startswith(('ctypes.', 'k0_fact_foundation',
            'k1_state_derivation', 'candidate_canonical_capability_contract',
            'candidate_capability_feasibility_projection', 'runtime_windows.assembly')):
        raise AssertionError('No native or runtime import in pure admission tests')
    return _original_import(name, *args, **kwargs)


with mock.patch.object(builtins, '__import__', _import_guard):
    from runtime_windows import runtime_admission as subject
    from runtime_windows.errors import PreparationError


def pins():
    return {'SYSTEMROOT': 'C:\\Windows', 'WINDIR': 'C:\\Windows',
            'TEMP': 'C:\\private\\scratch', 'TMP': 'C:\\private\\scratch',
            'H56W_SESSION': 'synthetic_test_only', 'H56W_RELEASE_SHA256': '1' * 64,
            'H56W_SOURCE_SHA256': '2' * 64, 'H56W_ENVIRONMENT_SHA256': '3' * 64,
            'H56W_PREFLIGHT_SHA256': '4' * 64, 'H56W_HOST_ACCEPTANCE_SHA256': 'a' * 64}


def identities():
    return {key: str(index + 5) * 64 for index, key in enumerate(subject.LINEAGE_FIELDS)}


def release():
    return dict(identities(), schema='h56.windows-runtime-release.v2',
        status='EXTERNALLY_APPROVED_CANDIDATE_ONLY', session_id='synthetic_test_only',
        allowed_operations=['candidate_compute', 'fresh_process_replay'],
        environment_sha256='3' * 64, preflight_sha256='4' * 64, host_acceptance_sha256='a' * 64,
        candidate_planning_only=True, authority_granted=False, execution_permitted=False,
        formal_history_write=False, external_services=False)


def worker_documents():
    """Synthetic documents are data, never issued permits or actual preflight."""
    roots = {'control_root': 'C:\\private\\control',
             'scratch_root': pins()['TEMP'], 'receipt_input_root': 'C:\\private\\replay_input'}
    environment = dict(roots, schema='h56.windows-runtime-environment.v2',
        session_id=pins()['H56W_SESSION'], python_executable='C:\\private\\python.exe',
        python_sha256='b' * 64, variables={name: pins()[name] for name in ('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP')},
        observation_policy={}, runtime_read_roots=['C:\\private\\runtime'],
        profile_storage_root='C:\\private\\profile', resource_contract_sha256='c' * 64)
    preflight = dict(schema='h56.windows-controller-preflight-record.v2',
        status='EXTERNALLY_ACCEPTED_RECORD', environment_sha256=pins()['H56W_ENVIRONMENT_SHA256'],
        runtime_source_manifest_sha256=identities()['runtime_source_manifest_sha256'],
        resource_contract_sha256='c' * 64, preflight_evidence_index_sha256='d' * 64,
        required_checks={name: 'VERIFIED' for name in subject.PREFLIGHT_CHECKS})
    acceptance = {name: identities()[name] for name in ('runtime_source_manifest_sha256',
        'runtime_contract_sha256', 'public_lock_sha256')}
    acceptance.update(schema='h56.windows-host-acceptance.v1', status='EXTERNALLY_ACCEPTED_CANDIDATE_HOST',
        session_id=pins()['H56W_SESSION'], resource_contract_sha256='c' * 64,
        preflight_sha256=pins()['H56W_PREFLIGHT_SHA256'], allowed_operations=release()['allowed_operations'],
        domain_scenarios={'DEVSECOPS': ['positive'], 'FINANCE_REFUND': ['positive']},
        worker_attempt_budget=2, candidate_planning_only=True, authority_granted=False,
        execution_permitted=False, formal_history_write=False, external_services=False)
    return [release(), environment, preflight, acceptance, 'candidate_compute', pins(), identities(), roots]


class AdmissionPureTests(unittest.TestCase):
    def refused(self, function, code=None):
        with self.assertRaises(PreparationError) as found:
            function()
        if code is not None:
            self.assertEqual(found.exception.code, code)

    def test_exact_names_and_independent_required_variables(self):
        self.assertEqual(subject.checked_environment_pins(pins()), pins())
        for name in pins():
            candidate = pins()
            candidate.pop(name)
            self.refused(lambda: subject.checked_environment_pins(candidate), 'WIN_ENV_NAMES_NOT_EXACT')
        for extra in ('PATH', 'API_KEY', 'APPDATA', 'http_proxy', 'SystemRoot'):
            candidate = dict(pins(), **{extra: 'synthetic_not_a_secret'})
            self.refused(lambda: subject.checked_environment_pins(candidate), 'WIN_ENV_NAMES_NOT_EXACT')

    def test_digest_types_values_and_session_bounded(self):
        for bad in ('', 'x' * 64, 'A' * 64, '0' * 63, True, None):
            candidate = pins()
            candidate['H56W_RELEASE_SHA256'] = bad
            self.refused(lambda: subject.checked_environment_pins(candidate))
        for session in ('../escape', 'a/b', 'x' * 65, 'a\\b', 'a:b'):
            candidate = pins()
            candidate['H56W_SESSION'] = session
            self.refused(lambda: subject.checked_environment_pins(candidate), 'WIN_SESSION_ID_INVALID')

    def test_values_are_required_without_secret_in_error(self):
        for value in ('', '\x00', 5, None):
            candidate = pins()
            candidate['SYSTEMROOT'] = value
            self.refused(lambda: subject.checked_environment_pins(candidate), 'WIN_ENV_VALUES_INVALID')

    def test_replay_requires_explicit_compute_closure(self):
        subject.operation_closure('candidate_compute', ['candidate_compute'])
        subject.operation_closure('fresh_process_replay', ['candidate_compute', 'fresh_process_replay'])
        self.refused(lambda: subject.operation_closure('fresh_process_replay', ['fresh_process_replay']), 'WIN_OPERATION_NOT_GRANTED')
        for operation, allowed in (([], []), ('execute', ['candidate_compute']),
                ('candidate_compute', ['candidate_compute', 'candidate_compute']),
                ('candidate_compute', ['candidate_compute', 'real_payment']),
                ('candidate_compute', [True])):
            self.refused(lambda: subject.operation_closure(operation, allowed))

    def test_structural_release_match_is_not_authority(self):
        original = release()
        self.assertIsNone(subject.validate_release(original, 'candidate_compute', pins(), identities()))
        self.assertEqual(original, release())
        for field in ('authority_granted', 'execution_permitted', 'formal_history_write', 'external_services'):
            candidate = release()
            candidate[field] = True
            self.refused(lambda: subject.validate_release(candidate, 'candidate_compute', pins(), identities()), 'WIN_AUTHORITY_BOUNDARY_DRIFT')

    def test_release_bindings_and_unknown_fields_rejected(self):
        for field in subject.LINEAGE_FIELDS + ('environment_sha256', 'preflight_sha256', 'host_acceptance_sha256', 'session_id'):
            candidate = release()
            candidate[field] = 'changed'
            self.refused(lambda: subject.validate_release(candidate, 'candidate_compute', pins(), identities()))
        candidate = release()
        candidate['approved'] = True
        self.refused(lambda: subject.validate_release(candidate, 'candidate_compute', pins(), identities()), 'WIN_RELEASE_FIELDS')
        candidate = release()
        candidate['status'] = 'PASS'
        self.refused(lambda: subject.validate_release(candidate, 'candidate_compute', pins(), identities()), 'WIN_SEPARATE_RUNTIME_RELEASE_REQUIRED')

    def test_duplicate_float_nonfinite_and_budget_rejected(self):
        for raw in (b'{"a":1,"a":1}', b'{"x":1.5}', b'{"x":NaN}', b'\xff', b' ' * 1048577):
            self.refused(lambda: subject.decode(raw))
        self.assertEqual(subject.decode(b'{"n":1,"value":true}'), {'n': 1, 'value': True})

    def test_source_paths_fail_before_open(self):
        for path in ('../x', '/x', 'a//b', 'a/./b', 'C:/x', 'a\\b', 'nul',
                     'a/CON.txt', 'a/ads:stream', 'a/trail.', 'a/space here'):
            self.refused(lambda: subject._relative(path))

    def test_registry_missing_duplicate_private_and_tamper(self):
        raw = b'synthetic metadata,not native source'
        manifest = {'schema': 'h56.windows-effective-source.v1', 'member_count': 1,
                    'files': [{'path': 'runtime_windows/example.json', 'size': len(raw),
                               'sha256': hashlib.sha256(raw).hexdigest()}]}
        with mock.patch.object(subject, '_bytes', return_value=raw):
            self.assertEqual(set(subject.verify_current_sources(manifest)), {'runtime_windows/example.json'})
            for change in ('digest', 'count', 'bool_size', 'private', 'self', 'duplicate'):
                candidate = copy.deepcopy(manifest)
                if change == 'digest':
                    candidate['files'][0]['sha256'] = 'f' * 64
                elif change == 'count':
                    candidate['member_count'] = True
                elif change == 'bool_size':
                    candidate['files'][0]['size'] = True
                elif change == 'private':
                    candidate['files'][0]['path'] = 'runtime_windows/.local/private.json'
                elif change == 'self':
                    candidate['files'][0]['path'] = subject.SOURCE_PATH
                elif change == 'duplicate':
                    candidate['files'].append(copy.deepcopy(candidate['files'][0]))
                    candidate['member_count'] = 2
                self.refused(lambda: subject.verify_current_sources(candidate))

    def test_source_contract_remains_not_released(self):
        contract = json.loads((PRODUCT / subject.CONTRACT_PATH).read_bytes())
        self.assertEqual(contract['launch_status'], 'PREPARED_NOT_RUNTIME_ACCEPTED')
        self.assertEqual(contract['boundary'], {'candidate_planning_only': True,
            'authority_granted': False, 'execution_permitted': False,
            'formal_history_write': False, 'external_services': False})
        tree = ast.parse((PRODUCT / 'runtime_windows' / 'runtime_admission.py').read_bytes())
        admission = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'admit_runtime')
        self.assertIn('host_acceptance.json', ast.dump(admission))
        self.assertIn('validate_worker_documents', ast.dump(admission))
        self.assertIn('collect_current_process_observation', ast.dump(admission))
        self.assertNotIn('EXTERNALLY_APPROVED', contract['role'])

    def test_complete_runtime_closure_excludes_private_old_lock(self):
        lock = json.loads((PRODUCT / subject.LOCK_PATH).read_bytes())
        names = subject.required_runtime_paths(lock)
        self.assertEqual(len(names), 152)
        for source in ('host_authority.py', 'host_resources.py', 'candidate_host.py', 'tasks.py', 'task_cli.py'):
            self.assertIn('runtime_windows/' + source, names)
        self.assertIn('runtime_windows/assembly/unit_admission.py', names)
        self.assertIn('runtime_binding_v1_20261024/engineering/contracts/money_unit_admission.json', names)
        self.assertEqual(sum('/vendor/' in name for name in names), 110)
        self.assertFalse(any('/offline/' in name or '/.local/' in name for name in names))
        self.assertNotIn('runtime_binding_v1_20261024/SOURCE_MANIFEST.json', names)
        # The original 110-file closure includes native project manifests;
        # their presence is required source identity, not private old RB trust.
        self.assertTrue(any('/vendor/' in name and name.endswith('SOURCE_MANIFEST.json') for name in names))
        self.assertFalse(any('/engineering/assembly/' in name for name in names))

    def test_no_native_or_ctypes_import_and_no_top_level_runtime_call(self):
        self.assertFalse(any(name == 'ctypes' or name.startswith(('k0_fact_foundation',
            'k1_state_derivation', 'candidate_canonical_capability_contract',
            'candidate_capability_feasibility_projection', 'assembly', 'mother')) for name in sys.modules))
        tree = ast.parse((PRODUCT / 'runtime_windows' / 'runtime_admission.py').read_bytes())
        for node in tree.body:
            if isinstance(node, ast.Expr):
                self.assertIsInstance(node.value, ast.Constant)
        native_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute) and node.func.attr == 'Popen']
        self.assertEqual(native_calls, [])

    def test_retired_nested_worker_route_always_refuses_without_admission(self):
        tree = ast.parse((PRODUCT / 'runtime_windows' / 'runtime_admission.py').read_bytes())
        runner = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run_bounded')
        self.assertIn('HOST_FRESH_PROCESS_REQUIRED', ast.dump(runner))
        self.assertNotIn('admit_runtime', ast.dump(runner))
        with mock.patch.object(subject, 'admit_runtime', side_effect=AssertionError('no admission')):
            self.refused(lambda: subject.run_bounded(['arbitrary'], {}), 'HOST_FRESH_PROCESS_REQUIRED')

    def test_worker_documents_structural_match_is_not_runtime_acceptance(self):
        documents = worker_documents()
        self.assertIsNone(subject.validate_worker_documents(*documents))
        self.assertEqual(documents, worker_documents())

    def test_worker_documents_missing_unknown_or_legacy_fields_fail_closed(self):
        for index in (0, 1, 2, 3, 7):
            changed = worker_documents()
            changed[index]['approved'] = True
            self.refused(lambda: subject.validate_worker_documents(*changed))
        for field in ('receipt_input_root', 'resource_contract_sha256'):
            changed = worker_documents()
            del changed[1][field]
            self.refused(lambda: subject.validate_worker_documents(*changed))
        for index in (0, 1, 2):
            changed = worker_documents()
            changed[index]['schema'] = changed[index]['schema'].replace('.v2', '.v1')
            self.refused(lambda: subject.validate_worker_documents(*changed))

    def test_worker_host_source_resource_scope_and_boundary_bindings(self):
        for field in ('session_id', 'runtime_source_manifest_sha256', 'runtime_contract_sha256',
                      'public_lock_sha256', 'resource_contract_sha256', 'preflight_sha256'):
            changed = worker_documents()
            changed[3][field] = 'changed'
            self.refused(lambda: subject.validate_worker_documents(*changed))
        for field in ('authority_granted', 'execution_permitted', 'formal_history_write', 'external_services'):
            changed = worker_documents()
            changed[3][field] = True
            self.refused(lambda: subject.validate_worker_documents(*changed), 'WIN_HOST_AUTHORITY_BOUNDARY_DRIFT')
        changed = worker_documents()
        changed[3]['allowed_operations'] = ['candidate_compute']
        self.refused(lambda: subject.validate_worker_documents(*changed), 'WIN_HOST_OPERATION_BINDING_MISMATCH')

    def test_worker_preflight_requires_every_accepted_raw_evidence_binding(self):
        for name in subject.PREFLIGHT_CHECKS:
            changed = worker_documents()
            changed[2]['required_checks'][name] = 'NOT_RUN'
            self.refused(lambda: subject.validate_worker_documents(*changed), 'WIN_ISOLATION_PREFLIGHT_INCOMPLETE')
        for field in ('environment_sha256', 'runtime_source_manifest_sha256', 'resource_contract_sha256',
                      'preflight_evidence_index_sha256'):
            changed = worker_documents()
            changed[2][field] = None
            self.refused(lambda: subject.validate_worker_documents(*changed))

    def test_worker_domain_scenario_and_attempt_budget_do_not_default_allow(self):
        for domains in ({}, {'OTHER': ['positive']}, {'DEVSECOPS': []},
                        {'DEVSECOPS': ['positive', 'positive']}, {'DEVSECOPS': ['../escape']}):
            changed = worker_documents()
            changed[3]['domain_scenarios'] = domains
            self.refused(lambda: subject.validate_worker_documents(*changed))
        for budget in (True, 0, -1, 101, '2'):
            changed = worker_documents()
            changed[3]['worker_attempt_budget'] = budget
            self.refused(lambda: subject.validate_worker_documents(*changed))
        decision = {'allowed_domain_scenarios': {'DEVSECOPS': ['positive']}}
        subject.check_domain_scope(decision, 'DEVSECOPS', 'positive')
        self.refused(lambda: subject.check_domain_scope(decision, 'FINANCE_REFUND', 'positive'), 'WIN_DOMAIN_SCENARIO_NOT_GRANTED')
        self.refused(lambda: subject.check_domain_scope(decision, 'DEVSECOPS', 'unknown'), 'WIN_DOMAIN_SCENARIO_NOT_GRANTED')

    def test_worker_roots_and_exact_variable_values_are_independent_requirements(self):
        changed = worker_documents()
        changed[1]['receipt_input_root'] = changed[7]['receipt_input_root'] = changed[7]['scratch_root']
        self.refused(lambda: subject.validate_worker_documents(*changed), 'WIN_RECEIPT_INPUT_NOT_SEPARATE')
        changed = worker_documents()
        changed[1]['variables']['WINDIR'] = 'C:\\another'
        self.refused(lambda: subject.validate_worker_documents(*changed), 'WIN_ENVIRONMENT_VALUE_MISMATCH')


if __name__ == '__main__':
    unittest.main(verbosity=2)
