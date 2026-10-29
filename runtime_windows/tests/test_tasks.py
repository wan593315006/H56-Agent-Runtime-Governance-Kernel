"""TEST_DOUBLE_ONLY task-control tests, never native, Host resources or OS proof.

All result/trace dictionaries below are synthetic self-consistent contract data.
Passing shared validators does not prove those events happened. Actual local
I/O is limited to fresh fixtures under the explicitly approved evidence root.
"""
import ast
import base64
import builtins
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock

PRODUCT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(PRODUCT))
EVIDENCE = PRODUCT.parent / 'evidence/product/eng01_candidate_host_v1_20261024/task_build'
FORBIDDEN = ('ctypes', 'assembly', 'frontdoor', 'runtime_windows.candidate_host',
             'runtime_windows.host_resources', 'runtime_windows.host_authority',
             'runtime_windows.win32_backend', 'runtime_windows.candidate_cli',
             'runtime_windows.assembly.pipeline', 'runtime_windows.assembly.loader',
             'k0_fact_foundation', 'k1_state_derivation',
             'candidate_canonical_capability_contract', 'candidate_capability_feasibility_projection')


def import_guard():
    actual = builtins.__import__
    def check(name, globals=None, locals=None, fromlist=(), level=0):
        full = importlib.util.resolve_name('.' * level + name, globals['__package__']) if level else name
        values = [full] + [full + '.' + value for value in fromlist or () if value != '*']
        if any(value == prefix or value.startswith(prefix + '.') for value in values for prefix in FORBIDDEN):
            raise AssertionError('Forbidden execution-capable import: ' + full)
        return actual(name, globals, locals, fromlist, level)
    return mock.patch.object(builtins, '__import__', side_effect=check)


with import_guard():
    from runtime_windows.assembly.contracts import canonical, digest
    from runtime_windows import task_store, task_cli
    from runtime_windows.task_store import TaskJournal, TaskStoreError
    from runtime_windows.tasks import TaskService
    from runtime_windows.host_contract import validate_host_result, boundary, HostEvidencePersistenceError


LINEAGE = dict(runtime_source_manifest_sha256='1' * 64, runtime_contract_sha256='2' * 64,
               public_lock_sha256='3' * 64, original_component_manifest_sha256='4' * 64)


def synthetic_input(domain, scenario):
    return {'fixture': 'TEST_DOUBLE_ONLY', 'domain_id': domain, 'scenario_id': scenario}


class SyntheticCatalog:
    """Pure task descriptors, not the actual product's DATA catalog."""
    def __init__(self):
        self.identity = dict(LINEAGE, grade='TEST_DOUBLE_ONLY')
        self.changed = False
    def verify(self):
        return dict(self.identity, public_lock_sha256='f' * 64) if self.changed else copy.deepcopy(self.identity)
    def describe(self, domain, scenario='positive'):
        if domain not in ('DEVSECOPS', 'FINANCE_REFUND'):
            raise ValueError('UNREGISTERED_DOMAIN')
        if scenario not in ('positive', 'violation'):
            raise ValueError('UNREGISTERED_FROZEN_SCENARIO')
        return dict(self.identity, domain_id=domain, scenario_id=scenario,
                    domain_asset_manifest_sha256=digest({'TEST_DOUBLE_ONLY_DOMAIN_MANIFEST': domain}),
                    input_sha256=digest(synthetic_input(domain, scenario)))


def reference(path, value):
    raw = (canonical(value) + '\n').encode('utf-8')
    return {'path': path, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'raw_base64': base64.b64encode(raw).decode('ascii')}


def synthetic_host_result(domain, scenario, run_id, task_id, operation='candidate_compute',
                          source_run_id=None, decision='FEASIBLE'):
    """Self-consistent TEST_DOUBLE_ONLY bytes, no worker or original computation."""
    labels = ('Ontology.load_default_profile', 'K0.Fact.create', 'K0.CanonicalFactLedger',
        'K0.append', 'K1.StateCompiler', 'K1.compile', 'C1.Catalog.from_mapping',
        'C1.Catalog.require_definition', 'C2.Evaluator', 'C2.project', 'C2.Projection.verify')
    trace = []
    for label in labels:
        trace += [{'label': label, 'event': 'CALL', 'origin': 'vendor/TEST_DOUBLE_ONLY.py',
                   'function': 'TEST_DOUBLE_ONLY', 'arguments_hash': digest({'fixture': 'TEST_DOUBLE_ONLY'})},
                  {'label': label, 'event': 'RETURN', 'value': {'fixture': 'TEST_DOUBLE_ONLY'}}]
    inputs = synthetic_input(domain, scenario)
    projection = {'decision': decision, 'candidate_planning_only': True,
                  'authority_granted': False, 'execution_permitted': False}
    semantic = {'domain_id': domain, 'scenario_id': scenario, 'input_bundle': inputs,
                'source_identity': {'input_hash': digest(inputs), 'formal_trust': False,
                                    'manifest_sha256': digest({'TEST_DOUBLE_ONLY_DOMAIN_MANIFEST': domain}),
                                    'source_kind': 'ISOLATED_SYNTHETIC_TEST_ONLY'},
                'native_calls': trace, 'projection': projection,
                'boundary': dict(candidate_planning_only=True, authority_granted=False,
                                 execution_permitted=False, business_action_calls=0, formal_history_writes=0)}
    actual = {'status': 'COMPUTED_CANDIDATE_ONLY', 'semantic': semantic, 'semantic_hash': digest(semantic)}
    record = {'schema_id': 'H56OS:CANDIDATE_RECEIPT:WINDOWS_V1', 'result': actual,
              'result_hash': digest(actual), 'lineage': dict(LINEAGE),
              'unverified_runtime_claim': {'release_sha256': '5' * 64, 'environment_sha256': '6' * 64,
                  'preflight_sha256': '7' * 64, 'grade': 'UNVERIFIED_RECORDED_DIGESTS_NOT_REPLAYED_OR_AUTHORITY'},
              'candidate_planning_only': True, 'authority_granted': False, 'execution_permitted': False}
    record['receipt_hash'] = digest(record)
    observation = dict(schema='h56.windows-candidate-started.v1', pid=2468, run_id=run_id,
        operation=operation, task_id=task_id, runtime_source_manifest_sha256=LINEAGE['runtime_source_manifest_sha256'],
        resource_contract_sha256='8' * 64)
    comparison = None if operation == 'candidate_compute' else {
        'status': 'ACTUAL_RECOMPUTATION_MATCH', 'semantic_hash': actual['semantic_hash'],
        'source_receipt_hash': digest(record), 'recomputed_result': actual,
        'authority_granted': False, 'execution_permitted': False}
    prefix = 'runtime_windows/.local/TEST_DOUBLE_ONLY/'
    receipt_path = prefix + ('scratch/runs/' + run_id if operation == 'candidate_compute' else
                             'replay_input/' + source_run_id) + '/receipt.json'
    stdout = (canonical({'status': 'COMPUTED_CANDIDATE_ONLY',
                        'receipt': 'C:\\TEST_DOUBLE_ONLY\\product\\' + receipt_path.replace('/', '\\')}
                        if comparison is None else comparison) + '\n').encode('utf-8')
    argv = [r'C:\TEST_DOUBLE_ONLY\python.exe', '-I', '-B', '-S', '-X', 'utf8',
            r'C:\TEST_DOUBLE_ONLY\product\runtime_windows\candidate_cli.py']
    argv += (['--domain', domain, '--scenario', scenario, '--run-id', run_id]
             if operation == 'candidate_compute' else ['--recompute-file', source_run_id])
    transport = {'schema': 'h56.windows-candidate-transport.v1',
        'argv': argv, 'pid': 2468, 'exit_code': 0,
        'raw_stdout_base64': base64.b64encode(stdout).decode('ascii'), 'raw_stderr_base64': '',
        'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(b'').hexdigest(),
        'observed_output_bytes': {'stdout': len(stdout), 'stderr': 0},
        'capture_prefix_truncated': {'stdout': False, 'stderr': False},
        'cleanup': {'status': 'CLOSED', 'errors': []},
        'events': ['OWNED_CHILD_RESUMED', 'OWNED_CHILD_EXITED_OUTPUT_DRAINED'], 'stop_reason': None,
        'runtime_source_manifest_sha256': LINEAGE['runtime_source_manifest_sha256'],
        'resource_contract_sha256': observation['resource_contract_sha256'], 'started_event': observation}
    return {'schema': 'h56.windows-candidate-host-result.v1', 'operation': operation, 'run_id': run_id,
        'task_id': task_id, 'source_run_id': source_run_id,
        'status': 'COMPUTED_CANDIDATE_ONLY' if comparison is None else 'ACTUAL_RECOMPUTATION_MATCH',
        'pid': 2468, 'started': True, 'exit_code': 0, 'source_lineage': dict(LINEAGE),
        'record': record, 'receipt_ref': reference(receipt_path, record),
        'native_trace_ref': reference(prefix + 'host_evidence/' + run_id + '/native_trace.json', trace),
        'projection': projection, 'comparison': comparison, 'transport_receipt': transport,
        'failure': None, 'boundary': boundary()}


def reseal_synthetic_result(result):
    """Only rebuild TEST_DOUBLE_ONLY checksums, never runtime evidence."""
    actual = result['record']['result']
    if actual['status'] == 'COMPUTED_CANDIDATE_ONLY':
        actual['semantic_hash'] = digest(actual['semantic'])
    result['record']['result_hash'] = digest(actual)
    result['record']['receipt_hash'] = digest({key: value for key, value in result['record'].items() if key != 'receipt_hash'})
    result['receipt_ref'] = reference(result['receipt_ref']['path'], result['record'])


def replace_synthetic_stdout(result, output):
    raw = (canonical(output) + '\n').encode('utf-8')
    result['transport_receipt'].update(raw_stdout_base64=base64.b64encode(raw).decode('ascii'),
        stdout_sha256=hashlib.sha256(raw).hexdigest(), observed_output_bytes={'stdout': len(raw), 'stderr': 0})


class SimulatedCrash(BaseException):
    pass


SyntheticEvidenceFailure = HostEvidencePersistenceError


def synthetic_evidence_failure():
    value = synthetic_host_result('DEVSECOPS', 'positive', 'failed_run', 'failed_task')
    value.update(status='HOST_FAILED', record=None, receipt_ref=None, native_trace_ref=None,
                 projection=None, comparison=None,
                 failure={'code': 'TEST_DOUBLE_ONLY_NOT_ARCHIVED', 'detail': ''})
    return SyntheticEvidenceFailure(value, 'TEST_DOUBLE_ONLY_ARCHIVE_ERROR')


class RecordHost:
    test_double_only = True
    def __init__(self, mode='complete'):
        self.calls, self.mode, self.after_started = [], mode, None
    def compute(self, domain, scenario, run_id, on_started=None, task_id=None):
        self.calls.append(('TEST_DOUBLE_ONLY_COMPUTE', domain, scenario, run_id, task_id))
        if self.mode == 'raise':
            raise RuntimeError('TEST_DOUBLE_ONLY_HOST_FAILURE')
        if self.mode == 'crash':
            raise SimulatedCrash('TEST_DOUBLE_ONLY_CRASH')
        if self.mode == 'evidence_failure':
            raise synthetic_evidence_failure()
        result = synthetic_host_result(domain, scenario, run_id, task_id,
                                       decision='INFEASIBLE' if scenario == 'violation' else 'FEASIBLE')
        if self.mode in ('blocked_result', 'failed_result'):
            result.update(status='HOST_BLOCKED' if self.mode == 'blocked_result' else 'HOST_FAILED',
                pid=None, started=False, exit_code=None, record=None, receipt_ref=None,
                native_trace_ref=None, projection=None, comparison=None, transport_receipt=None,
                failure={'code': 'TEST_DOUBLE_ONLY_UNAVAILABLE', 'detail': ''})
            return result
        if self.mode != 'missing_callback':
            observation = copy.deepcopy(result['transport_receipt']['started_event'])
            if self.mode == 'bad_callback':
                observation['pid'] = False
            on_started(observation)
            if self.after_started:
                self.after_started()
        if self.mode == 'missing_evidence':
            result['receipt_ref'] = None
        if self.mode == 'wrong_projection':
            result['projection'] = {'decision': 'FAKE'}
        if self.mode == 'pipeline_rejected':
            result.update(status='PIPELINE_REJECTED', exit_code=2, projection=None)
            result['transport_receipt']['exit_code'] = 2
            result['record']['result'] = dict(status='REJECTED', stage='ADMISSION', error_type='TEST_DOUBLE_ONLY',
                error='TEST_DOUBLE_ONLY_REJECTION', domain_id=domain, scenario_id=scenario, native_calls=[],
                candidate_planning_only=True, authority_granted=False, execution_permitted=False, business_action_calls=0)
            reseal_synthetic_result(result)
            result['native_trace_ref'] = reference(result['native_trace_ref']['path'], [])
            prefix = 'runtime_windows/.local/TEST_DOUBLE_ONLY/scratch/runs/' + run_id + '/receipt.json'
            replace_synthetic_stdout(result, {'status': 'REJECTED', 'receipt': 'C:\\TEST_DOUBLE_ONLY\\product\\' + prefix.replace('/', '\\')})
        if self.mode == 'wrong_input':
            semantic = result['record']['result']['semantic']
            semantic['input_bundle']['fixture'] = 'DIFFERENT_TEST_DOUBLE_INPUT'
            semantic['source_identity']['input_hash'] = digest(semantic['input_bundle'])
            reseal_synthetic_result(result)
        return result
    def replay(self, source_run_id, replay_id, on_started=None, task_id=None):
        self.calls.append(('TEST_DOUBLE_ONLY_REPLAY', source_run_id, replay_id, task_id))
        result = synthetic_host_result('DEVSECOPS', 'positive', replay_id, task_id,
            operation='fresh_process_replay', source_run_id=source_run_id)
        on_started(copy.deepcopy(result['transport_receipt']['started_event']))
        return result


class TaskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (EVIDENCE / 'fixtures').mkdir(parents=True, exist_ok=True)
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='task_', dir=str(EVIDENCE / 'fixtures')))
        self.catalog, self.host = SyntheticCatalog(), RecordHost()
        self.store = TaskJournal('synthetic_session', self.root)
        self.service = TaskService(self.catalog, self.store, self.host)
    def submit(self, domain='DEVSECOPS', request='request', scenario='positive'):
        return self.service.submit(request, domain, scenario)

    def test_01_two_synthetic_domains_same_task_consumer_test_double_only(self):
        for domain in ('DEVSECOPS', 'FINANCE_REFUND'):
            task = self.submit(domain, domain)
            self.assertEqual(task['status'], 'QUEUED')
            self.assertFalse(task['authority_granted'])
        self.assertEqual(len(self.host.calls), 0)

    def test_02_submit_idempotency_and_cross_domain_conflict(self):
        task = self.submit()
        before = self.store.path.read_bytes()
        self.assertTrue(self.submit()['duplicate'])
        with self.assertRaisesRegex(ValueError, 'IDEMPOTENCY_KEY_REUSED'):
            self.submit('FINANCE_REFUND')
        self.assertEqual(before, self.store.path.read_bytes())
        self.assertEqual(self.host.calls, [])

    def test_03_unregistered_inputs_no_write(self):
        before = self.store.path.read_bytes()
        for domain, scenario in (('PRODUCTION', 'positive'), ('DEVSECOPS', 'live_input')):
            with self.assertRaises(ValueError):
                self.submit(domain, 'bad', scenario)
        self.assertEqual(before, self.store.path.read_bytes())

    def test_04_unbound_host_blocked_no_import_or_resource(self):
        task = self.submit()
        self.service.host = None
        self.assertEqual(self.service.dispatch(task['task_id'])['status'], 'BLOCKED')
        self.assertEqual(self.host.calls, [])

    def test_05_successful_synthetic_control_and_duplicate_no_retry(self):
        task = self.submit()
        final = self.service.dispatch(task['task_id'])
        self.assertEqual(final['status'], 'COMPLETED')
        self.assertEqual(final['verification_grade'], 'TEST_DOUBLE_ONLY')
        self.assertEqual(final['host_result']['projection']['decision'], 'FEASIBLE')
        self.assertNotIn('raw_base64', final['host_result']['receipt_ref'])
        before = self.store.path.read_bytes()
        self.service.dispatch(task['task_id'])
        self.assertEqual(before, self.store.path.read_bytes())
        self.assertEqual(len(self.host.calls), 1)

    def test_06_infeasible_synthetic_computation_completes_without_authority(self):
        task = self.submit(scenario='violation')
        final = self.service.dispatch(task['task_id'])
        self.assertEqual(final['status'], 'COMPLETED')
        self.assertEqual(final['host_result']['projection']['decision'], 'INFEASIBLE')
        self.assertFalse(final['authority_granted'])
        self.assertFalse(final['execution_permitted'])

    def test_07_queued_cancel_zero_host_calls(self):
        task = self.submit()
        self.assertEqual(self.service.cancel(task['task_id'])['status'], 'CANCELLED')
        self.service.dispatch(task['task_id'])
        self.assertEqual(self.host.calls, [])

    def test_08_running_cancel_request_not_real_termination(self):
        task = self.submit()
        self.host.after_started = lambda: self.service.cancel(task['task_id'])
        final = self.service.dispatch(task['task_id'])
        self.assertEqual(final['status'], 'COMPLETED')
        self.assertEqual(final['cancel_state'], 'NOT_CONFIRMED_NO_RUNNING_CANCEL_INTERFACE')

    def test_09_restart_restores_history_unverified_no_host_calls(self):
        task = self.submit()
        self.service.dispatch(task['task_id'])
        other_host = RecordHost()
        restored = TaskService(self.catalog, TaskJournal('synthetic_session', self.root), other_host)
        final = restored.tasks[task['task_id']]
        self.assertEqual(final['status'], 'COMPLETED')
        self.assertEqual(final['verification_grade'], 'UNVERIFIED_RESTORED_TASK_OBSERVATION')
        restored.dispatch(task['task_id'])
        self.assertEqual(other_host.calls, [])

    def test_10_crash_recovery_requires_review_no_automatic_retry(self):
        task = self.submit()
        self.host.mode = 'crash'
        with self.assertRaises(SimulatedCrash):
            self.service.dispatch(task['task_id'])
        other = RecordHost()
        restored = TaskService(self.catalog, TaskJournal('synthetic_session', self.root), other)
        self.assertEqual(restored.tasks[task['task_id']]['status'], 'RECOVERY_REQUIRED')
        restored.recover()
        restored.dispatch(task['task_id'])
        self.assertEqual(other.calls, [])

    def test_11_host_failure_is_not_computation(self):
        task = self.submit()
        self.host.mode = 'raise'
        final = self.service.dispatch(task['task_id'])
        self.assertEqual(final['status'], 'FAILED')
        self.assertIsNone(final['host_result'])

    def test_12_bad_callback_and_started_without_callback_fail(self):
        for mode in ('bad_callback', 'missing_callback', 'missing_evidence', 'wrong_projection'):
            with self.subTest(mode=mode):
                task = self.submit(request=mode)
                self.host.mode = mode
                final = self.service.dispatch(task['task_id'])
                self.assertEqual(final['status'], 'FAILED')
                self.assertIsNone(final['host_result'])

    def test_13_source_changed_stops_before_host_and_write(self):
        task = self.submit()
        before = self.store.path.read_bytes()
        self.catalog.changed = True
        with self.assertRaisesRegex(TaskStoreError, 'TASK_SOURCE_CHANGED'):
            self.service.dispatch(task['task_id'])
        self.assertEqual(self.host.calls, [])
        self.assertEqual(before, self.store.path.read_bytes())

    def test_14_replay_is_separate_call_and_bounded_summary(self):
        task = self.submit()
        self.service.dispatch(task['task_id'])
        final = self.service.replay(task['task_id'], 'new_replay')
        replayed = final['replays']['new_replay']
        self.assertEqual(replayed['status'], 'COMPLETED')
        comparison = replayed['host_result']['comparison']
        self.assertNotIn('recomputed_result', comparison)
        self.assertIn('recomputed_result_digest', comparison)
        self.service.replay(task['task_id'], 'new_replay')
        self.assertEqual(len(self.host.calls), 2)

    def test_15_partial_journal_preserved(self):
        with self.store.path.open('ab') as stream:
            stream.write(b'{"partial":')
        before = self.store.path.read_bytes()
        with self.assertRaisesRegex(TaskStoreError, 'PARTIAL_EVENT'):
            TaskJournal('synthetic_session', self.root)
        self.assertEqual(before, self.store.path.read_bytes())

    def test_16_stale_writer_and_lock_preserved(self):
        stale = TaskService(self.catalog, TaskJournal('synthetic_session', self.root))
        self.submit()
        before = self.store.path.read_bytes()
        with self.assertRaisesRegex(TaskStoreError, 'CONCURRENT_WRITER'):
            stale.submit('other', 'FINANCE_REFUND')
        self.assertEqual(before, self.store.path.read_bytes())
        self.store.lock.write_bytes(b'Preserve stale lock')
        with self.assertRaises(FileExistsError):
            self.submit(request='locked')
        self.assertEqual(self.store.lock.read_bytes(), b'Preserve stale lock')

    def test_17_path_escape_and_event_budget_zero_host_call(self):
        for session in ('../escape', 'C:\\escape', '', 'a/b'):
            with self.assertRaises(TaskStoreError):
                TaskJournal(session, self.root)
        task = self.submit()
        before = self.store.path.read_bytes()
        with mock.patch.object(task_store, 'MAX_EVENTS', len(self.store.events) + 2), self.assertRaises(TaskStoreError):
            self.service.dispatch(task['task_id'])
        self.assertEqual(self.host.calls, [])
        self.assertEqual(before, self.store.path.read_bytes())

    def test_18_append_handle_object_replacement_stops_before_write(self):
        before = self.store.path.read_bytes()
        actual = os.open
        swapped = []
        def swap(name, flags, *args, **kwargs):
            if str(name) == str(self.store.path) and flags & os.O_WRONLY and not swapped:
                swapped.append(True)
                os.replace(self.store.path, self.root / 'preserved_original.jsonl')
                self.store.path.write_bytes(before)
            return actual(name, flags, *args, **kwargs)
        with mock.patch.object(os, 'open', side_effect=swap), self.assertRaisesRegex(TaskStoreError, 'OPENED_IDENTITY_DRIFT'):
            self.submit()
        self.assertTrue(swapped)
        self.assertEqual(before, self.store.path.read_bytes())

    def test_19_hash_tamper_preserved_and_rejected(self):
        self.submit()
        before = self.store.path.read_bytes().replace(b'QUEUED', b'FAILED')
        self.store.path.write_bytes(before)
        with self.assertRaisesRegex(TaskStoreError, 'EVENT_CHAIN_INTEGRITY_FAILURE'):
            TaskJournal('synthetic_session', self.root)
        self.assertEqual(before, self.store.path.read_bytes())

    def test_20_operator_unbound_and_partial_pins_do_not_import_host(self):
        with import_guard():
            args = SimpleNamespace(trusted_hc_sha256=None, controller_bundle_sha256=None, host_session=None)
            self.assertIsNone(task_cli.operator_host(args))
            args.host_session = 'not_an_approval'
            with self.assertRaises(ValueError):
                task_cli.operator_host(args)
        parsed = ast.parse((PRODUCT / 'runtime_windows/task_cli.py').read_bytes())
        pins = next(node for node in ast.walk(parsed) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == 'BootstrapPins')
        value = next(keyword.value for keyword in pins.keywords if keyword.arg == 'product_root')
        self.assertIsInstance(value, ast.Call)
        self.assertEqual(value.func.id, 'str')
        self.assertEqual(len(value.args), 1)

    def test_21_shared_validator_rejects_forged_success_without_evidence(self):
        descriptor = self.catalog.describe('DEVSECOPS')
        result = synthetic_host_result('DEVSECOPS', 'positive', 'run_x', 'task_x')
        observation = result['transport_receipt']['started_event']
        validate_host_result(result, 'candidate_compute', 'run_x', 'task_x', None, LINEAGE, observation)
        for field in ('record', 'receipt_ref', 'native_trace_ref', 'transport_receipt'):
            changed = copy.deepcopy(result)
            changed[field] = None
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_host_result(changed, 'candidate_compute', 'run_x', 'task_x', None, LINEAGE, observation)

    def test_22_no_native_host_or_windows_module_imported(self):
        for prefix in FORBIDDEN:
            self.assertFalse(any(name == prefix or name.startswith(prefix + '.') for name in sys.modules), prefix)
        parsed = ast.parse((PRODUCT / 'runtime_windows/task_cli.py').read_bytes())
        node = next(value for value in parsed.body if isinstance(value, ast.FunctionDef) and value.name == 'main')
        text = ast.dump(node)
        self.assertIn('utf8_mode', text)
        self.assertIn('operator_host', text)

    def test_23_host_terminal_statuses_are_distinct_test_double_only(self):
        for mode, expected in (('blocked_result', 'BLOCKED'), ('failed_result', 'FAILED'),
                               ('pipeline_rejected', 'REJECTED')):
            with self.subTest(mode=mode):
                task = self.submit(request=mode)
                self.host.mode = mode
                final = self.service.dispatch(task['task_id'])
                self.assertEqual(final['status'], expected)
                self.assertIsNotNone(final['host_result'])
                self.assertIsNone(final['host_result']['projection'])
                self.assertEqual(final['verification_grade'], 'TEST_DOUBLE_ONLY')

    def test_24_self_consistent_wrong_frozen_input_rejected_by_task_binding(self):
        task = self.submit()
        self.host.mode = 'wrong_input'
        final = self.service.dispatch(task['task_id'])
        self.assertEqual(final['status'], 'FAILED')
        self.assertIn('HOST_RESULT_FROZEN_INPUT_MISMATCH', final['reason'])

    def test_25_output_fd_hardlink_metadata_refused_before_append(self):
        before = self.store.path.read_bytes()
        actual_open, actual_fstat, output_handles = os.open, os.fstat, []
        def remember(name, flags, *args, **kwargs):
            handle = actual_open(name, flags, *args, **kwargs)
            if str(name) == str(self.store.path) and flags & os.O_WRONLY:
                output_handles.append(handle)
            return handle
        def metadata(handle):
            value = actual_fstat(handle)
            if handle in output_handles:
                return SimpleNamespace(st_nlink=2, st_mode=value.st_mode,
                                       st_file_attributes=getattr(value, 'st_file_attributes', 0))
            return value
        with mock.patch.object(os, 'open', side_effect=remember), mock.patch.object(os, 'fstat', side_effect=metadata), self.assertRaisesRegex(ValueError, 'HARDLINK_OR_UNKNOWN_LINK_COUNT'):
            self.submit()
        self.assertEqual(before, self.store.path.read_bytes())

    def test_26_raw_evidence_archive_failure_stops_and_preserves_live_exception(self):
        task = self.submit()
        self.host.mode = 'evidence_failure'
        with self.assertRaises(SyntheticEvidenceFailure) as caught:
            self.service.dispatch(task['task_id'])
        self.assertEqual(caught.exception.raw_result['failure']['code'], 'TEST_DOUBLE_ONLY_NOT_ARCHIVED')
        final = self.service.tasks[task['task_id']]
        self.assertEqual(final['status'], 'FAILED')
        self.assertEqual(final['verification_grade'], 'RAW_EVIDENCE_PRESERVATION_BLOCKED')
        self.assertIsNone(final['host_result'])
        document = task_cli.error_document(caught.exception)
        self.assertEqual(document['evidence_persistence'], 'FAILED')
        self.assertEqual(document['raw_result'], caught.exception.raw_result)
        self.assertFalse(document['candidate_result_verified'])
        other = self.submit(request='also_journal_failure')
        append = self.store.append
        def reject_failure_event(kind, payload):
            if kind == 'TASK_FAILED':
                raise TaskStoreError('TEST_DOUBLE_ONLY_JOURNAL_FAILURE')
            return append(kind, payload)
        with mock.patch.object(self.store, 'append', side_effect=reject_failure_event), self.assertRaises(SyntheticEvidenceFailure) as still_raw:
            self.service.dispatch(other['task_id'])
        document = task_cli.error_document(still_raw.exception)
        self.assertEqual(document['raw_result'], caught.exception.raw_result)
        self.assertEqual(document['task_record_failure']['type'], 'TaskStoreError')
        arbitrary = ValueError('UNTRUSTED_EXCEPTION_ATTRIBUTES')
        arbitrary.code, arbitrary.raw_result = 'HOST_RAW_EVIDENCE_ARCHIVE_FAILED', {'must_not_be_output': True}
        self.assertNotIn('raw_result', task_cli.error_document(arbitrary))

    def test_27_actual_frozen_catalog_data_only_no_runtime_or_host(self):
        """Real fixed file DATA reads; not a simulated or actual core execution."""
        with import_guard():
            from runtime_windows.task_catalog import FrozenTaskCatalog
            from runtime_windows import runtime_admission, source_identity
        manifest = json.loads((PRODUCT / 'runtime_windows/RUNTIME_SOURCE_MANIFEST.json').read_bytes())
        self.assertEqual(manifest['member_count'], 152)
        reads = []
        actual = source_identity._read_checked
        def observe(path, size, maximum):
            raw = actual(path, size, maximum)
            relative = path.relative_to(PRODUCT).as_posix()
            reads.append({'path': relative, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
            return raw
        deny = mock.Mock(side_effect=AssertionError('Runtime admission is forbidden in DATA test'))
        with import_guard(), mock.patch.object(runtime_admission, 'admit_runtime', deny), \
                mock.patch.object(source_identity, '_read_checked', side_effect=observe), \
                mock.patch.object(runtime_admission, '_read_checked', side_effect=observe):
            catalog = FrozenTaskCatalog()
            dev, fin = catalog.describe('DEVSECOPS'), catalog.describe('FINANCE_REFUND')
            self.assertEqual(catalog.verify(), catalog.identity)
        deny.assert_not_called()
        self.assertEqual(dev['core_fingerprint'], fin['core_fingerprint'])
        self.assertEqual(dev['runtime_source_manifest_sha256'], fin['runtime_source_manifest_sha256'])
        self.assertNotEqual(dev['domain_asset_manifest_sha256'], fin['domain_asset_manifest_sha256'])
        self.assertNotEqual(dev['input_sha256'], fin['input_sha256'])
        payload = {'grade': 'DATA_IDENTITY_ONLY_NOT_RUNTIME_ACCEPTANCE',
                   'product_modules_imported_for_core': False, 'runtime_admission_calls': 0,
                   'candidate_host_calls': 0, 'native_calls': 0, 'identity': catalog.identity,
                   'descriptors': [dev, fin], 'actual_reads': reads}
        (self.root / 'catalog_read_observations.json').write_bytes((canonical(payload) + '\n').encode('utf-8'))
        self.assertTrue(reads)
        # The fixed vendor110 legitimately contains audit EVIDENCE source
        # manifests. Only the old component-wide private manifest is forbidden.
        forbidden_paths = {'runtime_binding_v1_20261024/offline/source-lock.json',
                           'runtime_binding_v1_20261024/SOURCE_MANIFEST.json'}
        self.assertFalse(any(item['path'] in forbidden_paths or '/.local/' in item['path'] for item in reads))


if __name__ == '__main__':
    with import_guard():
        unittest.main(verbosity=2)
