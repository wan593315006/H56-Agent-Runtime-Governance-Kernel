"""Task control consumes a candidate Host; never owns K0/K1 or execution rights."""
from copy import deepcopy
import re

from .assembly.contracts import canonical, digest
from .task_store import SCOPE, TOKEN, TaskJournal, TaskStoreError
from .host_contract import HostEvidencePersistenceError

HOST_SCHEMA = 'h56.windows-candidate-host-result.v1'
STARTED_SCHEMA = 'h56.windows-candidate-started.v1'
HOST_FIELDS = frozenset(('schema', 'operation', 'run_id', 'task_id', 'source_run_id',
    'status', 'pid', 'started', 'exit_code', 'source_lineage', 'record', 'receipt_ref',
    'native_trace_ref', 'projection', 'comparison', 'transport_receipt', 'failure', 'boundary'))
STARTED_FIELDS = frozenset(('schema', 'pid', 'run_id', 'operation', 'task_id',
                           'runtime_source_manifest_sha256', 'resource_contract_sha256'))
HOST_STATUSES = frozenset(('HOST_BLOCKED', 'HOST_FAILED', 'PIPELINE_REJECTED',
                           'COMPUTED_CANDIDATE_ONLY', 'ACTUAL_RECOMPUTATION_MATCH'))
TERMINAL = frozenset(('COMPLETED', 'REJECTED', 'FAILED', 'BLOCKED', 'CANCELLED'))
IN_FLIGHT = frozenset(('DISPATCHING', 'RUNNING', 'CANCEL_REQUESTED'))


def _exact(value, keys, reason):
    if type(value) is not dict or set(value) != set(keys):
        raise TaskStoreError(reason)


def _token(value):
    return type(value) is str and TOKEN.fullmatch(value) is not None


def _boundary(value):
    _exact(value, ('candidate_planning_only', 'authority_granted', 'execution_permitted',
                   'formal_history_write', 'external_services'), 'HOST_BOUNDARY_FIELDS')
    if value.get('candidate_planning_only') is not True:
        raise TaskStoreError('HOST_CANDIDATE_BOUNDARY_REQUIRED')
    for key in ('authority_granted', 'execution_permitted'):
        if value.get(key) is not False:
            raise TaskStoreError('HOST_AUTHORITY_BOUNDARY_DRIFT')
    for key in ('formal_history_write', 'external_services'):
        if value[key] is not False:
            raise TaskStoreError('HOST_AUTHORITY_BOUNDARY_DRIFT')


def summarize_host_result(result, descriptor, operation, run_id, task_id, source_run_id,
                          started_observation):
    """Validate only the fixed Host contract. Not an independent execution attestation."""
    from .host_contract import validate_host_result
    expected_lineage = {key: descriptor[key] for key in (
        'runtime_source_manifest_sha256', 'runtime_contract_sha256',
        'public_lock_sha256', 'original_component_manifest_sha256')}
    validate_host_result(result, operation, run_id, task_id, source_run_id,
                         expected_lineage, started_observation=started_observation)
    observed_started = started_observation is not None
    _exact(result, HOST_FIELDS, 'HOST_RESULT_FIELDS')
    if result['schema'] != HOST_SCHEMA or result['status'] not in HOST_STATUSES:
        raise TaskStoreError('HOST_RESULT_SCHEMA_OR_STATUS')
    if (result['operation'], result['run_id'], result['task_id'], result['source_run_id']) != (
            operation, run_id, task_id, source_run_id):
        raise TaskStoreError('HOST_RESULT_OPERATION_BINDING_MISMATCH')
    if type(result['started']) is not bool or result['started'] is not observed_started:
        raise TaskStoreError('HOST_STARTED_WITHOUT_MATCHING_OBSERVATION')
    if observed_started:
        if type(result['pid']) is not int or result['pid'] <= 0:
            raise TaskStoreError('HOST_PID_REQUIRED')
    elif result['pid'] is not None and not (result['status'] == 'HOST_FAILED' and
            type(result['pid']) is int and result['pid'] > 0):
        raise TaskStoreError('HOST_UNSTARTED_PID_DRIFT')
    if result['exit_code'] is not None and type(result['exit_code']) is not int:
        raise TaskStoreError('HOST_EXIT_CODE_TYPE')
    _boundary(result['boundary'])
    completed = result['status'] in ('COMPUTED_CANDIDATE_ONLY', 'ACTUAL_RECOMPUTATION_MATCH')
    if completed and (not observed_started or result['exit_code'] != 0):
        raise TaskStoreError('HOST_COMPLETION_WITHOUT_SUCCESSFUL_CHILD')
    if completed and any(result[key] is None for key in ('record', 'receipt_ref', 'native_trace_ref', 'transport_receipt')):
        raise TaskStoreError('HOST_COMPLETION_EVIDENCE_MISSING')
    if operation == 'candidate_compute' and result['status'] == 'ACTUAL_RECOMPUTATION_MATCH':
        raise TaskStoreError('HOST_WRONG_OPERATION_RESULT')
    if operation == 'fresh_process_replay' and result['status'] == 'COMPUTED_CANDIDATE_ONLY':
        raise TaskStoreError('HOST_WRONG_OPERATION_RESULT')
    if result['status'] in ('COMPUTED_CANDIDATE_ONLY', 'PIPELINE_REJECTED', 'ACTUAL_RECOMPUTATION_MATCH'):
        lineage = result['source_lineage']
        if type(lineage) is not dict or any(lineage.get(key) != descriptor[key]
                for key in ('runtime_source_manifest_sha256', 'public_lock_sha256')):
            raise TaskStoreError('HOST_RESULT_SOURCE_BINDING_MISMATCH')
        stored_result = result['record']['result']
        candidates = [stored_result]
        if result['status'] == 'ACTUAL_RECOMPUTATION_MATCH':
            candidates.append(result['comparison']['recomputed_result'])
        for candidate in candidates:
            semantic = candidate.get('semantic')
            bound = candidate if semantic is None else semantic
            if (bound.get('domain_id'), bound.get('scenario_id')) != (descriptor['domain_id'], descriptor['scenario_id']):
                raise TaskStoreError('HOST_RESULT_DOMAIN_OR_SCENARIO_MISMATCH')
            if semantic is not None and (digest(semantic.get('input_bundle')) != descriptor['input_sha256'] or
                    semantic.get('source_identity', {}).get('input_hash') != descriptor['input_sha256']):
                raise TaskStoreError('HOST_RESULT_FROZEN_INPUT_MISMATCH')
            if semantic is not None and semantic.get('source_identity', {}).get('manifest_sha256') != descriptor['domain_asset_manifest_sha256']:
                raise TaskStoreError('HOST_RESULT_DOMAIN_ASSET_MANIFEST_MISMATCH')
    # A full receipt/native trace stays in the Host evidence store. A bounded
    # task journal retains references and digests, never replaces that evidence.
    summary = {key: deepcopy(result[key]) for key in (
        'schema', 'operation', 'run_id', 'task_id', 'source_run_id', 'status', 'pid',
        'started', 'exit_code', 'source_lineage', 'receipt_ref', 'native_trace_ref',
        'projection', 'comparison', 'failure', 'boundary')}
    summary['record_digest'] = None if result['record'] is None else digest(result['record'])
    summary['transport_receipt_digest'] = None if result['transport_receipt'] is None else digest(result['transport_receipt'])
    for key in ('receipt_ref', 'native_trace_ref'):
        if summary[key] is not None:
            summary[key] = {name: value for name, value in summary[key].items() if name != 'raw_base64'}
    if summary['comparison'] is not None:
        comparison = summary['comparison']
        summary['comparison'] = {key: deepcopy(comparison.get(key)) for key in (
            'status', 'semantic_hash', 'source_receipt_hash', 'authority_granted', 'execution_permitted')}
        summary['comparison']['recomputed_result_digest'] = digest(comparison.get('recomputed_result'))
    if summary['failure'] is not None and len(canonical(summary['failure']).encode('utf-8')) > 4096:
        summary['failure'] = {'failure_digest': digest(summary['failure']),
                              'evidence': deepcopy(summary['failure'].get('evidence')),
                              'details': 'RETAINED_IN_HOST_EVIDENCE_NOT_TASK_JOURNAL'}
    summary['grade'] = 'HOST_REPORTED_RESULT_NOT_TASK_ATTESTED'
    return summary


class TaskService:
    def __init__(self, catalog, store, host=None):
        self.catalog, self.journal, self.host = catalog, store, host
        self.tasks = {}
        if catalog.verify() != catalog.identity:
            raise TaskStoreError('TASK_SOURCE_CHANGED_BEFORE_SESSION_BINDING')
        if not store.events:
            store.append('SESSION_BOUND', {'source': catalog.identity, 'scope': SCOPE})
        if store.events[0]['kind'] != 'SESSION_BOUND' or store.events[0]['payload'] != {
                'source': catalog.identity, 'scope': SCOPE}:
            raise TaskStoreError('SESSION_SOURCE_BINDING_MISMATCH')
        for event in store.events[1:]:
            self._consume(event)
        # Observing an unfinished durable intent does not prove that its old
        # process died. Never create a retry or contact the Host during recovery.
        for task in self.tasks.values():
            if task['status'] in IN_FLIGHT:
                task['interrupted_status'] = task['status']
                task['status'] = 'RECOVERY_REQUIRED'
            if task['status'] in TERMINAL and task.get('host_result'):
                task['verification_grade'] = 'UNVERIFIED_RESTORED_TASK_OBSERVATION'
            for replay in task['replays'].values():
                if replay['status'] in IN_FLIGHT:
                    replay['interrupted_status'] = replay['status']
                    replay['status'] = 'RECOVERY_REQUIRED'
                else:
                    replay['verification_grade'] = 'UNVERIFIED_RESTORED_TASK_OBSERVATION'

    def _task(self, task_id):
        if type(task_id) is not str or task_id not in self.tasks:
            raise TaskStoreError('UNKNOWN_TASK_ID')
        return self.tasks[task_id]

    def _consume(self, event):
        kind, payload = event['kind'], event['payload']
        if kind == 'TASK_QUEUED':
            _exact(payload, ('task_id', 'request_id', 'descriptor'), 'TASK_EVENT_SHAPE')
            descriptor = payload['descriptor']
            if type(descriptor) is not dict or not _token(payload['request_id']):
                raise TaskStoreError('TASK_INPUT_SHAPE')
            if payload['task_id'] != 'task_' + digest({'request_id': payload['request_id']})[:24]:
                raise TaskStoreError('TASK_IDENTITY_MISMATCH')
            if descriptor != self.catalog.describe(descriptor.get('domain_id'), descriptor.get('scenario_id')) or payload['task_id'] in self.tasks:
                raise TaskStoreError('TASK_DOMAIN_SOURCE_OR_DUPLICATE_MISMATCH')
            self.tasks[payload['task_id']] = dict(deepcopy(payload), status='QUEUED', run_id=None,
                host_result=None, started_observation=None, replays={}, verification_grade='NO_COMPUTATION',
                authority_granted=False, execution_permitted=False, cancel_state=None)
            return
        if kind == 'TASK_CANCELLED':
            _exact(payload, ('task_id',), 'TASK_EVENT_SHAPE')
            task = self._task(payload['task_id'])
            if task['status'] != 'QUEUED':
                raise TaskStoreError('INVALID_TASK_TRANSITION')
            task.update(status='CANCELLED', cancel_state='CONFIRMED_BEFORE_HOST_CALL')
            return
        if kind == 'TASK_CANCEL_REQUESTED':
            _exact(payload, ('task_id',), 'TASK_EVENT_SHAPE')
            task = self._task(payload['task_id'])
            if task['status'] not in IN_FLIGHT:
                raise TaskStoreError('INVALID_TASK_TRANSITION')
            task.update(status='CANCEL_REQUESTED', cancel_state='NOT_CONFIRMED_NO_RUNNING_CANCEL_INTERFACE')
            return
        if kind == 'TASK_BLOCKED':
            _exact(payload, ('task_id', 'reason'), 'TASK_EVENT_SHAPE')
            task = self._task(payload['task_id'])
            if task['status'] != 'QUEUED' or payload['reason'] != 'HOST_BOOTSTRAP_UNBOUND':
                raise TaskStoreError('INVALID_TASK_TRANSITION')
            task.update(status='BLOCKED', reason=payload['reason'], verification_grade='NO_HOST_RESOURCE_CREATED')
            return
        if kind in ('TASK_DISPATCHING', 'REPLAY_DISPATCHING'):
            fields = ('task_id', 'run_id') if kind == 'TASK_DISPATCHING' else ('task_id', 'run_id', 'source_run_id')
            _exact(payload, fields, 'TASK_EVENT_SHAPE')
            task = self._task(payload['task_id'])
            if not _token(payload['run_id']):
                raise TaskStoreError('TASK_RUN_ID_INVALID')
            if kind == 'TASK_DISPATCHING':
                if task['status'] != 'QUEUED':
                    raise TaskStoreError('INVALID_TASK_TRANSITION')
                task.update(status='DISPATCHING', run_id=payload['run_id'])
            else:
                if task['status'] != 'COMPLETED' or payload['source_run_id'] != task['run_id'] or payload['run_id'] in task['replays']:
                    raise TaskStoreError('INVALID_REPLAY_TRANSITION')
                task['replays'][payload['run_id']] = {'run_id': payload['run_id'], 'source_run_id': task['run_id'],
                    'status': 'DISPATCHING', 'started_observation': None, 'host_result': None,
                    'authority_granted': False, 'execution_permitted': False}
            return
        if kind in ('TASK_RUNNING', 'REPLAY_RUNNING'):
            _exact(payload, ('task_id', 'observation'), 'TASK_EVENT_SHAPE')
            task = self._task(payload['task_id'])
            observation = payload['observation']
            _exact(observation, STARTED_FIELDS, 'HOST_STARTED_FIELDS')
            operation = 'candidate_compute' if kind == 'TASK_RUNNING' else 'fresh_process_replay'
            target = task if kind == 'TASK_RUNNING' else task['replays'].get(observation['run_id'])
            if target is None or target['status'] not in ('DISPATCHING', 'CANCEL_REQUESTED') or target['started_observation'] is not None:
                raise TaskStoreError('INVALID_STARTED_TRANSITION')
            if (observation['schema'], observation['operation'], observation['task_id'], observation['run_id']) != (
                    STARTED_SCHEMA, operation, payload['task_id'], target['run_id']):
                raise TaskStoreError('HOST_STARTED_BINDING_MISMATCH')
            if type(observation['pid']) is not int or observation['pid'] <= 0 or observation['runtime_source_manifest_sha256'] != self.catalog.identity['runtime_source_manifest_sha256'] or type(observation['resource_contract_sha256']) is not str or re.fullmatch('[0-9a-f]{64}', observation['resource_contract_sha256']) is None:
                raise TaskStoreError('HOST_STARTED_SOURCE_OR_RESOURCE_MISMATCH')
            target.update(status='RUNNING' if target['status'] != 'CANCEL_REQUESTED' else 'CANCEL_REQUESTED',
                          started_observation=deepcopy(observation))
            return
        if kind in ('TASK_FINISHED', 'REPLAY_FINISHED'):
            _exact(payload, ('task_id', 'run_id', 'summary', 'producer_grade'), 'TASK_EVENT_SHAPE')
            task = self._task(payload['task_id'])
            target = task if kind == 'TASK_FINISHED' else task['replays'].get(payload['run_id'])
            if target is None or target['status'] not in IN_FLIGHT or target['run_id'] != payload['run_id']:
                raise TaskStoreError('INVALID_TASK_TERMINAL_TRANSITION')
            summary = payload['summary']
            if type(summary) is not dict or summary.get('status') not in HOST_STATUSES:
                raise TaskStoreError('HOST_SUMMARY_SHAPE')
            keys = (HOST_FIELDS - {'record', 'transport_receipt'}) | {'record_digest', 'transport_receipt_digest', 'grade'}
            _exact(summary, keys, 'HOST_SUMMARY_FIELDS')
            _boundary(summary.get('boundary'))
            operation = 'candidate_compute' if kind == 'TASK_FINISHED' else 'fresh_process_replay'
            if (summary['schema'], summary['operation'], summary['run_id'], summary['task_id'], summary['source_run_id']) != (
                    HOST_SCHEMA, operation, target['run_id'], payload['task_id'],
                    None if kind == 'TASK_FINISHED' else task['run_id']):
                raise TaskStoreError('HOST_SUMMARY_BINDING_MISMATCH')
            if type(summary['started']) is not bool or summary['started'] is not (target['started_observation'] is not None):
                raise TaskStoreError('HOST_SUMMARY_STARTED_MISMATCH')
            if target['started_observation'] is not None and summary['pid'] != target['started_observation']['pid']:
                raise TaskStoreError('HOST_SUMMARY_PID_MISMATCH')
            if payload['producer_grade'] not in ('TEST_DOUBLE_ONLY', 'HOST_REPORTED_RESULT_NOT_TASK_ATTESTED') or summary['grade'] != 'HOST_REPORTED_RESULT_NOT_TASK_ATTESTED':
                raise TaskStoreError('TASK_RESULT_VERIFICATION_GRADE_INVALID')
            state = {'HOST_BLOCKED': 'BLOCKED', 'HOST_FAILED': 'FAILED', 'PIPELINE_REJECTED': 'REJECTED',
                     'COMPUTED_CANDIDATE_ONLY': 'COMPLETED', 'ACTUAL_RECOMPUTATION_MATCH': 'COMPLETED'}[summary['status']]
            target.update(status=state, host_result=deepcopy(summary), verification_grade=payload['producer_grade'])
            return
        if kind in ('TASK_FAILED', 'REPLAY_FAILED'):
            _exact(payload, ('task_id', 'run_id', 'reason'), 'TASK_EVENT_SHAPE')
            task = self._task(payload['task_id'])
            target = task if kind == 'TASK_FAILED' else task['replays'].get(payload['run_id'])
            if target is None or target['status'] not in IN_FLIGHT or target['run_id'] != payload['run_id']:
                raise TaskStoreError('INVALID_TASK_FAILURE_TRANSITION')
            grade = ('RAW_EVIDENCE_PRESERVATION_BLOCKED' if payload['reason'].startswith('RAW_EVIDENCE_PRESERVATION_BLOCKED:')
                     else 'FAILED_OR_UNKNOWN_NO_CANDIDATE_ACCEPTANCE')
            target.update(status='FAILED', reason=payload['reason'], verification_grade=grade)
            return
        raise TaskStoreError('UNREGISTERED_TASK_EVENT')

    def _record(self, kind, payload):
        # Validate a prospective transition before durable append.
        before = deepcopy(self.tasks)
        try:
            self._consume({'kind': kind, 'payload': payload})
        finally:
            self.tasks = before
        event = self.journal.append(kind, payload)
        self._consume(event)

    def submit(self, request_id, domain, scenario='positive'):
        if not _token(request_id):
            raise ValueError('BOUNDED_REQUEST_ID_REQUIRED')
        if self.catalog.verify() != self.catalog.identity:
            raise TaskStoreError('TASK_SOURCE_CHANGED_BEFORE_SUBMIT')
        descriptor = self.catalog.describe(domain, scenario)
        task_id = 'task_' + digest({'request_id': request_id})[:24]
        if task_id in self.tasks:
            task = self.tasks[task_id]
            if task['descriptor'] != descriptor or task['request_id'] != request_id:
                raise ValueError('IDEMPOTENCY_KEY_REUSED_FOR_DIFFERENT_INPUT')
            return dict(deepcopy(task), duplicate=True)
        self._record('TASK_QUEUED', {'task_id': task_id, 'request_id': request_id, 'descriptor': descriptor})
        return dict(deepcopy(self.tasks[task_id]), duplicate=False)

    def _start_observer(self, task_id, replay_id=None):
        def observe(value):
            kind = 'TASK_RUNNING' if replay_id is None else 'REPLAY_RUNNING'
            if replay_id is not None and value.get('run_id') != replay_id:
                raise TaskStoreError('REPLAY_STARTED_RUN_MISMATCH')
            self._record(kind, {'task_id': task_id, 'observation': value})
        return observe

    def _invoke(self, task_id, replay_id=None):
        task = self._task(task_id)
        target = task if replay_id is None else task['replays'][replay_id]
        operation = 'candidate_compute' if replay_id is None else 'fresh_process_replay'
        run_id = target['run_id']
        prefix = 'TASK_' if replay_id is None else 'REPLAY_'
        try:
            if replay_id is None:
                descriptor = task['descriptor']
                result = self.host.compute(descriptor['domain_id'], descriptor['scenario_id'], run_id,
                    on_started=self._start_observer(task_id), task_id=task_id)
            else:
                result = self.host.replay(task['run_id'], replay_id,
                    on_started=self._start_observer(task_id, replay_id), task_id=task_id)
            target = self.tasks[task_id] if replay_id is None else self.tasks[task_id]['replays'][replay_id]
            summary = summarize_host_result(result, task['descriptor'], operation, run_id, task_id,
                None if replay_id is None else task['run_id'], target['started_observation'])
            if target['started_observation'] is not None and summary['pid'] != target['started_observation']['pid']:
                raise TaskStoreError('HOST_RESULT_PID_MISMATCH')
            grade = 'TEST_DOUBLE_ONLY' if getattr(self.host, 'test_double_only', False) is True else 'HOST_REPORTED_RESULT_NOT_TASK_ATTESTED'
            self._record(prefix + 'FINISHED', {'task_id': task_id, 'run_id': run_id,
                                             'summary': summary, 'producer_grade': grade})
        except Exception as exc:
            if isinstance(exc, HostEvidencePersistenceError):
                try:
                    self._record(prefix + 'FAILED', {'task_id': task_id, 'run_id': run_id,
                        'reason': 'RAW_EVIDENCE_PRESERVATION_BLOCKED:HOST_RAW_EVIDENCE_ARCHIVE_FAILED'})
                except Exception as journal_error:
                    exc.task_record_failure = {'type': type(journal_error).__name__, 'reason': str(journal_error)[:512]}
                    raise exc from journal_error
                # Keep the bounded raw_result attached to the original live
                # exception. Never replace missing raw evidence with its digest
                # or report a normal archived failure. Operator must stop.
                raise
            self._record(prefix + 'FAILED', {'task_id': task_id, 'run_id': run_id,
                                           'reason': type(exc).__name__ + ':' + str(exc)[:256]})
        return deepcopy(self.tasks[task_id])

    def dispatch(self, task_id):
        task = self._task(task_id)
        if task['status'] != 'QUEUED':
            return dict(deepcopy(task), duplicate=True)
        if self.catalog.verify() != self.catalog.identity:
            raise TaskStoreError('TASK_SOURCE_CHANGED_BEFORE_DISPATCH')
        if self.host is None:
            self._record('TASK_BLOCKED', {'task_id': task_id, 'reason': 'HOST_BOOTSTRAP_UNBOUND'})
            return deepcopy(self.tasks[task_id])
        self.journal.require_capacity(4)
        run_id = 'run_' + digest({'session': self.journal.session, 'task_id': task_id})[:32]
        self._record('TASK_DISPATCHING', {'task_id': task_id, 'run_id': run_id})
        return self._invoke(task_id)

    def dispatch_next(self):
        for task in self.tasks.values():
            if task['status'] == 'QUEUED':
                return self.dispatch(task['task_id'])
        return {'status': 'QUEUE_EMPTY', 'authority_granted': False, 'execution_permitted': False}

    def cancel(self, task_id):
        task = self._task(task_id)
        if task['status'] == 'QUEUED':
            self._record('TASK_CANCELLED', {'task_id': task_id})
        elif task['status'] in ('DISPATCHING', 'RUNNING'):
            self._record('TASK_CANCEL_REQUESTED', {'task_id': task_id})
        return deepcopy(self.tasks[task_id])

    def replay(self, task_id, replay_id):
        task = self._task(task_id)
        if not _token(replay_id):
            raise TaskStoreError('BOUNDED_REPLAY_ID_REQUIRED')
        if replay_id in task['replays']:
            return deepcopy(task)
        if any(replay_id == item.get('run_id') or replay_id in item['replays'] for item in self.tasks.values()):
            raise TaskStoreError('RUN_OR_REPLAY_ID_ALREADY_BOUND')
        if task['status'] != 'COMPLETED' or self.host is None:
            raise TaskStoreError('COMPLETED_SOURCE_AND_BOUND_HOST_REQUIRED_FOR_REPLAY')
        if self.catalog.verify() != self.catalog.identity:
            raise TaskStoreError('TASK_SOURCE_CHANGED_BEFORE_REPLAY')
        self.journal.require_capacity(4)
        self._record('REPLAY_DISPATCHING', {'task_id': task_id, 'run_id': replay_id, 'source_run_id': task['run_id']})
        return self._invoke(task_id, replay_id)

    def recover(self):
        return self.view()

    def view(self):
        return {'component_status': 'LOCAL_TASK_CONTROL_RUNNING', 'complete_os_runtime_verified': False,
                'source': deepcopy(self.catalog.identity), 'tasks': deepcopy(list(self.tasks.values())),
                'operational_events': len(self.journal.events), 'record_scope': SCOPE,
                'authority_granted': False, 'execution_permitted': False}
