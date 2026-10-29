"""Pure candidate-host plans and contracts, never a Human approval producer."""
import hashlib
import json
import ntpath
import re

from .errors import PreparationError
from .kernel_probe import validate_policy
from .launch_contract import (BoundedCapture, canonical, digest, exact, fail,
                              quote_argument, sha, windows_path)


BUNDLE_FILES = frozenset(('host_acceptance.json', 'release.json', 'environment.json',
    'preflight.json', 'resource_contract.json', 'dependency_closure.json',
    'preflight_evidence_index.json'))
CANDIDATE_ENV_NAMES = frozenset(('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'H56W_SESSION',
    'H56W_RELEASE_SHA256', 'H56W_SOURCE_SHA256', 'H56W_ENVIRONMENT_SHA256',
    'H56W_PREFLIGHT_SHA256', 'H56W_HOST_ACCEPTANCE_SHA256'))
ACCEPTANCE_KEYS = frozenset(('schema', 'status', 'session_id',
    'runtime_source_manifest_sha256', 'runtime_contract_sha256', 'public_lock_sha256',
    'resource_contract_sha256', 'preflight_sha256', 'allowed_operations',
    'domain_scenarios', 'worker_attempt_budget', 'candidate_planning_only',
    'authority_granted', 'execution_permitted', 'formal_history_write', 'external_services'))
RESOURCE_KEYS = frozenset(('schema', 'session_id', 'product_root', 'host_user_sid',
    'system_root', 'profile', 'python', 'paths', 'observation_policy', 'limits',
    'acl_objects', 'registry_objects'))
RESULT_KEYS = frozenset(('schema', 'operation', 'run_id', 'task_id', 'source_run_id',
    'status', 'pid', 'started', 'exit_code', 'source_lineage', 'record', 'receipt_ref',
    'native_trace_ref', 'projection', 'comparison', 'transport_receipt', 'failure', 'boundary'))
OPS = frozenset(('candidate_compute', 'fresh_process_replay'))
LINEAGE_KEYS = frozenset(('runtime_source_manifest_sha256', 'runtime_contract_sha256',
    'public_lock_sha256', 'original_component_manifest_sha256'))
TOKEN = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_SEAL = object()


def token(value, optional=False):
    if optional and value is None:
        return value
    if type(value) is not str or not TOKEN.fullmatch(value):
        fail('HOST_BOUNDED_TOKEN_REQUIRED')
    return value


def boundary():
    return dict(candidate_planning_only=True, authority_granted=False,
                execution_permitted=False, formal_history_write=False, external_services=False)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            fail('HOST_DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(raw, maximum=1048576):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        fail('HOST_JSON_BYTES_BUDGET')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
            parse_float=lambda value: fail('HOST_NONINTEGER_NUMBER'),
            parse_constant=lambda value: fail('HOST_NONFINITE_NUMBER'))
    except PreparationError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        fail('HOST_INVALID_JSON')


def validate_bundle(bundle, session_id):
    exact(bundle, ('schema', 'session_id', 'files'), 'HOST_BUNDLE_FIELDS')
    if bundle['schema'] != 'h56.human-controller-bundle.v1' or bundle['session_id'] != session_id:
        fail('HOST_BUNDLE_SESSION')
    exact(bundle['files'], BUNDLE_FILES, 'HOST_BUNDLE_NO_SELF_HASH_OR_EXTRA_FILES')
    for identity in bundle['files'].values():
        exact(identity, ('size', 'sha256'), 'HOST_BUNDLE_MEMBER_FIELDS')
        if type(identity['size']) is not int or not 1 <= identity['size'] <= 1048576 or not sha(identity['sha256']):
            fail('HOST_BUNDLE_MEMBER_IDENTITY')


def validate_acceptance(value):
    exact(value, ACCEPTANCE_KEYS, 'HOST_ACCEPTANCE_FIELDS')
    if value['schema'] != 'h56.windows-host-acceptance.v1' or value['status'] != 'EXTERNALLY_ACCEPTED_CANDIDATE_HOST':
        fail('HOST_EXTERNAL_ACCEPTANCE_REQUIRED')
    token(value['session_id'])
    for key in ('runtime_source_manifest_sha256', 'runtime_contract_sha256',
                'public_lock_sha256', 'resource_contract_sha256', 'preflight_sha256'):
        if not sha(value[key]):
            fail('HOST_ACCEPTANCE_IDENTITY_UNBOUND')
    if value['candidate_planning_only'] is not True or any(value[x] is not False for x in
            ('authority_granted', 'execution_permitted', 'formal_history_write', 'external_services')):
        fail('HOST_ACCEPTANCE_AUTHORITY_DRIFT')
    operations = value['allowed_operations']
    if type(operations) is not list or not operations or any(type(x) is not str for x in operations) or len(set(operations)) != len(operations) or not set(operations) <= OPS:
        fail('HOST_ACCEPTANCE_OPERATIONS')
    if 'fresh_process_replay' in operations and 'candidate_compute' not in operations:
        fail('HOST_ACCEPTANCE_REPLAY_COMPUTE_CLOSURE')
    domains = value['domain_scenarios']
    if type(domains) is not dict or not domains or not set(domains) <= {'DEVSECOPS', 'FINANCE_REFUND'}:
        fail('HOST_ACCEPTANCE_DOMAIN_SCOPE')
    for scenarios in domains.values():
        if type(scenarios) is not list or not scenarios or len(scenarios) > 64:
            fail('HOST_ACCEPTANCE_SCENARIOS')
        for scenario in scenarios:
            token(scenario)
        if len(set(scenarios)) != len(scenarios):
            fail('HOST_ACCEPTANCE_SCENARIOS')
    if type(value['worker_attempt_budget']) is not int or not 1 <= value['worker_attempt_budget'] <= 100:
        fail('HOST_ACCEPTANCE_WORKER_BUDGET')


def validate_resource_contract(value):
    exact(value, RESOURCE_KEYS, 'HOST_RESOURCE_FIELDS')
    if value['schema'] != 'h56.windows-host-resources.v1':
        fail('HOST_RESOURCE_SCHEMA')
    token(value['session_id'])
    windows_path(value['product_root'])
    windows_path(value['system_root'])
    if type(value['host_user_sid']) is not str or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', value['host_user_sid']):
        fail('HOST_OWNER_SID_UNBOUND')
    profile, python = value['profile'], value['python']
    exact(profile, ('name', 'sid', 'storage_root', 'provisioning_receipt_sha256'), 'HOST_PROFILE_FIELDS')
    if type(profile['name']) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', profile['name']) or not sha(profile['provisioning_receipt_sha256']):
        fail('HOST_PROFILE_UNBOUND')
    windows_path(profile['storage_root'])
    exact(python, ('executable', 'sha256', 'version', 'arch', 'dependency_closure_sha256'), 'HOST_PYTHON_FIELDS')
    windows_path(python['executable'])
    if (not sha(python['sha256']) or not sha(python['dependency_closure_sha256']) or
            python['arch'] != 'WINDOWS_X64' or python['version'] not in ('3.9.13', '3.13.12')):
        fail('HOST_PYTHON_UNBOUND')
    paths = value['paths']
    exact(paths, ('control_root', 'scratch_root', 'receipt_input_root', 'host_evidence_root', 'active_lock_path'), 'HOST_PATH_FIELDS')
    for path in paths.values():
        windows_path(path)
    base = ntpath.join(value['product_root'], 'runtime_windows', '.local', value['session_id'])
    expected = dict(control_root=ntpath.join(base, 'control'), scratch_root=ntpath.join(base, 'scratch'),
        receipt_input_root=ntpath.join(base, 'replay_input'), host_evidence_root=ntpath.join(base, 'host_evidence'),
        active_lock_path=ntpath.join(base, 'active.lock'))
    if any(windows_path(paths[key]) != windows_path(expected[key]) for key in expected):
        fail('HOST_PRIVATE_PATH_GEOMETRY')
    validate_policy(value['observation_policy'])
    if value['observation_policy']['appcontainer_sid'] != profile['sid'] or value['observation_policy']['capabilities'] != []:
        fail('HOST_PROFILE_POLICY_MISMATCH')
    limits = value['limits']
    ranges = dict(startup_ms=(1, 30000), total_ms=(1, 120000), cleanup_ms=(1, 10000),
                  stdout_bytes=(1, 1048576), stderr_bytes=(1, 65536), control_bytes=(32772, 65536))
    exact(limits, ranges, 'HOST_LIMIT_FIELDS')
    for key, (low, high) in ranges.items():
        if type(limits[key]) is not int or not low <= limits[key] <= high:
            fail('HOST_LIMIT_INVALID')
    if limits['startup_ms'] > limits['total_ms']:
        fail('HOST_LIMIT_TIMES')
    acls = value['acl_objects']
    if type(acls) is not list or not 1 <= len(acls) <= 4096:
        fail('HOST_ACL_CLOSURE_UNBOUND')
    seen = set()
    for item in acls:
        exact(item, ('path', 'kind', 'sddl_sha256'), 'HOST_ACL_FIELDS')
        path = windows_path(item['path'])
        if path in seen or item['kind'] not in ('file', 'directory') or not sha(item['sddl_sha256']):
            fail('HOST_ACL_IDENTITY')
        seen.add(path)
    registries = value['registry_objects']
    if type(registries) is not list or not 1 <= len(registries) <= 64:
        fail('HOST_PROFILE_REGISTRY_UNBOUND')
    seen = set()
    for item in registries:
        exact(item, ('hive', 'subkey', 'sddl_sha256'), 'HOST_REGISTRY_FIELDS')
        key = item['subkey']
        if (item['hive'] != 'HKEY_CURRENT_USER' or type(key) is not str or not 1 <= len(key) <= 512
                or '\x00' in key or '/' in key or any(x in ('', '.', '..') for x in key.split('\\'))
                or profile['sid'] not in key.split('\\') or not sha(item['sddl_sha256']) or key.casefold() in seen):
            fail('HOST_PROFILE_REGISTRY_SCOPE')
        seen.add(key.casefold())


def validate_file_index(value, schema, maximum):
    exact(value, ('schema', 'files'), 'HOST_FILE_INDEX_FIELDS')
    if value['schema'] != schema or type(value['files']) is not list or not 1 <= len(value['files']) <= maximum:
        fail('HOST_FILE_INDEX_SCHEMA_OR_BUDGET')
    seen, total = set(), 0
    for item in value['files']:
        exact(item, ('path', 'size', 'sha256'), 'HOST_FILE_INDEX_MEMBER')
        path = windows_path(item['path'])
        if path in seen or type(item['size']) is not int or not 0 <= item['size'] <= 67108864 or not sha(item['sha256']):
            fail('HOST_FILE_INDEX_IDENTITY')
        seen.add(path)
        total += item['size']
    if total > 1073741824:
        fail('HOST_FILE_INDEX_TOTAL_BUDGET')


class CandidatePlan:
    __slots__ = ('_raw', 'sha256')
    def __init__(self, data):
        object.__setattr__(self, '_raw', canonical(data))
        object.__setattr__(self, 'sha256', hashlib.sha256(self._raw).hexdigest())

    def __setattr__(self, name, value):
        raise AttributeError('CandidatePlan immutable')

    def decoded(self):
        return json.loads(self._raw.decode('utf-8'))


def make_candidate_plan(configuration, operation, run_id, domain_id=None, scenario_id=None,
                        source_run_id=None, task_id=None):
    token(run_id)
    token(task_id, optional=True)
    acceptance = configuration['host_acceptance']
    validate_acceptance(acceptance)
    if operation not in acceptance['allowed_operations']:
        fail('HOST_OPERATION_NOT_GRANTED')
    if operation == 'candidate_compute':
        if (domain_id not in acceptance['domain_scenarios'] or
                scenario_id not in acceptance['domain_scenarios'][domain_id] or source_run_id is not None):
            fail('HOST_DOMAIN_SCENARIO_NOT_GRANTED')
    elif operation == 'fresh_process_replay':
        token(source_run_id)
        if domain_id is not None or scenario_id is not None or source_run_id == run_id:
            fail('HOST_REPLAY_DESCRIPTOR_INVALID')
    else:
        fail('HOST_OPERATION_NOT_GRANTED')
    resource = configuration['resources']
    validate_resource_contract(resource)
    data = dict(operation=operation, run_id=run_id, domain_id=domain_id, scenario_id=scenario_id,
        source_run_id=source_run_id, task_id=task_id, session_id=resource['session_id'],
        runtime={'python_executable': resource['python']['executable']},
        profile=resource['profile'], observation_policy=resource['observation_policy'], limits=resource['limits'],
        paths=dict(resource['paths'], product_root=resource['product_root']),
        environment=configuration['child_environment'], source_lineage=configuration['source_lineage'])
    exact(data['environment'], CANDIDATE_ENV_NAMES, 'HOST_CANDIDATE_ENV_EXACT')
    if any(type(x) is not str or not x or '\x00' in x for x in data['environment'].values()):
        fail('HOST_CANDIDATE_ENV_VALUE')
    return CandidatePlan(data)


def candidate_argv(plan):
    value = plan.decoded()
    cli = ntpath.join(value['paths']['product_root'], 'runtime_windows', 'candidate_cli.py')
    fixed = [value['runtime']['python_executable'], '-I', '-B', '-S', '-X', 'utf8', cli]
    if value['operation'] == 'candidate_compute':
        return fixed + ['--domain', value['domain_id'], '--scenario', value['scenario_id'], '--run-id', value['run_id']]
    return fixed + ['--recompute-file', value['source_run_id']]


def candidate_command_line(plan):
    return ' '.join(quote_argument(x) for x in candidate_argv(plan))


def candidate_environment_block(plan):
    env = plan.decoded()['environment']
    exact(env, CANDIDATE_ENV_NAMES, 'HOST_CANDIDATE_ENV_EXACT')
    return '\x00'.join(key + '=' + env[key] for key in sorted(env)) + '\x00\x00'


class _HostPermit:
    __slots__ = ('scope', 'identity', '_seal')
    def __init__(self, scope, identity, seal):
        if seal is not _SEAL:
            fail('HOST_OPAQUE_PERMIT_REQUIRED')
        self.scope, self.identity, self._seal = scope, identity, seal


def _issue_permit(scope, identity):
    return _HostPermit(scope, identity, _SEAL)


def require_host_permit(permit, scope, identity=None):
    if (type(permit) is not _HostPermit or permit._seal is not _SEAL or permit.scope != scope
            or (identity is not None and permit.identity != identity)):
        fail('HOST_OPAQUE_PERMIT_REQUIRED')


def require_candidate_permit(plan, permit):
    if type(plan) is not CandidatePlan:
        fail('HOST_CANDIDATE_PLAN_REQUIRED')
    require_host_permit(permit, 'CANDIDATE_WORKER', plan.sha256)


def new_result(plan):
    value = plan.decoded()
    return dict(schema='h56.windows-candidate-host-result.v1', operation=value['operation'],
        run_id=value['run_id'], task_id=value['task_id'], source_run_id=value['source_run_id'],
        status='HOST_BLOCKED', pid=None, started=False, exit_code=None,
        source_lineage=value['source_lineage'], record=None, receipt_ref=None, native_trace_ref=None,
        projection=None, comparison=None, transport_receipt=None, failure=None, boundary=boundary())


class HostEvidencePersistenceError(PreparationError):
    """Explicit bounded raw handoff when the private failure archive fails.

    The embedding must report this stop and preserve the snapshot; it cannot
    silently reduce it to a journal digest or claim evidence was archived.
    This type is pure and does not load the real host/native implementation.
    """
    def __init__(self, raw_result, archive_error):
        exact(raw_result, RESULT_KEYS, 'HOST_UNARCHIVED_RESULT_FIELDS')
        if raw_result['status'] != 'HOST_FAILED' or any(raw_result[x] is not None for x in
                ('record', 'receipt_ref', 'native_trace_ref', 'projection', 'comparison')):
            fail('HOST_UNARCHIVED_FAILURE_ONLY')
        self._raw = canonical(raw_result)
        if len(self._raw) > 2097152:
            fail('HOST_UNARCHIVED_CAPTURE_BUDGET')
        super().__init__('HOST_RAW_EVIDENCE_ARCHIVE_FAILED', str(archive_error)[:4096])

    @property
    def raw_result(self):
        return json.loads(self._raw.decode('utf-8'))


def validate_record(record, lineage, vendor=None, require_complete=False):
    exact(record, ('schema_id', 'result', 'result_hash', 'lineage', 'unverified_runtime_claim',
        'receipt_hash', 'candidate_planning_only', 'authority_granted', 'execution_permitted'), 'HOST_RECEIPT_FIELDS')
    if (record['schema_id'] != 'H56OS:CANDIDATE_RECEIPT:WINDOWS_V1' or record['candidate_planning_only'] is not True
            or record['authority_granted'] is not False or record['execution_permitted'] is not False
            or record['receipt_hash'] != digest({k: v for k, v in record.items() if k != 'receipt_hash'})
            or record['result_hash'] != digest(record['result'])):
        fail('HOST_RECEIPT_INTEGRITY_OR_BOUNDARY')
    exact(lineage, LINEAGE_KEYS, 'HOST_STATIC_LINEAGE_FIELDS')
    if (type(record['lineage']) is not dict or
            set(record['lineage']) not in (set(LINEAGE_KEYS), set(LINEAGE_KEYS) | {'unit_proof_hash'}) or
            any(record['lineage'].get(k) != v for k, v in lineage.items()) or
            any(not sha(value) for value in record['lineage'].values())):
        fail('HOST_RECEIPT_SOURCE_LINEAGE')
    claim = record['unverified_runtime_claim']
    exact(claim, ('release_sha256', 'environment_sha256', 'preflight_sha256', 'grade'), 'HOST_UNVERIFIED_CLAIM_FIELDS')
    if (claim['grade'] != 'UNVERIFIED_RECORDED_DIGESTS_NOT_REPLAYED_OR_AUTHORITY' or
            any(not sha(claim[k]) for k in ('release_sha256', 'environment_sha256', 'preflight_sha256'))):
        fail('HOST_UNVERIFIED_CLAIM_INVALID')
    result = record['result']
    if type(result) is not dict or result.get('status') not in ('REJECTED', 'COMPUTED_CANDIDATE_ONLY'):
        fail('HOST_PIPELINE_RESULT_INVALID')
    if result['status'] == 'REJECTED':
        if require_complete:
            fail('HOST_REPLAY_REQUIRES_COMPLETED_RECORD')
        exact(result, ('status', 'stage', 'error_type', 'error', 'domain_id', 'scenario_id',
            'native_calls', 'candidate_planning_only', 'authority_granted', 'execution_permitted',
            'business_action_calls'), 'HOST_REJECTED_PIPELINE_FIELDS')
        if (result['candidate_planning_only'] is not True or result['authority_granted'] is not False or
                result['execution_permitted'] is not False or type(result['business_action_calls']) is not int or
                result['business_action_calls'] != 0 or result['domain_id'] not in ('DEVSECOPS', 'FINANCE_REFUND')):
            fail('HOST_REJECTED_PIPELINE_BOUNDARY')
        token(result['scenario_id'])
        for key in ('stage', 'error_type', 'error'):
            if type(result[key]) is not str or len(result[key]) > 65536:
                fail('HOST_REJECTED_PIPELINE_ERROR')
        _validate_trace(result['native_calls'], vendor, complete=False)
        return
    semantic = result.get('semantic')
    if type(semantic) is not dict or result.get('semantic_hash') != digest(semantic):
        fail('HOST_RECEIPT_SEMANTIC_HASH')
    if (semantic.get('boundary') != dict(candidate_planning_only=True, authority_granted=False,
            execution_permitted=False, business_action_calls=0, formal_history_writes=0) or
            type(semantic['boundary']['business_action_calls']) is not int or
            type(semantic['boundary']['formal_history_writes']) is not int or
            semantic['boundary']['candidate_planning_only'] is not True or
            semantic['boundary']['authority_granted'] is not False or
            semantic['boundary']['execution_permitted'] is not False):
        fail('HOST_RECEIPT_SEMANTIC_BOUNDARY')
    if semantic.get('domain_id') not in ('DEVSECOPS', 'FINANCE_REFUND'):
        fail('HOST_RECEIPT_DOMAIN')
    token(semantic.get('scenario_id'))
    _validate_trace(semantic.get('native_calls'), vendor, complete=True)


def _validate_trace(events, vendor=None, complete=True):
    if type(events) is not list or len(events) > 512 or (complete and not events):
        fail('HOST_NATIVE_TRACE_MISSING')
    calls = set()
    for event in events:
        if type(event) is not dict or event.get('event') not in ('CALL', 'RETURN', 'RAISE'):
            fail('HOST_NATIVE_TRACE_SHAPE')
        if event['event'] == 'CALL':
            origin = event.get('origin')
            if (type(origin) is not str or not origin.startswith('vendor/') or
                    '\\' in origin or ':' in origin or '..' in origin.split('/') or
                    (vendor is not None and origin not in {'vendor/' + x for x in vendor})):
                fail('HOST_NATIVE_TRACE_ORIGIN')
            calls.add(event.get('label'))
    required = {'Ontology.load_default_profile', 'K0.Fact.create', 'K0.CanonicalFactLedger',
        'K0.append', 'K1.StateCompiler', 'K1.compile', 'C1.Catalog.from_mapping',
        'C1.Catalog.require_definition', 'C2.Evaluator', 'C2.project', 'C2.Projection.verify'}
    if complete and not required <= calls:
        fail('HOST_NATIVE_TRACE_INCOMPLETE')
    pending = None
    for event in events:
        if event['event'] == 'CALL' and pending is None:
            pending = event.get('label')
        elif event['event'] in ('RETURN', 'RAISE') and pending == event.get('label'):
            if complete and event['event'] == 'RAISE':
                fail('HOST_NATIVE_TRACE_RAISE_ON_COMPLETION')
            pending = None
        else:
            fail('HOST_NATIVE_TRACE_PAIRING')
    if complete and pending is not None:
        fail('HOST_NATIVE_TRACE_PAIRING')


TRANSPORT_KEYS = frozenset(('schema', 'argv', 'pid', 'exit_code', 'raw_stdout_base64',
    'raw_stderr_base64', 'stdout_sha256', 'stderr_sha256', 'observed_output_bytes',
    'capture_prefix_truncated', 'cleanup', 'events', 'stop_reason',
    'runtime_source_manifest_sha256', 'resource_contract_sha256', 'started_event'))


def _raw_base64(value, maximum):
    import base64
    import binascii
    if type(value) is not str or len(value) > ((maximum + 2) // 3) * 4:
        fail('HOST_RAW_BASE64_BUDGET')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        fail('HOST_RAW_BASE64_INVALID')
    if len(raw) > maximum or base64.b64encode(raw).decode('ascii') != value:
        fail('HOST_RAW_BASE64_INVALID')
    return raw


def validate_ref(reference, maximum):
    exact(reference, ('path', 'size', 'sha256', 'raw_base64'), 'HOST_EVIDENCE_REF_FIELDS')
    path = reference['path']
    if (type(path) is not str or not path or path.startswith('/') or '\\' in path or ':' in path
            or any(x in ('', '.', '..') for x in path.split('/'))):
        fail('HOST_EVIDENCE_REF_PATH')
    raw = _raw_base64(reference['raw_base64'], maximum)
    if (type(reference['size']) is not int or len(raw) != reference['size'] or
            hashlib.sha256(raw).hexdigest() != reference['sha256']):
        fail('HOST_EVIDENCE_REF_BYTES')
    return raw


def validate_host_result(result, operation, run_id, task_id, source_run_id,
                         expected_source_lineage, started_observation=None):
    """Pure status-specific consistency only, never empirical authentication.

    Self-consistent synthetic dictionaries can pass this check. Only the real
    approved host/worker and checked file consumption provide runtime evidence.
    Task code must also bind the actual callback it observed, not invent one.
    """
    exact(result, RESULT_KEYS, 'HOST_RESULT_FIELDS')
    exact(result['boundary'], boundary(), 'HOST_RESULT_BOUNDARY_FIELDS')
    if result['boundary']['candidate_planning_only'] is not True or any(result['boundary'][key] is not False for key in
            ('authority_granted', 'execution_permitted', 'formal_history_write', 'external_services')):
        fail('HOST_RESULT_BOUNDARY_TYPES')
    if result['exit_code'] is not None and (type(result['exit_code']) is not int or not 0 <= result['exit_code'] <= 0xFFFFFFFF):
        fail('HOST_RESULT_EXIT_CODE_TYPE')
    if (result['schema'] != 'h56.windows-candidate-host-result.v1' or
            result['operation'] != operation or result['run_id'] != run_id or
            result['task_id'] != task_id or result['source_run_id'] != source_run_id or
            result['boundary'] != boundary()):
        fail('HOST_RESULT_REQUEST_OR_BOUNDARY')
    statuses = {'HOST_BLOCKED', 'HOST_FAILED', 'PIPELINE_REJECTED',
                'COMPUTED_CANDIDATE_ONLY', 'ACTUAL_RECOMPUTATION_MATCH'}
    if result['status'] not in statuses or type(result['started']) is not bool:
        fail('HOST_RESULT_STATUS')
    exact(result['source_lineage'], LINEAGE_KEYS, 'HOST_RESULT_LINEAGE_FIELDS')
    exact(expected_source_lineage, LINEAGE_KEYS, 'HOST_EXPECTED_LINEAGE_FIELDS')
    if any(not sha(value) for value in result['source_lineage'].values()):
        fail('HOST_RESULT_LINEAGE')
    if any(result['source_lineage'].get(k) != v for k, v in expected_source_lineage.items()):
        fail('HOST_RESULT_LINEAGE')
    success = result['status'] in {'COMPUTED_CANDIDATE_ONLY', 'ACTUAL_RECOMPUTATION_MATCH'}
    if result['status'] in {'HOST_BLOCKED', 'HOST_FAILED'}:
        if type(result['failure']) is not dict or not result['failure'].get('code'):
            fail('HOST_FAILURE_REASON_REQUIRED')
        if any(result[x] is not None for x in ('record', 'receipt_ref', 'native_trace_ref', 'projection', 'comparison')):
            fail('HOST_FAILURE_CANNOT_CLAIM_BUSINESS_RESULT')
        if 'evidence' in result['failure']:
            evidence = result['failure']['evidence']
            exact(evidence, ('path', 'size', 'sha256'), 'HOST_FAILURE_EVIDENCE_REF')
            if (not sha(evidence['sha256']) or type(evidence['size']) is not int or not 1 <= evidence['size'] <= 16777216 or
                    type(evidence['path']) is not str or not re.fullmatch(
                        r'runtime_windows/\.local/[A-Za-z0-9_-]{1,64}/host_evidence/' + re.escape(run_id) + r'/host_failure\.json', evidence['path'])):
                fail('HOST_FAILURE_EVIDENCE_REF')
    if result['status'] == 'HOST_BLOCKED' and (result['started'] or result['pid'] is not None or result['exit_code'] is not None):
        fail('HOST_BLOCKED_CANNOT_CLAIM_STARTED')
    transport = result['transport_receipt']
    if success or result['started'] or result['pid'] is not None or result['status'] == 'PIPELINE_REJECTED':
        exact(transport, TRANSPORT_KEYS, 'HOST_TRANSPORT_FIELDS')
        if transport['schema'] != 'h56.windows-candidate-transport.v1':
            fail('HOST_TRANSPORT_SCHEMA')
        if (type(transport['argv']) is not list or len(transport['argv']) not in (9, 13) or
                transport['argv'][1:6] != ['-I', '-B', '-S', '-X', 'utf8'] or
                not sha(transport['resource_contract_sha256'])):
            fail('HOST_TRANSPORT_FIXED_COMMAND')
        argv = transport['argv']
        windows_path(argv[0])
        windows_path(argv[6])
        if (not argv[6].casefold().endswith('\\runtime_windows\\candidate_cli.py') or
                (operation == 'candidate_compute' and (len(argv) != 13 or argv[7] != '--domain' or
                    argv[9] != '--scenario' or argv[11:] != ['--run-id', run_id])) or
                (operation == 'fresh_process_replay' and argv[7:] != ['--recompute-file', source_run_id])):
            fail('HOST_TRANSPORT_FIXED_COMMAND')
        if (transport['pid'] != result['pid'] or type(result['pid']) is not int or
                not 1 <= result['pid'] <= 0xFFFFFFFF or transport['exit_code'] != result['exit_code']):
            fail('HOST_TRANSPORT_PROCESS_BINDING')
        stdout = _raw_base64(transport['raw_stdout_base64'], 1048576)
        stderr = _raw_base64(transport['raw_stderr_base64'], 65536)
        if (transport['stdout_sha256'] != hashlib.sha256(stdout).hexdigest() or
                transport['stderr_sha256'] != hashlib.sha256(stderr).hexdigest()):
            fail('HOST_TRANSPORT_RAW_HASH')
        exact(transport['observed_output_bytes'], ('stdout', 'stderr'), 'HOST_TRANSPORT_COUNTS')
        exact(transport['capture_prefix_truncated'], ('stdout', 'stderr'), 'HOST_TRANSPORT_TRUNCATION')
        for name, raw in (('stdout', stdout), ('stderr', stderr)):
            count, truncated = transport['observed_output_bytes'][name], transport['capture_prefix_truncated'][name]
            if type(count) is not int or count < len(raw) or type(truncated) is not bool or (not truncated and count != len(raw)):
                fail('HOST_TRANSPORT_CAPTURE_ACCOUNTING')
        if result['started']:
            keys = ('schema', 'pid', 'run_id', 'operation', 'task_id',
                    'runtime_source_manifest_sha256', 'resource_contract_sha256')
            exact(started_observation, keys, 'HOST_ACTUAL_CALLBACK_REQUIRED')
            expected = dict(schema='h56.windows-candidate-started.v1', pid=result['pid'],
                run_id=run_id, operation=operation, task_id=task_id,
                runtime_source_manifest_sha256=transport['runtime_source_manifest_sha256'],
                resource_contract_sha256=transport['resource_contract_sha256'])
            if started_observation != expected or transport['started_event'] != expected:
                fail('HOST_CALLBACK_PROCESS_SOURCE_BINDING')
        elif transport['started_event'] is not None or 'OWNED_CHILD_RESUMED' in transport['events']:
            fail('HOST_UNRESUMED_RESULT_CANNOT_CLAIM_CALLBACK')
        if transport['runtime_source_manifest_sha256'] != result['source_lineage'].get('runtime_source_manifest_sha256'):
            fail('HOST_TRANSPORT_SOURCE_BINDING')
        if success or result['status'] == 'PIPELINE_REJECTED':
            if (not result['started'] or transport['stop_reason'] is not None or
                    transport['cleanup'] != {'status': 'CLOSED', 'errors': []} or
                    any(transport['capture_prefix_truncated'].values()) or
                    'OWNED_CHILD_RESUMED' not in transport['events'] or
                    'OWNED_CHILD_EXITED_OUTPUT_DRAINED' not in transport['events']):
                fail('HOST_COMPLETION_TRANSPORT_NOT_VERIFIED')
    if success or result['status'] == 'PIPELINE_REJECTED':
        if success and (result['exit_code'] != 0 or result['failure'] is not None):
            fail('HOST_SUCCESS_WITH_FAILURE')
        record = result['record']
        validate_record(record, result['source_lineage'], require_complete=success)
        receipt_raw = validate_ref(result['receipt_ref'], 12582912)
        if decode(receipt_raw, 12582912) != record:
            fail('HOST_RECEIPT_REF_CONTENT')
        if result['status'] == 'PIPELINE_REJECTED':
            output = decode(stdout)
            exact(output, ('status', 'receipt'), 'HOST_REJECTED_STDOUT_FIELDS')
            if (record['result']['status'] != 'REJECTED' or result['projection'] is not None or result['comparison'] is not None
                    or operation != 'candidate_compute' or result['exit_code'] != 2 or result['failure'] is not None
                    or output['status'] != 'REJECTED'):
                fail('HOST_REJECTION_RESULT_MISMATCH')
            _bind_compute_path(output, result['receipt_ref'], argv, run_id)
            if [record['result']['domain_id'], record['result']['scenario_id']] != [argv[8], argv[10]]:
                fail('HOST_REJECTION_INPUT_MISMATCH')
            if decode(validate_ref(result['native_trace_ref'], 12582912), 12582912) != record['result']['native_calls']:
                fail('HOST_REJECTED_TRACE_REF')
            return
        if operation == 'candidate_compute':
            if result['status'] != 'COMPUTED_CANDIDATE_ONLY' or result['comparison'] is not None:
                fail('HOST_COMPUTE_STATUS')
            actual = record['result']
            output = decode(stdout)
            exact(output, ('status', 'receipt'), 'HOST_COMPUTE_STDOUT_FIELDS')
            if output['status'] != 'COMPUTED_CANDIDATE_ONLY':
                fail('HOST_COMPUTE_STDOUT_STATUS')
            _bind_compute_path(output, result['receipt_ref'], argv, run_id)
            if [actual['semantic']['domain_id'], actual['semantic']['scenario_id']] != [argv[8], argv[10]]:
                fail('HOST_COMPUTE_INPUT_MISMATCH')
        elif operation == 'fresh_process_replay':
            if not re.fullmatch(r'runtime_windows/\.local/[A-Za-z0-9_-]{1,64}/replay_input/' + re.escape(source_run_id) + r'/receipt\.json', result['receipt_ref']['path']):
                fail('HOST_REPLAY_SOURCE_REF_PATH')
            comparison = result['comparison']
            exact(comparison, ('status', 'semantic_hash', 'authority_granted', 'execution_permitted',
                  'source_receipt_hash', 'recomputed_result'), 'HOST_RECOMPUTE_FIELDS')
            if (result['status'] != 'ACTUAL_RECOMPUTATION_MATCH' or comparison['status'] != result['status'] or
                    comparison['authority_granted'] is not False or comparison['execution_permitted'] is not False or
                    comparison['source_receipt_hash'] != digest(record) or
                    comparison['semantic_hash'] != record['result']['semantic_hash'] or
                    comparison['recomputed_result'] != record['result'] or decode(stdout) != comparison):
                fail('HOST_RECOMPUTATION_FULL_RESULT_MISMATCH')
            actual = comparison['recomputed_result']
        else:
            fail('HOST_COMPLETION_OPERATION')
        trace = actual['semantic']['native_calls']
        if decode(validate_ref(result['native_trace_ref'], 12582912), 12582912) != trace:
            fail('HOST_FRESH_NATIVE_TRACE_REF_MISMATCH')
        if result['projection'] != actual['semantic']['projection']:
            fail('HOST_PROJECTION_REF_MISMATCH')
        projection = result['projection']
        if (type(projection) is not dict or projection.get('candidate_planning_only') is not True or
                projection.get('authority_granted') is not False or projection.get('execution_permitted') is not False):
            fail('HOST_PROJECTION_AUTHORITY_BOUNDARY')


def _bind_compute_path(output, reference, argv, run_id):
    root = ntpath.dirname(ntpath.dirname(argv[6]))
    relative = reference['path']
    match = re.fullmatch(r'runtime_windows/\.local/([A-Za-z0-9_-]{1,64})/scratch/runs/' + re.escape(run_id) + r'/receipt\.json', relative)
    if not match or windows_path(output['receipt']) != windows_path(ntpath.join(root, *relative.split('/'))):
        fail('HOST_COMPUTE_RECEIPT_PATH_BINDING')
