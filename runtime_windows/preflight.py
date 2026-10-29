"""Fixed observation/seven-check orchestration; raw evidence never grants power.

Only ``run_preflight`` is a production entry. It verifies the separately pinned
preparation authority before any archive write. Tests may call the private pure
sequence with explicitly synthetic producers; those are not native evidence.
No import creates a Profile, launches a process, opens a socket or loads cores.
"""
import base64
import hashlib
import os
from pathlib import Path
import stat
import time

from .bootstrap_contract import FrozenPlan
from .errors import PreparationError
from .launch_contract import canonical, exact, sha, validate_launch_request, windows_path


SCHEMA = 'h56.windows-neutral-preflight-plan.v1'
CHECKS = ('file_access_negative', 'credential_access_negative',
          'network_access_negative', 'child_escape_negative',
          'resource_limit_negative', 'read_only_source', 'profile_storage_scope')
FIELDS = frozenset(('schema', 'session_id', 'product_root', 'observer_request',
                    'probe_requests', 'prelaunch_readback_sha256', 'evidence_root', 'limits'))
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_ELAPSED = 1100000


def _fail(reason):
    raise PreparationError(reason)


def validate_preflight_plan(value):
    """Check fixed identities/one policy. Validation is not authorization."""
    from .probe_backend import validate_probe_plan
    exact(value, FIELDS, 'PREFLIGHT_EXACT_FIELDS')
    if value['schema'] != SCHEMA:
        _fail('PREFLIGHT_SCHEMA')
    session = value['session_id']
    if (type(session) is not str or not 1 <= len(session) <= 64 or
            any(x not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for x in session)):
        _fail('PREFLIGHT_SESSION')
    observer = validate_launch_request(value['observer_request']).decoded()
    if (windows_path(value['product_root']) != windows_path(observer['paths']['product_root']) or
            windows_path(value['evidence_root']) != windows_path(observer['paths']['evidence_root'])):
        _fail('PREFLIGHT_ROOT_BINDING')
    if (not sha(value['prelaunch_readback_sha256']) or
            value['prelaunch_readback_sha256'] != observer['release_binding']['preflight_receipt_sha256']):
        _fail('PREFLIGHT_READBACK_BINDING')
    exact(value['probe_requests'], CHECKS, 'PREFLIGHT_SEVEN_CHECKS_REQUIRED')
    run_ids = {observer['run_id']}
    duration = observer['limits']['total_ms'] + observer['limits']['cleanup_ms']
    for check in CHECKS:
        probe = validate_probe_plan(value['probe_requests'][check]).decoded()
        if probe['check'] != check or probe['run_id'] in run_ids:
            _fail('PREFLIGHT_CHECK_OR_RUN_ID_BINDING')
        run_ids.add(probe['run_id'])
        for field in ('source_identity', 'runtime', 'profile', 'paths', 'observation_policy', 'release_binding'):
            if probe[field] != observer[field]:
                _fail('PREFLIGHT_SHARED_POLICY_OR_SOURCE_DRIFT')
        if probe['session_id'] != session:
            _fail('PREFLIGHT_PROBE_SESSION_DRIFT')
        duration += probe['limits']['total_ms'] + probe['limits']['cleanup_ms']
    exact(value['limits'], ('elapsed_ms', 'archive_bytes'), 'PREFLIGHT_LIMIT_FIELDS')
    budget = value['limits']
    if (type(budget['elapsed_ms']) is not int or not duration <= budget['elapsed_ms'] <= MAX_ELAPSED or
            type(budget['archive_bytes']) is not int or not 1024 <= budget['archive_bytes'] <= MAX_ARCHIVE):
        _fail('PREFLIGHT_TOTAL_BUDGET')
    return FrozenPlan(value)


def _transport_ok(receipt, request):
    if type(receipt) is not dict:
        _fail('PREFLIGHT_PARENT_RECEIPT_REQUIRED')
    pid = receipt.get('pid')
    if type(pid) is not int or not 1 <= pid <= 0xffffffff:
        _fail('PREFLIGHT_ACTUAL_PARENT_PID_REQUIRED')
    if receipt.get('request_sha256') != hashlib.sha256(canonical(request)).hexdigest():
        _fail('PREFLIGHT_PARENT_REQUEST_DRIFT')
    if (type(receipt.get('exit_code')) is not int or receipt['exit_code'] != 0 or
            receipt.get('stop_reason') is not None or receipt.get('cleanup_exception') is not None or
            type(receipt.get('cleanup')) is not dict or receipt['cleanup'].get('status') != 'CLOSED' or
            receipt['cleanup'].get('errors') != []):
        _fail('PREFLIGHT_PARENT_FAILURE_OR_CLEANUP_UNKNOWN')
    limits = request['limits']
    exact(receipt.get('capture_prefix_truncated'), ('stdout', 'stderr'), 'PREFLIGHT_CAPTURE_FLAGS')
    exact(receipt.get('observed_output_bytes'), ('stdout', 'stderr'), 'PREFLIGHT_CAPTURE_COUNTS')
    for role in ('stdout', 'stderr'):
        raw = receipt.get('raw_' + role)
        if type(raw) is not bytes or len(raw) > limits[role + '_bytes']:
            _fail('PREFLIGHT_RAW_OUTPUT_BUDGET')
        if receipt.get('capture_prefix_truncated', {}).get(role) is not False:
            _fail('PREFLIGHT_CAPTURE_TRUNCATED_OR_UNKNOWN')
        if (type(receipt['observed_output_bytes'][role]) is not int or
                receipt['observed_output_bytes'][role] != len(raw)):
            _fail('PREFLIGHT_CAPTURE_ACCOUNTING_MISMATCH')
    events = receipt.get('events')
    if (type(events) is not list or not 1 <= len(events) <= 128 or
            any(type(item) is not str or len(item) > 256 for item in events)):
        _fail('PREFLIGHT_PARENT_EVENTS_REQUIRED')
    required = ('OWNED_JOB_LIMITS_READ_BACK', 'THREE_PRIVATE_NAMED_PIPE_PAIRS_CREATED',
                'CREATED_SUSPENDED_IN_OWNED_JOB_TOKEN_CHECKED', 'OWNED_CHILD_RESUMED',
                'OWNED_CHILD_EXITED_OUTPUT_DRAINED')
    if any(events.count(item) != 1 for item in required):
        _fail('PREFLIGHT_PARENT_EVENT_CHAIN_INCOMPLETE')
    if [events.index(item) for item in required] != sorted(events.index(item) for item in required):
        _fail('PREFLIGHT_PARENT_EVENT_ORDER')
    return pid


def evaluate_observer_receipt(request, receipt):
    """Pure consistency comparison, not authentication of a supplied receipt."""
    from .launcher import check_child_result
    plan = validate_launch_request(request)
    pid = _transport_ok(receipt, request)
    result = check_child_result(plan, receipt['raw_stdout'], pid)
    if (receipt.get('schema') != 'h56.windows-observer-parent-receipt.v1' or
            receipt.get('status') != 'OBSERVED_MATCH_NEGATIVE_TESTS_PENDING' or
            result['status'] != 'OBSERVED_MATCH_NEGATIVE_TESTS_PENDING'):
        _fail('PREFLIGHT_OBSERVATION_NOT_MATCHED')
    return result


def evaluate_probe_receipt(request, receipt):
    """Require real-parent fields, then consume the fixed child result schema."""
    from .probe_backend import validate_probe_plan, evaluate_parent_probe
    plan = validate_probe_plan(request)
    pid = _transport_ok(receipt, request)
    if (receipt.get('schema') != 'h56.windows-neutral-parent-receipt.v1' or
            receipt.get('status') != 'RAW_RESULT_COLLECTED' or
            receipt.get('check') != request['check'] or
            receipt.get('run_id') != request['run_id'] or
            receipt.get('source_identity') != request['source_identity']):
        _fail('PREFLIGHT_PROBE_PARENT_BINDING')
    if request['check'] == 'network_access_negative':
        positive = receipt.get('positive_control')
        exact(positive, ('schema', 'sentinel_id', 'address', 'port', 'challenge_sha256', 'status'),
              'PREFLIGHT_NETWORK_POSITIVE_FIELDS')
        target = request['target']
        challenge = hashlib.sha256(('H56_LOOPBACK:' + target['sentinel_id']).encode('utf-8')).digest()
        if (positive['schema'] != 'h56.windows-loopback-positive.v1' or
                positive['status'] != 'HOST_ROUNDTRIP_OBSERVED' or
                any(positive[key] != target[key] for key in ('sentinel_id', 'address', 'port')) or
                positive['challenge_sha256'] != hashlib.sha256(challenge).hexdigest() or
                hashlib.sha256(canonical(positive)).hexdigest() != target['positive_receipt_sha256']):
            _fail('PREFLIGHT_NETWORK_POSITIVE_BINDING')
    if request['check'] == 'profile_storage_scope':
        actual = receipt.get('independent_readback')
        exact(actual, ('path', 'size', 'sha256', 'status'), 'PREFLIGHT_PROFILE_PARENT_FIELDS')
        target = request['target']
        if (actual['path'] != target['path'] or type(actual['size']) is not int or
                actual['size'] != len(bytes.fromhex(target['nonce_hex'])) or
                actual['sha256'] != target['nonce_sha256'] or actual['status'] != 'HOST_FILE_READ_BACK'):
            _fail('PREFLIGHT_PROFILE_PARENT_READBACK_BINDING')
    result = evaluate_parent_probe(plan, receipt)
    if (result.get('isolation_accepted') is not False or result.get('runtime_authorized') is not False or
            result.get('candidate_computation') != 'NOT_RUN'):
        _fail('PREFLIGHT_PROBE_AUTHORITY_DRIFT')
    return result


def _json_value(value, depth=0, counter=None):
    if counter is None:
        counter = [0]
    counter[0] += 1
    if depth > 32 or counter[0] > 100000:
        _fail('PREFLIGHT_EVIDENCE_STRUCTURE_BUDGET')
    if type(value) is bytes:
        if len(value) > 1048576:
            _fail('PREFLIGHT_EVIDENCE_RAW_BUDGET')
        return {'encoding': 'base64', 'length': len(value),
                'sha256': hashlib.sha256(value).hexdigest(),
                'value': base64.b64encode(value).decode('ascii')}
    if value is None or type(value) in (bool, int, str):
        if type(value) is str and len(value) > 1048576:
            _fail('PREFLIGHT_EVIDENCE_STRING_BUDGET')
        return value
    if type(value) is list:
        return [_json_value(item, depth + 1, counter) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: _json_value(item, depth + 1, counter) for key, item in value.items()}
    _fail('PREFLIGHT_EVIDENCE_NON_JSON_VALUE')


def public_report(report):
    """Lossless bounded JSON representation. This does not mean public release."""
    value = _json_value(report)
    if len(canonical(value)) > MAX_ARCHIVE:
        _fail('PREFLIGHT_REPORT_BUDGET')
    return value


def _new_archive(root, ordinal, value, remaining):
    """Write once to a fixed filename; member/canary names never form paths."""
    from .source_identity import _check_chain, _check_stat
    if type(ordinal) is not int or not 0 <= ordinal <= 9:
        _fail('PREFLIGHT_ARCHIVE_ORDINAL')
    _check_chain(root)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode):
        _fail('PREFLIGHT_ARCHIVE_ROOT_REQUIRED')
    raw = canonical(_json_value(value)) + b'\n'
    if len(raw) > remaining:
        _fail('PREFLIGHT_ARCHIVE_TOTAL_BUDGET')
    target = root / ('preflight_claim.json' if ordinal == 9 else 'preflight_%02d.json' % ordinal)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOINHERIT', 0)
    handle = os.open(str(target), flags, 0o600)
    try:
        with os.fdopen(handle, 'wb') as stream:
            handle = None
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                _fail('PREFLIGHT_ARCHIVE_FILE_IDENTITY')
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            after = os.fstat(stream.fileno())
            if (after.st_ino, after.st_dev, after.st_nlink, after.st_size) != (before.st_ino, before.st_dev, 1, len(raw)):
                _fail('PREFLIGHT_ARCHIVE_FILE_CHANGED')
        _check_chain(target, include_leaf=False)
        final = target.lstat()
        _check_stat(final, False, str(target))
        if (final.st_ino, final.st_dev, final.st_size) != (after.st_ino, after.st_dev, len(raw)):
            _fail('PREFLIGHT_ARCHIVE_PATH_CHANGED')
    finally:
        if handle is not None:
            os.close(handle)
    return {'filename': target.name, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def _claim_run(root, plan):
    """Permanent exclusive run claim: duplicate calls stop before any launch."""
    from .source_identity import _check_chain
    _check_chain(root)
    for ordinal in range(9):
        target = root / ('preflight_%02d.json' % ordinal)
        try:
            target.lstat()
        except FileNotFoundError:
            continue
        _fail('PREFLIGHT_EVIDENCE_SLOT_ALREADY_EXISTS')
    try:
        return _new_archive(root, 9, dict(schema='h56.windows-preflight-exclusive-claim.v1',
            plan_sha256=plan.sha256, status='CLAIMED_NOT_VERIFIED',
            recovery='MANUAL_REVIEW_REQUIRED_NO_AUTOMATIC_RETRY'), plan.decoded()['limits']['archive_bytes'])
    except FileExistsError:
        _fail('PREFLIGHT_DUPLICATE_RUN_CLAIM_REFUSED')


def _sequence(plan, observer, probe, archive, clock, evidence_grade, initial_bytes=0):
    """Internal serial consumer; injectable producers are only test fixtures.

    A matching dictionary cannot authenticate native execution. The production
    caller below fixes concrete producers and first verifies their authority.
    """
    if evidence_grade not in ('FIXED_NATIVE_PRODUCERS_UNACCEPTED', 'TEST_DOUBLE_ONLY'):
        _fail('PREFLIGHT_EVIDENCE_GRADE')
    data = plan.decoded()
    report = {'schema': 'h56.windows-neutral-preflight-raw-report.v1',
        'plan_sha256': plan.sha256, 'session_id': data['session_id'],
        'prelaunch_readback_sha256': data['prelaunch_readback_sha256'],
        'status': 'STOPPED', 'evidence_grade': evidence_grade,
        'isolation_accepted': False, 'runtime_authorized': False,
        'candidate_computation': 'NOT_RUN', 'business_action_calls': 0,
        'checks': {key: 'NOT_RUN' for key in CHECKS}, 'trace': [],
        'stop_reason': None, 'archive_failure': None,
        'acceptance': 'SEPARATE_HUMAN_REVIEW_REQUIRED'}
    if type(initial_bytes) is not int or not 0 <= initial_bytes < data['limits']['archive_bytes']:
        _fail('PREFLIGHT_INITIAL_ARCHIVE_ACCOUNTING')
    started, written = clock(), initial_bytes
    steps = [('observation', data['observer_request'])] + [(key, data['probe_requests'][key]) for key in CHECKS]
    for ordinal, (name, request) in enumerate(steps):
        if (clock() - started) * 1000 > data['limits']['elapsed_ms']:
            report['stop_reason'] = 'PREFLIGHT_ELAPSED_BUDGET'
            break
        entry = {'step': name, 'request_sha256': hashlib.sha256(canonical(request)).hexdigest(),
                 'receipt': None, 'evaluation': None, 'reason': None, 'archive': None}
        report['trace'].append(entry)
        try:
            receipt = observer(request) if name == 'observation' else probe(request)
            entry['receipt'] = receipt
            result = (evaluate_observer_receipt(request, receipt) if name == 'observation'
                      else evaluate_probe_receipt(request, receipt))
            entry['evaluation'] = result
            if name != 'observation':
                report['checks'][name] = result['status']
                if result['status'] != 'RAW_EXPECTATION_MET_PENDING_ACCEPTANCE':
                    _fail('PREFLIGHT_CHECK_NOT_MET:' + name)
            if (clock() - started) * 1000 > data['limits']['elapsed_ms']:
                _fail('PREFLIGHT_ELAPSED_BUDGET')
        except (Exception, KeyboardInterrupt) as error:
            entry['reason'] = getattr(error, 'code', 'PREFLIGHT_PRODUCER_EXCEPTION:' + type(error).__name__)
            report['stop_reason'] = entry['reason']
            if name in CHECKS and report['checks'][name] == 'NOT_RUN':
                report['checks'][name] = 'UNKNOWN'
        try:
            reference = archive(ordinal, entry, data['limits']['archive_bytes'] - written)
            if (type(reference) is not dict or type(reference.get('size')) is not int or
                    not 1 <= reference['size'] <= data['limits']['archive_bytes'] - written or
                    not sha(reference.get('sha256'))):
                _fail('PREFLIGHT_ARCHIVE_REFERENCE')
            entry['archive'] = reference
            written += reference['size']
        except (Exception, KeyboardInterrupt) as error:
            report['archive_failure'] = getattr(error, 'code', 'PREFLIGHT_ARCHIVE_EXCEPTION:' + type(error).__name__)
            report['status'] = 'STOPPED_ARCHIVE_FAILED'
            report['stop_reason'] = report['stop_reason'] or report['archive_failure']
            break
        if entry['reason'] is not None:
            break
    if len(report['trace']) == 8 and report['stop_reason'] is None:
        report['status'] = 'RAW_PREFLIGHT_COMPLETE_PENDING_HUMAN_ACCEPTANCE'
    report['elapsed_ms'] = max(0, int((clock() - started) * 1000))
    report['archived_bytes'] = written
    report['archive_accounting_scope'] = 'CLAIM_AND_STEP_FILES_EXCLUDING_FINAL_REPORT'
    return report


def run_preflight(plan, authority):
    """Only future approved staged CLI may call this concrete native route."""
    from .preflight_authority import PinnedPreparationAuthority
    from .probe_backend import run_probe, validate_probe_plan
    from .launcher import run_observer
    if type(plan) is not FrozenPlan or type(authority) is not PinnedPreparationAuthority:
        _fail('PREFLIGHT_CONCRETE_AUTHORITY_REQUIRED')
    checked = validate_preflight_plan(plan.decoded())
    if checked.sha256 != plan.sha256:
        _fail('PREFLIGHT_PLAN_DRIFT')
    authority.verify_preflight_binding(plan)
    root = Path(plan.decoded()['evidence_root'])
    if windows_path(str(Path(__file__).absolute().parents[1])) != windows_path(plan.decoded()['product_root']):
        _fail('PREFLIGHT_COPIED_ENTRY_REQUIRED')

    def observer(request):
        observed = validate_launch_request(request)
        bridge = authority.observation_authority(observed)
        return run_observer(request, bridge.expected_hc_sha256, authority=bridge)

    def probe(request):
        proposed = validate_probe_plan(request)
        return run_probe(proposed, authority.probe_permit(proposed))

    claim = _claim_run(root, plan)
    report = _sequence(plan, observer, probe,
        lambda ordinal, entry, room: _new_archive(root, ordinal, entry, room),
        time.monotonic, 'FIXED_NATIVE_PRODUCERS_UNACCEPTED', claim['size'])
    report['exclusive_claim'] = claim
    try:
        report['report_archive'] = _new_archive(root, 8, report,
            plan.decoded()['limits']['archive_bytes'] - report['archived_bytes'])
        report['total_archived_bytes_including_report'] = report['archived_bytes'] + report['report_archive']['size']
    except (Exception, KeyboardInterrupt) as error:
        report['archive_failure'] = getattr(error, 'code', 'PREFLIGHT_REPORT_ARCHIVE_EXCEPTION:' + type(error).__name__)
        report['status'] = 'STOPPED_ARCHIVE_FAILED'
        report['stop_reason'] = report['stop_reason'] or report['archive_failure']
    return report
