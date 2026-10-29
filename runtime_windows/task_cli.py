"""Fixed local stdio task consumer. Operator Host pins never come from task JSON."""
import argparse
import json
from pathlib import Path
import re
import sys


def error_document(exc):
    """Bounded private stderr handoff; never an arbitrary fallback file write."""
    from runtime_windows.host_contract import HostEvidencePersistenceError
    critical = isinstance(exc, HostEvidencePersistenceError)
    document = {'status': 'STOPPED', 'error_type': type(exc).__name__, 'reason': str(exc)[:1024],
        'evidence_preservation': 'BLOCKED' if critical else 'NOT_DETERMINED_BY_TASK_CLI',
        'candidate_result_verified': False, 'authority_granted': False, 'execution_permitted': False}
    if critical:
        document['evidence_persistence'] = 'FAILED'
        document['raw_result'] = getattr(exc, 'raw_result', None)
        if getattr(exc, 'task_record_failure', None) is not None:
            document['task_record_failure'] = exc.task_record_failure
    # Shared raw snapshot <=2MiB plus <=8KiB of fixed diagnostic envelope.
    if len(json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')) > 2 * 1024 * 1024 + 8192:
        raise RuntimeError('TASK_ERROR_RAW_CAPTURE_BUDGET_EXCEEDED') from exc
    return document


def operator_host(args):
    values = (args.trusted_hc_sha256, args.controller_bundle_sha256, args.host_session)
    if all(value is None for value in values):
        return None
    if not all(type(value) is str and value for value in values):
        raise ValueError('ALL_THREE_OPERATOR_HOST_PINS_REQUIRED')
    if any(re.fullmatch('[0-9a-f]{64}', value) is None for value in values[:2]) or re.fullmatch('[A-Za-z0-9_-]{1,64}', values[2]) is None:
        raise ValueError('OPERATOR_HOST_PIN_SHAPE')
    # This is the only Host import path. No arbitrary provider/backend/module,
    # UI field, submitted task, or persisted journal can select these anchors.
    from runtime_windows.host_authority import BootstrapPins
    from runtime_windows.candidate_host import CandidateHost
    pins = BootstrapPins(expected_hc_original_sha256=values[0],
                         expected_controller_bundle_sha256=values[1],
                         session_id=values[2], product_root=str(Path(__file__).absolute().parents[1]))
    return CandidateHost.from_bootstrap(pins)


def main():
    if not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode or not sys.flags.utf8_mode:
        raise RuntimeError('USE_PYTHON_-I_-B_-S_-X_UTF8')
    product = Path(__file__).absolute().parents[1]
    sys.path.insert(0, str(product))
    from runtime_windows.task_catalog import FrozenTaskCatalog
    from runtime_windows.task_store import TaskJournal
    from runtime_windows.tasks import TaskService
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('status', 'recover'):
        commands.add_parser(name)
    submit = commands.add_parser('submit')
    submit.add_argument('--request-id', required=True)
    submit.add_argument('--domain', choices=('DEVSECOPS', 'FINANCE_REFUND'), required=True)
    submit.add_argument('--scenario', default='positive')
    cancel = commands.add_parser('cancel')
    cancel.add_argument('--task-id', required=True)
    for name in ('dispatch', 'replay'):
        command = commands.add_parser(name)
        command.add_argument('--task-id', required=True)
        command.add_argument('--trusted-hc-sha256')
        command.add_argument('--controller-bundle-sha256')
        command.add_argument('--host-session')
        if name == 'replay':
            command.add_argument('--replay-id', required=True)
    args = parser.parse_args()
    try:
        # Intake/recovery cannot load a CandidateHost, create a Windows resource
        # or run a worker. Source DATA checks are not runtime qualification.
        host = operator_host(args) if args.command in ('dispatch', 'replay') else None
        service = TaskService(FrozenTaskCatalog(), TaskJournal(args.session), host)
        if args.command == 'submit':
            result = service.submit(args.request_id, args.domain, args.scenario)
        elif args.command == 'dispatch':
            result = service.dispatch(args.task_id)
        elif args.command == 'cancel':
            result = service.cancel(args.task_id)
        elif args.command == 'replay':
            result = service.replay(args.task_id, args.replay_id)
        elif args.command == 'recover':
            result = service.recover()
        else:
            result = service.view()
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 3 if result.get('status') in ('BLOCKED', 'FAILED', 'REJECTED', 'RECOVERY_REQUIRED') else 0
    except Exception as exc:
        print(json.dumps(error_document(exc), ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
