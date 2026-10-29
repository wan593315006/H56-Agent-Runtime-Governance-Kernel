"""C1 observation-only launcher source; no runtime release is bundled here.

Top-level import is inert with respect to filesystem and native Windows APIs.
The trusted parent API refuses unbound authority before native construction.
The fixed child entry is a transport endpoint of that parent, not a release
mechanism; an observer dictionary or digest is never an execution permit.
"""

from .errors import PreparationError
from .launch_contract import (
    CHILD_RESULT_SCHEMA, SOURCE_FILES, build_environment, canonical,
    decode_frame, digest, encode_frame, exact, fail, parse_request,
    validate_launch_request, authorize_observation,
)


def verify_named_sources(plan):
    """Explicit bounded source reads only after external launch authorization."""
    import hashlib
    from pathlib import Path
    from . import source_identity

    data = plan.decoded()
    root = Path(__file__).absolute().parents[1]
    if str(root).casefold() != data['paths']['product_root'].casefold():
        fail('LAUNCH_PRODUCT_ROOT_MISMATCH')
    identity = data['source_identity']
    for relative in SOURCE_FILES:
        path = root.joinpath(*relative.split('/'))
        raw = source_identity._read_checked(path, None, 65536)
        if hashlib.sha256(raw).hexdigest() != identity['source_files'][relative]:
            fail('LAUNCH_HELPER_SOURCE_DRIFT', relative)
    for relative, key in (
        ('PACKAGE_MANIFEST.json', 'product_manifest_sha256'),
        ('runtime_windows/RUNTIME_SOURCE_MANIFEST.json', 'runtime_manifest_sha256'),
    ):
        raw = source_identity._read_checked(root.joinpath(*relative.split('/')), None, 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != identity[key]:
            fail('LAUNCH_MANIFEST_IDENTITY_MISMATCH', relative)
    public_raw = source_identity._read_checked(root / 'runtime_windows' / 'public-source-lock.json', None, 65536)
    lock = source_identity.parse_public_lock(public_raw)
    source = source_identity.verify_public_lock(root / 'runtime_binding_v1_20261024', lock)
    runtime = data['runtime']
    raw_python = source_identity._read_checked(Path(runtime['python_executable']), None, 1024 * 1024)
    if hashlib.sha256(raw_python).hexdigest() != runtime['python_sha256']:
        fail('BOUND_PYTHON_EXECUTABLE_DRIFT')
    return source


def check_child_result(plan, raw_stdout, expected_pid):
    """Pure validation of transport/provenance tags; not empirical isolation."""
    from .kernel_probe import evaluate_observation
    data = plan.decoded()
    value = decode_frame(raw_stdout, data['limits']['control_bytes'])
    exact(value, ('schema', 'request_sha256', 'run_id', 'pid',
                  'environment_sha256', 'observation'), 'OBSERVER_RESULT_FIELDS')
    if (value['schema'] != CHILD_RESULT_SCHEMA or value['request_sha256'] != plan.sha256 or
            value['run_id'] != data['run_id'] or type(value['pid']) is not int or
            not 1 <= value['pid'] <= 0xFFFFFFFF or value['pid'] != expected_pid or
            value['environment_sha256'] != digest(build_environment(plan))):
        fail('OBSERVER_RESULT_BINDING_MISMATCH')
    return evaluate_observation(data['observation_policy'], value['observation'])


def run_observer(request, release_anchor, *, authority=None):
    """Future authorized observer parent. No default authority implementation.

The authority is trusted embedding code with independent source/resource and
Controller checks. Passing a matching hash, a JSON approved flag or an object
created from JSON cannot replace it. This API never computes core candidates.
"""
    plan = validate_launch_request(request)
    permit = authorize_observation(plan, release_anchor, authority)
    source = verify_named_sources(plan)
    from .win32_backend import WindowsBackend

    backend = None
    receipt = {
        'schema': 'h56.windows-observer-parent-receipt.v1',
        'status': 'NOT_VERIFIED', 'request_sha256': plan.sha256,
        'runtime_authorized': False, 'isolation_verified': False,
        'native_core_imported': False, 'candidate_computation': 'NOT_RUN',
        'file_network_negative_tests': 'NOT_RUN', 'source_identity': source,
        'command_kind': 'FIXED_OBSERVATION_CHILD_ONLY', 'exit_code': None,
        'raw_stdout': b'', 'raw_stderr': b'', 'events': [],
        'stop_reason': None, 'cleanup': {'status': 'NO_RESOURCES_CREATED'},
        'cleanup_exception': None,
    }
    try:
        backend = WindowsBackend(plan, permit)
        backend.create_job()
        backend.create_pipes()
        backend.create_suspended_child_in_job()
        backend.resume()
        actual = backend.pump()
        receipt.update({'exit_code': actual['exit_code'], 'raw_stdout': actual['stdout'],
                        'raw_stderr': actual['stderr'], 'pid': actual['pid']})
        if actual['exit_code'] != 0:
            fail('OBSERVER_CHILD_NONZERO_EXIT')
        evaluation = check_child_result(plan, actual['stdout'], actual['pid'])
        receipt['evaluation'] = evaluation
        receipt['status'] = evaluation['status']
    except PreparationError as error:
        receipt['stop_reason'] = error.code + (':' + error.detail if error.detail else '')
    except (OSError, AttributeError, ValueError, TypeError, OverflowError):
        receipt['stop_reason'] = 'OBSERVER_NATIVE_UNAVAILABLE_OR_INVALID'
    except KeyboardInterrupt:
        receipt['stop_reason'] = 'OBSERVER_INTERRUPTED'
    except Exception as error:
        receipt['stop_reason'] = 'OBSERVER_UNEXPECTED_FAILURE:' + type(error).__name__
    finally:
        if backend is not None:
            receipt.update(backend.snapshot())
            receipt['events'] = list(backend.events)
            try:
                receipt['cleanup'] = backend.cleanup()
            except BaseException as error:
                receipt['cleanup'] = {'status': 'CLEANUP_NOT_VERIFIED'}
                receipt['cleanup_exception'] = type(error).__name__
            receipt.update(backend.snapshot())
            if receipt['cleanup']['status'] != 'CLOSED':
                receipt['status'] = 'NOT_VERIFIED'
    return receipt


def child_main():
    """Fixed parent-owned child endpoint, never a public action executor.

No release may be inferred from request fields by this endpoint. Its caller is
the already approved parent-created AppContainer process. Manual invocation is
not a recognized preflight and cannot create a parent receipt or authority.
"""
    import os
    import sys
    from .kernel_probe import collect_current_process_observation

    try:
        if os.name != 'nt' or not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
            fail('OBSERVER_CHILD_PLATFORM_FLAGS_INVALID')
        header = sys.stdin.buffer.read(4)
        if len(header) != 4:
            fail('OBSERVER_CHILD_FRAME_HEADER')
        length = int.from_bytes(header, 'little')
        if not 1 <= length <= 32768:
            fail('OBSERVER_CHILD_REQUEST_BUDGET')
        payload = sys.stdin.buffer.read(length)
        if len(payload) != length:
            fail('OBSERVER_CHILD_FRAME_INCOMPLETE')
        plan = parse_request(payload)
        env = dict(os.environ)
        if env != build_environment(plan):
            fail('OBSERVER_CHILD_ENV_NAMES_OR_VALUES_MISMATCH')
        # This frame carries no action/module/command selection, only one probe.
        result = {
            'schema': CHILD_RESULT_SCHEMA, 'request_sha256': plan.sha256,
            'run_id': plan.decoded()['run_id'], 'pid': os.getpid(),
            'environment_sha256': digest(env),
            'observation': collect_current_process_observation(plan.decoded()['observation_policy']),
        }
        frame = encode_frame(result, plan.decoded()['limits']['control_bytes'])
        sys.stdout.buffer.write(frame)
        sys.stdout.buffer.flush()
        return 0
    except PreparationError as error:
        # Bounded reason only. No environment, input, credentials or traceback.
        sys.stderr.buffer.write(('OBSERVER_STOP:' + error.code + '\n').encode('ascii')[:256])
        sys.stderr.buffer.flush()
        return 2
