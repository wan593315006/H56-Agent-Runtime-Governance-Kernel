"""Pure observation-launch contracts. No filesystem, ctypes or process calls.

Source construction does not release actual launches. A trusted embedding must
provide the external Controller authority and preprovisioned-resource checks.
JSON fields or hashes cannot instantiate an approved resource or that authority.
"""

from abc import ABC, abstractmethod
import hashlib
import json
import ntpath
import re

from .errors import PreparationError
from .kernel_probe import validate_policy


SCHEMA = 'h56.windows-observation-launch.v1'
CHILD_RESULT_SCHEMA = 'h56.windows-observer-result.v1'
SOURCE_FILES = (
    'runtime_windows/__init__.py', 'runtime_windows/errors.py',
    'runtime_windows/kernel_probe.py', 'runtime_windows/source_identity.py',
    'runtime_windows/launch_contract.py', 'runtime_windows/launcher.py',
    'runtime_windows/win32_backend.py', 'runtime_windows/public-source-lock.json',
)
REQUEST_ENV_KEYS = frozenset(('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'H56_RUN_ID'))
CHILD_ENV_KEYS = REQUEST_ENV_KEYS | {'H56_REQUEST_SHA256'}
TOP_KEYS = frozenset((
    'schema', 'mode', 'run_id', 'source_identity', 'runtime', 'profile',
    'paths', 'environment', 'observation_policy', 'limits', 'release_binding',
))
MAX_REQUEST_BYTES = 32768
MAX_CONTROL_BYTES = 65536
MAX_STDOUT_BYTES = 1048576
MAX_STDERR_BYTES = 65536
_HEX = re.compile(r'^[0-9a-f]{64}$')
_RUN = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_PROFILE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
_PERMIT_SEAL = object()


def fail(code, detail=''):
    raise PreparationError(code, detail)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def exact(value, keys, code):
    if type(value) is not dict or set(value) != set(keys):
        fail(code)


def sha(value):
    return type(value) is str and bool(_HEX.fullmatch(value)) and value != '0' * 64


def windows_path(value):
    if type(value) is not str or not 3 <= len(value) <= 240:
        fail('BOUND_WINDOWS_PATH_REQUIRED')
    if ('/' in value or '\x00' in value or '"' in value or value.startswith('\\\\')
            or len(value) < 3 or not value[0].isascii() or not value[0].isalpha()
            or value[1:3] != ':\\'):
        fail('LOCAL_WINDOWS_PATH_REQUIRED')
    for part in value[3:].split('\\'):
        if not part or part in ('.', '..') or ':' in part or part.endswith((' ', '.')):
            fail('WINDOWS_PATH_COMPONENT_INVALID')
        if (any(ord(x) < 32 or x in '<>|?*' for x in part) or
                part.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL'} or
                part.split('.')[0].upper() in {'COM' + str(i) for i in range(1, 10)} or
                part.split('.')[0].upper() in {'LPT' + str(i) for i in range(1, 10)}):
            fail('WINDOWS_PATH_COMPONENT_INVALID')
    return ntpath.normcase(value)


def contains(root, child):
    root, child = windows_path(root), windows_path(child)
    return child == root or child.startswith(root.rstrip('\\') + '\\')


class LaunchPlan:
    """Canonical bytes avoid mutability between validation and native use."""
    __slots__ = ('_raw', '_sha256')

    def __init__(self, raw):
        object.__setattr__(self, '_raw', raw)
        object.__setattr__(self, '_sha256', hashlib.sha256(raw).hexdigest())

    def __setattr__(self, name, value):
        raise AttributeError('LaunchPlan is immutable')

    @property
    def sha256(self):
        return self._sha256

    @property
    def raw(self):
        return self._raw

    def decoded(self):
        return json.loads(self._raw.decode('utf-8'))


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            fail('DUPLICATE_LAUNCH_JSON_KEY')
        result[key] = value
    return result


def parse_request(raw):
    if type(raw) is not bytes or len(raw) > MAX_REQUEST_BYTES:
        fail('LAUNCH_REQUEST_BYTES_BUDGET')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda value: fail('NONFINITE_LAUNCH_JSON'))
    except (ValueError, UnicodeError, RecursionError):
        fail('INVALID_LAUNCH_JSON')
    return validate_launch_request(data)


def validate_launch_request(request):
    exact(request, TOP_KEYS, 'LAUNCH_EXACT_FIELDS')
    if request['schema'] != SCHEMA or request['mode'] != 'OBSERVATION_ONLY':
        fail('OBSERVATION_ONLY_MODE_REQUIRED')
    if type(request['run_id']) is not str or not _RUN.fullmatch(request['run_id']):
        fail('RUN_ID_INVALID')
    identity = request['source_identity']
    exact(identity, ('product_manifest_sha256', 'runtime_manifest_sha256',
                     'source_files'), 'LAUNCH_SOURCE_FIELDS')
    if not sha(identity['product_manifest_sha256']) or not sha(identity['runtime_manifest_sha256']):
        fail('LAUNCH_SOURCE_IDENTITY_UNBOUND')
    exact(identity['source_files'], SOURCE_FILES, 'LAUNCH_SOURCE_CLOSURE_FIELDS')
    if not all(sha(x) for x in identity['source_files'].values()):
        fail('LAUNCH_SOURCE_IDENTITY_UNBOUND')
    paths = request['paths']
    exact(paths, ('product_root', 'runtime_root', 'scratch_root', 'evidence_root'),
          'LAUNCH_PATH_FIELDS')
    for value in paths.values():
        windows_path(value)
    if contains(paths['scratch_root'], paths['product_root']) or contains(paths['evidence_root'], paths['product_root']):
        fail('WRITABLE_ROOT_CONTAINS_SOURCE')
    if (contains(paths['scratch_root'], paths['runtime_root']) or
            contains(paths['evidence_root'], paths['runtime_root'])):
        fail('WRITABLE_ROOT_CONTAINS_RUNTIME')
    if contains(paths['scratch_root'], paths['evidence_root']) or contains(paths['evidence_root'], paths['scratch_root']):
        fail('SCRATCH_EVIDENCE_OVERLAP')
    for relative in SOURCE_FILES:
        member = ntpath.join(paths['product_root'], *relative.split('/'))
        if contains(paths['scratch_root'], member) or contains(paths['evidence_root'], member):
            fail('SOURCE_IN_WRITABLE_ROOT')
    runtime = request['runtime']
    exact(runtime, ('python_executable', 'python_sha256', 'version', 'arch',
                    'closure_sha256'), 'LAUNCH_RUNTIME_FIELDS')
    windows_path(runtime['python_executable'])
    if not contains(paths['runtime_root'], runtime['python_executable']):
        fail('PYTHON_NOT_IN_BOUND_RUNTIME_ROOT')
    if (not sha(runtime['python_sha256']) or not sha(runtime['closure_sha256']) or
            runtime['arch'] != 'WINDOWS_X64' or runtime['version'] not in ('3.9.13', '3.13.12')):
        fail('RUNTIME_IDENTITY_UNBOUND_OR_UNSUPPORTED')
    profile = request['profile']
    exact(profile, ('name', 'sid', 'storage_root', 'provisioning_receipt_sha256'),
          'LAUNCH_PROFILE_FIELDS')
    if (type(profile['name']) is not str or not _PROFILE.fullmatch(profile['name']) or
            not sha(profile['provisioning_receipt_sha256'])):
        fail('PREPROVISIONED_PROFILE_UNBOUND')
    windows_path(profile['storage_root'])
    for key in ('product_root', 'runtime_root', 'scratch_root', 'evidence_root'):
        if contains(paths[key], profile['storage_root']) or contains(profile['storage_root'], paths[key]):
            fail('PROFILE_STORAGE_OVERLAPS_PRODUCT_PATHS')
    validate_policy(request['observation_policy'])
    if profile['sid'] != request['observation_policy']['appcontainer_sid']:
        fail('PROFILE_OBSERVATION_IDENTITY_MISMATCH')
    if request['observation_policy']['capabilities'] != []:
        fail('OBSERVATION_LAUNCH_CAPABILITIES_MUST_BE_EMPTY')
    env = request['environment']
    exact(env, REQUEST_ENV_KEYS, 'LAUNCH_ENV_NAMES_EXACT')
    for name, value in env.items():
        if type(value) is not str or not value or len(value) > 512 or '\x00' in value:
            fail('LAUNCH_ENV_VALUE_INVALID', name)
    if (windows_path(env['SYSTEMROOT']) != windows_path(env['WINDIR']) or
            windows_path(env['TEMP']) != windows_path(paths['scratch_root']) or
            windows_path(env['TMP']) != windows_path(paths['scratch_root']) or
            env['H56_RUN_ID'] != request['run_id']):
        fail('LAUNCH_ENV_VALUE_MISMATCH')
    limits = request['limits']
    budgets = {'startup_ms': (1, 30000), 'total_ms': (1, 120000),
               'cleanup_ms': (1, 10000), 'stdout_bytes': (1, MAX_STDOUT_BYTES),
               'stderr_bytes': (1, MAX_STDERR_BYTES),
               'control_bytes': (MAX_REQUEST_BYTES + 4, MAX_CONTROL_BYTES)}
    exact(limits, budgets, 'LAUNCH_LIMIT_FIELDS')
    for name, (lower, upper) in budgets.items():
        if type(limits[name]) is not int or not lower <= limits[name] <= upper:
            fail('LAUNCH_LIMIT_INVALID', name)
    if limits['startup_ms'] > limits['total_ms']:
        fail('LAUNCH_TIME_BUDGET_INCONSISTENT')
    release = request['release_binding']
    exact(release, ('external_decision_sha256', 'source_scope_sha256',
                    'resource_binding_sha256', 'preflight_receipt_sha256'),
          'LAUNCH_RELEASE_FIELDS')
    if not all(sha(x) for x in release.values()):
        fail('EXTERNAL_RELEASE_BINDING_UNBOUND')
    raw = canonical(request)
    if len(raw) > MAX_REQUEST_BYTES:
        fail('LAUNCH_REQUEST_BYTES_BUDGET')
    return LaunchPlan(raw)


def build_environment(plan):
    data = plan.decoded()
    env = dict(data['environment'])
    env['H56_REQUEST_SHA256'] = plan.sha256
    return env


def environment_block(plan):
    env = build_environment(plan)
    return ('\x00'.join(key + '=' + env[key] for key in sorted(env)) + '\x00\x00')


def command_arguments(plan):
    data = plan.decoded()
    bootstrap = ('import sys;sys.path.insert(0,' + repr(data['paths']['product_root']) +
                 ');from runtime_windows.launcher import child_main;'
                 'raise SystemExit(child_main())')
    return (data['runtime']['python_executable'], '-I', '-B', '-S', '-X', 'utf8',
            '-c', bootstrap)


def quote_argument(value):
    if type(value) is not str or '\x00' in value:
        fail('COMMAND_ARGUMENT_INVALID')
    output, slashes = ['"'], 0
    for char in value:
        if char == '\\':
            slashes += 1
        elif char == '"':
            output.extend(('\\' * (slashes * 2 + 1), '"'))
            slashes = 0
        else:
            output.extend(('\\' * slashes, char))
            slashes = 0
    output.extend(('\\' * (slashes * 2), '"'))
    return ''.join(output)


def command_line(plan):
    result = ' '.join(quote_argument(value) for value in command_arguments(plan))
    if len(result) > 30000:
        fail('COMMAND_LINE_BUDGET')
    return result


def encode_frame(value, budget):
    raw = canonical(value)
    if len(raw) + 4 > budget:
        fail('CONTROL_FRAME_BUDGET')
    return len(raw).to_bytes(4, 'little') + raw


def decode_frame(raw, budget):
    if type(raw) is not bytes or len(raw) < 4 or len(raw) > budget:
        fail('CONTROL_FRAME_BUDGET')
    length = int.from_bytes(raw[:4], 'little')
    if length != len(raw) - 4:
        fail('CONTROL_FRAME_LENGTH')
    try:
        return json.loads(raw[4:].decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda value: fail('NONFINITE_LAUNCH_JSON'))
    except (ValueError, UnicodeError, RecursionError):
        fail('CONTROL_FRAME_INVALID_JSON')


class BoundedCapture:
    """Pure bounded raw-byte capture shared by the native pump and tests.

    The first excess chunk preserves its permitted prefix and marks truncation
    before the caller stops. This is output accounting, never OS isolation.
    """
    def __init__(self, stdout_limit, stderr_limit):
        if (type(stdout_limit) is not int or not 1 <= stdout_limit <= MAX_STDOUT_BYTES or
                type(stderr_limit) is not int or not 1 <= stderr_limit <= MAX_STDERR_BYTES):
            fail('CAPTURE_LIMIT_INVALID')
        self.limits = {'stdout': stdout_limit, 'stderr': stderr_limit}
        self.buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        self.observed = {'stdout': 0, 'stderr': 0}
        self.truncated = {'stdout': False, 'stderr': False}

    def accept(self, role, block):
        if role not in self.buffers or type(block) is not bytes or len(block) > 4096:
            fail('CAPTURE_CHUNK_INVALID')
        if self.truncated[role]:
            fail('CAPTURE_ALREADY_STOPPED', role)
        self.observed[role] += len(block)
        room = self.limits[role] - len(self.buffers[role])
        self.buffers[role].extend(block[:room])
        if len(block) > room:
            self.truncated[role] = True
            return False
        return True

    def snapshot(self):
        return {
            'raw_stdout': bytes(self.buffers['stdout']),
            'raw_stderr': bytes(self.buffers['stderr']),
            'observed_output_bytes': dict(self.observed),
            'capture_prefix_truncated': dict(self.truncated),
        }


class ObservationAuthority(ABC):
    """Trusted host code, not request data; no implementation ships in C1.

The embedding must independently verify the Human decision/anchor AND the
prebuilt profile, ACL, runtime closure, paths and allowed side effects. Returning
True or a dictionary is forbidden. This is an explicit trust boundary, not a
cryptographic claim that Python can authenticate a human from JSON.
"""
    @abstractmethod
    def authorize(self, plan, release_anchor):
        raise NotImplementedError

    @abstractmethod
    def verify_preprovisioned_resources(self, plan):
        raise NotImplementedError


class _ObservationPermit:
    __slots__ = ('plan_sha256', '_seal')

    def __init__(self, plan, seal):
        if seal is not _PERMIT_SEAL:
            fail('OPAQUE_OBSERVATION_PERMIT_REQUIRED')
        self.plan_sha256, self._seal = plan.sha256, seal


def authorize_observation(plan, release_anchor, authority):
    if not isinstance(authority, ObservationAuthority) or release_anchor is None:
        fail('TRUSTED_EXTERNAL_OBSERVATION_AUTHORITY_UNBOUND')
    if authority.authorize(plan, release_anchor) is not None:
        fail('AUTHORITY_BRIDGE_RESULT_INVALID')
    if authority.verify_preprovisioned_resources(plan) is not None:
        fail('RESOURCE_PREFLIGHT_BRIDGE_RESULT_INVALID')
    return _ObservationPermit(plan, _PERMIT_SEAL)


def require_permit(plan, permit):
    if (type(permit) is not _ObservationPermit or permit._seal is not _PERMIT_SEAL or
            permit.plan_sha256 != plan.sha256):
        fail('OPAQUE_OBSERVATION_PERMIT_REQUIRED')
