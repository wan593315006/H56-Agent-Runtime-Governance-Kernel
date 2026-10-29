"""Explicit, read-only current-process observations; never an execution release.

Import and pure evaluation do not import ctypes or bind/call Windows APIs.
The collector is prepared for a separately authorized dedicated child process.
It does not create tokens, jobs, processes, ACLs, network rules or resources.

Microsoft contracts used: GetTokenInformation / TOKEN_INFORMATION_CLASS,
TOKEN_GROUPS, JOBOBJECT_BASIC_LIMIT_INFORMATION,
JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
and QueryInformationJobObject (NULL means the calling process's immediate job).
This version intentionally supports only the checked Windows 64-bit ABI.
"""

from .errors import PreparationError


POLICY_SCHEMA = 'h56.windows-observation-policy.v1'
OBSERVATION_SCHEMA = 'h56.windows-process-observation.v1'
RESULT_SCHEMA = 'h56.windows-observation-evaluation.v1'
MAX_TOKEN_BYTES = 65536
MAX_CAPABILITIES = 64
MAX_MEMORY_BYTES = 16 * 1024 * 1024 * 1024
REQUIRED_JOB_FLAGS = 0x00000008 | 0x00000100 | 0x00000200 | 0x00002000
FORBIDDEN_JOB_FLAGS = 0x00000800 | 0x00001000
CPU_HARD_CAP_FLAGS = 0x1 | 0x4
PENDING_CHECKS = (
    'external_resource_release', 'file_access_negative',
    'network_access_negative', 'child_escape_negative',
    'resource_limit_negative', 'dedicated_runtime_acceptance',
)
POLICY_KEYS = frozenset((
    'schema', 'appcontainer_sid', 'capabilities', 'token_has_restrictions',
    'elevation_type', 'active_process_limit', 'process_memory_limit_bytes',
    'job_memory_limit_bytes', 'cpu_rate_hundredths',
))
TOKEN_KEYS = frozenset((
    'primary_token_type', 'thread_impersonation_present', 'is_appcontainer',
    'appcontainer_sid', 'capabilities', 'has_restrictions', 'elevated',
    'elevation_type',
))
JOB_KEYS = frozenset((
    'in_job', 'scope', 'limit_flags', 'active_process_limit',
    'process_memory_limit_bytes', 'job_memory_limit_bytes',
    'cpu_control_flags', 'cpu_rate_hundredths',
))
OBSERVATION_KEYS = frozenset((
    'schema', 'scope', 'query_complete', 'token', 'job', 'collection_error',
))


def _integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def _sid_parts(value):
    if type(value) is not str or len(value) > 184:
        return None
    parts = value.split('-')
    if len(parts) < 4 or parts[0] != 'S' or parts[1] != '1':
        return None
    numbers = []
    for index, part in enumerate(parts[2:]):
        if not part or not part.isascii() or not part.isdecimal():
            return None
        number = int(part)
        if str(number) != part or number > (0xFFFFFFFFFFFF if index == 0 else 0xFFFFFFFF):
            return None
        numbers.append(number)
    if not 1 <= len(numbers) - 1 <= 15:
        return None
    return numbers


def _capabilities_valid(value):
    if type(value) is not list or len(value) > MAX_CAPABILITIES:
        return False
    seen = set()
    for item in value:
        if type(item) is not dict or set(item) != {'sid', 'attributes'}:
            return False
        parts = _sid_parts(item['sid'])
        if parts is None or len(parts) < 3 or parts[:2] != [15, 3]:
            return False
        if item['sid'] in seen or not _integer(item['attributes'], 0, 0xFFFFFFFF):
            return False
        seen.add(item['sid'])
    return True


def validate_policy(policy):
    """Validate a proposed comparison policy; does not grant probe permission."""
    if type(policy) is not dict or set(policy) != POLICY_KEYS:
        raise PreparationError('POLICY_FIELDS_INVALID')
    if policy['schema'] != POLICY_SCHEMA:
        raise PreparationError('POLICY_SCHEMA_INVALID')
    sid = _sid_parts(policy['appcontainer_sid'])
    if sid is None or len(sid) < 3 or sid[:2] != [15, 2]:
        raise PreparationError('APPCONTAINER_IDENTITY_UNBOUND_OR_INVALID')
    if not _capabilities_valid(policy['capabilities']):
        raise PreparationError('POLICY_CAPABILITIES_INVALID')
    if type(policy['token_has_restrictions']) is not bool:
        raise PreparationError('TOKEN_RESTRICTIONS_EXPECTATION_INVALID')
    if not _integer(policy['elevation_type'], 1, 3) or policy['elevation_type'] == 2:
        raise PreparationError('ELEVATION_EXPECTATION_INVALID')
    limits = (
        ('active_process_limit', 1, 64),
        ('process_memory_limit_bytes', 1, MAX_MEMORY_BYTES),
        ('job_memory_limit_bytes', 1, MAX_MEMORY_BYTES),
        ('cpu_rate_hundredths', 1, 10000),
    )
    for name, lower, upper in limits:
        if not _integer(policy[name], lower, upper):
            raise PreparationError('POLICY_LIMIT_INVALID', name)
    if policy['process_memory_limit_bytes'] > policy['job_memory_limit_bytes']:
        raise PreparationError('POLICY_MEMORY_LIMITS_INCONSISTENT')


def _result(reasons):
    return {
        'schema': RESULT_SCHEMA,
        'status': ('NOT_VERIFIED' if reasons else
                   'OBSERVED_MATCH_NEGATIVE_TESTS_PENDING'),
        'reasons': reasons,
        'observation_provenance': 'CALLER_DATA_NOT_AUTHENTICATED_BY_EVALUATOR',
        'isolation_verified': False,
        'runtime_authorized': False,
        'candidate_qualification': 'NOT_COMPUTED',
        'required_runtime_checks': {key: 'NOT_RUN' for key in PENDING_CHECKS},
    }


def evaluate_observation(policy, observation):
    """Pure comparison, including mode/enable flags; never isolation PASS.

An input dictionary can be fabricated. This comparison cannot authenticate its
origin, prove OS-denied accesses, or replace a Human Controller release.
CPU values are hundredths of percent of host CPU capacity, not CPU-core counts.
Job memory values are committed-memory limits, not resident working-set usage.
"""
    try:
        validate_policy(policy)
    except PreparationError as error:
        return _result([error.code])
    if type(observation) is not dict or set(observation) != OBSERVATION_KEYS:
        return _result(['OBSERVATION_FIELDS_INVALID'])
    reasons = []
    if observation['schema'] != OBSERVATION_SCHEMA:
        reasons.append('OBSERVATION_SCHEMA_INVALID')
    if observation['scope'] != 'CURRENT_PROCESS_AND_IMMEDIATE_JOB_ONLY':
        reasons.append('OBSERVATION_SCOPE_INVALID')
    if observation['query_complete'] is not True or observation['collection_error'] is not None:
        reasons.append('OBSERVATION_INCOMPLETE')
    token, job = observation['token'], observation['job']
    if type(token) is not dict or set(token) != TOKEN_KEYS:
        reasons.append('TOKEN_OBSERVATION_INCOMPLETE')
    else:
        if type(token['primary_token_type']) is not int or token['primary_token_type'] != 1:
            reasons.append('PRIMARY_TOKEN_NOT_PROVED')
        if token['thread_impersonation_present'] is not False:
            reasons.append('THREAD_TOKEN_AMBIGUOUS')
        if token['is_appcontainer'] is not True:
            reasons.append('APPCONTAINER_NOT_PROVED')
        if _sid_parts(token['appcontainer_sid']) is None or token['appcontainer_sid'] != policy['appcontainer_sid']:
            reasons.append('APPCONTAINER_IDENTITY_MISMATCH')
        if not _capabilities_valid(token['capabilities']):
            reasons.append('CAPABILITIES_NOT_PROVED')
        else:
            expected = sorted((x['sid'], x['attributes']) for x in policy['capabilities'])
            actual = sorted((x['sid'], x['attributes']) for x in token['capabilities'])
            if actual != expected:
                reasons.append('CAPABILITIES_MISMATCH')
        if (type(token['has_restrictions']) is not bool or
                token['has_restrictions'] != policy['token_has_restrictions']):
            reasons.append('TOKEN_RESTRICTIONS_MISMATCH')
        if token['elevated'] is not False:
            reasons.append('ELEVATED_OR_UNKNOWN_TOKEN')
        if (type(token['elevation_type']) is not int or
                token['elevation_type'] != policy['elevation_type']):
            reasons.append('TOKEN_ELEVATION_TYPE_MISMATCH')
    if type(job) is not dict or set(job) != JOB_KEYS:
        reasons.append('JOB_OBSERVATION_INCOMPLETE')
    else:
        if job['in_job'] is not True:
            reasons.append('CURRENT_JOB_NOT_PROVED')
        if job['scope'] != 'IMMEDIATE_JOB_ONLY':
            reasons.append('JOB_SCOPE_INVALID')
        flags = job['limit_flags']
        if not _integer(flags, 0, 0xFFFFFFFF):
            reasons.append('JOB_LIMIT_FLAGS_INVALID')
        elif flags != REQUIRED_JOB_FLAGS:
            reasons.append('JOB_ENFORCEMENT_FLAGS_MISMATCH')
        if job['cpu_control_flags'] != CPU_HARD_CAP_FLAGS or type(job['cpu_control_flags']) is not int:
            reasons.append('CPU_HARD_CAP_MODE_NOT_PROVED')
        for name in ('active_process_limit', 'process_memory_limit_bytes',
                     'job_memory_limit_bytes', 'cpu_rate_hundredths'):
            if type(job[name]) is not int or job[name] != policy[name]:
                reasons.append('JOB_LIMIT_MISMATCH:' + name)
    return _result(reasons)


def _decode_sid_bytes(raw):
    """Pure SID decoder; callers must first validate pointer bounds."""
    if type(raw) is not bytes or len(raw) < 8 or raw[0] != 1 or not 1 <= raw[1] <= 15:
        raise PreparationError('SID_BYTES_INVALID')
    if len(raw) != 8 + 4 * raw[1]:
        raise PreparationError('SID_LENGTH_INVALID')
    authority = int.from_bytes(raw[2:8], 'big')
    subauth = [int.from_bytes(raw[i:i + 4], 'little') for i in range(8, len(raw), 4)]
    return 'S-1-' + '-'.join(str(x) for x in [authority] + subauth)


def _bind_windows_api():
    """Lazy ABI declarations and read-only bindings, only on explicit call."""
    import ctypes as ct

    if ct.sizeof(ct.c_void_p) != 8:
        raise PreparationError('ABI_UNSUPPORTED', 'Windows64-only')
    DWORD, SIZE_T, HANDLE = ct.c_uint32, ct.c_size_t, ct.c_void_p

    class SID_AND_ATTRIBUTES(ct.Structure):
        _fields_ = [('Sid', HANDLE), ('Attributes', DWORD)]

    class TOKEN_GROUPS(ct.Structure):
        _fields_ = [('GroupCount', DWORD), ('Groups', SID_AND_ATTRIBUTES * 1)]

    class BASIC_LIMIT(ct.Structure):
        _fields_ = [
            ('PerProcessUserTimeLimit', ct.c_int64), ('PerJobUserTimeLimit', ct.c_int64),
            ('LimitFlags', DWORD), ('MinimumWorkingSetSize', SIZE_T),
            ('MaximumWorkingSetSize', SIZE_T), ('ActiveProcessLimit', DWORD),
            ('Affinity', SIZE_T), ('PriorityClass', DWORD), ('SchedulingClass', DWORD),
        ]

    class IO_COUNTERS(ct.Structure):
        _fields_ = [(name, ct.c_uint64) for name in (
            'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
            'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]

    class EXTENDED_LIMIT(ct.Structure):
        _fields_ = [
            ('BasicLimitInformation', BASIC_LIMIT), ('IoInfo', IO_COUNTERS),
            ('ProcessMemoryLimit', SIZE_T), ('JobMemoryLimit', SIZE_T),
            ('PeakProcessMemoryUsed', SIZE_T), ('PeakJobMemoryUsed', SIZE_T),
        ]

    class CPU_LIMIT(ct.Structure):
        # DWORD union is read only when ControlFlags is exactly ENABLE|HARD_CAP.
        _fields_ = [('ControlFlags', DWORD), ('CpuRate', DWORD)]

    if (ct.sizeof(BASIC_LIMIT), ct.sizeof(EXTENDED_LIMIT), ct.sizeof(CPU_LIMIT),
            BASIC_LIMIT.MinimumWorkingSetSize.offset, BASIC_LIMIT.Affinity.offset,
            EXTENDED_LIMIT.ProcessMemoryLimit.offset, TOKEN_GROUPS.Groups.offset,
            ct.sizeof(SID_AND_ATTRIBUTES)) != (64, 144, 8, 24, 48, 112, 8, 16):
        raise PreparationError('ABI_LAYOUT_MISMATCH')
    kernel = ct.WinDLL('kernel32.dll', use_last_error=True)
    security = ct.WinDLL('advapi32.dll', use_last_error=True)

    def bind(dll, name, args, result):
        function = getattr(dll, name)
        function.argtypes, function.restype = args, result
        return function

    api = {
        'current_process': bind(kernel, 'GetCurrentProcess', [], HANDLE),
        'current_thread': bind(kernel, 'GetCurrentThread', [], HANDLE),
        'open_process_token': bind(security, 'OpenProcessToken', [HANDLE, DWORD, ct.POINTER(HANDLE)], ct.c_int),
        'open_thread_token': bind(security, 'OpenThreadToken', [HANDLE, DWORD, ct.c_int, ct.POINTER(HANDLE)], ct.c_int),
        'token_info': bind(security, 'GetTokenInformation', [HANDLE, ct.c_int, HANDLE, DWORD, ct.POINTER(DWORD)], ct.c_int),
        'in_job': bind(kernel, 'IsProcessInJob', [HANDLE, HANDLE, ct.POINTER(ct.c_int)], ct.c_int),
        'job_info': bind(kernel, 'QueryInformationJobObject', [HANDLE, ct.c_int, HANDLE, DWORD, ct.POINTER(DWORD)], ct.c_int),
        'close': bind(kernel, 'CloseHandle', [HANDLE], ct.c_int),
    }
    return ct, api, (DWORD, HANDLE, TOKEN_GROUPS, SID_AND_ATTRIBUTES, EXTENDED_LIMIT, CPU_LIMIT)


def collect_current_process_observation(policy):
    """Future authorized query-only probe. No resource creation or release.

The caller must have a separately approved dedicated-child resource contract.
This function does not establish that approval. Failure returns incomplete data
and a bounded error code; evaluate_observation must still be called separately.
It reads only current process/thread tokens and the current immediate job.
It never lists processes, job member PIDs, named jobs, directories or sockets.
"""
    validate_policy(policy)
    import os

    result = {
        'schema': OBSERVATION_SCHEMA,
        'scope': 'CURRENT_PROCESS_AND_IMMEDIATE_JOB_ONLY',
        'query_complete': False, 'token': None, 'job': None,
        'collection_error': None,
    }
    if os.name != 'nt':
        result['collection_error'] = 'WINDOWS_REQUIRED'
        return result
    try:
        ct, api, layouts = _bind_windows_api()
        DWORD, HANDLE, TOKEN_GROUPS, SID_AND_ATTRIBUTES, EXTENDED_LIMIT, CPU_LIMIT = layouts
        handles = []

        def fail(code):
            raise PreparationError(code, str(ct.get_last_error()))

        def token_buffer(handle, info_class):
            needed = DWORD(0)
            ct.set_last_error(0)
            first = api['token_info'](handle, info_class, None, 0, ct.byref(needed))
            if first or ct.get_last_error() != 122:
                fail('TOKEN_SIZE_QUERY_FAILED')
            if not 4 <= needed.value <= MAX_TOKEN_BYTES:
                raise PreparationError('TOKEN_BUFFER_BUDGET_EXCEEDED')
            buffer = ct.create_string_buffer(needed.value)
            returned = DWORD(0)
            if not api['token_info'](handle, info_class, buffer, len(buffer), ct.byref(returned)):
                fail('TOKEN_READ_FAILED')
            if not 4 <= returned.value <= len(buffer):
                raise PreparationError('TOKEN_RETURN_LENGTH_INVALID')
            return buffer, returned.value

        def token_dword(handle, info_class):
            buffer, length = token_buffer(handle, info_class)
            if length != 4:
                raise PreparationError('TOKEN_DWORD_LENGTH_INVALID')
            return DWORD.from_buffer_copy(buffer.raw[:4]).value

        def token_bool(handle, info_class):
            value = token_dword(handle, info_class)
            if value not in (0, 1):
                raise PreparationError('TOKEN_BOOL_VALUE_INVALID')
            return bool(value)

        def sid_in_buffer(buffer, length, pointer):
            if not pointer:
                return None
            start = ct.addressof(buffer)
            offset = pointer - start
            if offset < 0 or offset + 8 > length:
                raise PreparationError('SID_POINTER_OUT_OF_BUFFER')
            head = buffer.raw[offset:offset + 8]
            size = 8 + 4 * head[1]
            if offset + size > length:
                raise PreparationError('SID_POINTER_OUT_OF_BUFFER')
            return _decode_sid_bytes(buffer.raw[offset:offset + size])

        def query_job(info_class, layout):
            value, returned = layout(), DWORD(0)
            if not api['job_info'](None, info_class, ct.byref(value), ct.sizeof(value), ct.byref(returned)):
                fail('CURRENT_JOB_QUERY_FAILED')
            if returned.value != ct.sizeof(value):
                raise PreparationError('JOB_RETURN_LENGTH_INVALID')
            return value

        try:
            thread_token = HANDLE()
            ct.set_last_error(0)
            if api['open_thread_token'](api['current_thread'](), 0x0008, 1, ct.byref(thread_token)):
                if not thread_token.value:
                    raise PreparationError('THREAD_TOKEN_HANDLE_INVALID')
                handles.append(thread_token)
                impersonating = True
            elif ct.get_last_error() == 1008:  # ERROR_NO_TOKEN, not access denied.
                impersonating = False
            else:
                fail('THREAD_TOKEN_STATE_UNKNOWN')
            process_token = HANDLE()
            if not api['open_process_token'](api['current_process'](), 0x0008, ct.byref(process_token)):
                fail('PROCESS_TOKEN_OPEN_FAILED')
            if not process_token.value:
                raise PreparationError('PROCESS_TOKEN_HANDLE_INVALID')
            handles.append(process_token)
            app_buffer, app_length = token_buffer(process_token, 31)
            if app_length < ct.sizeof(HANDLE):
                raise PreparationError('APPCONTAINER_BUFFER_INVALID')
            sid_pointer = HANDLE.from_buffer_copy(app_buffer.raw[:ct.sizeof(HANDLE)]).value
            app_sid = sid_in_buffer(app_buffer, app_length, sid_pointer)
            cap_buffer, cap_length = token_buffer(process_token, 30)
            count = DWORD.from_buffer_copy(cap_buffer.raw[:4]).value
            offset = TOKEN_GROUPS.Groups.offset
            stride = ct.sizeof(SID_AND_ATTRIBUTES)
            if count > MAX_CAPABILITIES or (count and offset + count * stride > cap_length):
                raise PreparationError('CAPABILITIES_BUFFER_INVALID')
            capabilities = []
            for index in range(count):
                begin = offset + index * stride
                item = SID_AND_ATTRIBUTES.from_buffer_copy(cap_buffer.raw[begin:begin + stride])
                capabilities.append({
                    'sid': sid_in_buffer(cap_buffer, cap_length, item.Sid),
                    'attributes': item.Attributes,
                })
            result['token'] = {
                'primary_token_type': token_dword(process_token, 8),
                'thread_impersonation_present': impersonating,
                'is_appcontainer': token_bool(process_token, 29),
                'appcontainer_sid': app_sid, 'capabilities': capabilities,
                'has_restrictions': token_bool(process_token, 21),
                'elevated': token_bool(process_token, 20),
                'elevation_type': token_dword(process_token, 18),
            }
            inside = ct.c_int(0)
            if not api['in_job'](api['current_process'](), None, ct.byref(inside)):
                fail('CURRENT_JOB_MEMBERSHIP_FAILED')
            if inside.value not in (0, 1):
                raise PreparationError('CURRENT_JOB_MEMBERSHIP_INVALID')
            if inside.value:
                extended = query_job(9, EXTENDED_LIMIT)
                cpu = query_job(15, CPU_LIMIT)
                result['job'] = {
                    'in_job': True, 'scope': 'IMMEDIATE_JOB_ONLY',
                    'limit_flags': extended.BasicLimitInformation.LimitFlags,
                    'active_process_limit': extended.BasicLimitInformation.ActiveProcessLimit,
                    'process_memory_limit_bytes': extended.ProcessMemoryLimit,
                    'job_memory_limit_bytes': extended.JobMemoryLimit,
                    'cpu_control_flags': cpu.ControlFlags,
                    'cpu_rate_hundredths': (cpu.CpuRate if
                                            cpu.ControlFlags == CPU_HARD_CAP_FLAGS else None),
                }
            else:
                result['job'] = {
                    'in_job': False, 'scope': 'IMMEDIATE_JOB_ONLY',
                    'limit_flags': None, 'active_process_limit': None,
                    'process_memory_limit_bytes': None, 'job_memory_limit_bytes': None,
                    'cpu_control_flags': None, 'cpu_rate_hundredths': None,
                }
        finally:
            close_failed = False
            for handle in reversed(handles):
                if not api['close'](handle):
                    close_failed = True
            if close_failed:
                raise PreparationError('TOKEN_HANDLE_CLOSE_FAILED')
        result['query_complete'] = True
    except PreparationError as error:
        result['collection_error'] = error.code + (':' + error.detail if error.detail else '')
    except (OSError, AttributeError, ValueError, TypeError, OverflowError):
        # Bounded code only: no platform/user/credential-bearing error strings.
        result['collection_error'] = 'WINDOWS_QUERY_UNAVAILABLE_OR_INVALID'
    return result
