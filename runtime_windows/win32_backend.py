"""Prepared native Windows observer backend. Explicit use only after a permit.

No native binding at import. This module is NOT run by source/pure tests.
Only objects created by this instance and current/returned-process tokens are
queried. No arbitrary PID, existing Job lookup, Profile creation or ACL edits.
"""

from .launch_contract import (
    BoundedCapture, command_line, environment_block, encode_frame,
    fail, require_permit,
)


_QUARANTINED_NATIVE_OPERATIONS = []
_NATIVE_TRANSPORT_SEAL = object()


class _OwnedWindowsTransport:
    """One native lifecycle; only explicit typed wrappers select a protocol."""
    def __init__(self, plan, construction_seal):
        if construction_seal is not _NATIVE_TRANSPORT_SEAL:
            fail('TYPED_TRANSPORT_WRAPPER_REQUIRED')
        import os
        if os.name != 'nt':
            fail('WINDOWS_REQUIRED')
        import time
        from .kernel_probe import _bind_windows_api
        ct, queries, layouts = _bind_windows_api()
        self.ct, self.time, self.plan = ct, time, plan
        self.data, self.queries = plan.decoded(), queries
        self.DWORD, self.HANDLE, _, _, self.EXTENDED, self.CPU = layouts
        self.handles, self.ops, self.buffers, self.errors, self.events = [], [], [], [], []
        self.capture = BoundedCapture(self.data['limits']['stdout_bytes'], self.data['limits']['stderr_bytes'])
        self.exit_code = None
        self.job = self.process = self.thread = None
        self.started = time.monotonic()
        self.deadline = self.started + self.data['limits']['total_ms'] / 1000
        self.startup_deadline = min(self.deadline, self.started + self.data['limits']['startup_ms'] / 1000)
        self._declare_and_bind()

    def _declare_and_bind(self):
        ct, D, H = self.ct, self.DWORD, self.HANDLE

        class SECURITY_ATTRIBUTES(ct.Structure):
            _fields_ = [('nLength', D), ('lpSecurityDescriptor', H), ('bInheritHandle', ct.c_int)]

        class OVERLAPPED(ct.Structure):
            _fields_ = [('Internal', ct.c_size_t), ('InternalHigh', ct.c_size_t),
                        ('Offset', D), ('OffsetHigh', D), ('hEvent', H)]

        class STARTUPINFO(ct.Structure):
            _fields_ = [('cb', D), ('lpReserved', ct.c_wchar_p), ('lpDesktop', ct.c_wchar_p),
                        ('lpTitle', ct.c_wchar_p), ('dwX', D), ('dwY', D), ('dwXSize', D),
                        ('dwYSize', D), ('dwXCountChars', D), ('dwYCountChars', D),
                        ('dwFillAttribute', D), ('dwFlags', D), ('wShowWindow', ct.c_uint16),
                        ('cbReserved2', ct.c_uint16), ('lpReserved2', H),
                        ('hStdInput', H), ('hStdOutput', H), ('hStdError', H)]

        class STARTUPINFOEX(ct.Structure):
            _fields_ = [('StartupInfo', STARTUPINFO), ('lpAttributeList', H)]

        class PROCESS_INFORMATION(ct.Structure):
            _fields_ = [('hProcess', H), ('hThread', H), ('dwProcessId', D), ('dwThreadId', D)]

        class SECURITY_CAPABILITIES(ct.Structure):
            _fields_ = [('AppContainerSid', H), ('Capabilities', H), ('CapabilityCount', D), ('Reserved', D)]

        if (ct.sizeof(SECURITY_ATTRIBUTES), ct.sizeof(OVERLAPPED), ct.sizeof(STARTUPINFO),
                ct.sizeof(STARTUPINFOEX), ct.sizeof(PROCESS_INFORMATION),
                ct.sizeof(SECURITY_CAPABILITIES)) != (24, 32, 104, 112, 24, 24):
            fail('LAUNCHER_ABI_LAYOUT_MISMATCH')
        self.SA, self.OV, self.SI, self.PI, self.SC = (
            SECURITY_ATTRIBUTES, OVERLAPPED, STARTUPINFOEX, PROCESS_INFORMATION,
            SECURITY_CAPABILITIES)
        kernel = ct.WinDLL('kernel32.dll', use_last_error=True)
        security = ct.WinDLL('advapi32.dll', use_last_error=True)

        def bind(dll, name, args, result):
            function = getattr(dll, name)
            function.argtypes, function.restype = args, result
            return function

        P = ct.POINTER
        specs = {
            'CreateJobObjectW': ([H, ct.c_wchar_p], H),
            'SetInformationJobObject': ([H, ct.c_int, H, D], ct.c_int),
            'QueryInformationJobObject': ([H, ct.c_int, H, D, P(D)], ct.c_int),
            'CreateNamedPipeW': ([ct.c_wchar_p, D, D, D, D, D, D, P(self.SA)], H),
            'CreateFileW': ([ct.c_wchar_p, D, D, P(self.SA), D, D, H], H),
            'CreateEventW': ([H, ct.c_int, ct.c_int, ct.c_wchar_p], H),
            'ConnectNamedPipe': ([H, P(self.OV)], ct.c_int),
            'GetOverlappedResultEx': ([H, P(self.OV), P(D), D, ct.c_int], ct.c_int),
            'CancelIoEx': ([H, P(self.OV)], ct.c_int),
            'ReadFile': ([H, H, D, P(D), P(self.OV)], ct.c_int),
            'WriteFile': ([H, H, D, P(D), P(self.OV)], ct.c_int),
            'SetHandleInformation': ([H, D, D], ct.c_int),
            'InitializeProcThreadAttributeList': ([H, D, D, P(ct.c_size_t)], ct.c_int),
            'UpdateProcThreadAttribute': ([H, D, ct.c_size_t, H, ct.c_size_t, H, H], ct.c_int),
            'DeleteProcThreadAttributeList': ([H], None),
            'CreateProcessW': ([ct.c_wchar_p, H, H, H, ct.c_int, D, H, ct.c_wchar_p,
                                P(self.SI), P(self.PI)], ct.c_int),
            'IsProcessInJob': ([H, H, P(ct.c_int)], ct.c_int),
            'ResumeThread': ([H], D),
            'WaitForSingleObject': ([H, D], D),
            'GetExitCodeProcess': ([H, P(D)], ct.c_int),
            'TerminateJobObject': ([H, D], ct.c_int),
            'CloseHandle': ([H], ct.c_int),
            'LocalFree': ([H], H),
        }
        self.api = {name: bind(kernel, name, args, result)
                    for name, (args, result) in specs.items()}
        self.api['ConvertStringSidToSidW'] = bind(security, 'ConvertStringSidToSidW',
                                                 [ct.c_wchar_p, P(H)], ct.c_int)
        self.api['ConvertStringSecurityDescriptorToSecurityDescriptorW'] = bind(
            security, 'ConvertStringSecurityDescriptorToSecurityDescriptorW',
            [ct.c_wchar_p, D, P(H), P(D)], ct.c_int)
        self.allocations, self.attributes = [], None

    def _native_error(self, code):
        fail(code, str(self.ct.get_last_error()))

    def _own(self, role, handle):
        if not handle or handle == self.ct.c_void_p(-1).value:
            self._native_error('OWNED_HANDLE_CREATION_FAILED:' + role)
        self.handles.append((role, handle))
        return handle

    def _close(self, handle):
        match = [(role, value) for role, value in self.handles if value == handle]
        if not match:
            return
        if not self.api['CloseHandle'](handle):
            self._native_error('OWNED_HANDLE_CLOSE_FAILED:' + match[0][0])
        self.handles.remove(match[0])

    def _deadline_ms(self, deadline):
        remaining = deadline - self.time.monotonic()
        if remaining <= 0:
            fail('OBSERVER_TIMEOUT')
        return max(1, min(100, int(remaining * 1000)))

    def _query_job(self, info_class, layout):
        value, length = layout(), self.DWORD(0)
        if not self.api['QueryInformationJobObject'](self.job, info_class,
                self.ct.byref(value), self.ct.sizeof(value), self.ct.byref(length)):
            self._native_error('OWNED_JOB_READBACK_FAILED')
        if length.value != self.ct.sizeof(value):
            fail('OWNED_JOB_READBACK_LENGTH')
        return value

    def create_job(self):
        from .kernel_probe import REQUIRED_JOB_FLAGS, CPU_HARD_CAP_FLAGS
        self.job = self._own('job', self.api['CreateJobObjectW'](None, None))
        policy, extended, cpu = self.data['observation_policy'], self.EXTENDED(), self.CPU()
        extended.BasicLimitInformation.LimitFlags = REQUIRED_JOB_FLAGS
        extended.BasicLimitInformation.ActiveProcessLimit = policy['active_process_limit']
        extended.ProcessMemoryLimit = policy['process_memory_limit_bytes']
        extended.JobMemoryLimit = policy['job_memory_limit_bytes']
        cpu.ControlFlags, cpu.CpuRate = CPU_HARD_CAP_FLAGS, policy['cpu_rate_hundredths']
        for number, value in ((9, extended), (15, cpu)):
            if not self.api['SetInformationJobObject'](self.job, number,
                    self.ct.byref(value), self.ct.sizeof(value)):
                self._native_error('OWNED_JOB_LIMIT_SET_FAILED')
        actual, rate = self._query_job(9, self.EXTENDED), self._query_job(15, self.CPU)
        if (actual.BasicLimitInformation.LimitFlags != REQUIRED_JOB_FLAGS or
                actual.BasicLimitInformation.ActiveProcessLimit != policy['active_process_limit'] or
                actual.ProcessMemoryLimit != policy['process_memory_limit_bytes'] or
                actual.JobMemoryLimit != policy['job_memory_limit_bytes'] or
                rate.ControlFlags != CPU_HARD_CAP_FLAGS or rate.CpuRate != policy['cpu_rate_hundredths']):
            fail('OWNED_JOB_LIMIT_READBACK_MISMATCH')
        self.events.append('OWNED_JOB_LIMITS_READ_BACK')

    def _token_buffer(self, token, info_class):
        needed = self.DWORD()
        self.ct.set_last_error(0)
        first = self.queries['token_info'](token, info_class, None, 0, self.ct.byref(needed))
        if first or self.ct.get_last_error() != 122 or not 4 <= needed.value <= 65536:
            fail('OWNED_TOKEN_SIZE_INVALID')
        buffer, returned = self.ct.create_string_buffer(needed.value), self.DWORD()
        if not self.queries['token_info'](token, info_class, buffer, len(buffer), self.ct.byref(returned)):
            self._native_error('OWNED_TOKEN_READ_FAILED')
        if not 4 <= returned.value <= len(buffer):
            fail('OWNED_TOKEN_LENGTH_INVALID')
        return buffer, returned.value

    def _sid(self, buffer, length, offset):
        from .kernel_probe import _decode_sid_bytes
        if offset < 0 or offset + 8 > length:
            fail('OWNED_TOKEN_SID_BOUNDS')
        size = 8 + 4 * buffer.raw[offset + 1]
        if offset + size > length:
            fail('OWNED_TOKEN_SID_BOUNDS')
        return _decode_sid_bytes(buffer.raw[offset:offset + size])

    def _with_process_token(self, process, callback):
        token = self.HANDLE()
        if not self.queries['open_process_token'](process, 8, self.ct.byref(token)):
            self._native_error('BOUND_PROCESS_TOKEN_QUERY_FAILED')
        self._own('queried_token', token.value)
        try:
            return callback(token)
        finally:
            self._close(token.value)

    def _current_user_sid(self):
        def read(token):
            buffer, length = self._token_buffer(token, 1)
            if length < 16:
                fail('CURRENT_USER_TOKEN_INVALID')
            pointer = self.HANDLE.from_buffer_copy(buffer.raw[:8]).value
            if not pointer:
                fail('CURRENT_USER_TOKEN_SID_MISSING')
            return self._sid(buffer, length, pointer - self.ct.addressof(buffer))
        return self._with_process_token(self.queries['current_process'](), read)

    def _new_operation(self, handle, kind, buffer=None):
        event = self._own('overlapped_event', self.api['CreateEventW'](None, 1, 0, None))
        operation = {'handle': handle, 'kind': kind, 'buffer': buffer,
                     'ov': self.OV(), 'done': False, 'bytes': 0, 'eof': False}
        operation['ov'].hEvent = event
        self.ops.append(operation)
        return operation

    def _poll(self, operation, milliseconds=0, cancelling=False):
        if operation['done']:
            return True
        count = self.DWORD()
        if self.api['GetOverlappedResultEx'](operation['handle'], self.ct.byref(operation['ov']),
                                           self.ct.byref(count), milliseconds, 0):
            operation['done'], operation['bytes'] = True, count.value
            return True
        code = self.ct.get_last_error()
        if code in (258, 996):
            return False
        if code in (109, 38) or (cancelling and code == 995):
            operation['done'], operation['eof'] = True, True
            return True
        operation['done'] = True
        fail('OWNED_OVERLAPPED_FAILED', str(code))

    def _retire(self, operation):
        if operation.get('retired'):
            return
        if not operation['done']:
            fail('PENDING_OPERATION_CANNOT_BE_RETIRED')
        self._close(operation['ov'].hEvent)
        self.ops.remove(operation)
        operation['retired'] = True

    def create_pipes(self):
        import secrets
        parent_sid, child_sid = self._current_user_sid(), self.data['profile']['sid']
        self.parent_pipes, self.child_pipes = {}, {}
        for role in ('control', 'stdout', 'stderr'):
            # Exact rights exclude FILE_CREATE_PIPE_INSTANCE / FILE_APPEND_DATA.
            child_access = 0x00100001 if role == 'control' else 0x00100002
            descriptor = self.HANDLE()
            sddl = ('O:' + parent_sid + 'D:P(A;;GA;;;' + parent_sid +
                    ')(A;;GA;;;SY)(A;;0x' + format(child_access, 'x') + ';;;' +
                    child_sid + ')S:(ML;;NW;;;LW)')
            if not self.api['ConvertStringSecurityDescriptorToSecurityDescriptorW'](
                    sddl, 1, self.ct.byref(descriptor), None):
                self._native_error('PIPE_PRIVATE_DESCRIPTOR_FAILED')
            self.allocations.append(descriptor.value)
            server_sa, child_sa = self.SA(), self.SA()
            server_sa.nLength = child_sa.nLength = self.ct.sizeof(self.SA)
            server_sa.lpSecurityDescriptor = descriptor.value
            child_sa.bInheritHandle = 1
            name = '\\\\.\\pipe\\LOCAL\\h56_observe_' + secrets.token_hex(16) + '_' + role
            access = 2 if role == 'control' else 1
            server = self._own(role + '_parent', self.api['CreateNamedPipeW'](
                name, access | 0x40000000 | 0x00080000, 8, 1, 4096, 4096,
                0, self.ct.byref(server_sa)))
            operation = self._new_operation(server, 'connect')
            if self.api['ConnectNamedPipe'](server, self.ct.byref(operation['ov'])):
                operation['done'] = True
            elif self.ct.get_last_error() not in (997, 535):
                self._native_error('PIPE_CONNECT_BEGIN_FAILED')
            elif self.ct.get_last_error() == 535:
                operation['done'] = True
            child = self._own(role + '_child', self.api['CreateFileW'](
                name, child_access, 0, self.ct.byref(child_sa), 3, 0, None))
            while not self._poll(operation, self._deadline_ms(self.startup_deadline)):
                pass
            self._retire(operation)
            self.parent_pipes[role], self.child_pipes[role] = server, child
        self.events.append('THREE_PRIVATE_NAMED_PIPE_PAIRS_CREATED')

    def _attribute(self, key, value):
        self.buffers.append(value)
        if not self.api['UpdateProcThreadAttribute'](self.attributes, 0, key,
                self.ct.byref(value), self.ct.sizeof(value), None, None):
            self._native_error('PROCESS_ATTRIBUTE_FAILED:' + str(key))

    def create_suspended_child_in_job(self):
        ct, count = self.ct, self.ct.c_size_t()
        ct.set_last_error(0)
        if self.api['InitializeProcThreadAttributeList'](None, 4, 0, ct.byref(count)) or ct.get_last_error() != 122:
            fail('ATTRIBUTE_LIST_SIZE_QUERY_FAILED')
        if not 1 <= count.value <= 65536:
            fail('ATTRIBUTE_LIST_BUDGET')
        buffer = ct.create_string_buffer(count.value)
        self.buffers.append(buffer)
        if not self.api['InitializeProcThreadAttributeList'](buffer, 4, 0, ct.byref(count)):
            self._native_error('ATTRIBUTE_LIST_INIT_FAILED')
        self.attributes = ct.cast(buffer, self.HANDLE)
        sid = self.HANDLE()
        if not self.api['ConvertStringSidToSidW'](self.data['profile']['sid'], ct.byref(sid)):
            self._native_error('BOUND_PROFILE_SID_CONVERSION_FAILED')
        self.allocations.append(sid.value)
        capabilities = self.SC()
        capabilities.AppContainerSid = sid.value
        # CapabilityCount=0 and Capabilities=NULL intentionally.
        self._attribute(0x00020009, capabilities)  # SECURITY_CAPABILITIES
        inherited = (self.HANDLE * 3)(*(self.child_pipes[x] for x in ('control', 'stdout', 'stderr')))
        self._attribute(0x00020002, inherited)  # HANDLE_LIST
        self._attribute(0x0002000D, (self.HANDLE * 1)(self.job))  # JOB_LIST (Windows10+)
        self._attribute(0x0002000E, self.DWORD(1))  # CHILD_PROCESS_POLICY
        startup, process = self.SI(), self.PI()
        startup.StartupInfo.cb = ct.sizeof(startup)
        startup.StartupInfo.dwFlags = 0x100  # STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = self.child_pipes['control']
        startup.StartupInfo.hStdOutput = self.child_pipes['stdout']
        startup.StartupInfo.hStdError = self.child_pipes['stderr']
        startup.lpAttributeList = self.attributes
        command = ct.create_unicode_buffer(self._command_line())
        environment = ct.create_unicode_buffer(self._environment_block())
        self.buffers.extend((command, environment, startup, process))
        flags = 0x4 | 0x00080000 | 0x400 | 0x08000000
        if not self.api['CreateProcessW'](self.data['runtime']['python_executable'],
                command, None, None, 1, flags, environment,
                self.data['paths']['scratch_root'], ct.byref(startup), ct.byref(process)):
            self._native_error('APPContainer_JOB_LIST_SUSPENDED_CREATE_FAILED')
        self.process = self._own('process', process.hProcess)
        self.thread = self._own('thread', process.hThread)
        self.pid = process.dwProcessId
        inside = ct.c_int()
        if not self.api['IsProcessInJob'](self.process, self.job, ct.byref(inside)) or inside.value != 1:
            fail('CREATED_CHILD_NOT_IN_OWNED_JOB')
        def check_token(token):
            expected_policy = self.data['observation_policy']
            for info_class, expected in ((8, 1), (29, 1), (20, 0),
                    (18, expected_policy['elevation_type']),
                    (21, int(expected_policy['token_has_restrictions']))):
                raw, size = self._token_buffer(token, info_class)
                if size != 4 or self.DWORD.from_buffer_copy(raw.raw[:4]).value != expected:
                    fail('CREATED_CHILD_TOKEN_READBACK_MISMATCH')
            caps, _ = self._token_buffer(token, 30)
            if self.DWORD.from_buffer_copy(caps.raw[:4]).value != 0:
                fail('CREATED_CHILD_CAPABILITIES_NOT_EMPTY')
            raw, size = self._token_buffer(token, 31)
            if size < 8:
                fail('CREATED_CHILD_PROFILE_BUFFER_INVALID')
            pointer = self.HANDLE.from_buffer_copy(raw.raw[:8]).value
            if not pointer or self._sid(raw, size, pointer - ct.addressof(raw)) != self.data['profile']['sid']:
                fail('CREATED_CHILD_PROFILE_IDENTITY_MISMATCH')
        self._with_process_token(self.process, check_token)
        for handle in tuple(self.child_pipes.values()):
            self._close(handle)
        self.events.append('CREATED_SUSPENDED_IN_OWNED_JOB_TOKEN_CHECKED')

    def resume(self):
        self._deadline_ms(self.startup_deadline)
        if not self.thread or self.api['ResumeThread'](self.thread) != 1:
            self._native_error('OWNED_CHILD_RESUME_FAILED')
        self.events.append('OWNED_CHILD_RESUMED')

    def _io(self, handle, kind, data=None):
        buffer = self.ct.create_string_buffer(data, len(data)) if kind == 'write' else self.ct.create_string_buffer(4096)
        operation = self._new_operation(handle, kind, buffer)
        amount = self.DWORD()
        function = self.api['WriteFile'] if kind == 'write' else self.api['ReadFile']
        if function(handle, buffer, len(buffer), self.ct.byref(amount), self.ct.byref(operation['ov'])):
            operation['done'], operation['bytes'] = True, amount.value
        elif self.ct.get_last_error() in (109, 38):
            operation['done'], operation['eof'] = True, True
        elif self.ct.get_last_error() != 997:
            self._native_error('OWNED_PIPE_IO_BEGIN_FAILED')
        return operation

    def pump(self):
        control = self._control_payload()
        writer = self._io(self.parent_pipes['control'], 'write', control) if control is not None else None
        if writer is None:
            self._close(self.parent_pipes['control'])
        reads = {role: self._io(self.parent_pipes[role], 'read') for role in ('stdout', 'stderr')}
        output = self.capture.buffers
        exited = False
        while True:
            self._deadline_ms(self.deadline)
            if writer is not None:
                self._poll(writer)
            if writer is not None and writer['done'] and writer['bytes'] != len(control):
                fail('CONTROL_WRITE_INCOMPLETE')
            if writer is not None and writer['done'] and not writer.get('retired'):
                self._retire(writer)
                self._close(self.parent_pipes['control'])
            for role in ('stdout', 'stderr'):
                op = reads[role]
                if op is not None and self._poll(op):
                    if op['bytes']:
                        if not 0 <= op['bytes'] <= len(op['buffer']):
                            fail('OWNED_PIPE_RETURN_LENGTH_INVALID')
                        if not self.capture.accept(role, op['buffer'].raw[:op['bytes']]):
                            fail('OBSERVER_OUTPUT_BUDGET', role)
                    self._retire(op)
                    reads[role] = None if op['eof'] else self._io(self.parent_pipes[role], 'read')
            if not self._startup_ready(output['stdout']) and self.time.monotonic() >= self.startup_deadline:
                fail('OBSERVER_STARTUP_FRAME_TIMEOUT')
            wait = self.api['WaitForSingleObject'](self.process, 0)
            if wait == 0:
                exited = True
            elif wait != 258:
                self._native_error('OWNED_PROCESS_WAIT_FAILED')
            if exited and all(value is None for value in reads.values()) and (writer is None or writer['done']):
                break
            self.time.sleep(min(0.01, max(0, self.deadline - self.time.monotonic())))
        code = self.DWORD()
        if not self.api['GetExitCodeProcess'](self.process, self.ct.byref(code)):
            self._native_error('OWNED_PROCESS_EXIT_QUERY_FAILED')
        self.exit_code = code.value
        self.events.append('OWNED_CHILD_EXITED_OUTPUT_DRAINED')
        return {'exit_code': code.value, 'stdout': bytes(output['stdout']),
                'stderr': bytes(output['stderr']), 'pid': self.pid}

    def snapshot(self):
        """Pure copy of already observed bounded bytes, including on failure."""
        value = self.capture.snapshot()
        value.update({'pid': getattr(self, 'pid', None), 'exit_code': self.exit_code})
        return value

    def cleanup(self):
        deadline = self.time.monotonic() + self.data['limits']['cleanup_ms'] / 1000
        if self.job and not self.api['TerminateJobObject'](self.job, 0xE0560001):
            self.errors.append('OWNED_JOB_TERMINATION_FAILED:' + str(self.ct.get_last_error()))
        if self.process:
            remaining = max(0, int((deadline - self.time.monotonic()) * 1000))
            if self.api['WaitForSingleObject'](self.process, remaining) != 0:
                self.errors.append('OWNED_PROCESS_TERMINATION_NOT_CONFIRMED')
        for operation in self.ops:
            if not operation['done']:
                if not self.api['CancelIoEx'](operation['handle'], self.ct.byref(operation['ov'])):
                    if self.ct.get_last_error() != 1168:
                        self.errors.append('OWNED_IO_CANCEL_REQUEST_FAILED')
                try:
                    while not operation['done'] and self.time.monotonic() < deadline:
                        self._poll(operation, max(1, min(20, int((deadline - self.time.monotonic()) * 1000))), cancelling=True)
                except Exception:
                    self.errors.append('OWNED_IO_CANCEL_COMPLETION_FAILED')
        pending = [op for op in self.ops if not op['done']]
        if pending:
            # Retain buffers/OVERLAPPED/handles: cancellation is not completion.
            _QUARANTINED_NATIVE_OPERATIONS.append(self)
            self.errors.append('OWNED_IO_PENDING_QUARANTINED_LEAK_POSSIBLE')
            if self.job:
                try:
                    self._close(self.job)
                except Exception:
                    self.errors.append('OWNED_JOB_CLOSE_FAILED')
            return {'status': 'UNKNOWN_LEAK_POSSIBLE', 'errors': list(self.errors)}
        if self.attributes is not None:
            self.api['DeleteProcThreadAttributeList'](self.attributes)
            self.attributes = None
        for pointer in reversed(self.allocations):
            if self.api['LocalFree'](pointer):
                self.errors.append('OWNED_LOCALFREE_FAILED')
        self.allocations.clear()
        # Job last; no child receives it or can keep its last owning handle alive.
        ordered = [item for item in reversed(self.handles) if item[0] != 'job']
        ordered += [item for item in self.handles if item[0] == 'job']
        for role, handle in ordered:
            try:
                self._close(handle)
            except Exception:
                self.errors.append('OWNED_HANDLE_CLOSE_FAILED:' + role)
        return {'status': 'CLOSED' if not self.errors else 'CLEANUP_NOT_VERIFIED',
                'errors': list(self.errors)}


class WindowsBackend(_OwnedWindowsTransport):
    """Original C1 observation wrapper; cannot consume a candidate permit."""
    def __init__(self, plan, permit):
        require_permit(plan, permit)
        super().__init__(plan, _NATIVE_TRANSPORT_SEAL)

    def _command_line(self):
        return command_line(self.plan)

    def _environment_block(self):
        return environment_block(self.plan)

    def _control_payload(self):
        return encode_frame(self.plan.decoded(), self.data['limits']['control_bytes'])

    def _startup_ready(self, output):
        if len(output) >= 4 and int.from_bytes(output[:4], 'little') + 4 > self.data['limits']['control_bytes']:
            fail('OBSERVER_FRAME_LENGTH_BUDGET')
        return len(output) >= 4 and len(output) >= int.from_bytes(output[:4], 'little') + 4


class CandidateWindowsBackend(_OwnedWindowsTransport):
    """Typed fixed-CLI wrapper. Imports candidate dependencies only on use."""
    def __init__(self, plan, permit):
        from .host_contract import require_candidate_permit
        require_candidate_permit(plan, permit)
        super().__init__(plan, _NATIVE_TRANSPORT_SEAL)

    def _command_line(self):
        from .host_contract import candidate_command_line
        return candidate_command_line(self.plan)

    def _environment_block(self):
        from .host_contract import candidate_environment_block
        return candidate_environment_block(self.plan)

    def _control_payload(self):
        return None  # CLI receives no stdin action/module/request transport.

    def _startup_ready(self, output):
        # Windows startup ends after checked suspended creation and Resume.
        # Core initialization/computation has only the separate total deadline.
        return True
