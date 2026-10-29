"""Typed neutral-probe protocol over the existing single native transport.

Import does not bind native APIs. Preparation permits are scoped trusted-host
objects, not candidate permission or proof of empirical isolation.
"""
import hashlib
from pathlib import PureWindowsPath

from .bootstrap_contract import FrozenPlan, require_preparation_permit
from .launch_contract import (SCHEMA, TOP_KEYS, canonical, digest, exact, fail,
    validate_launch_request, windows_path, contains, quote_argument, encode_frame,
    decode_frame, environment_block)
from .win32_backend import _OwnedWindowsTransport, _NATIVE_TRANSPORT_SEAL


CHECKS = ('file_access_negative', 'credential_access_negative', 'network_access_negative',
    'child_escape_negative', 'resource_limit_negative', 'read_only_source', 'profile_storage_scope')
PROBE_KEYS = frozenset(TOP_KEYS) | {'session_id', 'check', 'target'}
PARENT_KEYS = frozenset(('schema', 'check', 'run_id', 'request_sha256', 'source_identity',
    'status', 'pid', 'exit_code', 'raw_stdout', 'raw_stderr', 'observed_output_bytes',
    'capture_prefix_truncated', 'events', 'stop_reason', 'cleanup', 'cleanup_exception',
    'positive_control', 'independent_readback', 'resource_evidence'))


def validate_probe_plan(value):
    from .bootstrap_contract import token, relative_name
    exact(value, PROBE_KEYS, 'PROBE_PLAN_FIELDS')
    if value['schema'] != 'h56.windows-neutral-probe.v1' or value['mode'] != 'NEUTRAL_PROBE_ONLY':
        fail('PROBE_MODE_ONLY')
    token(value['session_id'])
    if value['check'] not in CHECKS:
        fail('PROBE_FIXED_CHECK_REQUIRED')
    base = {key:value[key] for key in TOP_KEYS}
    base.update(schema=SCHEMA, mode='OBSERVATION_ONLY')
    validate_launch_request(base)  # pure reuse; does not issue an observation permit
    target, check = value['target'], value['check']
    if check in ('file_access_negative', 'credential_access_negative'):
        from .launch_contract import sha
        exact(target, ('path', 'expected_size', 'expected_sha256'), 'PROBE_CANARY_FIELDS')
        windows_path(target['path'])
        private = str(PureWindowsPath(value['paths']['product_root']) / 'runtime_windows' / '.local' / value['session_id'] / 'host_private')
        if (PureWindowsPath(target['path']).parent != PureWindowsPath(private) or
                type(target['expected_size']) is not int or not 16 <= target['expected_size'] <= 4096 or not sha(target['expected_sha256'])):
            fail('PROBE_HOST_ONLY_CANARY_SCOPE')
    elif check == 'network_access_negative':
        from .launch_contract import sha
        exact(target, ('address', 'port', 'sentinel_id', 'positive_receipt_sha256'), 'PROBE_SENTINEL_FIELDS')
        token(target['sentinel_id'])
        if (target['address'] != '127.0.0.1' or type(target['port']) is not int or not 1024 <= target['port'] <= 65535
                or not sha(target['positive_receipt_sha256'])):
            fail('PROBE_OWN_LOOPBACK_ONLY')
    elif check == 'child_escape_negative':
        exact(target, ('script_relative',), 'PROBE_NOOP_FIELDS')
        if target['script_relative'] != 'runtime_windows/probe_cli.py':
            fail('PROBE_FIXED_NOOP_ONLY')
    elif check == 'resource_limit_negative':
        exact(target, ('allocation_budget_bytes', 'chunk_bytes', 'policy_relation'), 'PROBE_MEMORY_FIELDS')
        if (type(target['allocation_budget_bytes']) is not int or not 1048576 <= target['allocation_budget_bytes'] <= 134217728 or
                target['chunk_bytes'] != 1048576 or type(target['chunk_bytes']) is not int or
                target['policy_relation'] != 'SAME_AS_OBSERVER' or
                target['allocation_budget_bytes'] != value['observation_policy']['process_memory_limit_bytes'] or
                target['allocation_budget_bytes'] != value['observation_policy']['job_memory_limit_bytes']):
            fail('PROBE_MEMORY_SAME_POLICY_BUDGET_REQUIRED')
    elif check == 'read_only_source':
        exact(target, ('relative_files',), 'PROBE_SOURCE_FIELDS')
        paths = target['relative_files']
        if (type(paths) is not list or not 1 <= len(paths) <= 256 or
                any(type(x) is not str or not 1 <= len(x) <= 512 for x in paths) or len({x.casefold() for x in paths}) != len(paths)):
            fail('PROBE_SOURCE_FILE_BUDGET')
        for name in paths:
            relative_name(name)
            if name.startswith('runtime_windows/.local/'):
                fail('PROBE_SOURCE_PRIVATE_INPUT_FORBIDDEN')
    else:
        import hashlib
        exact(target, ('path', 'nonce_sha256', 'nonce_hex'), 'PROBE_PROFILE_FIELDS')
        windows_path(target['path'])
        if type(target['nonce_hex']) is not str or not 32 <= len(target['nonce_hex']) <= 512:
            fail('PROBE_SYNTHETIC_NONCE_INVALID')
        try:
            nonce = bytes.fromhex(target['nonce_hex'])
        except (ValueError, TypeError):
            fail('PROBE_SYNTHETIC_NONCE_INVALID')
        if (not 16 <= len(nonce) <= 256 or hashlib.sha256(nonce).hexdigest() != target['nonce_sha256'] or
                not contains(value['profile']['storage_root'], target['path']) or
                PureWindowsPath(target['path']).parent != PureWindowsPath(value['profile']['storage_root'])):
            fail('PROBE_PROFILE_OWN_NEW_FILE_ONLY')
    if len(canonical(value)) > 32768:
        fail('PROBE_CONTROL_REQUEST_BUDGET')
    if check=='read_only_source':
        files,directories=source_actions(value)
        sample=[]
        for path in files:
            sample.extend([dict(operation='CreateFileW',path=path,access=access,error=5) for access in (0x40000000,0x10000)])
            sample.append(dict(operation='SOURCE_BYTES',path=path,before_sha256='f'*64,after_sha256='f'*64))
        sample.extend(dict(operation='CreateFileW',path=path,access=0x40,error=5) for path in directories)
        if len(canonical(sample))+4096>value['limits']['control_bytes']-4: fail('PROBE_SOURCE_RESULT_FRAME_BUDGET')
    return FrozenPlan(value)


def probe_argv(plan):
    value = plan.decoded()
    path = str(PureWindowsPath(value['paths']['product_root']) / 'runtime_windows' / 'probe_cli.py')
    return [value['runtime']['python_executable'], '-I', '-B', '-S', '-X', 'utf8', path, '--check', value['check']]


class PreflightWindowsBackend(_OwnedWindowsTransport):
    def __init__(self, plan, permit):
        if type(plan) is not FrozenPlan or validate_probe_plan(plan.decoded()).sha256 != plan.sha256:
            fail('PROBE_FROZEN_PLAN_REQUIRED')
        require_preparation_permit(plan, permit, 'NEGATIVE_PROBE')
        super().__init__(plan, _NATIVE_TRANSPORT_SEAL)
        self.resource_evidence = None

    def create_job(self):
        super().create_job()
        if self.data['check'] != 'resource_limit_negative':
            return
        # This one private port is associated while the newly owned Job is
        # inactive. It is not inherited and never receives shared-engine data.
        ct,D,H=self.ct,self.DWORD,self.HANDLE
        class ASSOCIATION(ct.Structure):
            _fields_=[('CompletionKey',H),('CompletionPort',H)]
        if ct.sizeof(ASSOCIATION)!=16: fail('PROBE_IOCP_ABI_LAYOUT')
        kernel=ct.WinDLL('kernel32.dll',use_last_error=True)
        create=kernel.CreateIoCompletionPort
        create.argtypes,create.restype=[H,H,ct.c_size_t,D],H
        get=kernel.GetQueuedCompletionStatus
        get.argtypes,get.restype=[H,ct.POINTER(D),ct.POINTER(ct.c_size_t),ct.POINTER(H),D],ct.c_int
        self._get_completion=get
        self.completion_port=self._own('probe_completion_port',create(H(-1),None,0,1))
        association=ASSOCIATION(self.job,self.completion_port)
        if not self.api['SetInformationJobObject'](self.job,7,ct.byref(association),ct.sizeof(association)):
            self._native_error('PROBE_OWNED_JOB_IOCP_ASSOCIATION_FAILED')
        actual=self._query_job(9,self.EXTENDED)
        self.resource_evidence=dict(schema='h56.windows-owned-job-memory-evidence.v1',
            association='OWNED_JOB_BEFORE_CHILD',completion_key=int(self.job),process_id=None,
            process_memory_limit_bytes=int(actual.ProcessMemoryLimit),job_memory_limit_bytes=int(actual.JobMemoryLimit),
            limit_flags=int(actual.BasicLimitInformation.LimitFlags),messages=[],collection_status='NOT_COLLECTED',
            message_budget=64,elapsed_budget_ms=50)

    def _collect_owned_notifications(self):
        if self.resource_evidence is None: return
        ct=self.ct;deadline=min(self.deadline,self.time.monotonic()+0.05)
        self.resource_evidence['process_id']=getattr(self,'pid',None)
        # lpOverlapped is a message-specific integer PID, not an address to
        # dereference. Process and Job handles remain owned until cleanup.
        for unused in range(64):
            if self.time.monotonic()>=deadline:
                self.resource_evidence['collection_status']='BUDGET_EXHAUSTED';return
            message,key,pid=self.DWORD(),ct.c_size_t(),self.HANDLE()
            ct.set_last_error(0)
            if not self._get_completion(self.completion_port,ct.byref(message),ct.byref(key),ct.byref(pid),0):
                error=ct.get_last_error()
                if error==258 and not pid.value:
                    self.resource_evidence['collection_status']='QUEUE_DRAINED';return
                self.resource_evidence['collection_status']='NATIVE_READ_FAILED'
                fail('PROBE_OWNED_IOCP_READ_FAILED',str(error))
            self.resource_evidence['messages'].append(dict(message=message.value,completion_key=key.value,process_id=pid.value))
        self.resource_evidence['collection_status']='BUDGET_EXHAUSTED'

    def pump(self):
        primary=None;result=None
        try: result=super().pump()
        except BaseException as error: primary=error
        try: self._collect_owned_notifications()
        except Exception as error:
            if primary is None: primary=error
            else: self.errors.append('PROBE_IOCP_COLLECTION_NOT_VERIFIED')
        if primary is not None: raise primary
        return result

    def _command_line(self):
        return ' '.join(quote_argument(x) for x in probe_argv(self.plan))

    def _environment_block(self):
        return environment_block(self.plan)

    def _control_payload(self):
        return encode_frame(self.data, self.data['limits']['control_bytes'])

    def _startup_ready(self, output):
        if len(output) >= 4 and int.from_bytes(output[:4], 'little') + 4 > self.data['limits']['control_bytes']:
            fail('PROBE_FRAME_BUDGET')
        return len(output) >= 4 and len(output) >= int.from_bytes(output[:4], 'little') + 4


def canary_bytes(value):
    """Fixed synthetic bytes only; never reads host credentials."""
    seed=hashlib.sha256(('H56_TEST_CANARY:'+value['session_id']+':'+value['check']+':'+value['run_id']).encode('ascii')).digest()
    size=value['target']['expected_size']
    return (seed*((size+31)//32))[:size]


class _LoopbackSentinel:
    def __init__(self,value):
        self.value=value;self.listener=None;self.positive=None

    def start(self):
        import socket
        target=self.value['target']
        listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);self.listener=listener
        # No SO_REUSEADDR: collision must stop, never adopt another endpoint.
        listener.settimeout(1.0);listener.bind((target['address'],target['port']));listener.listen(1)
        challenge=hashlib.sha256(('H56_LOOPBACK:'+target['sentinel_id']).encode('ascii')).digest()
        client=socket.socket(socket.AF_INET,socket.SOCK_STREAM);accepted=None;primary=None
        try:
            client.settimeout(1.0);client.connect((target['address'],target['port']))
            accepted,peer=listener.accept();accepted.settimeout(1.0)
            if peer[0]!='127.0.0.1': fail('PROBE_SENTINEL_PEER_MISMATCH')
            client.sendall(challenge)
            observed=accepted.recv(len(challenge)+1)
            if observed!=challenge: fail('PROBE_SENTINEL_CHALLENGE_MISMATCH')
            accepted.sendall(observed)
            if client.recv(len(challenge)+1)!=challenge: fail('PROBE_SENTINEL_ECHO_MISMATCH')
            self.positive=dict(schema='h56.windows-loopback-positive.v1',sentinel_id=target['sentinel_id'],
                address=target['address'],port=target['port'],challenge_sha256=hashlib.sha256(challenge).hexdigest(),
                status='HOST_ROUNDTRIP_OBSERVED')
            if digest(self.positive)!=target['positive_receipt_sha256']: fail('PROBE_SENTINEL_POSITIVE_IDENTITY')
        except BaseException as error:
            primary=error
        finally:
            _close_sentinel_endpoints((accepted,client),primary)

    def close(self):
        if self.listener is not None:
            self.listener.close();self.listener=None


def _close_sentinel_endpoints(endpoints,primary=None):
    """Attempt every owned close and retain the original stop cause."""
    cleanup=[]
    for index,endpoint in enumerate(endpoints):
        if endpoint is None: continue
        try: endpoint.close()
        except BaseException as error: cleanup.append('OWNED_ENDPOINT_'+str(index)+'_CLOSE_FAILED:'+type(error).__name__)
    if primary is not None:
        if cleanup: primary.args+=('cleanup='+','.join(cleanup),)
        raise primary
    if cleanup: fail('PROBE_SENTINEL_ENDPOINT_CLEANUP_NOT_VERIFIED',','.join(cleanup))


def run_probe(plan, permit):
    require_preparation_permit(plan, permit, 'NEGATIVE_PROBE')
    value = validate_probe_plan(plan.decoded()).decoded()
    receipt = dict(schema='h56.windows-neutral-parent-receipt.v1', check=value['check'],
        run_id=value['run_id'], request_sha256=plan.sha256, source_identity=value['source_identity'],
        status='NOT_VERIFIED', pid=None, exit_code=None, raw_stdout=b'', raw_stderr=b'',
        observed_output_bytes=dict(stdout=0, stderr=0), capture_prefix_truncated=dict(stdout=False, stderr=False),
        events=[], stop_reason=None, cleanup=dict(status='NO_RESOURCES_CREATED',errors=[]), cleanup_exception=None,
        positive_control=None,independent_readback=None,resource_evidence=None)
    import time
    started=time.monotonic();deadline=started+value['limits']['total_ms']/1000
    backend=sentinel=None;source_before=None
    try:
        from pathlib import Path
        from .run_projection import read_projection_file
        if value['check'] in ('file_access_negative','credential_access_negative'):
            raw=canary_bytes(value)
            if hashlib.sha256(raw).hexdigest()!=value['target']['expected_sha256']: fail('PROBE_CANARY_DECLARATION_IDENTITY')
            target=Path(value['target']['path'])
            from .source_identity import _check_chain
            _check_chain(target.parent)
            # A collision stops without overwriting or deleting that object.
            with target.open('xb') as stream:
                import os
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            if read_projection_file(target,len(raw),4096)!=raw: fail('PROBE_HOST_CANARY_READBACK')
            receipt['independent_readback']=dict(path=str(target),size=len(raw),sha256=hashlib.sha256(raw).hexdigest(),status='HOST_CANARY_BYTES_READ_BACK')
        elif value['check']=='network_access_negative':
            sentinel=_LoopbackSentinel(value);sentinel.start();receipt['positive_control']=dict(sentinel.positive)
        elif value['check']=='profile_storage_scope':
            from .source_identity import _check_chain
            target=Path(value['target']['path']);_check_chain(target.parent)
            try: target.lstat()
            except FileNotFoundError: pass
            else: fail('PROBE_PROFILE_TARGET_COLLISION')
        elif value['check']=='read_only_source':
            source_before=[]
            for path in source_actions(value)[0]:
                raw=read_projection_file(Path(path),None,1048576)
                source_before.append(dict(path=path,before_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw)))
        if time.monotonic()>=deadline: fail('PROBE_PARENT_PREPARATION_TIMEOUT')
        backend = PreflightWindowsBackend(plan, permit)
        backend.deadline=min(backend.deadline,deadline)
        backend.startup_deadline=min(backend.startup_deadline,deadline)
        backend.create_job()
        backend.create_pipes()
        backend.create_suspended_child_in_job()
        backend.resume()
        backend.pump()
        receipt['status'] = 'RAW_RESULT_COLLECTED'
    except (Exception,KeyboardInterrupt) as error:
        receipt['stop_reason'] = getattr(error, 'code', type(error).__name__)
    finally:
        if backend is not None:
            try: receipt.update(backend.snapshot())
            except Exception as error:
                receipt['stop_reason']=receipt['stop_reason'] or 'PROBE_CAPTURE_SNAPSHOT_FAILED'
            receipt['events'] = list(backend.events)
            receipt['resource_evidence']=backend.resource_evidence
            try:
                receipt['cleanup'] = backend.cleanup()
            except BaseException as error:
                receipt['cleanup'], receipt['cleanup_exception'] = dict(status='CLEANUP_NOT_VERIFIED',errors=['PROBE_CLEANUP_EXCEPTION']), type(error).__name__
            try: receipt.update(backend.snapshot())
            except Exception:
                receipt['stop_reason']=receipt['stop_reason'] or 'PROBE_CAPTURE_SNAPSHOT_FAILED'
            if value['check']=='profile_storage_scope' and receipt['cleanup'].get('status')=='CLOSED' and receipt['stop_reason'] is None:
                try:
                    target=value['target'];raw=read_projection_file(Path(target['path']),len(bytes.fromhex(target['nonce_hex'])),256)
                    if raw!=bytes.fromhex(target['nonce_hex']): fail('PROBE_PROFILE_PARENT_CONTENT_DRIFT')
                    receipt['independent_readback']=dict(path=target['path'],size=len(raw),sha256=hashlib.sha256(raw).hexdigest(),status='HOST_FILE_READ_BACK')
                except (Exception,KeyboardInterrupt) as error:
                    receipt['stop_reason']=getattr(error,'code',type(error).__name__)
            if source_before is not None and receipt['cleanup'].get('status')=='CLOSED':
                records=[]
                try:
                    for item in source_before:
                        raw=read_projection_file(Path(item['path']),item['size'],1048576)
                        records.append(dict(item,after_sha256=hashlib.sha256(raw).hexdigest()))
                    receipt['independent_readback']=dict(schema='h56.windows-source-bytes-readback.v1',files=records,status='HOST_SOURCE_BYTES_READ_BACK')
                except (Exception,KeyboardInterrupt) as error:
                    receipt['stop_reason']=receipt['stop_reason'] or getattr(error,'code',type(error).__name__)
            if (receipt['cleanup'].get('status') != 'CLOSED' or receipt['exit_code'] != 0 or receipt['stop_reason'] is not None
                    or any(receipt['capture_prefix_truncated'].values())):
                receipt['status'] = 'NOT_VERIFIED'
        if sentinel is not None:
            try: sentinel.close()
            except BaseException as error:
                receipt['cleanup']['errors'].append('PROBE_SENTINEL_CLOSE_FAILED')
                receipt['cleanup']['status']='CLEANUP_NOT_VERIFIED';receipt['status']='NOT_VERIFIED'
                receipt['stop_reason']=receipt['stop_reason'] or type(error).__name__
    return receipt


def _file_event(event,path,access):
    if type(event) is not dict: fail('PROBE_NATIVE_FILE_EVENT_REQUIRED')
    keys=('operation','path','access','error')
    if event.get('error')==0:
        keys+=('unexpected_access','handle_closed')
    exact(event,keys,'PROBE_NATIVE_FILE_EVENT_FIELDS')
    if (event['operation']!='CreateFileW' or event['path']!=path or type(event['access']) is not int or
            event['access']!=access or type(event['error']) is not int or not 0<=event['error']<=0xffffffff):
        fail('PROBE_NATIVE_FILE_ACTION_OR_TARGET_MISMATCH')
    if event['error']==0 and (event['unexpected_access'] is not True or type(event['handle_closed']) is not bool):
        fail('PROBE_UNEXPECTED_HANDLE_EVENT_REQUIRED')
    return event['error']


def source_actions(value):
    root=PureWindowsPath(value['paths']['product_root']);files=[];directories=set()
    for relative in value['target']['relative_files']:
        path=root.joinpath(*relative.split('/'));files.append(str(path));parent=path.parent
        while contains(str(root),str(parent)):
            directories.add(str(parent))
            if parent==root: break
            parent=parent.parent
    return files,sorted(directories)


def _action_status(value,action):
    """Exact per-check event contract, never generic error-code matching."""
    check,target=value['check'],value['target'];events=action['events'];codes=[];unchanged=True
    if check in ('file_access_negative','credential_access_negative'):
        if len(events)!=2: fail('PROBE_CANARY_ACTION_COUNT')
        codes=[_file_event(event,target['path'],access) for event,access in zip(events,(0x80000000,0x40000000))]
    elif check=='network_access_negative':
        if len(events)!=1: fail('PROBE_NETWORK_ACTION_COUNT')
        item=events[0];exact(item,('operation','address','port','error'),'PROBE_NETWORK_EVENT_FIELDS')
        if (item['operation']!='connect' or item['address']!=target['address'] or type(item['port']) is not int or
                item['port']!=target['port'] or type(item['error']) is not int or not 0<=item['error']<=0xffffffff):
            fail('PROBE_NETWORK_EVENT_SCOPE')
        codes=[item['error']]
    elif check=='child_escape_negative':
        if len(events)!=1: fail('PROBE_CHILD_ACTION_COUNT')
        item=events[0]
        keys=('operation','error')
        if item.get('error')==0: keys+=('unexpected_pid','unexpected_access','terminated','wait_signaled','handles_closed')
        exact(item,keys,'PROBE_CHILD_EVENT_FIELDS')
        if item['operation']!='CreateProcessW' or type(item['error']) is not int or not 0<=item['error']<=0xffffffff:
            fail('PROBE_CHILD_EVENT_SCOPE')
        if item['error']==0 and (type(item['unexpected_pid']) is not int or not 1<=item['unexpected_pid']<=0xffffffff or
                item['unexpected_access'] is not True or any(type(item[x]) is not bool for x in ('terminated','wait_signaled','handles_closed'))):
            fail('PROBE_UNEXPECTED_CHILD_CLEANUP_EVENT')
        codes=[item['error']]
    elif check=='read_only_source':
        files,directories=source_actions(value)
        if len(events)!=len(files)*3+len(directories): fail('PROBE_SOURCE_ACTION_COUNT')
        for index,path in enumerate(files):
            block=events[index*3:index*3+3]
            codes.extend((_file_event(block[0],path,0x40000000),_file_event(block[1],path,0x10000)))
            item=block[2];exact(item,('operation','path','before_sha256','after_sha256'),'PROBE_SOURCE_BYTES_FIELDS')
            from .launch_contract import sha
            if item['operation']!='SOURCE_BYTES' or item['path']!=path or not sha(item['before_sha256']) or not sha(item['after_sha256']):
                fail('PROBE_SOURCE_BYTES_BINDING')
            unchanged=unchanged and item['before_sha256']==item['after_sha256']
        for event,path in zip(events[len(files)*3:],directories): codes.append(_file_event(event,path,0x40))
    elif check=='profile_storage_scope':
        if len(events)!=1: fail('PROBE_PROFILE_ACTION_COUNT')
        item=events[0];exact(item,('operation','path','size','sha256'),'PROBE_PROFILE_EVENT_FIELDS')
        if (item['operation']!='PROFILE_WRITE_READBACK' or item['path']!=target['path'] or type(item['size']) is not int or
                item['size']!=len(bytes.fromhex(target['nonce_hex'])) or item['sha256']!=target['nonce_sha256']):
            fail('PROBE_PROFILE_EVENT_BINDING')
        if action['status']!='OWN_PROFILE_WRITE_READBACK': fail('PROBE_PROFILE_STATUS_INCONSISTENT')
        return 'RAW_EXPECTATION_MET_PENDING_ACCEPTANCE'
    else:
        if len(events)!=1: fail('PROBE_MEMORY_ACTION_COUNT')
        item=events[0];exact(item,('operation','allocated_bytes','maximum_bytes','reason'),'PROBE_MEMORY_EVENT_FIELDS')
        if (item['operation']!='bounded_memory_allocation' or type(item['allocated_bytes']) is not int or
                not 0<=item['allocated_bytes']<=target['allocation_budget_bytes'] or item['allocated_bytes']%target['chunk_bytes'] or
                type(item['maximum_bytes']) is not int or item['maximum_bytes']!=target['allocation_budget_bytes'] or
                item['reason'] not in ('MEMORY_REFUSAL_UNATTRIBUTED','ALLOCATION_BUDGET_OR_DEADLINE_REACHED') or action['status']!='UNKNOWN'):
            fail('PROBE_MEMORY_EVENT_BINDING')
        return 'UNKNOWN'  # parent-only owned Job notification may add attribution
    expected=10013 if check=='network_access_negative' else 5
    derived=('UNEXPECTED_ACCESS_OR_CREATION' if not unchanged or 0 in codes else
        'EXPECTED_OS_REFUSAL' if codes and all(x==expected for x in codes) else 'UNKNOWN')
    if action['status']!=derived: fail('PROBE_ACTION_STATUS_INCONSISTENT')
    return 'FAIL' if derived=='UNEXPECTED_ACCESS_OR_CREATION' else 'RAW_EXPECTATION_MET_PENDING_ACCEPTANCE' if derived=='EXPECTED_OS_REFUSAL' else 'UNKNOWN'


def validate_probe_result(plan, raw_stdout, parent_pid):
    """Pure scope/result consistency; cannot authenticate a fabricated frame."""
    from .kernel_probe import evaluate_observation
    value = validate_probe_plan(plan.decoded()).decoded()
    child = decode_frame(raw_stdout, value['limits']['control_bytes'])
    exact(child, ('schema', 'check', 'run_id', 'request_sha256', 'pid', 'environment_sha256',
        'observation', 'action'), 'PROBE_CHILD_RESULT_FIELDS')
    from .launch_contract import build_environment
    if (child['schema'] != 'h56.windows-neutral-probe-result.v1' or child['check'] != value['check'] or
            child['run_id'] != value['run_id'] or child['request_sha256'] != plan.sha256 or
            type(parent_pid) is not int or not 1 <= parent_pid <= 0xFFFFFFFF or child['pid'] != parent_pid or
            type(child['pid']) is not int or child['environment_sha256'] != digest(build_environment(plan))):
        fail('PROBE_CHILD_BINDING_MISMATCH')
    evaluation = evaluate_observation(value['observation_policy'], child['observation'])
    action = child['action']
    exact(action, ('kind', 'events', 'status'), 'PROBE_ACTION_FIELDS')
    if action['kind'] != value['check'] or type(action['events']) is not list or len(action['events']) > 2048:
        fail('PROBE_ACTION_SCOPE')
    status=_action_status(value,action)
    if evaluation['status']!='OBSERVED_MATCH_NEGATIVE_TESTS_PENDING': status='UNKNOWN'
    # MemoryError cannot by itself establish whether this Job or host pressure
    # caused refusal. Narrower-policy or unattributed evidence never becomes PASS.
    return dict(schema='h56.windows-neutral-check-evaluation.v1', check=value['check'], run_id=value['run_id'],
        status=status, details=action, observation_evaluation=evaluation,
        isolation_accepted=False, runtime_authorized=False, candidate_computation='NOT_RUN')


def evaluate_parent_probe(plan,receipt):
    """Pure consumption of child+parent evidence; not a receipt authenticator.

    Only the approved concrete native producer makes these fields observations.
    A synthetic dictionary passed here remains synthetic consistency evidence.
    """
    value=validate_probe_plan(plan.decoded()).decoded();check=value['check'];target=value['target']
    exact(receipt,PARENT_KEYS,'PROBE_PARENT_RECEIPT_FIELDS')
    if (receipt['schema']!='h56.windows-neutral-parent-receipt.v1' or receipt['check']!=check or
            receipt['run_id']!=value['run_id'] or receipt['request_sha256']!=plan.sha256 or receipt['source_identity']!=value['source_identity']):
        fail('PROBE_PARENT_RECEIPT_BINDING')
    result=validate_probe_result(plan,receipt['raw_stdout'],receipt['pid'])
    if (receipt['status']!='RAW_RESULT_COLLECTED' or type(receipt['exit_code']) is not int or receipt['exit_code']!=0 or
            receipt['stop_reason'] is not None or receipt['cleanup_exception'] is not None or
            receipt['cleanup']!={'status':'CLOSED','errors':[]}):
        result['status']='UNKNOWN';return result
    if check in ('file_access_negative','credential_access_negative'):
        observed=receipt['independent_readback']
        exact(observed,('path','size','sha256','status'),'PROBE_PARENT_CANARY_FIELDS')
        expected=dict(path=target['path'],size=target['expected_size'],sha256=target['expected_sha256'],status='HOST_CANARY_BYTES_READ_BACK')
        if observed!=expected or type(observed['size']) is not int: fail('PROBE_PARENT_CANARY_IDENTITY')
    elif check=='network_access_negative':
        positive=receipt['positive_control'];exact(positive,('schema','sentinel_id','address','port','challenge_sha256','status'),'PROBE_POSITIVE_FIELDS')
        challenge=hashlib.sha256(('H56_LOOPBACK:'+target['sentinel_id']).encode('ascii')).digest()
        expected=dict(schema='h56.windows-loopback-positive.v1',sentinel_id=target['sentinel_id'],address=target['address'],port=target['port'],
            challenge_sha256=hashlib.sha256(challenge).hexdigest(),status='HOST_ROUNDTRIP_OBSERVED')
        if positive!=expected or type(positive['port']) is not int or digest(positive)!=target['positive_receipt_sha256']:
            fail('PROBE_PARENT_SENTINEL_BINDING')
    elif check=='profile_storage_scope':
        observed=receipt['independent_readback'];exact(observed,('path','size','sha256','status'),'PROBE_PARENT_PROFILE_FIELDS')
        if observed!=dict(path=target['path'],size=len(bytes.fromhex(target['nonce_hex'])),sha256=target['nonce_sha256'],status='HOST_FILE_READ_BACK') or type(observed['size']) is not int:
            fail('PROBE_PARENT_PROFILE_BINDING')
    elif check=='read_only_source':
        observed=receipt['independent_readback'];exact(observed,('schema','files','status'),'PROBE_PARENT_SOURCE_FIELDS')
        files=source_actions(value)[0]
        if (observed['schema']!='h56.windows-source-bytes-readback.v1' or observed['status']!='HOST_SOURCE_BYTES_READ_BACK' or
                type(observed['files']) is not list or len(observed['files'])!=len(files)): fail('PROBE_PARENT_SOURCE_COVERAGE')
        for index,(item,path) in enumerate(zip(observed['files'],files)):
            exact(item,('path','size','before_sha256','after_sha256'),'PROBE_PARENT_SOURCE_FILE_FIELDS')
            from .launch_contract import sha
            child=result['details']['events'][index*3+2]
            if (item['path']!=path or type(item['size']) is not int or not 0<=item['size']<=1048576 or
                    not sha(item['before_sha256']) or not sha(item['after_sha256']) or
                    item['before_sha256']!=child['before_sha256'] or item['after_sha256']!=child['after_sha256']):
                fail('PROBE_PARENT_SOURCE_BINDING')
            if item['before_sha256']!=item['after_sha256']: result['status']='FAIL'
    if check!='network_access_negative' and receipt['positive_control'] is not None: fail('PROBE_UNEXPECTED_POSITIVE_CONTROL')
    if check not in ('file_access_negative','credential_access_negative','profile_storage_scope','read_only_source') and receipt['independent_readback'] is not None:
        fail('PROBE_UNEXPECTED_PARENT_FILE_READBACK')
    if check!='resource_limit_negative':
        if receipt['resource_evidence'] is not None: fail('PROBE_UNEXPECTED_RESOURCE_EVIDENCE')
        return result
    evidence=receipt['resource_evidence']
    if evidence is None: return result
    exact(evidence,('schema','association','completion_key','process_id','process_memory_limit_bytes',
        'job_memory_limit_bytes','limit_flags','messages','collection_status','message_budget','elapsed_budget_ms'),'PROBE_MEMORY_PARENT_FIELDS')
    from .kernel_probe import REQUIRED_JOB_FLAGS
    integer_keys=('completion_key','process_id','process_memory_limit_bytes','job_memory_limit_bytes','limit_flags','message_budget','elapsed_budget_ms')
    if any(type(evidence[key]) is not int for key in integer_keys): fail('PROBE_MEMORY_PARENT_INTEGER_FIELDS')
    if (evidence['schema']!='h56.windows-owned-job-memory-evidence.v1' or evidence['association']!='OWNED_JOB_BEFORE_CHILD' or
            not 1<=evidence['completion_key']<=0xffffffffffffffff or evidence['process_id']!=receipt['pid'] or
            evidence['process_memory_limit_bytes']!=value['observation_policy']['process_memory_limit_bytes'] or
            evidence['job_memory_limit_bytes']!=value['observation_policy']['job_memory_limit_bytes'] or
            evidence['limit_flags']!=REQUIRED_JOB_FLAGS or evidence['message_budget']!=64 or evidence['elapsed_budget_ms']!=50 or
            evidence['collection_status'] not in ('QUEUE_DRAINED','BUDGET_EXHAUSTED','NATIVE_READ_FAILED','NOT_COLLECTED')):
        fail('PROBE_MEMORY_PARENT_POLICY_OR_IDENTITY')
    messages=evidence['messages']
    if type(messages) is not list or len(messages)>64: fail('PROBE_MEMORY_PARENT_MESSAGE_BUDGET')
    match=False
    for item in messages:
        exact(item,('message','completion_key','process_id'),'PROBE_MEMORY_PARENT_MESSAGE_FIELDS')
        if (type(item['message']) is not int or not 1<=item['message']<=0xffffffff or type(item['completion_key']) is not int or
                not 1<=item['completion_key']<=0xffffffffffffffff or
                (item['process_id'] is not None and (type(item['process_id']) is not int or not 1<=item['process_id']<=0xffffffff))):
            fail('PROBE_MEMORY_PARENT_MESSAGE_TYPES')
        if item['completion_key']!=evidence['completion_key']: fail('PROBE_FOREIGN_COMPLETION_KEY')
        # Microsoft-owned SDK implementation defines process-memory=9 and
        # job-memory=10. No generic exit or MemoryError is accepted instead.
        if item['message'] in (9,10) and item['process_id']==receipt['pid']: match=True
    child_refusal=result['details']['events'][0]['reason']=='MEMORY_REFUSAL_UNATTRIBUTED'
    if (match and child_refusal and evidence['collection_status']=='QUEUE_DRAINED' and
            result['observation_evaluation']['status']=='OBSERVED_MATCH_NEGATIVE_TESTS_PENDING'):
        result['status']='RAW_EXPECTATION_MET_PENDING_ACCEPTANCE'
    return result
