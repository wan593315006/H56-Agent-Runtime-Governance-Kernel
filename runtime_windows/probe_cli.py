"""Fixed neutral actions in an already restricted, explicitly approved child.

No native import at module load. Manual host invocation cannot pass the live
AppContainer/token/Job readback and therefore cannot reach any probe action.
"""

_CHILD_ACTION_SEAL = object()


def _file_access(path, access, directory=False):
    import ctypes as ct
    kernel = ct.WinDLL('kernel32.dll', use_last_error=True)
    function = kernel.CreateFileW
    function.argtypes = [ct.c_wchar_p, ct.c_uint32, ct.c_uint32, ct.c_void_p,
                         ct.c_uint32, ct.c_uint32, ct.c_void_p]
    function.restype = ct.c_void_p
    close = kernel.CloseHandle
    close.argtypes, close.restype = [ct.c_void_p], ct.c_int
    handle = function(path, access, 7, None, 3, 0x00200000 | (0x02000000 if directory else 0), None)
    if not handle or handle == ct.c_void_p(-1).value:
        return dict(operation='CreateFileW', path=path, access=access, error=ct.get_last_error())
    closed = close(handle)
    return dict(operation='CreateFileW', path=path, access=access, error=0,
                unexpected_access=True, handle_closed=bool(closed))


def _no_child(plan):
    import ctypes as ct
    from .launch_contract import quote_argument
    value = plan.decoded()
    D, H, W = ct.c_uint32, ct.c_void_p, ct.c_wchar_p
    class SI(ct.Structure):
        _fields_ = [('cb',D),('lpReserved',W),('lpDesktop',W),('lpTitle',W),
            ('dwX',D),('dwY',D),('dwXSize',D),('dwYSize',D),('dwXCountChars',D),('dwYCountChars',D),
            ('dwFillAttribute',D),('dwFlags',D),('wShowWindow',ct.c_uint16),('cbReserved2',ct.c_uint16),
            ('lpReserved2',H),('hStdInput',H),('hStdOutput',H),('hStdError',H)]
    class PI(ct.Structure):
        _fields_ = [('hProcess',H),('hThread',H),('dwProcessId',D),('dwThreadId',D)]
    if ct.sizeof(SI) != 104 or ct.sizeof(PI) != 24:
        from .errors import PreparationError
        raise PreparationError('PROBE_CHILD_ABI_UNSUPPORTED')
    kernel = ct.WinDLL('kernel32.dll',use_last_error=True)
    def bind(name,args,result):
        fn=getattr(kernel,name); fn.argtypes,fn.restype=args,result; return fn
    create=bind('CreateProcessW',[W,H,H,H,ct.c_int,D,H,W,ct.POINTER(SI),ct.POINTER(PI)],ct.c_int)
    terminate=bind('TerminateProcess',[H,D],ct.c_int)
    wait=bind('WaitForSingleObject',[H,D],D)
    close=bind('CloseHandle',[H],ct.c_int)
    from pathlib import PureWindowsPath
    argv=[value['runtime']['python_executable'],'-I','-B','-S','-X','utf8',
        str(PureWindowsPath(value['paths']['product_root'])/'runtime_windows'/'probe_cli.py'),'--noop']
    command=ct.create_unicode_buffer(' '.join(quote_argument(x) for x in argv))
    startup,process=SI(),PI(); startup.cb=ct.sizeof(SI)
    # No inherited handles, no breakaway, never Resume an unexpected child.
    if not create(argv[0],command,None,None,0,0x4|0x08000000,None,
                  value['paths']['scratch_root'],ct.byref(startup),ct.byref(process)):
        return [dict(operation='CreateProcessW',error=ct.get_last_error())]
    event=dict(operation='CreateProcessW',error=0,unexpected_pid=process.dwProcessId,
               unexpected_access=True,terminated=False,wait_signaled=False,handles_closed=False)
    try:
        event['terminated']=bool(terminate(process.hProcess,0xE0560002))
        event['wait_signaled']=wait(process.hProcess,1000)==0
    finally:
        thread_closed=bool(close(process.hThread))
        process_closed=bool(close(process.hProcess))
        event['handles_closed']=thread_closed and process_closed
    return [event]


def execute_probe(plan, seal=None):
    """Called only after child_main's real current-token/Job comparison."""
    if seal is not _CHILD_ACTION_SEAL:
        from .errors import PreparationError
        raise PreparationError('PROBE_LIVE_CHILD_ACTION_CONTEXT_REQUIRED')
    value=plan.decoded(); check,target=value['check'],value['target']
    events,status=[], 'UNKNOWN'
    if check in ('file_access_negative','credential_access_negative'):
        events=[_file_access(target['path'],0x80000000),_file_access(target['path'],0x40000000)]
        status='EXPECTED_OS_REFUSAL' if all(item['error']==5 for item in events) else 'UNEXPECTED_ACCESS_OR_CREATION' if any(item['error']==0 for item in events) else 'UNKNOWN'
    elif check=='network_access_negative':
        import socket
        client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            client.settimeout(1.0)
            try:
                client.connect((target['address'],target['port']))
                error=0
            except OSError as failure:
                error=getattr(failure,'winerror',None) or failure.errno
            events=[dict(operation='connect',address=target['address'],port=target['port'],error=error)]
            status='EXPECTED_OS_REFUSAL' if error==10013 else 'UNEXPECTED_ACCESS_OR_CREATION' if error==0 else 'UNKNOWN'
        finally:
            client.close()
    elif check=='child_escape_negative':
        events=_no_child(plan)
        status='EXPECTED_OS_REFUSAL' if events[0]['error']==5 else 'UNEXPECTED_ACCESS_OR_CREATION' if events[0]['error']==0 else 'UNKNOWN'
    elif check=='resource_limit_negative':
        import time
        chunks=[]; allocated=0; deadline=time.monotonic()+min(2.0,value['limits']['total_ms']/2000)
        try:
            while allocated<target['allocation_budget_bytes'] and time.monotonic()<deadline:
                chunks.append(bytearray(target['chunk_bytes']))
                allocated+=target['chunk_bytes']
            reason='ALLOCATION_BUDGET_OR_DEADLINE_REACHED'
        except MemoryError:
            reason='MEMORY_REFUSAL_UNATTRIBUTED'
        finally:
            chunks.clear()
        # Refusal is real, but no false unique attribution to the Job is made.
        events=[dict(operation='bounded_memory_allocation',allocated_bytes=allocated,
            maximum_bytes=target['allocation_budget_bytes'],reason=reason)]
    elif check=='read_only_source':
        import hashlib
        from pathlib import Path,PureWindowsPath
        from .run_projection import read_projection_file as _read_checked
        root=Path(value['paths']['product_root']); directories=set()
        for relative in target['relative_files']:
            path=root.joinpath(*relative.split('/'))
            before=hashlib.sha256(_read_checked(path,None,1048576)).hexdigest()
            events.extend([_file_access(str(path),0x40000000),_file_access(str(path),0x00010000)])
            after=hashlib.sha256(_read_checked(path,None,1048576)).hexdigest()
            events.append(dict(operation='SOURCE_BYTES',path=str(path),before_sha256=before,after_sha256=after))
            parent=PureWindowsPath(str(path)).parent
            while str(parent).casefold().startswith(str(root).casefold()):
                directories.add(str(parent))
                if str(parent).casefold()==str(root).casefold(): break
                parent=parent.parent
        for path in sorted(directories):
            events.append(_file_access(path,0x40,directory=True))  # DELETE_CHILD
        opens=[item for item in events if item['operation']=='CreateFileW']
        unchanged=all(item['before_sha256']==item['after_sha256'] for item in events if item['operation']=='SOURCE_BYTES')
        status=('UNEXPECTED_ACCESS_OR_CREATION' if not unchanged or any(item['error']==0 for item in opens)
            else 'EXPECTED_OS_REFUSAL' if all(item['error']==5 for item in opens) else 'UNKNOWN')
    else:
        import hashlib
        from pathlib import Path
        from .source_identity import _check_chain
        from .run_projection import read_projection_file as _read_checked
        path=Path(target['path']); _check_chain(path,include_leaf=False)
        raw=bytes.fromhex(target['nonce_hex'])
        with path.open('xb') as stream:
            stream.write(raw); stream.flush()
        actual=_read_checked(path,len(raw),256)
        events=[dict(operation='PROFILE_WRITE_READBACK',path=str(path),size=len(actual),sha256=hashlib.sha256(actual).hexdigest())]
        status='OWN_PROFILE_WRITE_READBACK' if actual==raw else 'UNEXPECTED_ACCESS_OR_CREATION'
    return dict(kind=check,events=events,status=status)


def child_main(check):
    import os,sys
    from .launch_contract import decode_frame,encode_frame,build_environment,digest,fail
    from .probe_backend import validate_probe_plan
    from .kernel_probe import collect_current_process_observation,evaluate_observation
    if (os.name!='nt' or not sys.flags.isolated or not sys.flags.no_site or
            not sys.dont_write_bytecode or sys.flags.utf8_mode!=1):
        fail('PROBE_ISOLATED_CHILD_REQUIRED')
    header=sys.stdin.buffer.read(4)
    if len(header)!=4 or not 1<=int.from_bytes(header,'little')<=32768:
        fail('PROBE_CONTROL_HEADER')
    length=int.from_bytes(header,'little'); payload=sys.stdin.buffer.read(length)
    if len(payload)!=length: fail('PROBE_CONTROL_INCOMPLETE')
    from .bootstrap_contract import decode
    plan=validate_probe_plan(decode(payload)); value=plan.decoded()
    if check!=value['check'] or dict(os.environ)!=build_environment(plan):
        fail('PROBE_MODE_OR_ENV_MISMATCH')
    from pathlib import Path
    if str(Path(__file__).absolute().parents[1]).casefold()!=value['paths']['product_root'].casefold():
        fail('PROBE_ACTUAL_COPIED_ENTRY_REQUIRED')
    observation=collect_current_process_observation(value['observation_policy'])
    evaluation=evaluate_observation(value['observation_policy'],observation)
    if evaluation['status']!='OBSERVED_MATCH_NEGATIVE_TESTS_PENDING':
        fail('PROBE_LIVE_RESTRICTED_PROCESS_REQUIRED')
    action=execute_probe(plan,_CHILD_ACTION_SEAL)
    result=dict(schema='h56.windows-neutral-probe-result.v1',check=check,run_id=value['run_id'],
        request_sha256=plan.sha256,pid=os.getpid(),environment_sha256=digest(build_environment(plan)),
        observation=observation,action=action)
    sys.stdout.buffer.write(encode_frame(result,value['limits']['control_bytes']))
    sys.stdout.buffer.flush()
    return 0


def main():
    import argparse,sys
    from pathlib import Path
    sys.path.insert(0,str(Path(__file__).absolute().parents[1]))
    parser=argparse.ArgumentParser()
    parser.add_argument('--check'); parser.add_argument('--noop',action='store_true')
    args=parser.parse_args()
    if args.noop and args.check is None: return 0
    if args.noop or args.check is None: parser.error('Fixed check or no-op only')
    from runtime_windows.probe_backend import CHECKS
    if args.check not in CHECKS: parser.error('Unknown fixed check')
    from runtime_windows.probe_cli import child_main
    try:
        return child_main(args.check)
    except Exception as error:
        code=getattr(error,'code',type(error).__name__)
        sys.stderr.buffer.write(('PROBE_STOP:'+code+'\n').encode('ascii',errors='replace')[:256])
        sys.stderr.buffer.flush()
        return 2


if __name__=='__main__':
    raise SystemExit(main())
