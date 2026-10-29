"""Explicit new-object resource production, never candidate acceptance.

No native binding at import. A scoped preparation permit, immutable plan and
real materialization ledger are required before binding any Windows APIs.
Original files/ACLs, shared ancestors and existing Profiles are never adopted.
"""
import hashlib
import ntpath
from pathlib import Path

from .bootstrap_contract import FrozenPlan, canonical, decode, digest, exact, fail, sha, token, require_preparation_permit
from .launch_contract import windows_path, contains
from .host_resources import ResourceReadback


RESOURCE_KEYS=('schema','session_id','projection_receipt_sha256','projection_plan_sha256',
    'candidate_manifest_sha256','bootstrap_manifest_sha256','product_root','runtime_root','host_user_sid',
    'profile_name','profile_store_parent','paths','policy','registry_objects')


def validate_resource_plan(value):
    import re
    exact(value,RESOURCE_KEYS,'PREPARE_RESOURCE_FIELDS')
    if value['schema']!='h56.windows-resource-preparation-plan.v1': fail('PREPARE_RESOURCE_SCHEMA')
    token(value['session_id'])
    for key in ('projection_receipt_sha256','projection_plan_sha256','candidate_manifest_sha256','bootstrap_manifest_sha256'):
        if not sha(value[key]) or value[key]=='0'*64: fail('PREPARE_SOURCE_UNBOUND')
    for key in ('product_root','runtime_root','profile_store_parent'): windows_path(value[key])
    if contains(value['product_root'],value['runtime_root']) or contains(value['runtime_root'],value['product_root']):
        fail('PREPARE_RUNTIME_SOURCE_OVERLAP')
    if type(value['host_user_sid']) is not str or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',value['host_user_sid']):
        fail('PREPARE_OWNER_SID_UNBOUND')
    if type(value['profile_name']) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',value['profile_name']):
        fail('PREPARE_UNIQUE_PROFILE_NAME_REQUIRED')
    paths=value['paths']; exact(paths,('scratch_root','receipt_input_root','control_root','evidence_root','host_private_root'),'PREPARE_PATH_FIELDS')
    base=ntpath.join(value['product_root'],'runtime_windows','.local',value['session_id'])
    names=dict(scratch_root='scratch',receipt_input_root='replay_input',control_root='control',
        evidence_root='host_evidence',host_private_root='host_private')
    for key,name in names.items():
        if windows_path(paths[key])!=windows_path(ntpath.join(base,name)): fail('PREPARE_FIXED_PRIVATE_ROOTS_REQUIRED')
    policy=value['policy']
    exact(policy,('capabilities','token_has_restrictions','elevation_type','active_process_limit',
        'process_memory_limit_bytes','job_memory_limit_bytes','cpu_rate_hundredths'),'PREPARE_POLICY_FIELDS')
    if (policy['capabilities']!=[] or type(policy['token_has_restrictions']) is not bool or
            type(policy['elevation_type']) is not int or policy['elevation_type'] not in (1,3) or
            type(policy['active_process_limit']) is not int or policy['active_process_limit']!=1):
        fail('PREPARE_FIXED_SINGLE_PROCESS_POLICY')
    for key in ('process_memory_limit_bytes','job_memory_limit_bytes'):
        if type(policy[key]) is not int or not 33554432<=policy[key]<=134217728: fail('PREPARE_MEMORY_BUDGET')
    if policy['process_memory_limit_bytes']!=policy['job_memory_limit_bytes']:
        fail('PREPARE_SAME_MEMORY_BUDGET_REQUIRED')
    if type(policy['cpu_rate_hundredths']) is not int or not 1<=policy['cpu_rate_hundredths']<=1000:
        fail('PREPARE_CPU_BUDGET')
    registries=value['registry_objects']
    if type(registries) is not list or len(registries)>16: fail('PREPARE_REGISTRY_BUDGET')
    for item in registries:
        exact(item,('hive','subkey'),'PREPARE_NAMED_REGISTRY_FIELDS')
        if (item['hive']!='HKEY_CURRENT_USER' or type(item['subkey']) is not str or not 1<=len(item['subkey'])<=512 or
                '/' in item['subkey'] or '\x00' in item['subkey'] or any(x in ('','.','..') for x in item['subkey'].split('\\'))):
            fail('PREPARE_NAMED_REGISTRY_ONLY')
        if any(('{' in part or '}' in part) and part!='{PROFILE_SID}' for part in item['subkey'].split('\\')):
            fail('PREPARE_REGISTRY_TEMPLATE_COMPONENT')
    return FrozenPlan(value)


def validate_projection_ownership(plan,raw):
    """Pure ledger scope; actual file identities are rechecked before ACL writes."""
    value=validate_resource_plan(plan.decoded()).decoded()
    if type(raw) is not bytes or hashlib.sha256(raw).hexdigest()!=value['projection_receipt_sha256']:
        fail('PREPARE_PROJECTION_RECEIPT_IDENTITY')
    receipt=decode(raw)
    if (receipt.get('schema')!='h56.windows-run-projection-receipt.v1' or receipt.get('status')!='COPIED_BYTES_VERIFIED_ONLY' or
            receipt.get('plan_sha256')!=value['projection_plan_sha256'] or
            receipt.get('product_root')!=value['product_root'] or receipt.get('runtime_root')!=value['runtime_root'] or
            receipt.get('owned_roots')!=[value['product_root'],value['runtime_root']] or
            receipt.get('isolation_verified') is not False or receipt.get('authority_granted') is not False):
        fail('PREPARE_REAL_NEW_COPY_LEDGER_REQUIRED')
    objects=receipt.get('created_objects')
    if type(objects) is not list or not 2<=len(objects)<=16384: fail('PREPARE_OWNED_OBJECT_LEDGER_REQUIRED')
    seen=set();total=0
    for item in objects:
        if type(item) is not dict or item.get('kind') not in ('file','directory'): fail('PREPARE_OWNED_OBJECT_INVALID')
        path=windows_path(item.get('path'))
        if path in seen or not any(contains(root,item['path']) for root in receipt['owned_roots']):
            fail('PREPARE_OWNED_OBJECT_OUTSIDE_NEW_ROOTS')
        if item.get('role')!=owned_role(value,item['path']): fail('PREPARE_OWNED_OBJECT_ROLE_GEOMETRY')
        seen.add(path)
        identity=item.get('file_identity')
        exact(identity,('device','inode','links','attributes'),'PREPARE_FILE_IDENTITY_REQUIRED')
        if any(type(identity[key]) is not int for key in identity) or identity['attributes']&0x400:
            fail('PREPARE_REPARSE_OR_UNKNOWN_IDENTITY')
        if item['kind']=='file' and (identity['links']!=1 or type(item.get('size')) is not int or not sha(item.get('sha256'))):
            fail('PREPARE_PLAIN_COPY_FILE_REQUIRED')
        if item['kind']=='file':
            if not 0<=item['size']<=67108864: fail('PREPARE_OWNED_FILE_BUDGET')
            total+=item['size']
    if total>1073741824: fail('PREPARE_OWNED_TOTAL_BYTES_BUDGET')
    if not all(windows_path(root) in seen for root in receipt['owned_roots']): fail('PREPARE_ROOT_OWNERSHIP_MISSING')
    return receipt


def _same_identity(path,item):
    from .source_identity import _check_chain,_check_stat
    directory=item['kind']=='directory'
    _check_chain(Path(path),include_leaf=directory)
    value=Path(path).lstat(); _check_stat(value,directory,str(path))
    expected=item['file_identity']
    if (value.st_dev,value.st_ino,value.st_nlink,getattr(value,'st_file_attributes',0))!=(
            expected['device'],expected['inode'],expected['links'],expected['attributes']):
        fail('PREPARE_COPIED_OBJECT_IDENTITY_DRIFT')
    if not directory:
        from .run_projection import read_projection_file
        raw=read_projection_file(Path(path),item['size'],67108864)
        if hashlib.sha256(raw).hexdigest()!=item['sha256']: fail('PREPARE_COPIED_BYTES_DRIFT')


def _descriptor(host_sid,app_sid,kind,role):
    inherit='OICI' if kind=='directory' else ''
    prefix='D:P(A;'+inherit+';FA;;;'+host_sid+')(A;'+inherit+';FA;;;SY)'
    if role=='HOST_ONLY': return prefix
    if role=='RECEIPT_READ_ONLY' and kind=='directory':
        return prefix+'(A;;0x1200a9;;;'+app_sid+')(A;OIIO;0x120089;;;'+app_sid+')(A;CIIO;0x1200a9;;;'+app_sid+')S:(ML;OICI;NW;;;LW)'
    rights='0x1301bf' if role=='SCRATCH_READ_WRITE' else '0x120089' if role=='RECEIPT_READ_ONLY' else '0x1200a9'
    result=prefix+'(A;'+inherit+';'+rights+';;;'+app_sid+')'
    if role=='SCRATCH_READ_WRITE': result+='S:(ML;'+inherit+';NW;;;LW)'
    return result


def owned_role(value,path):
    """The role is fixed by new-root geometry, never a ledger-supplied claim."""
    base=ntpath.join(value['product_root'],'runtime_windows','.local',value['session_id'])
    private=[value['paths']['evidence_root'],value['paths']['host_private_root'],
        ntpath.join(base,'preparation'),ntpath.join(base,'preparation_control')]
    if any(contains(root,path) for root in private): return 'HOST_ONLY'
    if contains(value['paths']['scratch_root'],path): return 'SCRATCH_READ_WRITE'
    if contains(value['paths']['receipt_input_root'],path): return 'RECEIPT_READ_ONLY'
    return 'SOURCE_READ_EXECUTE'


class _PreparationNative(ResourceReadback):
    """Reuse handle-bound readback methods, not final candidate verification.

    The final ResourceReadback constructor/verify is deliberately not called:
    it requires controls that do not yet exist. This explicit phase binder only
    exposes new-owned mutation and named metadata readback behind its own permit.
    """
    def __init__(self,plan,permit,scope):
        require_preparation_permit(plan,permit,scope)
        if scope not in ('RESOURCE_PREPARE','RESOURCE_READBACK'): fail('PREPARE_NATIVE_SCOPE')
        self.data=validate_resource_plan(plan.decoded()).decoded()
        self.scope=scope
        import os
        if os.name!='nt': fail('PREPARE_WINDOWS_REQUIRED')
        import ctypes as ct
        if ct.sizeof(ct.c_void_p)!=8: fail('PREPARE_ABI_UNSUPPORTED')
        self.ct,self.D,self.H=ct,ct.c_uint32,ct.c_void_p
        self.last_profile_state=None;self.mutation_attempts=[]
        D,H,W,P=self.D,self.H,ct.c_wchar_p,ct.POINTER
        k=ct.WinDLL('kernel32.dll',use_last_error=True); a=ct.WinDLL('advapi32.dll',use_last_error=True)
        u=ct.WinDLL('userenv.dll',use_last_error=True); o=ct.WinDLL('ole32.dll',use_last_error=True)
        self.api={}
        def bind(dll,name,args,result):
            fn=getattr(dll,name);fn.argtypes,fn.restype=args,result;self.api[name]=fn
        for name,args,result in (
            ('CreateFileW',[W,D,D,H,D,D,H],H),('CloseHandle',[H],ct.c_int),('LocalFree',[H],H),
            ('GetFinalPathNameByHandleW',[H,W,D,D],D),('GetFileInformationByHandle',[H,H],ct.c_int)):
            bind(k,name,args,result)
        bind(a,'GetSecurityInfo',[H,ct.c_int,D,H,H,H,H,P(H)],D)
        bind(a,'ConvertSecurityDescriptorToStringSecurityDescriptorW',[H,D,D,P(H),P(D)],ct.c_int)
        bind(a,'ConvertStringSecurityDescriptorToSecurityDescriptorW',[W,D,P(H),P(D)],ct.c_int)
        bind(a,'GetSecurityDescriptorDacl',[H,P(ct.c_int),P(H),P(ct.c_int)],ct.c_int)
        bind(a,'GetSecurityDescriptorSacl',[H,P(ct.c_int),P(H),P(ct.c_int)],ct.c_int)
        bind(a,'SetSecurityInfo',[H,ct.c_int,D,H,H,H,H],D)
        bind(a,'ConvertSidToStringSidW',[H,P(H)],ct.c_int);bind(a,'FreeSid',[H],H)
        bind(a,'RegOpenKeyExW',[H,W,D,D,P(H)],ct.c_int32);bind(a,'RegCloseKey',[H],ct.c_int32)
        bind(u,'CreateAppContainerProfile',[W,W,W,H,D,P(H)],ct.c_int32)
        bind(u,'DeriveAppContainerSidFromAppContainerName',[W,P(H)],ct.c_int32)
        bind(u,'GetAppContainerFolderPath',[W,P(H)],ct.c_int32);bind(o,'CoTaskMemFree',[H],None)

    def _sid_text(self,pointer):
        text=self.H()
        if not self.api['ConvertSidToStringSidW'](pointer,self.ct.byref(text)): self._error('PREPARE_SID_TEXT_FAILED')
        result=None;primary=None;cleanup=[]
        try:
            result=self.ct.wstring_at(text.value)
            if not 1<=len(result)<=184: fail('PREPARE_SID_BUDGET')
        except Exception as error: primary=error
        finally:
            if text.value and self.api['LocalFree'](text.value): cleanup.append('PREPARE_SID_TEXT_FREE_FAILED')
        if primary is not None:
            if cleanup: primary.args+=('cleanup='+','.join(cleanup),)
            raise primary
        if cleanup: fail('PREPARE_SID_TEXT_FREE_FAILED')
        return result

    def current_owner(self):
        from .kernel_probe import _bind_windows_api,_decode_sid_bytes
        ct=self.ct; _,queries,_=_bind_windows_api();handle=self.H();needed=self.D()
        thread=self.H();ct.set_last_error(0)
        if queries['open_thread_token'](queries['current_thread'](),8,1,ct.byref(thread)):
            try: fail('PREPARE_IMPERSONATION_NOT_ALLOWED')
            finally:
                if thread.value: self._close(thread)
        if ct.get_last_error()!=1008: fail('PREPARE_THREAD_TOKEN_STATE_UNKNOWN')
        if not queries['open_process_token'](queries['current_process'](),8,ct.byref(handle)): fail('PREPARE_CURRENT_OWNER_QUERY')
        try:
            ct.set_last_error(0)
            if queries['token_info'](handle,1,None,0,ct.byref(needed)) or ct.get_last_error()!=122 or not 16<=needed.value<=65536:
                fail('PREPARE_CURRENT_OWNER_BUFFER')
            buffer=ct.create_string_buffer(needed.value);returned=self.D()
            if not queries['token_info'](handle,1,buffer,len(buffer),ct.byref(returned)): fail('PREPARE_CURRENT_OWNER_READ')
            ptr=self.H.from_buffer_copy(buffer.raw[:8]).value;offset=(ptr or 0)-ct.addressof(buffer)
            if not 16<=returned.value<=len(buffer) or offset<0 or offset+8>returned.value: fail('PREPARE_OWNER_SID_BOUNDS')
            size=8+4*buffer.raw[offset+1]
            if offset+size>returned.value: fail('PREPARE_OWNER_SID_BOUNDS')
            actual=_decode_sid_bytes(buffer.raw[offset:offset+size])
            if actual!=self.data['host_user_sid']: fail('PREPARE_CURRENT_OWNER_MISMATCH')
        finally: self._close(handle)

    def profile(self,create=False):
        if create and self.scope!='RESOURCE_PREPARE': fail('PREPARE_MUTATION_SCOPE_REQUIRED')
        ct=self.ct;sid=self.H();derived=self.H();folder=self.H()
        name=self.data['profile_name'];result={};primary=None;cleanup=[]
        try:
            if create:
                code=self.api['CreateAppContainerProfile'](name,name,'H56 dedicated neutral preparation',None,0,ct.byref(sid))
                if code: fail('PREPARE_PROFILE_CREATE_NEW_FAILED',str(code))
                result['ownership']='CREATED_THIS_ATTEMPT'
                self.last_profile_state=dict(name=name,ownership='CREATED_THIS_ATTEMPT')
            if self.api['DeriveAppContainerSidFromAppContainerName'](name,ct.byref(derived))!=0:
                fail('PREPARE_PROFILE_DERIVE_FAILED')
            actual=self._sid_text(derived)
            if self.last_profile_state is not None: self.last_profile_state['sid']=actual
            if sid.value and actual!=self._sid_text(sid): fail('PREPARE_PROFILE_DERIVE_MISMATCH')
            if self.api['GetAppContainerFolderPath'](actual,ct.byref(folder))!=0: fail('PREPARE_PROFILE_STORE_READ_FAILED')
            store=ct.wstring_at(folder.value);windows_path(store)
            if not contains(self.data['profile_store_parent'],store) or windows_path(store)==windows_path(self.data['profile_store_parent']):
                fail('PREPARE_PROFILE_STORE_OUTSIDE_APPROVED_PARENT')
            result.update(name=name,sid=actual,storage_root=store)
            if self.last_profile_state is not None: self.last_profile_state['storage_root']=store
        except Exception as error:
            # A successful create may have produced OS-managed objects even if
            # later identity readback failed. Preserve ownership; never delete
            # or retry/adopt an unknown existing profile here.
            error.owned_profile_state=dict(name=name,ownership=result.get('ownership','UNKNOWN'))
            primary=error
        finally:
            if folder.value: self.api['CoTaskMemFree'](folder.value)
            for pointer in (sid,derived):
                if pointer.value and self.api['FreeSid'](pointer.value): cleanup.append('PREPARE_PROFILE_SID_CLEANUP_FAILED')
        if primary is not None:
            if cleanup: primary.args+=('cleanup='+','.join(cleanup),)
            raise primary
        if cleanup: fail('PREPARE_PROFILE_CLEANUP_NOT_VERIFIED',','.join(cleanup))
        return result

    def set_owned_acl(self,path,kind,sddl):
        if self.scope!='RESOURCE_PREPARE': fail('PREPARE_MUTATION_SCOPE_REQUIRED')
        ct=self.ct;descriptor=self.H();size=self.D();handle=None
        if not self.api['ConvertStringSecurityDescriptorToSecurityDescriptorW'](sddl,1,ct.byref(descriptor),ct.byref(size)):
            self._error('PREPARE_DESCRIPTOR_INVALID')
        primary=None;cleanup=[];result=None
        try:
            present,default=ct.c_int(),ct.c_int();dacl=self.H();sacl=self.H()
            if not self.api['GetSecurityDescriptorDacl'](descriptor,ct.byref(present),ct.byref(dacl),ct.byref(default)) or not present.value or not dacl.value:
                fail('PREPARE_NULL_DACL_FORBIDDEN')
            flags=0x4|0x80000000
            if 'S:' in sddl:
                if not self.api['GetSecurityDescriptorSacl'](descriptor,ct.byref(present),ct.byref(sacl),ct.byref(default)) or not present.value or not sacl.value:
                    fail('PREPARE_MANDATORY_LABEL_INVALID')
                flags|=0x10
            handle=self.api['CreateFileW'](path,0x000E0080,1,None,3,0x00200000|(0x02000000 if kind=='directory' else 0),None)
            if not handle or handle==self.H(-1).value: self._error('PREPARE_NEW_OBJECT_SECURITY_OPEN_FAILED')
            final=ct.create_unicode_buffer(512);length=self.api['GetFinalPathNameByHandleW'](handle,final,len(final),0)
            actual=final.value[4:] if final.value.startswith('\\\\?\\') else final.value
            if not 1<=length<len(final) or windows_path(actual)!=windows_path(path): fail('PREPARE_ACL_FINAL_PATH_MISMATCH')
            attempt=dict(path=path,kind=kind,status='ATTEMPTED_UNKNOWN');self.mutation_attempts.append(attempt)
            code=self.api['SetSecurityInfo'](handle,1,flags,None,None,dacl,sacl if flags&0x10 else None)
            if code: fail('PREPARE_NEW_OBJECT_ACL_SET_FAILED',str(code))
            attempt['status']='OS_SET_RETURNED_SUCCESS'
            result=self._security(handle,1)
        except Exception as error:
            primary=error
        finally:
            if handle and handle!=self.H(-1).value:
                try: self._close(handle)
                except Exception: cleanup.append('PREPARE_ACL_HANDLE_CLOSE_FAILED')
            if descriptor.value and self.api['LocalFree'](descriptor.value): cleanup.append('PREPARE_DESCRIPTOR_CLEANUP_FAILED')
        if primary is not None:
            if cleanup: primary.args+=('cleanup='+','.join(cleanup),)
            raise primary
        if cleanup: fail('PREPARE_ACL_CLEANUP_NOT_VERIFIED',','.join(cleanup))
        return result


class ResourcePreparationError(Exception):
    def __init__(self,error,scene):
        super().__init__('RESOURCE_PREPARATION_STOP:'+getattr(error,'code',type(error).__name__))
        self._raw=canonical(scene)
        if len(self._raw)>2097152: fail('PREPARE_FAILURE_SCENE_BUDGET')
        self.cause=error;self.cause_code=getattr(error,'code',type(error).__name__)
        self.cleanup_status='OWNED_OR_UNKNOWN_OBJECTS_PRESERVED'

    @property
    def scene(self):
        return decode(self._raw)


def validate_scene_budget(copy):
    """Reserve the full worst-case stopped ledger before creating OS objects."""
    # Every object can appear once in the final descriptor list and once in
    # mutation_attempts; both include the complete original path. Reserve extra
    # room for fixed directories, Profile identity and bounded error metadata.
    objects=[dict(path=x['path'],kind=x['kind'],sddl_sha256='f'*64) for x in copy['created_objects']]
    mutations=[dict(path=x['path'],kind=x['kind'],status='OS_SET_RETURNED_SUCCESS') for x in copy['created_objects']]
    if len(canonical(dict(objects=objects,mutation_attempts=mutations)))+131072>2097152:
        fail('PREPARE_FAILURE_SCENE_PREALLOCATION_BUDGET')


def prepare_resources(plan,permit,projection_receipt_raw):
    require_preparation_permit(plan,permit,'RESOURCE_PREPARE')
    value=validate_resource_plan(plan.decoded()).decoded();copy=validate_projection_ownership(plan,projection_receipt_raw)
    validate_scene_budget(copy)
    # Complete path and immutable byte checks precede native binding/creation.
    for item in copy['created_objects']: _same_identity(item['path'],item)
    native=_PreparationNative(plan,permit,'RESOURCE_PREPARE')
    scene=dict(schema='h56.windows-resource-preparation-receipt.v1',status='PREPARING',plan_sha256=plan.sha256,
        session_id=value['session_id'],projection_receipt_sha256=value['projection_receipt_sha256'],
        source_identity=dict(candidate_manifest_sha256=value['candidate_manifest_sha256'],bootstrap_manifest_sha256=value['bootstrap_manifest_sha256']),
        profile=None,objects=[],created_directories=[],registry_binding='UNKNOWN',
        isolation_verified=False,candidate_computation='NOT_RUN',authority_granted=False)
    try:
        native.current_owner();scene['profile']=native.profile(create=True)
        app_sid=scene['profile']['sid']
        for item in copy['created_objects']:
            _same_identity(item['path'],item)
            role=owned_role(value,item['path'])
            actual=native.set_owned_acl(item['path'],item['kind'],_descriptor(value['host_user_sid'],app_sid,item['kind'],role))
            scene['objects'].append(dict(path=item['path'],kind=item['kind'],sddl_sha256=hashlib.sha256(actual.encode('utf-8')).hexdigest()))
        from .source_identity import _check_chain
        # Only fixed new private descendants, never original/shared ancestors.
        targets=[(value['paths'][name],role) for name,role in (
            ('scratch_root','SCRATCH_READ_WRITE'),('receipt_input_root','RECEIPT_READ_ONLY'),
            ('control_root','SOURCE_READ_EXECUTE'),('evidence_root','HOST_ONLY'),('host_private_root','HOST_ONLY'))]
        targets.extend([(ntpath.join(value['paths']['scratch_root'],'runs'),'SCRATCH_READ_WRITE'),
            (ntpath.join(value['paths']['scratch_root'],'child_failures'),'SCRATCH_READ_WRITE'),
            (ntpath.join(value['product_root'],'runtime_windows','.local',value['session_id'],'preparation_control'),'HOST_ONLY'),
            (ntpath.join(value['product_root'],'runtime_windows','.local',value['session_id'],'preparation'),'HOST_ONLY')])
        base=Path(value['product_root'])/'runtime_windows'/'.local'/value['session_id']
        owned={windows_path(item['path']):item for item in copy['created_objects']}
        def owned_or_new(directory):
            _check_chain(directory.parent)
            existing=owned.get(windows_path(str(directory)))
            if existing is not None:
                if existing['kind']!='directory': fail('PREPARE_PRIVATE_DIRECTORY_KIND')
                _same_identity(str(directory),existing)
            else:
                directory.mkdir(exist_ok=False);scene['created_directories'].append(str(directory))
        for directory in (base.parent,base):
            owned_or_new(directory)
            native.set_owned_acl(str(directory),'directory',_descriptor(value['host_user_sid'],app_sid,'directory','SOURCE_READ_EXECUTE'))
        for path,role in targets:
            owned_or_new(Path(path))
            sddl=native.set_owned_acl(path,'directory',_descriptor(value['host_user_sid'],app_sid,'directory',role))
            scene['objects'].append(dict(path=path,kind='directory',sddl_sha256=hashlib.sha256(sddl.encode('utf-8')).hexdigest()))
        # Mutable roles intentionally replace their earlier inherited source
        # descriptor; readback must compare the final descriptor exactly once.
        final={windows_path(item['path']):item for item in scene['objects']}
        scene['objects']=list(final.values())
        scene['status']='RESOURCES_CREATED_NOT_PREFLIGHT_ACCEPTED'
        return scene
    except Exception as error:
        scene['status']='STOP_OWNED_OR_UNKNOWN_OBJECTS_PRESERVED'
        if native.last_profile_state is not None: scene['profile']=dict(native.last_profile_state)
        elif hasattr(error,'owned_profile_state'): scene['profile']=error.owned_profile_state
        scene['mutation_attempts']=list(native.mutation_attempts)
        raise ResourcePreparationError(error,scene) from error


def readback_resources(plan,preparation_receipt_raw,permit):
    require_preparation_permit(plan,permit,'RESOURCE_READBACK')
    value=validate_resource_plan(plan.decoded()).decoded();receipt=decode(preparation_receipt_raw)
    if (receipt.get('schema')!='h56.windows-resource-preparation-receipt.v1' or
            receipt.get('status')!='RESOURCES_CREATED_NOT_PREFLIGHT_ACCEPTED' or receipt.get('plan_sha256')!=plan.sha256 or
            receipt.get('projection_receipt_sha256')!=value['projection_receipt_sha256']):
        fail('PREPARE_COMPLETED_RECEIPT_REQUIRED')
    native=_PreparationNative(plan,permit,'RESOURCE_READBACK');native.current_owner();profile=native.profile()
    expected=receipt['profile']
    if any(profile.get(key)!=expected.get(key) for key in ('name','sid','storage_root')): fail('PREPARE_PROFILE_READBACK_DRIFT')
    objects=receipt.get('objects')
    if type(objects) is not list or not 1<=len(objects)<=16400: fail('PREPARE_READBACK_OBJECT_BUDGET')
    readback=[]
    allowed=[value['product_root'],value['runtime_root']]
    for item in objects:
        if not any(contains(root,item['path']) for root in allowed): fail('PREPARE_READBACK_OUTSIDE_NEW_ROOTS')
        sddl=native.file_descriptor(item['path'],item['kind'])
        actual=hashlib.sha256(sddl.encode('utf-8')).hexdigest()
        if actual!=item['sddl_sha256']: fail('PREPARE_RESOURCE_ACL_READBACK_DRIFT')
        readback.append(dict(item))
    # Registry naming remains explicit, never an HKCU traversal or invented OS
    # internal path. Empty/missing identity prevents C1 bootstrap acceptance.
    registry=[]
    for item in value['registry_objects']:
        subkey='\\'.join(profile['sid'] if part=='{PROFILE_SID}' else part for part in item['subkey'].split('\\'))
        if profile['sid'] not in subkey.split('\\'): fail('PREPARE_PROFILE_REGISTRY_SID_MISMATCH')
        handle=native.H();code=native.api['RegOpenKeyExW'](native.H(0xFFFFFFFF80000001),subkey,0,0x20000,native.ct.byref(handle))
        if code: fail('PREPARE_NAMED_REGISTRY_READ_FAILED',str(code))
        try:
            sddl=native._security(handle,4)
            registry.append(dict(hive=item['hive'],subkey=subkey,sddl_sha256=hashlib.sha256(sddl.encode('utf-8')).hexdigest()))
        finally:
            if native.api['RegCloseKey'](handle): fail('PREPARE_NAMED_REGISTRY_CLOSE_FAILED')
    policy=dict(value['policy'],schema='h56.windows-observation-policy.v1',appcontainer_sid=profile['sid'])
    return dict(schema='h56.windows-prelaunch-resource-readback.v1',plan_sha256=plan.sha256,
        session_id=value['session_id'],status='NAMED_METADATA_READ_BACK_ONLY',profile=profile,
        observation_policy=policy,objects=readback,registry_objects=registry,
        registry_binding='BOUND_NAMED_ONLY' if registry else 'UNKNOWN',
        preparation_receipt_sha256=hashlib.sha256(preparation_receipt_raw).hexdigest(),
        projection_receipt_sha256=value['projection_receipt_sha256'],source_identity=receipt['source_identity'],
        observation='NOT_RUN',negative_probes='NOT_RUN',core='NOT_RUN',isolation_verified=False,authority_granted=False)
