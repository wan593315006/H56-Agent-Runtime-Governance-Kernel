"""TEST_DOUBLE_ONLY: pure protocol/causality/AST checks, no OS experiment.

Never constructs a native backend or uses valid on-disk authority. All SID,
PID, Job key, source identity, frames and metadata below are synthetic data.
"""
import ast
import builtins
import copy
import hashlib
import importlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).absolute().parents[2]
sys.path.insert(0,str(ROOT))
ORIGINAL_IMPORT=builtins.__import__
BLOCKED=[]


def no_native(name,*args,**kwargs):
    if name.split('.')[0] in ('ctypes','socket','subprocess','winreg') or name.startswith('runtime_binding'):
        BLOCKED.append(name)
        raise AssertionError('TEST_DOUBLE_ONLY prohibited native/core import:'+name)
    return ORIGINAL_IMPORT(name,*args,**kwargs)


builtins.__import__=no_native
try:
    pb=importlib.import_module('runtime_windows.probe_backend')
    pc=importlib.import_module('runtime_windows.probe_cli')
    rp=importlib.import_module('runtime_windows.resource_prepare')
    pa=importlib.import_module('runtime_windows.preflight_authority')
    bc=importlib.import_module('runtime_windows.bootstrap_contract')
    lc=importlib.import_module('runtime_windows.launch_contract')
    kp=importlib.import_module('runtime_windows.kernel_probe')
    from runtime_windows.errors import PreparationError
finally:
    builtins.__import__=ORIGINAL_IMPORT


def request(check='file_access_negative'):
    """Synthetic frame only, deliberately not an approved real machine plan."""
    session='TEST_DOUBLE_ONLY';run='pure_'+check
    base='C:\\p\\runtime_windows\\.local\\'+session
    policy=dict(schema=kp.POLICY_SCHEMA,appcontainer_sid='S-1-15-2-101-202-303-404-505-606-707',
        capabilities=[],token_has_restrictions=False,elevation_type=1,active_process_limit=1,
        process_memory_limit_bytes=134217728,job_memory_limit_bytes=134217728,cpu_rate_hundredths=1000)
    data=dict(schema='h56.windows-neutral-probe.v1',mode='NEUTRAL_PROBE_ONLY',run_id=run,session_id=session,check=check,
        source_identity=dict(product_manifest_sha256='a'*64,runtime_manifest_sha256='b'*64,
            source_files={name:'c'*64 for name in lc.SOURCE_FILES}),
        runtime=dict(python_executable='C:\\r\\python.exe',python_sha256='d'*64,version='3.13.12',arch='WINDOWS_X64',closure_sha256='e'*64),
        profile=dict(name='h56.TEST_DOUBLE_ONLY',sid=policy['appcontainer_sid'],storage_root='C:\\profiles\\own',provisioning_receipt_sha256='f'*64),
        paths=dict(product_root='C:\\p',runtime_root='C:\\r',scratch_root=base+'\\scratch',evidence_root=base+'\\host_evidence'),
        environment=dict(SYSTEMROOT='C:\\Windows',WINDIR='C:\\Windows',TEMP=base+'\\scratch',TMP=base+'\\scratch',H56_RUN_ID=run),
        observation_policy=policy,limits=dict(startup_ms=10000,total_ms=30000,cleanup_ms=5000,stdout_bytes=262144,stderr_bytes=32768,control_bytes=65536),
        release_binding={key:'1'*64 for key in ('external_decision_sha256','source_scope_sha256','resource_binding_sha256','preflight_receipt_sha256')},target={})
    if check in ('file_access_negative','credential_access_negative'):
        data['target']=dict(path=base+'\\host_private\\'+check+'.canary',expected_size=32,expected_sha256='2'*64)
        data['target']['expected_sha256']=hashlib.sha256(pb.canary_bytes(data)).hexdigest()
    elif check=='network_access_negative':
        data['target']=dict(address='127.0.0.1',port=49753,sentinel_id='TEST_DOUBLE_ONLY',positive_receipt_sha256='2'*64)
        data['target']['positive_receipt_sha256']=lc.digest(positive(data))
    elif check=='child_escape_negative': data['target']=dict(script_relative='runtime_windows/probe_cli.py')
    elif check=='resource_limit_negative': data['target']=dict(allocation_budget_bytes=134217728,chunk_bytes=1048576,policy_relation='SAME_AS_OBSERVER')
    elif check=='read_only_source': data['target']=dict(relative_files=['runtime_windows/errors.py'])
    else:
        raw=b'TEST_DOUBLE_ONLY_NONCE'
        data['target']=dict(path='C:\\profiles\\own\\TEST_DOUBLE_ONLY.bin',nonce_hex=raw.hex(),nonce_sha256=hashlib.sha256(raw).hexdigest())
    return data


def positive(value):
    t=value['target'];raw=hashlib.sha256(('H56_LOOPBACK:'+t['sentinel_id']).encode('ascii')).digest()
    return dict(schema='h56.windows-loopback-positive.v1',sentinel_id=t['sentinel_id'],address=t['address'],port=t['port'],
        challenge_sha256=hashlib.sha256(raw).hexdigest(),status='HOST_ROUNDTRIP_OBSERVED')


def observation(value):
    policy=value['observation_policy']
    return dict(schema=kp.OBSERVATION_SCHEMA,scope='CURRENT_PROCESS_AND_IMMEDIATE_JOB_ONLY',query_complete=True,collection_error=None,
        token=dict(primary_token_type=1,thread_impersonation_present=False,is_appcontainer=True,appcontainer_sid=policy['appcontainer_sid'],
            capabilities=[],has_restrictions=False,elevated=False,elevation_type=1),
        job=dict(in_job=True,scope='IMMEDIATE_JOB_ONLY',limit_flags=kp.REQUIRED_JOB_FLAGS,active_process_limit=policy['active_process_limit'],
            process_memory_limit_bytes=policy['process_memory_limit_bytes'],job_memory_limit_bytes=policy['job_memory_limit_bytes'],
            cpu_control_flags=5,cpu_rate_hundredths=policy['cpu_rate_hundredths']))


def native_file(path,access,error=5):
    value=dict(operation='CreateFileW',path=path,access=access,error=error)
    if error==0: value.update(unexpected_access=True,handle_closed=True)
    return value


def child(plan):
    value=plan.decoded();check=value['check'];t=value['target'];events=[];status='EXPECTED_OS_REFUSAL'
    if check in ('file_access_negative','credential_access_negative'):
        events=[native_file(t['path'],mask) for mask in (0x80000000,0x40000000)]
    elif check=='network_access_negative': events=[dict(operation='connect',address=t['address'],port=t['port'],error=10013)]
    elif check=='child_escape_negative': events=[dict(operation='CreateProcessW',error=5)]
    elif check=='resource_limit_negative':
        events=[dict(operation='bounded_memory_allocation',allocated_bytes=1048576,maximum_bytes=t['allocation_budget_bytes'],reason='MEMORY_REFUSAL_UNATTRIBUTED')];status='UNKNOWN'
    elif check=='read_only_source':
        files,dirs=pb.source_actions(value)
        for path in files:
            events.extend([native_file(path,0x40000000),native_file(path,0x10000),dict(operation='SOURCE_BYTES',path=path,before_sha256='6'*64,after_sha256='6'*64)])
        events.extend(native_file(path,0x40) for path in dirs)
    else:
        events=[dict(operation='PROFILE_WRITE_READBACK',path=t['path'],size=len(bytes.fromhex(t['nonce_hex'])),sha256=t['nonce_sha256'])];status='OWN_PROFILE_WRITE_READBACK'
    return dict(schema='h56.windows-neutral-probe-result.v1',check=check,run_id=value['run_id'],request_sha256=plan.sha256,pid=1234,
        environment_sha256=lc.digest(lc.build_environment(plan)),observation=observation(value),action=dict(kind=check,events=events,status=status))


def parent(plan,with_memory=False):
    value=plan.decoded();check=value['check'];t=value['target'];raw=lc.encode_frame(child(plan),65536)
    receipt=dict(schema='h56.windows-neutral-parent-receipt.v1',check=check,run_id=value['run_id'],request_sha256=plan.sha256,
        source_identity=value['source_identity'],status='RAW_RESULT_COLLECTED',pid=1234,exit_code=0,raw_stdout=raw,raw_stderr=b'',
        observed_output_bytes=dict(stdout=len(raw),stderr=0),capture_prefix_truncated=dict(stdout=False,stderr=False),
        events=['OWNED_JOB_LIMITS_READ_BACK','THREE_PRIVATE_NAMED_PIPE_PAIRS_CREATED','CREATED_SUSPENDED_IN_OWNED_JOB_TOKEN_CHECKED',
            'OWNED_CHILD_RESUMED','OWNED_CHILD_EXITED_OUTPUT_DRAINED'],stop_reason=None,cleanup=dict(status='CLOSED',errors=[]),cleanup_exception=None,
        positive_control=None,independent_readback=None,resource_evidence=None)
    if check in ('file_access_negative','credential_access_negative'):
        receipt['independent_readback']=dict(path=t['path'],size=t['expected_size'],sha256=t['expected_sha256'],status='HOST_CANARY_BYTES_READ_BACK')
    elif check=='network_access_negative': receipt['positive_control']=positive(value)
    elif check=='profile_storage_scope': receipt['independent_readback']=dict(path=t['path'],size=len(bytes.fromhex(t['nonce_hex'])),sha256=t['nonce_sha256'],status='HOST_FILE_READ_BACK')
    elif check=='read_only_source': receipt['independent_readback']=dict(schema='h56.windows-source-bytes-readback.v1',status='HOST_SOURCE_BYTES_READ_BACK',files=[
        dict(path=path,size=21,before_sha256='6'*64,after_sha256='6'*64) for path in pb.source_actions(value)[0]])
    if check=='resource_limit_negative' and with_memory:
        receipt['resource_evidence']=dict(schema='h56.windows-owned-job-memory-evidence.v1',association='OWNED_JOB_BEFORE_CHILD',completion_key=8192,process_id=1234,
            process_memory_limit_bytes=134217728,job_memory_limit_bytes=134217728,limit_flags=kp.REQUIRED_JOB_FLAGS,
            messages=[dict(message=9,completion_key=8192,process_id=1234)],collection_status='QUEUE_DRAINED',message_budget=64,elapsed_budget_ms=50)
    return receipt


def resource():
    base='C:\\p\\runtime_windows\\.local\\TEST_DOUBLE_ONLY'
    return dict(schema='h56.windows-resource-preparation-plan.v1',session_id='TEST_DOUBLE_ONLY',
        projection_receipt_sha256='1'*64,projection_plan_sha256='2'*64,candidate_manifest_sha256='3'*64,bootstrap_manifest_sha256='4'*64,
        product_root='C:\\p',runtime_root='C:\\r',host_user_sid='S-1-5-21-111-222-333-444',profile_name='h56.TEST_DOUBLE_ONLY',
        profile_store_parent='C:\\profiles',paths=dict(scratch_root=base+'\\scratch',receipt_input_root=base+'\\replay_input',
            control_root=base+'\\control',evidence_root=base+'\\host_evidence',host_private_root=base+'\\host_private'),
        policy={k:v for k,v in request()['observation_policy'].items() if k not in ('schema','appcontainer_sid')},registry_objects=[])


class PureProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): builtins.__import__=no_native
    @classmethod
    def tearDownClass(cls): builtins.__import__=ORIGINAL_IMPORT

    def plan(self,name='file_access_negative'): return pb.validate_probe_plan(request(name))
    def result(self,plan,item): return pb.validate_probe_result(plan,lc.encode_frame(item,65536),1234)

    def test_01_imports_are_inert_and_transport_is_shared(self):
        self.assertEqual([],BLOCKED)
        self.assertIs(pb.PreflightWindowsBackend.__bases__[0],importlib.import_module('runtime_windows.win32_backend')._OwnedWindowsTransport)
        for module in (pb,pc,rp,pa): self.assertNotIn('ctypes',module.__dict__)

    def test_02_all_seven_plan_schemas_and_synthetic_results(self):
        for check in pb.CHECKS:
            plan=self.plan(check);result=pb.evaluate_parent_probe(plan,parent(plan))
            self.assertEqual('UNKNOWN' if check=='resource_limit_negative' else 'RAW_EXPECTATION_MET_PENDING_ACCEPTANCE',result['status'])
            self.assertIs(False,result['isolation_accepted']);self.assertIs(False,result['runtime_authorized'])
            self.assertEqual('NOT_RUN',result['candidate_computation'])

    def test_03_permit_rejects_before_backend_binding(self):
        for permit in (None,{'approved':True},bc._issue_preparation_permit(self.plan(),'C1_OBSERVE')):
            with self.assertRaises(PreparationError): pb.PreflightWindowsBackend(self.plan(),permit)
        self.assertEqual([],BLOCKED)

    def test_04_manual_child_action_is_not_a_probe(self):
        with self.assertRaisesRegex(PreparationError,'LIVE_CHILD'): pc.execute_probe(self.plan())
        self.assertEqual([],BLOCKED)

    def test_05_default_unbound_authority_rejects_before_io(self):
        with self.assertRaisesRegex(PreparationError,'EXTERNAL_OPERATOR_PINS'): pa.PinnedPreparationAuthority.from_pins()

    def test_06_freeform_target_or_wrong_mode_rejected(self):
        for key,value in [('mode','OBSERVATION_ONLY'),('check','arbitrary')]:
            item=request();item[key]=value
            with self.assertRaises(PreparationError): pb.validate_probe_plan(item)
        item=request();item['target']['path']='C:\\other\\credential'
        with self.assertRaises(PreparationError): pb.validate_probe_plan(item)

    def test_07_bool_is_not_port_or_size(self):
        for check,key in [('network_access_negative','port'),('file_access_negative','expected_size'),('resource_limit_negative','chunk_bytes')]:
            item=request(check);item['target'][key]=True
            with self.assertRaises(PreparationError): pb.validate_probe_plan(item)

    def test_08_network_is_loopback_only(self):
        item=request('network_access_negative');item['target']['address']='8.8.8.8'
        with self.assertRaises(PreparationError): pb.validate_probe_plan(item)

    def test_09_memory_narrower_or_above_budget_rejected(self):
        for maximum in (67108864,536870912):
            item=request('resource_limit_negative');item['target']['allocation_budget_bytes']=maximum
            with self.assertRaises(PreparationError): pb.validate_probe_plan(item)

    def test_10_relative_source_path_escape_or_alias_rejected(self):
        for files in (['../other'],['runtime_windows/.local/session/private'],['X.py','x.py']):
            item=request('read_only_source');item['target']['relative_files']=files
            with self.assertRaises(PreparationError): pb.validate_probe_plan(item)

    def test_11_large_source_result_budget_rejected_before_launch(self):
        item=request('read_only_source');item['target']['relative_files']=['vendor/'+('x'*100)+str(i)+'.py' for i in range(128)]
        with self.assertRaises(PreparationError): pb.validate_probe_plan(item)

    def test_12_profile_is_own_direct_new_file_only(self):
        item=request('profile_storage_scope');item['target']['path']='C:\\profiles\\other\\nonce.bin'
        with self.assertRaises(PreparationError): pb.validate_probe_plan(item)

    def test_13_pid_bool_and_environment_mismatch_rejected(self):
        plan=self.plan();item=child(plan);item['pid']=True
        with self.assertRaises(PreparationError): self.result(plan,item)
        item=child(plan);item['environment_sha256']='0'*64
        with self.assertRaises(PreparationError): self.result(plan,item)

    def test_14_missing_capability_observation_is_unknown(self):
        plan=self.plan();item=child(plan);item['observation']['query_complete']=False
        self.assertEqual('UNKNOWN',self.result(plan,item)['status'])

    def test_15_wrong_native_operation_never_matches_file_denial(self):
        plan=self.plan();item=child(plan);item['action']['events']=[dict(operation='CreateProcessW',error=5)]
        with self.assertRaises(PreparationError): self.result(plan,item)

    def test_16_wrong_file_target_mask_count_rejected(self):
        plan=self.plan()
        for key,new in [('path','C:\\unrelated'),('access',5),('error',True)]:
            item=child(plan);item['action']['events'][0][key]=new
            with self.assertRaises(PreparationError): self.result(plan,item)
        item=child(plan);item['action']['events'].pop()
        with self.assertRaises(PreparationError): self.result(plan,item)

    def test_17_file_not_found_is_unknown_not_os_denial(self):
        plan=self.plan();item=child(plan)
        for event in item['action']['events']: event['error']=2
        item['action']['status']='UNKNOWN'
        self.assertEqual('UNKNOWN',self.result(plan,item)['status'])

    def test_18_unexpected_access_is_fail(self):
        plan=self.plan();item=child(plan);item['action']['events'][0]=native_file(plan.decoded()['target']['path'],0x80000000,0)
        item['action']['status']='UNEXPECTED_ACCESS_OR_CREATION'
        self.assertEqual('FAIL',self.result(plan,item)['status'])

    def test_19_status_cannot_lie_about_error(self):
        plan=self.plan();item=child(plan);item['action']['status']='UNEXPECTED_ACCESS_OR_CREATION'
        with self.assertRaises(PreparationError): self.result(plan,item)

    def test_20_readonly_requires_every_directory_and_file_action(self):
        plan=self.plan('read_only_source');item=child(plan);item['action']['events'].pop()
        with self.assertRaises(PreparationError): self.result(plan,item)

    def test_21_readonly_drift_is_fail(self):
        plan=self.plan('read_only_source');item=child(plan);item['action']['events'][2]['after_sha256']='7'*64;item['action']['status']='UNEXPECTED_ACCESS_OR_CREATION'
        self.assertEqual('FAIL',self.result(plan,item)['status'])

    def test_22_parent_source_and_child_digest_must_match(self):
        plan=self.plan('read_only_source');item=parent(plan);item['independent_readback']['files'][0]['before_sha256']='7'*64
        with self.assertRaises(PreparationError): pb.evaluate_parent_probe(plan,item)

    def test_23_parent_canary_is_not_optional(self):
        plan=self.plan();item=parent(plan);item['independent_readback']=None
        with self.assertRaises(PreparationError): pb.evaluate_parent_probe(plan,item)

    def test_24_network_needs_matching_host_positive(self):
        plan=self.plan('network_access_negative');item=parent(plan);item['positive_control']['port']+=1
        with self.assertRaises(PreparationError): pb.evaluate_parent_probe(plan,item)

    def test_25_profile_child_self_report_needs_parent_readback(self):
        plan=self.plan('profile_storage_scope');item=parent(plan);item['independent_readback']['sha256']='0'*64
        with self.assertRaises(PreparationError): pb.evaluate_parent_probe(plan,item)

    def test_26_memory_error_alone_stays_unknown(self):
        plan=self.plan('resource_limit_negative');self.assertEqual('UNKNOWN',pb.evaluate_parent_probe(plan,parent(plan))['status'])

    def test_27_matching_owned_job_message_adds_limited_attribution(self):
        plan=self.plan('resource_limit_negative')
        for message in (9,10):
            item=parent(plan,True);item['resource_evidence']['messages'][0]['message']=message
            self.assertEqual('RAW_EXPECTATION_MET_PENDING_ACCEPTANCE',pb.evaluate_parent_probe(plan,item)['status'])

    def test_28_wrong_completion_key_is_rejected(self):
        plan=self.plan('resource_limit_negative');item=parent(plan,True);item['resource_evidence']['messages'][0]['completion_key']+=1
        with self.assertRaises(PreparationError): pb.evaluate_parent_probe(plan,item)

    def test_29_other_pid_or_non_memory_message_stays_unknown(self):
        plan=self.plan('resource_limit_negative')
        for key,new in [('process_id',4321),('message',7)]:
            item=parent(plan,True);item['resource_evidence']['messages'][0][key]=new
            self.assertEqual('UNKNOWN',pb.evaluate_parent_probe(plan,item)['status'])

    def test_30_missing_or_exhausted_notifications_stay_unknown(self):
        plan=self.plan('resource_limit_negative')
        for new in ('BUDGET_EXHAUSTED','NATIVE_READ_FAILED','NOT_COLLECTED'):
            item=parent(plan,True);item['resource_evidence']['collection_status']=new
            self.assertEqual('UNKNOWN',pb.evaluate_parent_probe(plan,item)['status'])

    def test_31_wrong_limit_or_flags_not_substitutable(self):
        plan=self.plan('resource_limit_negative')
        for key,new in [('process_memory_limit_bytes',536870912),('limit_flags',0),('completion_key',True)]:
            item=parent(plan,True);item['resource_evidence'][key]=new
            with self.assertRaises(PreparationError): pb.evaluate_parent_probe(plan,item)

    def test_32_parent_cleanup_exit_failure_does_not_match(self):
        plan=self.plan()
        for key,new in [('exit_code',False),('stop_reason','KeyboardInterrupt'),('cleanup',dict(status='CLOSED',errors=['FAIL']))]:
            item=parent(plan);item[key]=new
            self.assertEqual('UNKNOWN',pb.evaluate_parent_probe(plan,item)['status'])

    def test_33_initial_resource_plan_needs_no_future_sid(self):
        value=resource();self.assertNotIn('sid',value)
        self.assertEqual([],rp.validate_resource_plan(value).decoded()['registry_objects'])

    def test_34_explicit_named_registry_template_allowed_no_enumeration(self):
        value=resource();value['registry_objects']=[dict(hive='HKEY_CURRENT_USER',subkey='EXPLICIT\\{PROFILE_SID}\\BOUND')]
        rp.validate_resource_plan(value)
        value['registry_objects'][0]['subkey']='EXPLICIT\\{OTHER}'
        with self.assertRaises(PreparationError): rp.validate_resource_plan(value)

    def test_35_resource_policy_not_candidate512_equivalence(self):
        value=resource();value['policy']['process_memory_limit_bytes']=536870912
        with self.assertRaises(PreparationError): rp.validate_resource_plan(value)

    def test_36_owned_roles_are_path_derived_not_claims(self):
        value=resource();base='C:\\p\\runtime_windows\\.local\\TEST_DOUBLE_ONLY'
        for suffix,expected in [('host_private','HOST_ONLY'),('host_evidence\\preflight','HOST_ONLY'),('preparation_control','HOST_ONLY'),
                ('scratch\\runs','SCRATCH_READ_WRITE'),('replay_input','RECEIPT_READ_ONLY'),('control','SOURCE_READ_EXECUTE')]:
            self.assertEqual(expected,rp.owned_role(value,base+'\\'+suffix))

    def test_37_failure_scene_is_immutable_and_class_specific(self):
        original={'schema':'TEST_DOUBLE_ONLY','profile':{'ownership':'UNKNOWN'}}
        error=rp.ResourcePreparationError(PreparationError('SYNTHETIC_STOP'),original)
        original['profile']['ownership']='fake'
        self.assertEqual('UNKNOWN',error.scene['profile']['ownership'])
        self.assertEqual('SYNTHETIC_STOP',error.cause_code)

    def test_38_scene_budget_rejects_before_any_os_objects(self):
        copy_ledger={'created_objects':[dict(path='C:\\p\\'+('x'*220)+str(i),kind='file') for i in range(10000)]}
        with self.assertRaisesRegex(PreparationError,'PREALLOCATION'): rp.validate_scene_budget(copy_ledger)

    def test_39_resource_native_missing_permit_fails_before_binding(self):
        plan=rp.validate_resource_plan(resource())
        for scope in ('RESOURCE_PREPARE','RESOURCE_READBACK'):
            with self.assertRaises(PreparationError): rp._PreparationNative(plan,None,scope)
        self.assertEqual([],BLOCKED)

    def test_40_canary_is_synthetic_and_request_bound(self):
        a=request();b=copy.deepcopy(a);b['run_id']='other'
        self.assertEqual(32,len(pb.canary_bytes(a)));self.assertNotEqual(pb.canary_bytes(a),pb.canary_bytes(b))

    def test_41_native_code_is_lazy_and_not_a_parallel_transport(self):
        for name in ('resource_prepare.py','preflight_authority.py','probe_backend.py','probe_cli.py'):
            path=ROOT/'runtime_windows'/name;source=path.read_text(encoding='utf-8');tree=ast.parse(source,str(path))
            compile(tree,str(path),'exec')
            for node in tree.body:
                if isinstance(node,(ast.Import,ast.ImportFrom)):
                    imports=[alias.name for alias in node.names]
                    self.assertFalse(any(x in ('ctypes','socket','subprocess','winreg') for x in imports))
                if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call):
                    self.fail('Top-level call:'+name)
            self.assertNotIn('os.walk(',source);self.assertNotIn('CreateAppContainerProfile',source if name!='resource_prepare.py' else '')
        self.assertNotIn('CreateProcessW',pb.__dict__)

    def test_42_no_synthetic_dictionary_is_an_accepted_record(self):
        plan=self.plan('resource_limit_negative');result=pb.evaluate_parent_probe(plan,parent(plan,True))
        self.assertNotIn('PASS',result.values());self.assertIs(False,result['runtime_authorized'])

    def test_43_sentinel_cleanup_attempts_every_synthetic_endpoint(self):
        calls=[]
        class SyntheticEndpoint:
            def __init__(self,name,broken=False): self.name,self.broken=name,broken
            def close(self):
                calls.append(self.name)
                if self.broken: raise ValueError('TEST_DOUBLE_ONLY_CLOSE')
        with self.assertRaisesRegex(PreparationError,'ENDPOINT_CLEANUP'):
            pb._close_sentinel_endpoints((SyntheticEndpoint('accepted',True),SyntheticEndpoint('client')))
        self.assertEqual(['accepted','client'],calls)

    def test_44_sentinel_cleanup_preserves_primary_stop_and_all_closes(self):
        calls=[]
        class SyntheticEndpoint:
            def close(self): calls.append('TEST_DOUBLE_ONLY');raise ValueError('close')
        primary=PreparationError('ORIGINAL_TEST_DOUBLE_ONLY_STOP')
        try: pb._close_sentinel_endpoints((SyntheticEndpoint(),SyntheticEndpoint()),primary)
        except PreparationError as error:
            self.assertIs(primary,error);self.assertEqual('ORIGINAL_TEST_DOUBLE_ONLY_STOP',error.code)
            self.assertIn('OWNED_ENDPOINT_1_CLOSE_FAILED',str(error.args))
        else: self.fail('Original stop lost')
        self.assertEqual(2,len(calls))


if __name__=='__main__': unittest.main(verbosity=2)
