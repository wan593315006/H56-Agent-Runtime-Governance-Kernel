"""TEST_DOUBLE_ONLY: pure consistency checks, never a real Windows launch."""
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).absolute().parents[2]))
from runtime_windows import host_contract as hc
from runtime_windows.errors import PreparationError
from runtime_windows.host_resources import validate_readonly_sddl
from runtime_windows.host_authority import BootstrapPins, validate_bootstrap_pins, validate_closure

TEST_LINEAGE = dict(zip(sorted(hc.LINEAGE_KEYS), ('1'*64, '2'*64, '3'*64, '4'*64)))


def test_double_ref(path, value):
    raw = hc.canonical(value) + b'\n'
    return dict(path=path, size=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                raw_base64=base64.b64encode(raw).decode('ascii'))


def test_double_result(operation='candidate_compute', run_id='run1', task_id='task1', source_run_id=None):
    """Full fabricated evidence for validator tests; not a runtime producer."""
    if operation == 'fresh_process_replay':
        source_run_id = source_run_id or 'source1'
    labels = ('Ontology.load_default_profile', 'K0.Fact.create', 'K0.CanonicalFactLedger',
        'K0.append', 'K1.StateCompiler', 'K1.compile', 'C1.Catalog.from_mapping',
        'C1.Catalog.require_definition', 'C2.Evaluator', 'C2.project', 'C2.Projection.verify')
    trace = []
    for label in labels:
        trace.extend([dict(event='CALL', label=label, origin='vendor/test_double.py',
                           function='TEST_DOUBLE_ONLY', arguments_hash='5'*64),
                      dict(event='RETURN', label=label, value=None)])
    projection = dict(candidate_planning_only=True, authority_granted=False,
                      execution_permitted=False, qualification='FEASIBLE')
    semantic = dict(domain_id='DEVSECOPS', scenario_id='positive', native_calls=trace,
        projection=projection, boundary=dict(candidate_planning_only=True,
            authority_granted=False, execution_permitted=False, business_action_calls=0, formal_history_writes=0))
    actual = dict(status='COMPUTED_CANDIDATE_ONLY', semantic=semantic, semantic_hash=hc.digest(semantic))
    record = dict(schema_id='H56OS:CANDIDATE_RECEIPT:WINDOWS_V1', result=actual,
        result_hash=hc.digest(actual), lineage=dict(TEST_LINEAGE),
        unverified_runtime_claim=dict(release_sha256='5'*64, environment_sha256='6'*64,
            preflight_sha256='7'*64, grade='UNVERIFIED_RECORDED_DIGESTS_NOT_REPLAYED_OR_AUTHORITY'),
        candidate_planning_only=True, authority_granted=False, execution_permitted=False)
    record['receipt_hash'] = hc.digest(record)
    prefix = 'runtime_windows/.local/TEST_DOUBLE_ONLY/'
    receipt_path = (prefix+'scratch/runs/'+run_id+'/receipt.json' if operation == 'candidate_compute'
                    else prefix+'replay_input/'+source_run_id+'/receipt.json')
    receipt_ref = test_double_ref(receipt_path, record)
    argv = [r'C:\TEST_DOUBLE_ONLY\python.exe', '-I', '-B', '-S', '-X', 'utf8',
            r'C:\TEST_DOUBLE_ONLY\product\runtime_windows\candidate_cli.py']
    comparison = None
    if operation == 'candidate_compute':
        argv += ['--domain', 'DEVSECOPS', '--scenario', 'positive', '--run-id', run_id]
        output = dict(status='COMPUTED_CANDIDATE_ONLY', receipt='C:\\TEST_DOUBLE_ONLY\\product\\'+receipt_path.replace('/', '\\'))
        status = 'COMPUTED_CANDIDATE_ONLY'
    else:
        argv += ['--recompute-file', source_run_id]
        comparison = dict(status='ACTUAL_RECOMPUTATION_MATCH', semantic_hash=actual['semantic_hash'],
            authority_granted=False, execution_permitted=False,
            source_receipt_hash=hc.digest(record), recomputed_result=actual)
        output, status = comparison, 'ACTUAL_RECOMPUTATION_MATCH'
    stdout = hc.canonical(output)+b'\n'
    started = dict(schema='h56.windows-candidate-started.v1', pid=123, run_id=run_id,
        operation=operation, task_id=task_id,
        runtime_source_manifest_sha256=TEST_LINEAGE['runtime_source_manifest_sha256'],
        resource_contract_sha256='8'*64)
    transport = dict(schema='h56.windows-candidate-transport.v1', argv=argv, pid=123, exit_code=0,
        raw_stdout_base64=base64.b64encode(stdout).decode('ascii'), raw_stderr_base64='',
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(b'').hexdigest(),
        observed_output_bytes=dict(stdout=len(stdout), stderr=0),
        capture_prefix_truncated=dict(stdout=False, stderr=False), cleanup=dict(status='CLOSED', errors=[]),
        events=['OWNED_CHILD_RESUMED', 'OWNED_CHILD_EXITED_OUTPUT_DRAINED'], stop_reason=None,
        runtime_source_manifest_sha256=TEST_LINEAGE['runtime_source_manifest_sha256'],
        resource_contract_sha256='8'*64, started_event=started)
    return dict(schema='h56.windows-candidate-host-result.v1', operation=operation, run_id=run_id,
        task_id=task_id, source_run_id=source_run_id, status=status, pid=123, started=True, exit_code=0,
        source_lineage=dict(TEST_LINEAGE), record=record, receipt_ref=receipt_ref,
        native_trace_ref=test_double_ref(prefix+'host_evidence/'+run_id+'/native_trace.json', trace),
        projection=projection, comparison=comparison, transport_receipt=transport, failure=None,
        boundary=hc.boundary())


def validate_double(value):
    return hc.validate_host_result(value, value['operation'], value['run_id'], value['task_id'],
        value['source_run_id'], TEST_LINEAGE,
        value['transport_receipt']['started_event'] if value['started'] else None)


class CandidateContractTests(unittest.TestCase):
    def test_native_bindings_inert_at_module_top_level(self):
        import ast
        root = Path(__file__).absolute().parents[1]
        for name in ('host_contract.py', 'host_authority.py', 'host_resources.py', 'candidate_host.py', 'win32_backend.py'):
            tree = ast.parse((root/name).read_bytes())
            imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
            for node in imports:
                names = [item.name for item in node.names] if isinstance(node, ast.Import) else [node.module or '']
                self.assertFalse(any(item.split('.')[0] in ('ctypes','subprocess','socket','winreg') for item in names), name)
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    self.fail('Unexpected top-level call: '+name)

    def test_one_shared_transport_and_two_typed_wrappers(self):
        import ast
        tree = ast.parse((Path(__file__).absolute().parents[1]/'win32_backend.py').read_bytes())
        classes = {node.name:node for node in tree.body if isinstance(node,ast.ClassDef)}
        self.assertEqual({key for key in classes if key.endswith('Transport')}, {'_OwnedWindowsTransport'})
        for wrapper in ('WindowsBackend','CandidateWindowsBackend'):
            self.assertEqual([x.id for x in classes[wrapper].bases], ['_OwnedWindowsTransport'])
        top_imports = [node.module for node in tree.body if isinstance(node,ast.ImportFrom)]
        self.assertNotIn('host_contract', top_imports)

    def test_failure_archive_exception_snapshot_is_bounded_and_copied(self):
        value=test_double_result()
        value.update(status='HOST_FAILED', failure=dict(code='TEST_DOUBLE_ONLY'))
        for key in ('record','receipt_ref','native_trace_ref','projection','comparison'):
            value[key]=None
        error=hc.HostEvidencePersistenceError(value,'TEST_DOUBLE_ONLY_ARCHIVE_DENIED')
        snapshot=error.raw_result
        snapshot['status']='MODIFIED_TEST_COPY'
        self.assertEqual(error.raw_result['status'],'HOST_FAILED')
        self.assertEqual(error.code,'HOST_RAW_EVIDENCE_ARCHIVE_FAILED')
    def test_complete_required_object_closure_pure(self):
        self.assertIsNone(validate_closure(*test_double_closure()))

    def test_missing_source_parent_acl_rejected(self):
        args = test_double_closure()
        args[0]['acl_objects'] = [x for x in args[0]['acl_objects'] if not x['path'].endswith(r'\runtime_windows\.local')]
        with self.assertRaises(PreparationError): validate_closure(*args)

    def test_missing_source_file_acl_rejected(self):
        args = test_double_closure()
        args[0]['acl_objects'] = [x for x in args[0]['acl_objects'] if not x['path'].endswith('example.py')]
        with self.assertRaises(PreparationError): validate_closure(*args)

    def test_control_cannot_be_preflight_index_member(self):
        args = test_double_closure()
        args[3]['files'][0]['path'] = args[0]['paths']['control_root'] + r'\preflight.json'
        with self.assertRaises(PreparationError): validate_closure(*args)

    def test_unregistered_profile_receipt_rejected(self):
        args = test_double_closure()
        args[0]['profile']['provisioning_receipt_sha256'] = '9'*64
        with self.assertRaises(PreparationError): validate_closure(*args)

    def test_dependency_outside_declared_runtime_root_rejected(self):
        args = test_double_closure()
        args[2]['files'][0]['path'] = r'C:\UNREGISTERED\python.exe'
        with self.assertRaises(PreparationError): validate_closure(*args)

    def test_failed_pre_resume_keeps_created_pid_no_callback(self):
        result = test_double_result()
        for key in ('record', 'receipt_ref', 'native_trace_ref', 'projection', 'comparison'):
            result[key] = None
        result.update(status='HOST_FAILED', started=False, exit_code=None, failure=dict(code='TEST_DOUBLE_ONLY_TOKEN_FAIL'))
        result['transport_receipt'].update(exit_code=None, started_event=None, stop_reason=result['failure'], events=['CREATED_SUSPENDED'])
        self.assertIsNone(validate_double(result))
        self.assertEqual(result['pid'], 123)

    def test_failed_after_callback_preserves_started(self):
        result = test_double_result()
        for key in ('record', 'receipt_ref', 'native_trace_ref', 'projection', 'comparison'):
            result[key] = None
        result.update(status='HOST_FAILED', failure=dict(code='TEST_DOUBLE_ONLY_CALLBACK_FAIL'))
        result['transport_receipt']['stop_reason'] = result['failure']
        self.assertIsNone(validate_double(result))
    def test_acceptance_scope_budget_boundaries(self):
        acceptance = test_double_configuration()['host_acceptance']
        acceptance['worker_attempt_budget'] = 100
        acceptance['domain_scenarios']['DEVSECOPS'] = ['scenario'+str(x) for x in range(64)]
        self.assertIsNone(hc.validate_acceptance(acceptance))
        acceptance['worker_attempt_budget'] = 101
        with self.assertRaises(PreparationError): hc.validate_acceptance(acceptance)
        acceptance['worker_attempt_budget'] = 100
        acceptance['domain_scenarios']['DEVSECOPS'].append('scenario64')
        with self.assertRaises(PreparationError): hc.validate_acceptance(acceptance)

    def test_acceptance_bool_budget_invalid(self):
        acceptance = test_double_configuration()['host_acceptance']
        acceptance['worker_attempt_budget'] = True
        with self.assertRaises(PreparationError): hc.validate_acceptance(acceptance)

    def test_fixed_compute_and_fresh_commands(self):
        config = test_double_configuration()
        plan = hc.make_candidate_plan(config, 'candidate_compute', 'run1', 'DEVSECOPS', 'positive')
        self.assertEqual(hc.candidate_argv(plan)[7:], ['--domain', 'DEVSECOPS', '--scenario', 'positive', '--run-id', 'run1'])
        replay = hc.make_candidate_plan(config, 'fresh_process_replay', 'run2', source_run_id='run1')
        self.assertEqual(hc.candidate_argv(replay)[7:], ['--recompute-file', 'run1'])
        self.assertEqual(hc.candidate_environment_block(plan).count('\x00'), 11)

    def test_unknown_task_scope_rejected(self):
        with self.assertRaises(PreparationError):
            hc.make_candidate_plan(test_double_configuration(), 'candidate_compute', 'run1', 'FINANCE_REFUND', 'unknown')

    def test_candidate_permit_not_observation_permit(self):
        from runtime_windows.launch_contract import require_permit
        plan = hc.make_candidate_plan(test_double_configuration(), 'candidate_compute', 'run1', 'DEVSECOPS', 'positive')
        permit = hc._issue_permit('CANDIDATE_WORKER', plan.sha256)
        self.assertIsNone(hc.require_candidate_permit(plan, permit))
        with self.assertRaises(PreparationError): require_permit(plan, permit)
        with self.assertRaises(PreparationError): hc.require_candidate_permit(plan, object())

    def test_exact_environment_not_partial(self):
        config = test_double_configuration()
        del config['child_environment']['H56W_HOST_ACCEPTANCE_SHA256']
        with self.assertRaises(PreparationError): hc.make_candidate_plan(config, 'candidate_compute', 'run1', 'DEVSECOPS', 'positive')

    def test_no_recursive_bundle_member(self):
        bundle = dict(schema='h56.human-controller-bundle.v1', session_id='TEST_DOUBLE_ONLY',
            files={name: dict(size=1, sha256='1'*64) for name in hc.BUNDLE_FILES})
        self.assertIsNone(hc.validate_bundle(bundle, 'TEST_DOUBLE_ONLY'))
        bundle['files']['controller_bundle.json'] = dict(size=1, sha256='1'*64)
        with self.assertRaises(PreparationError): hc.validate_bundle(bundle, 'TEST_DOUBLE_ONLY')
    def test_complete_synthetic_compute(self):
        self.assertIsNone(validate_double(test_double_result()))

    def test_complete_synthetic_replay(self):
        self.assertIsNone(validate_double(test_double_result('fresh_process_replay')))

    def test_missing_evidence_rejected(self):
        result = test_double_result()
        result['receipt_ref'] = None
        with self.assertRaises(PreparationError): validate_double(result)

    def test_exit_zero_not_sufficient(self):
        result = test_double_result()
        result['transport_receipt']['events'] = []
        with self.assertRaises(PreparationError): validate_double(result)

    def test_callback_binding_required(self):
        result = test_double_result()
        with self.assertRaises(PreparationError):
            hc.validate_host_result(result, 'candidate_compute', 'run1', 'task1', None, TEST_LINEAGE)

    def test_receipt_path_not_arbitrary(self):
        result = test_double_result()
        result['receipt_ref']['path'] = 'elsewhere/receipt.json'
        with self.assertRaises(PreparationError): validate_double(result)

    def test_raw_receipt_tampering_rejected(self):
        result = test_double_result()
        result['receipt_ref']['sha256'] = 'a'*64
        with self.assertRaises(PreparationError): validate_double(result)

    def test_fresh_trace_reference_required(self):
        result = test_double_result('fresh_process_replay')
        result['native_trace_ref'] = test_double_ref('wrong/trace.json', [])
        with self.assertRaises(PreparationError): validate_double(result)

    def test_projection_must_match(self):
        result = test_double_result()
        result['projection'] = dict(authority_granted=True)
        with self.assertRaises(PreparationError): validate_double(result)

    def test_cleanup_failure_rejected(self):
        result = test_double_result()
        result['transport_receipt']['cleanup']['status'] = 'UNKNOWN'
        with self.assertRaises(PreparationError): validate_double(result)

    def test_output_truncation_rejected(self):
        result = test_double_result()
        result['transport_receipt']['capture_prefix_truncated']['stdout'] = True
        with self.assertRaises(PreparationError): validate_double(result)

    def test_source_extra_authority_rejected(self):
        result = test_double_result()
        result['source_lineage']['approved'] = True
        with self.assertRaises(PreparationError): validate_double(result)

    def test_failure_cannot_smuggle_projection(self):
        result = test_double_result()
        result.update(status='HOST_FAILED', failure=dict(code='TEST_DOUBLE_ONLY'))
        with self.assertRaises(PreparationError): validate_double(result)

    def test_bool_not_exit_code(self):
        result = test_double_result()
        result['exit_code'] = result['transport_receipt']['exit_code'] = False
        with self.assertRaises(PreparationError): validate_double(result)

    def test_bool_not_boundary_integer(self):
        result = test_double_result()
        result['boundary']['candidate_planning_only'] = 1
        with self.assertRaises(PreparationError): validate_double(result)

    def test_no_pins_reject_before_files_or_native(self):
        from runtime_windows.candidate_host import CandidateHost
        with self.assertRaisesRegex(PreparationError, 'HOST_EXTERNAL_OPERATOR_PINS_REQUIRED'):
            CandidateHost.from_bootstrap()

    def test_unbound_pins_reject_before_files_or_native(self):
        with self.assertRaises(PreparationError):
            validate_bootstrap_pins(BootstrapPins('UNBOUND', 'UNBOUND', 'test', str(Path(__file__).absolute().parents[2])))

    def test_path_not_string_pin_rejected(self):
        with self.assertRaises(PreparationError):
            validate_bootstrap_pins(BootstrapPins('1'*64, '2'*64, 'test', Path(__file__).absolute().parents[2]))

    def test_bound_string_pin_pure_only(self):
        # Does not instantiate the bridge or read control files/resources.
        self.assertIsNone(validate_bootstrap_pins(BootstrapPins('1'*64, '2'*64, 'test', str(Path(__file__).absolute().parents[2]))))

    def test_readonly_sddl_supported_positive(self):
        self.assertIsNone(validate_readonly_sddl(test_double_sddl(), HOST_SID, APP_SID))

    def test_readonly_sddl_label_id_supported(self):
        self.assertIsNone(validate_readonly_sddl(test_double_sddl().replace('(ML;;', '(ML;ID;'), HOST_SID, APP_SID))

    def test_readonly_sddl_label_unknown_flags_rejected(self):
        with self.assertRaises(PreparationError):
            validate_readonly_sddl(test_double_sddl().replace('(ML;;', '(ML;OI;'), HOST_SID, APP_SID)

    def test_readonly_sddl_write_rejected(self):
        with self.assertRaises(PreparationError):
            validate_readonly_sddl(test_double_sddl('0x12019f'), HOST_SID, APP_SID)

    def test_readonly_sddl_null_dacl_rejected(self):
        with self.assertRaises(PreparationError):
            validate_readonly_sddl('O:'+HOST_SID+'G:SYD:NO_ACCESS_CONTROLS:(ML;;NW;;;LW)', HOST_SID, APP_SID)

    def test_readonly_sddl_callback_rejected(self):
        with self.assertRaises(PreparationError):
            validate_readonly_sddl(test_double_sddl().replace('(A;ID;', '(XA;ID;'), HOST_SID, APP_SID)

    def test_readonly_sddl_inherit_only_not_read(self):
        with self.assertRaises(PreparationError):
            validate_readonly_sddl(test_double_sddl().replace('(A;ID;', '(A;IOID;'), HOST_SID, APP_SID)

    def test_readonly_sddl_no_app_read(self):
        with self.assertRaises(PreparationError):
            validate_readonly_sddl(test_double_sddl('0x120088'), HOST_SID, APP_SID)


HOST_SID = 'S-1-5-21-1-2-3-1000'
APP_SID = 'S-1-15-2-1-2-3-4-5-6-7'


def test_double_sddl(rights='0x120089'):
    return 'O:'+HOST_SID+'G:SYD:PAI(A;;FA;;;'+HOST_SID+')(A;;FA;;;SY)(A;ID;'+rights+';;;'+APP_SID+')S:(ML;;NW;;;LW)'


def test_double_configuration():
    import ntpath
    root = r'C:\TEST_DOUBLE_ONLY\product'
    base = root + r'\runtime_windows\.local\TEST_DOUBLE_ONLY'
    paths = dict(control_root=base+r'\control', scratch_root=base+r'\scratch',
        receipt_input_root=base+r'\replay_input', host_evidence_root=base+r'\host_evidence', active_lock_path=base+r'\active.lock')
    policy = dict(schema='h56.windows-observation-policy.v1', appcontainer_sid=APP_SID,
        capabilities=[], token_has_restrictions=False, elevation_type=3, active_process_limit=4,
        process_memory_limit_bytes=536870912, job_memory_limit_bytes=536870912, cpu_rate_hundredths=1000)
    resources = dict(schema='h56.windows-host-resources.v1', session_id='TEST_DOUBLE_ONLY', product_root=root,
        host_user_sid=HOST_SID, system_root=r'C:\Windows',
        profile=dict(name='TEST_DOUBLE_ONLY', sid=APP_SID, storage_root=r'C:\TEST_DOUBLE_ONLY\profile', provisioning_receipt_sha256='1'*64),
        python=dict(executable=r'C:\TEST_DOUBLE_ONLY\python\python.exe', sha256='2'*64,
            version='3.9.13', arch='WINDOWS_X64', dependency_closure_sha256='3'*64), paths=paths,
        observation_policy=policy, limits=dict(startup_ms=1000, total_ms=5000, cleanup_ms=1000,
            stdout_bytes=1048576, stderr_bytes=65536, control_bytes=65536),
        acl_objects=[dict(path=root, kind='directory', sddl_sha256='4'*64)],
        registry_objects=[dict(hive='HKEY_CURRENT_USER', subkey='TEST_DOUBLE_ONLY\\'+APP_SID, sddl_sha256='5'*64)])
    acceptance = dict(schema='h56.windows-host-acceptance.v1', status='EXTERNALLY_ACCEPTED_CANDIDATE_HOST',
        session_id='TEST_DOUBLE_ONLY', resource_contract_sha256='8'*64, preflight_sha256='9'*64,
        allowed_operations=['candidate_compute', 'fresh_process_replay'],
        domain_scenarios=dict(DEVSECOPS=['positive'], FINANCE_REFUND=['positive']), worker_attempt_budget=2,
        **{key: TEST_LINEAGE[key] for key in ('runtime_source_manifest_sha256', 'runtime_contract_sha256', 'public_lock_sha256')}, **hc.boundary())
    env = dict(SYSTEMROOT=r'C:\Windows', WINDIR=r'C:\Windows', TEMP=paths['scratch_root'], TMP=paths['scratch_root'],
        H56W_SESSION='TEST_DOUBLE_ONLY', **{key:'6'*64 for key in hc.CANDIDATE_ENV_NAMES if key.endswith('_SHA256')})
    return dict(resources=resources, host_acceptance=acceptance, child_environment=env, source_lineage=dict(TEST_LINEAGE))


def test_double_closure():
    import ntpath
    resources = test_double_configuration()['resources']
    root, paths = resources['product_root'], resources['paths']
    environment = dict(python_executable=resources['python']['executable'], python_sha256=resources['python']['sha256'],
        profile_storage_root=resources['profile']['storage_root'], observation_policy=resources['observation_policy'],
        variables=dict(SYSTEMROOT=resources['system_root'], WINDIR=resources['system_root']),
        runtime_read_roots=[r'C:\TEST_DOUBLE_ONLY\python'])
    dependency = dict(schema='h56.windows-dependency-closure.v1', files=[dict(path=resources['python']['executable'], size=1, sha256='2'*64)])
    proof_path = paths['host_evidence_root']+r'\preflight\profile_provisioning_receipt.json'
    evidence = dict(schema='h56.windows-preflight-evidence-index.v1', files=[dict(path=proof_path, size=1, sha256='1'*64)])
    registry = {'runtime_windows/example.py':dict(size=1, sha256='3'*64)}
    controls = hc.BUNDLE_FILES | {'hc_original.txt', 'controller_bundle.json'}
    files = [root+r'\runtime_windows\example.py', root+r'\runtime_windows\RUNTIME_SOURCE_MANIFEST.json',
        resources['python']['executable'], proof_path] + [paths['control_root']+'\\'+name for name in controls]
    directories = [root, root+r'\runtime_windows', root+r'\runtime_windows\.local', ntpath.dirname(paths['control_root']),
        resources['profile']['storage_root'], r'C:\TEST_DOUBLE_ONLY\python', paths['control_root'], paths['scratch_root'],
        paths['receipt_input_root'], paths['host_evidence_root'], paths['host_evidence_root']+r'\preflight',
        paths['scratch_root']+r'\runs', paths['scratch_root']+r'\child_failures']
    resources['acl_objects'] = [dict(path=path, kind='file', sddl_sha256='4'*64) for path in files]
    resources['acl_objects'] += [dict(path=path, kind='directory', sddl_sha256='4'*64) for path in directories]
    return resources, environment, dependency, evidence, registry, controls


if __name__ == '__main__':
    unittest.main(verbosity=2)
