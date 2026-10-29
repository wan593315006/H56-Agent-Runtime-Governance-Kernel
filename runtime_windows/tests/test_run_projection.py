"""SYNTHETIC_FIXTURE_ONLY: no actual product/Python copy or native process.

Dummy python.exe/DLL bytes are never executed. Typed permits below model the
trusted test scope only and do not prove Human identity or runtime acceptance.
Actual local I/O is confined to new fixtures under the approved evidence root.
"""
import ast
import builtins
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PRODUCT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(PRODUCT))
EVIDENCE = PRODUCT.parent / 'evidence/product/eng01_preflight_bootstrap_v1_20261024/projection_build'
FORBIDDEN = ('ctypes', 'subprocess', 'socket', 'winreg', 'runtime_windows.candidate_host',
    'runtime_windows.host_authority',
    'runtime_windows.win32_backend', 'runtime_windows.assembly',
    'runtime_windows.launcher', 'runtime_windows.preflight',
    'runtime_windows.preflight_authority', 'runtime_windows.probe_backend', 'runtime_windows.probe_cli',
    'k0_fact_foundation', 'k1_state_derivation', 'candidate_canonical_capability_contract',
    'candidate_capability_feasibility_projection')
PREEXISTING_MODULES = frozenset(sys.modules)


def import_guard():
    actual = builtins.__import__
    def check(name, globals=None, locals=None, fromlist=(), level=0):
        full = importlib.util.resolve_name('.' * level + name, globals['__package__']) if level else name
        values = [full] + [full + '.' + item for item in fromlist or () if item != '*']
        if any(value == bad or value.startswith(bad + '.') for value in values for bad in FORBIDDEN):
            raise AssertionError('FORBIDDEN_RUNTIME_IMPORT:' + full)
        return actual(name, globals, locals, fromlist, level)
    return mock.patch.object(builtins, '__import__', side_effect=check)


with import_guard():
    from runtime_windows import bootstrap_contract as contract
    from runtime_windows import run_projection as projection
    from runtime_windows.errors import PreparationError


def identity(raw):
    return dict(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def record(name, raw):
    return dict(path=name, **identity(raw))


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='p_', dir=str(EVIDENCE)))
        self.source = self.root / 's'
        self.python_source = self.root / 'p'
        self.source.mkdir()
        self.python_source.mkdir()
        self.product_bytes = {'runtime_windows/frozen.py': b'# SYNTHETIC\r\nx=1\r\n'}
        self.extra_bytes = {'runtime_windows/bootstrap_cli.py': b'# SYNTHETIC_NOT_EXECUTABLE\n'}
        self.python_bytes = {'python.exe': b'NOT_AN_EXECUTABLE', 'python39.dll': b'NOT_A_DLL',
                             'python39.zip': b'NOT_A_STDLIB_ZIP', 'LICENSE.txt': b'SYNTHETIC_LICENSE'}
        self.candidate = dict(schema='h56.windows-effective-source.v1', member_count=1,
            files=[record(name, raw) for name, raw in self.product_bytes.items()])
        self.candidate_raw = contract.canonical(self.candidate)
        self.bootstrap = dict(schema='h56.windows-bootstrap-source.v1', baseline_package_sha256='6' * 64,
            candidate_runtime_manifest_sha256=identity(self.candidate_raw)['sha256'], member_count=1,
            files=[record(name, raw) for name, raw in self.extra_bytes.items()])
        self.bootstrap_raw = contract.canonical(self.bootstrap)
        self.runtime = dict(schema='h56.windows-python-source-index.v1', version='3.9.13',
            arch='WINDOWS_X64', entrypoint='python.exe', source_reference='SYNTHETIC_FIXTURE_ONLY',
            license_files=['LICENSE.txt'], files=[record(name, raw) for name, raw in self.python_bytes.items()])
        self.runtime_raw = contract.canonical(self.runtime)
        self.source_bytes = dict(self.product_bytes, **self.extra_bytes)
        self.source_bytes[projection.CANDIDATE_MANIFEST] = self.candidate_raw
        self.source_bytes[projection.BOOTSTRAP_MANIFEST] = self.bootstrap_raw
        self.parent_raw = contract.canonical(dict(schema='SYNTHETIC_CURRENT_PRODUCT',
            files=[record(name, raw) for name, raw in self.source_bytes.items()]))
        self.source_bytes['PACKAGE_MANIFEST.json'] = self.parent_raw
        for base, members in ((self.source, self.source_bytes), (self.python_source, self.python_bytes)):
            for name, raw in members.items():
                target = base.joinpath(*name.split('/'))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
        self.spec = dict(schema='h56.windows-projection-spec.v1', session_id='fixture',
            paths=dict(source_product_root=str(self.source), staged_product_root=str(self.root / 'd'),
                python_source_root=str(self.python_source), python_root=str(self.root / 'r')),
            source_pins=dict(current_product_manifest_sha256=identity(self.parent_raw)['sha256'],
                candidate_runtime_manifest_sha256=identity(self.candidate_raw)['sha256'],
                bootstrap_source_manifest_sha256=identity(self.bootstrap_raw)['sha256'],
                runtime_index_sha256=identity(self.runtime_raw)['sha256']),
            limits=dict(max_files=128, max_file_bytes=1048576, max_total_bytes=4194304, deadline_ms=30000))

    def build(self, **changes):
        values = dict(parent_raw=self.parent_raw, candidate_raw=self.candidate_raw,
            bootstrap_raw=self.bootstrap_raw, runtime_index_raw=self.runtime_raw,
            specification=self.spec)
        values.update(changes)
        return projection.build_projection_plan(**values)

    def materialize(self, plan=None):
        plan = plan or self.build()
        return projection.materialize_projection(plan, contract._issue_preparation_permit(plan, 'MATERIALIZE'))

    def rejected(self, code, function, *args):
        with self.assertRaises(PreparationError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)

    def test01_imports_inert_no_native(self):
        self.assertFalse(any(name in sys.modules and name not in PREEXISTING_MODULES for name in FORBIDDEN))

    def test02_frozen_plan_cannot_mutate(self):
        plan = contract.FrozenPlan({'x': {'y': 1}})
        detached = plan.decoded()
        detached['x']['y'] = 2
        self.assertEqual(plan.decoded()['x']['y'], 1)
        self.rejected('BOOTSTRAP_PLAN_IMMUTABLE', setattr, plan, 'sha256', '0' * 64)

    def test03_duplicate_float_and_nonfinite_rejected(self):
        for raw, code in ((b'{"x":1,"x":2}', 'BOOTSTRAP_DUPLICATE_JSON_KEY'),
                          (b'{"x":1.2}', 'BOOTSTRAP_NONINTEGER_NUMBER'),
                          (b'{"x":NaN}', 'BOOTSTRAP_NONFINITE_NUMBER')):
            self.rejected(code, contract.decode, raw)

    def test04_pins_are_not_root_redirect(self):
        pins = contract.PreparationPins('1' * 64, '2' * 64, 's1', str(PRODUCT))
        contract.validate_preparation_pins(pins, str(PRODUCT))
        self.rejected('BOOTSTRAP_ACTUAL_ENTRY_ROOT_MISMATCH',
            contract.validate_preparation_pins, pins, str(self.root))
        self.rejected('BOOTSTRAP_EXTERNAL_PINS_UNBOUND', contract.validate_preparation_pins,
            contract.PreparationPins('0' * 64, '2' * 64, 's1', str(PRODUCT)), str(PRODUCT))

    def test05_permit_scope_and_plan_match(self):
        plan, other = contract.FrozenPlan({'x': 1}), contract.FrozenPlan({'x': 2})
        permit = contract._issue_preparation_permit(plan, 'INVENTORY')
        contract.require_preparation_permit(plan, permit, 'INVENTORY')
        self.rejected('OPAQUE_PREPARATION_PERMIT_REQUIRED', contract.require_preparation_permit,
            plan, permit, 'MATERIALIZE')
        self.rejected('OPAQUE_PREPARATION_PERMIT_REQUIRED', contract.require_preparation_permit,
            other, permit, 'INVENTORY')
        self.assertNotIn('candidate_compute', contract.PREPARATION_SCOPES)

    def test06_bundle_exact_no_self_hash(self):
        bundle = dict(schema='h56.windows-preparation-bundle.v1', session_id='s',
            allowed_operations=['INVENTORY'], files={'projection.json': identity(b'{}')})
        contract.validate_preparation_bundle(bundle)
        bundle['files']['preparation_bundle.json'] = identity(b'{}')
        self.rejected('BOOTSTRAP_BUNDLE_COLLISION_OR_SELF_HASH', contract.validate_preparation_bundle, bundle)

    def test07_dag_no_future_isolation_dependency(self):
        graph = {'source': [], 'human_prepare': ['source'], 'readback': ['human_prepare'],
                 'raw_probe': ['readback'], 'human_accept': ['raw_probe'], 'candidate': ['human_accept']}
        self.assertLess(contract.topological_order(graph).index('raw_probe'),
                        contract.topological_order(graph).index('human_accept'))
        graph['human_prepare'].append('raw_probe')
        self.rejected('BOOTSTRAP_DAG_CYCLE', contract.topological_order, graph)

    def test08_generated_pth_relative_no_site(self):
        name, raw = projection.generated_pth(self.runtime)
        self.assertEqual(name, 'python39._pth')
        self.assertEqual(raw, b'.\npython39.zip\n')
        self.assertNotIn(b'import site', raw)
        self.assertNotIn(str(self.python_source).encode('utf-8'), raw)

    def test09_python_index_rejects_existing_configuration(self):
        for filename in ('python39._pth', 'pyvenv.cfg', 'Lib/pyvenv.cfg'):
            bad = copy.deepcopy(self.runtime)
            bad['files'].append(record(filename, b'C:/OTHER_PROJECT'))
            self.rejected('PROJECTION_UNCONTROLLED_PYTHON_CONFIGURATION', projection.validate_runtime_index, bad)

    def test10_current_parent_differs_from_historical_baseline(self):
        plan = self.build().decoded()
        self.assertNotEqual(plan['source_identity']['current_product_manifest_sha256'], '6' * 64)
        self.assertEqual(plan['source_identity']['baseline_package_sha256'], '6' * 64)
        package = contract.decode(plan['generated_product_files']['PACKAGE_MANIFEST.json'].encode('utf-8'))
        self.assertNotIn('PACKAGE_MANIFEST.json', [x['path'] for x in package['files']])
        self.assertNotIn('plan_sha256', plan['generated_product_files']['PROJECTION_PROVENANCE.json'])

    def test11_source_pin_drift(self):
        self.rejected('PROJECTION_SOURCE_MANIFEST_PIN_MISMATCH',
            lambda: self.build(parent_raw=self.parent_raw + b' '))

    def test12_traversal_and_case_collision(self):
        self.rejected('BOOTSTRAP_RELATIVE_PATH_INVALID', projection._index,
            [dict(path='../escape', **identity(b'a'))])
        self.rejected('PROJECTION_CASE_OR_DUPLICATE_MEMBER', projection._index,
            [record('A.py', b'a'), record('a.py', b'a')])

    def test13_overlapping_roots_rejected_without_io(self):
        bad = copy.deepcopy(self.spec)
        bad['paths']['staged_product_root'] = str(self.source / 'nested')
        self.rejected('PROJECTION_ROOTS_OVERLAP', lambda: self.build(specification=bad))

    def test14_destination_native_path_budget(self):
        bad = copy.deepcopy(self.spec)
        bad['paths']['staged_product_root'] = str(self.root / ('x' * 170))
        with self.assertRaises(PreparationError) as caught:
            self.build(specification=bad)
        self.assertIn(caught.exception.code, ('PROJECTION_ROOT_INVALID', 'PROJECTION_FINAL_PATH_LENGTH'))

    def test15_actual_synthetic_copy_preserves_bytes_and_no_authority(self):
        receipt = self.materialize()
        staged = Path(receipt['product_root'])
        self.assertEqual((staged / 'runtime_windows/frozen.py').read_bytes(), self.product_bytes['runtime_windows/frozen.py'])
        self.assertFalse(receipt['isolation_verified'])
        self.assertFalse(receipt['authority_granted'])
        self.assertEqual(receipt['candidate_computation'], 'NOT_RUN')
        self.assertTrue(receipt['created_objects'])
        self.assertEqual((Path(receipt['runtime_root']) / 'python39._pth').read_bytes(), b'.\npython39.zip\n')
        for item in receipt['created_objects']:
            self.assertTrue(str(self.root) in item['path'])
            if item['kind'] == 'file':
                self.assertEqual(item['file_identity']['links'], 1)
        roles = projection.managed_directory_roles('fixture')
        ledger = {item['path']: item for item in receipt['created_objects']}
        for name, role in roles.items():
            target = staged.joinpath(*name.split('/'))
            self.assertTrue(target.is_dir())
            self.assertEqual(ledger[str(target)]['role'], role)
            self.assertEqual(ledger[str(target)]['file_identity']['inode'], target.lstat().st_ino)
            if not any(other.startswith(name + '/') for other in roles):
                self.assertEqual(list(target.iterdir()), [])
        private = staged / 'runtime_windows/.local/fixture/preparation_control'
        control_identity = private.lstat().st_ino
        (private / 'fixture_control.json').write_bytes(b'{"fixture":"NO_HUMAN_APPROVAL"}')
        self.assertEqual(private.lstat().st_ino, control_identity)
        projection.verify_projection(self.build())  # Mutable data, not copied source.
        def forbidden(*args, **kwargs):
            raise AssertionError('PURE_CONSUMER_MUST_NOT_PERFORM_EFFECTS')
        # These are real new pure consumer functions. Imports are inert; any
        # accidental ctypes import, resource constructor or mutation stops here.
        with import_guard(), mock.patch.object(os, 'open', side_effect=forbidden), \
                mock.patch.object(os, 'mkdir', side_effect=forbidden), \
                mock.patch.object(builtins, 'open', side_effect=forbidden):
            from runtime_windows import resource_prepare
            from runtime_windows.host_resources import ResourceReadback
            from runtime_windows import kernel_probe
            with mock.patch.object(resource_prepare, '_PreparationNative', side_effect=forbidden), \
                    mock.patch.object(ResourceReadback, '__init__', side_effect=forbidden), \
                    mock.patch.object(kernel_probe, '_bind_windows_api', side_effect=forbidden):
                raw = contract.canonical(receipt)
                base = staged / 'runtime_windows/.local/fixture'
                resource_value = dict(schema='h56.windows-resource-preparation-plan.v1', session_id='fixture',
                    projection_receipt_sha256=identity(raw)['sha256'], projection_plan_sha256=self.build().sha256,
                    candidate_manifest_sha256=self.spec['source_pins']['candidate_runtime_manifest_sha256'],
                    bootstrap_manifest_sha256=self.spec['source_pins']['bootstrap_source_manifest_sha256'],
                    product_root=str(staged), runtime_root=receipt['runtime_root'],
                    host_user_sid='S-1-5-21-1-2-3-4', profile_name='SYNTHETIC_ONLY',
                    profile_store_parent=str(self.root / 'profile_store'),
                    paths=dict(scratch_root=str(base / 'scratch'), receipt_input_root=str(base / 'replay_input'),
                        control_root=str(base / 'control'), evidence_root=str(base / 'host_evidence'),
                        host_private_root=str(base / 'host_private')),
                    policy=dict(capabilities=[], token_has_restrictions=True, elevation_type=3,
                        active_process_limit=1, process_memory_limit_bytes=33554432,
                        job_memory_limit_bytes=33554432, cpu_rate_hundredths=100), registry_objects=[])
                resource_plan = resource_prepare.validate_resource_plan(resource_value)
                consumed = resource_prepare.validate_projection_ownership(resource_plan, raw)
                self.assertEqual(consumed['created_objects'], receipt['created_objects'])
                for item in receipt['created_objects']:
                    self.assertEqual(item['role'], resource_prepare.owned_role(resource_value, item['path']))
                forged = copy.deepcopy(receipt)
                for item in forged['created_objects']:
                    if item['path'] == str(private):
                        item['role'] = 'SOURCE_READ_EXECUTE'
                forged_raw = contract.canonical(forged)
                resource_value['projection_receipt_sha256'] = identity(forged_raw)['sha256']
                forged_plan = resource_prepare.validate_resource_plan(resource_value)
                self.rejected('PREPARE_OWNED_OBJECT_ROLE_GEOMETRY',
                    resource_prepare.validate_projection_ownership, forged_plan, forged_raw)

    def test16_existing_output_refused_before_overwrite(self):
        target = Path(self.spec['paths']['staged_product_root'])
        target.mkdir()
        (target / 'canary').write_bytes(b'KEEP')
        self.rejected('PROJECTION_TARGET_EXISTS', self.materialize)
        self.assertEqual((target / 'canary').read_bytes(), b'KEEP')
        self.assertFalse(Path(self.spec['paths']['python_root']).exists())

    def test17_changed_input_stops_before_output(self):
        (self.source / 'runtime_windows/frozen.py').write_bytes(b'changed')
        with self.assertRaises(PreparationError):
            self.materialize()
        self.assertFalse(Path(self.spec['paths']['staged_product_root']).exists())

    def test18_staged_verification_never_reads_original(self):
        plan = self.build()
        self.materialize(plan)
        actual, observed = projection._read_checked, []
        def bounded(path, size, maximum):
            text = str(path)
            self.assertFalse(text == str(self.source) or text.startswith(str(self.source) + os.sep))
            self.assertFalse(text == str(self.python_source) or text.startswith(str(self.python_source) + os.sep))
            observed.append(text)
            return actual(path, size, maximum)
        with mock.patch.object(projection, '_read_checked', side_effect=bounded):
            projection.verify_projection(plan)
        self.assertTrue(observed)

    def test19_extra_output_stops(self):
        plan = self.build()
        self.materialize(plan)
        (Path(self.spec['paths']['staged_product_root']) / 'unknown.py').write_bytes(b'not registered')
        self.rejected('PROJECTION_EXTRA_FILE', projection.verify_projection, plan)

    def test20_generated_pth_tampering_stops(self):
        plan = self.build()
        self.materialize(plan)
        (Path(self.spec['paths']['python_root']) / 'python39._pth').write_bytes(b'import site\n')
        with self.assertRaises(PreparationError):
            projection.verify_projection(plan)

    def test21_failed_copy_preserves_owned_ledger(self):
        actual, count = projection._write_new, [0]
        def fail_second(*args):
            count[0] += 1
            if count[0] == 2:
                raise OSError('SYNTHETIC_DISK_FAILURE')
            return actual(*args)
        with mock.patch.object(projection, '_write_new', side_effect=fail_second):
            with self.assertRaises(projection.ProjectionMaterializationError) as caught:
                self.materialize()
        self.assertTrue(caught.exception.created_paths)
        self.assertTrue(Path(caught.exception.created_paths[0]).exists())
        self.assertEqual(caught.exception.cause_code, 'OSError')

    def test22_hardlink_policy_rejects_unknown_or_multiple(self):
        for count in (0, 2):
            metadata = SimpleNamespace(st_mode=0o100600, st_nlink=count, st_file_attributes=0)
            with self.assertRaises(PreparationError):
                projection._check_stat(metadata, False, 'SYNTHETIC')
        reparse = SimpleNamespace(st_mode=0o100600, st_nlink=1, st_file_attributes=0x400)
        with self.assertRaises(PreparationError):
            projection._check_stat(reparse, False, 'SYNTHETIC_REPARSE')
        path = self.python_source / 'python.exe'
        before = path.lstat()
        fd = os.open(str(path), os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        try:
            opened = os.fstat(fd)
            self.assertEqual(projection._cross_api_identity(before), projection._cross_api_identity(opened))
            self.assertEqual(projection._same_api_identity(before), projection._same_api_identity(path.lstat()))
            self.assertEqual(projection._same_api_identity(opened), projection._same_api_identity(os.fstat(fd)))
            changed = SimpleNamespace(**{name: getattr(before, name, None) for name in
                ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
                 'st_nlink', 'st_file_attributes', 'st_birthtime_ns')})
            changed.st_mode = before.st_mode ^ 0o200
            self.assertNotEqual(projection._cross_api_identity(before), projection._cross_api_identity(changed))
        finally:
            os.close(fd)

    def test23_real_fixture_hardlink_rejected_if_supported(self):
        original, link = self.root / 'one', self.root / 'two'
        original.write_bytes(b'SYNTHETIC')
        try:
            os.link(str(original), str(link))
        except (OSError, NotImplementedError) as error:
            self.skipTest('Actual fixture hardlink unavailable: ' + type(error).__name__)
        with self.assertRaises(PreparationError):
            projection._read_checked(original, None, 1024)

    def test24_actual_entry_root_must_match_stage_role(self):
        plan = self.build()
        projection.enforce_entry_root(plan, 'MATERIALIZE', str(self.source))
        projection.enforce_entry_root(plan, 'C1_OBSERVE', self.spec['paths']['staged_product_root'])
        self.rejected('PROJECTION_ACTUAL_ENTRY_ROOT_MISMATCH', projection.enforce_entry_root,
            plan, 'C1_OBSERVE', str(self.source))

    def test25_foreign_private_lock_is_forbidden(self):
        self.assertTrue(projection._forbidden('runtime_binding_v1_20261024/offline/source-lock.json'))
        self.assertTrue(projection._forbidden('scratch/host_driver.py'))
        self.assertTrue(projection._forbidden('.git/config'))
        private_name = 'runtime_binding_v1_20261024/offline/source-lock.json'
        private_bytes = b'SYNTHETIC_PRIVATE_LOCK_CANARY_NOT_A_REAL_LOCK'
        candidate = copy.deepcopy(self.candidate)
        candidate['files'].append(record(private_name, private_bytes))
        candidate['member_count'] = 2
        candidate_raw = contract.canonical(candidate)
        bootstrap = copy.deepcopy(self.bootstrap)
        bootstrap['candidate_runtime_manifest_sha256'] = identity(candidate_raw)['sha256']
        bootstrap_raw = contract.canonical(bootstrap)
        members = dict(self.source_bytes)
        members.pop('PACKAGE_MANIFEST.json')
        members[private_name] = private_bytes
        members[projection.CANDIDATE_MANIFEST] = candidate_raw
        members[projection.BOOTSTRAP_MANIFEST] = bootstrap_raw
        parent_raw = contract.canonical({'files': [record(name, raw) for name, raw in members.items()]})
        specification = copy.deepcopy(self.spec)
        specification['source_pins'].update(current_product_manifest_sha256=identity(parent_raw)['sha256'],
            candidate_runtime_manifest_sha256=identity(candidate_raw)['sha256'],
            bootstrap_source_manifest_sha256=identity(bootstrap_raw)['sha256'])
        self.rejected('PROJECTION_FORBIDDEN_SOURCE', lambda: self.build(parent_raw=parent_raw,
            candidate_raw=candidate_raw, bootstrap_raw=bootstrap_raw, specification=specification))

    def test26_product_code_has_no_top_level_effects(self):
        for name in ('bootstrap_contract.py', 'run_projection.py', 'bootstrap_cli.py'):
            tree = ast.parse((PRODUCT / 'runtime_windows' / name).read_text(encoding='utf-8'))
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    self.fail('Top-level executable call: ' + name)
            if name == 'bootstrap_cli.py':
                source = (PRODUCT / 'runtime_windows' / name).read_text(encoding='utf-8')
                self.assertIn('authority.observation_authority(observation_plan)', source)
                self.assertNotIn('run_single_probe', source)
                self.assertIn('except ResourcePreparationError as error', source)
                self.assertIn('scene=error.scene', source)
        self.assertFalse(any(name in sys.modules and name not in PREEXISTING_MODULES for name in FORBIDDEN))

    def test27_cli_missing_pins_is_blocked_before_authority_import(self):
        with import_guard():
            from runtime_windows import bootstrap_cli
            result = bootstrap_cli.dispatch('observe', 'preflight.json', None, None, 'fixture')
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertFalse(result['runtime_authorized'])
        self.assertNotIn('runtime_windows.preflight_authority', sys.modules)


if __name__ == '__main__':
    unittest.main(verbosity=2)
