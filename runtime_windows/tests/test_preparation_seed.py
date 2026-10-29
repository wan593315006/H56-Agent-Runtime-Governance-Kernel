"""SYNTHETIC_IN_MEMORY_ONLY; no installation, copy, native or core entry.

Run this named suite with the approved -I -B -S -X utf8 interpreter flags.
The external private harness supplies any actual saved index separately; this
portable product test has no dependency on local evidence or private paths.
"""
import builtins
import copy
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


PRODUCT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(PRODUCT))
FORBIDDEN_IMPORTS = ('ctypes', 'subprocess', 'socket', 'winreg',
    'runtime_windows.preflight_authority', 'runtime_windows.host_authority',
    'runtime_windows.candidate_host', 'runtime_windows.launcher',
    'runtime_windows.win32_backend', 'runtime_windows.assembly',
    'k0_fact_foundation', 'k1_state_derivation',
    'candidate_canonical_capability_contract', 'candidate_capability_feasibility_projection')


def inert_import_guard():
    original = builtins.__import__
    def guarded(name, globals=None, locals=None, fromlist=(), level=0):
        full = importlib.util.resolve_name('.' * level + name, globals['__package__']) if level else name
        names = [full] + [full + '.' + item for item in fromlist or () if item != '*']
        if any(value == blocked or value.startswith(blocked + '.')
               for value in names for blocked in FORBIDDEN_IMPORTS):
            raise AssertionError('FORBIDDEN_RUNTIME_IMPORT:' + full)
        return original(name, globals, locals, fromlist, level)
    return mock.patch.object(builtins, '__import__', side_effect=guarded)


with inert_import_guard():
    from runtime_windows import bootstrap_contract as contract
    from runtime_windows import preparation_seed as seed
    from runtime_windows import run_projection as projection
    from runtime_windows.errors import PreparationError


def identity(raw):
    return {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def record(name, raw):
    return dict(path=name, **identity(raw))


class PreparationSeedTests(unittest.TestCase):
    def setUp(self):
        # These roots are lexical proposal data, never created or inspected.
        anchor = Path(seed.PRODUCT_ROOT).anchor
        self.specification = {'schema': 'h56.windows-projection-spec.v1',
            'session_id': 'synthetic_seed',
            'paths': {'source_product_root': seed.PRODUCT_ROOT,
                'staged_product_root': str(Path(anchor) / 'seed_dst'),
                'python_source_root': str(Path(anchor) / 'seed_src_py'),
                'python_root': str(Path(anchor) / 'seed_py')},
            'source_pins': {},
            'limits': {'max_files': 128, 'max_file_bytes': 1048576,
                       'max_total_bytes': 4194304, 'deadline_ms': 30000}}
        self.candidate = {'schema': 'h56.windows-effective-source.v1', 'member_count': 1,
            'files': [record('runtime_windows/frozen.py', b'# SYNTHETIC_NOT_RUN\r\n')]}
        self.candidate_raw = contract.canonical(self.candidate)
        self.bootstrap = {'schema': 'h56.windows-bootstrap-source.v1',
            'baseline_package_sha256': '6' * 64,
            'candidate_runtime_manifest_sha256': identity(self.candidate_raw)['sha256'],
            'member_count': 1, 'files': [record('runtime_windows/synthetic_extra.py', b'# NOT_RUN\n')]}
        self.bootstrap_raw = contract.canonical(self.bootstrap)
        self.runtime = {'schema': 'h56.windows-python-source-index.v1', 'version': '3.13.12',
            'arch': 'WINDOWS_X64', 'entrypoint': 'python.exe',
            'source_reference': 'SYNTHETIC_ONLY_来源', 'license_files': ['LICENSE.txt'],
            'files': [record(name, raw) for name, raw in (
                ('python.exe', b'NOT_AN_EXECUTABLE'), ('python313.dll', b'NOT_A_DLL'),
                ('Lib/encodings/__init__.py', b'# NOT_IMPORTED'),
                ('DLLs/synthetic.pyd', b'NOT_LOADED'), ('LICENSE.txt', b'SYNTHETIC_LICENSE'))]}
        self.runtime_raw = contract.canonical(self.runtime)
        self.parent = {'schema': 'SYNTHETIC_CURRENT_PRODUCT', 'files':
            self.candidate['files'] + self.bootstrap['files'] + [
                record(projection.CANDIDATE_MANIFEST, self.candidate_raw),
                record(projection.BOOTSTRAP_MANIFEST, self.bootstrap_raw)]}
        self.parent_raw = contract.canonical(self.parent)
        self.operations = ['INVENTORY', 'MATERIALIZE']
        self.refresh_pins()

    def refresh_pins(self):
        self.specification['source_pins'] = {
            'current_product_manifest_sha256': identity(self.parent_raw)['sha256'],
            'candidate_runtime_manifest_sha256': identity(self.candidate_raw)['sha256'],
            'bootstrap_source_manifest_sha256': identity(self.bootstrap_raw)['sha256'],
            'runtime_index_sha256': identity(self.runtime_raw)['sha256']}

    def compile(self, **changes):
        inputs = dict(product_manifest_raw=self.parent_raw, candidate_manifest_raw=self.candidate_raw,
            bootstrap_manifest_raw=self.bootstrap_raw, runtime_index_raw=self.runtime_raw,
            projection_spec_raw=contract.canonical(self.specification),
            proposed_operations=self.operations)
        inputs.update(changes)
        return seed.compile_preparation_seed(**inputs)

    def member(self, proposal, name):
        row = proposal.decoded()['files'][name]
        raw = row['raw_utf8'].encode('utf-8')
        self.assertEqual(identity(raw), {key: row[key] for key in ('size', 'sha256')})
        return raw

    def rejected(self, **changes):
        with self.assertRaises(PreparationError):
            self.compile(**changes)

    def test01_valid_proposal_uses_existing_builder(self):
        proposal = self.compile()
        self.assertIs(type(proposal), contract.FrozenPlan)
        value = proposal.decoded()
        self.assertEqual(value['status'], 'PROPOSED_NOT_APPROVED')
        self.assertEqual(value['session_id'], 'synthetic_seed')
        self.assertEqual(value['proposed_operations'], self.operations)
        plan_raw = self.member(proposal, 'projection_plan.json')
        direct = projection.build_projection_plan(self.parent_raw, self.candidate_raw,
            self.bootstrap_raw, self.runtime_raw, self.specification)
        self.assertEqual(plan_raw, direct.raw_bytes())
        self.assertTrue(value['boundary']['proposal_only'])
        self.assertFalse(any(flag for key, flag in value['boundary'].items() if key != 'proposal_only'))

    def test02_original_utf8_crlf_whitespace_preserved(self):
        index_raw = (json.dumps(self.runtime, ensure_ascii=False, indent=2).replace('\n', '\r\n') + '\r\n').encode('utf-8')
        self.runtime_raw = index_raw
        self.refresh_pins()
        spec_raw = (json.dumps(self.specification, indent=2).replace('\n', '\r\n') + ' \r\n').encode('utf-8')
        proposal = self.compile(projection_spec_raw=spec_raw)
        self.assertEqual(self.member(proposal, 'runtime_index.json'), index_raw)
        self.assertEqual(self.member(proposal, 'projection_spec.json'), spec_raw)

    def test03_input_and_decoded_result_are_detached(self):
        before = copy.deepcopy((self.specification, self.operations))
        proposal = self.compile()
        self.assertEqual((self.specification, self.operations), before)
        frozen_raw = proposal.raw_bytes()
        self.operations.append('RESOURCE_PREPARE')
        view = proposal.decoded()
        view['files']['runtime_index.json']['raw_utf8'] = 'CHANGED'
        view['proposed_operations'].append('C1_OBSERVE')
        self.assertEqual(proposal.raw_bytes(), frozen_raw)
        with self.assertRaises(PreparationError):
            proposal.sha256 = '1' * 64

    def test04_only_nonempty_unique_preparation_operation_list(self):
        for operations in ([], ['INVENTORY', 'INVENTORY'], ['RESOURCE_PREPARE'],
                           ['candidate_compute'], ['INVENTORY', 1], ('INVENTORY',), None):
            with self.subTest(operations=operations):
                self.rejected(proposed_operations=operations)
        self.assertEqual(self.compile(proposed_operations=['MATERIALIZE']).decoded()['proposed_operations'],
                         ['MATERIALIZE'])

    def test05_each_source_or_index_raw_pin_mismatch_rejected(self):
        for name, raw in (('product_manifest_raw', self.parent_raw),
                          ('candidate_manifest_raw', self.candidate_raw),
                          ('bootstrap_manifest_raw', self.bootstrap_raw),
                          ('runtime_index_raw', self.runtime_raw)):
            with self.subTest(input=name):
                self.rejected(**{name: raw + b' '})

    def test06_duplicate_malformed_json_and_numbers_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{', b'\xff', b'{"x":NaN}', b'{"x":1.25}'):
            with self.subTest(raw=raw):
                self.rejected(projection_spec_raw=raw)
        self.rejected(projection_spec_raw=b'[]')

    def test07_root_escape_overlap_and_unknown_fields_rejected(self):
        original = copy.deepcopy(self.specification)
        bad_roots = [str(Path(seed.PRODUCT_ROOT).parent / 'neighbor_project'),
                     seed.PRODUCT_ROOT + os.sep + '..' + os.sep + 'neighbor_project']
        for value in bad_roots:
            self.specification = copy.deepcopy(original)
            self.specification['paths']['source_product_root'] = value
            self.rejected()
        self.specification = copy.deepcopy(original)
        self.specification['paths']['python_root'] = self.specification['paths']['staged_product_root']
        self.rejected()
        self.specification = copy.deepcopy(original)
        self.specification['approved'] = True
        self.rejected()

    def test08_runtime_traversal_and_foreign_path_rejected(self):
        for name in ('../escape.py', 'Lib/../../escape.py', 'C:/foreign.py',
                     'Lib/CON.py', 'Lib/name./module.py'):
            with self.subTest(path=name):
                value = copy.deepcopy(self.runtime)
                value['files'].append(record(name, b'NEVER_READ'))
                self.runtime_raw = contract.canonical(value)
                self.refresh_pins()
                self.rejected()

    def test09_runtime_and_source_case_collisions_rejected(self):
        value = copy.deepcopy(self.runtime)
        value['files'].append(record('PYTHON.EXE', b'OTHER'))
        self.runtime_raw = contract.canonical(value)
        self.refresh_pins()
        self.rejected()
        self.runtime_raw = contract.canonical(self.runtime)
        candidate = copy.deepcopy(self.candidate)
        candidate['files'].append(record('RUNTIME_WINDOWS/FROZEN.PY', b'OTHER'))
        candidate['member_count'] = 2
        self.candidate_raw = contract.canonical(candidate)
        self.refresh_pins()
        self.rejected()

    def test10_runtime_config_license_and_version_remain_governed_by_shared_contract(self):
        for extra in ('pyvenv.cfg', 'python313._pth', 'Lib/site-packages/hidden.py'):
            with self.subTest(configuration=extra):
                value = copy.deepcopy(self.runtime)
                value['files'].append(record(extra, b'NOT_ALLOWED'))
                self.runtime_raw = contract.canonical(value)
                self.refresh_pins()
                self.rejected()
        for changes in ({'license_files': []}, {'version': '3.14.0'}):
            value = dict(self.runtime, **changes)
            self.runtime_raw = contract.canonical(value)
            self.refresh_pins()
            self.rejected()

    def test11_raw_and_final_proposal_budgets_and_types(self):
        for raw in (None, '', bytearray(b'{}'), b' ' * (contract.MAX_PLAN_BYTES + 1)):
            with self.subTest(raw_type=type(raw).__name__):
                self.rejected(projection_spec_raw=raw)
        normal = contract.canonical(self.specification)
        almost_limit = normal + b' ' * (contract.MAX_PLAN_BYTES - 256 - len(normal))
        with self.assertRaises(PreparationError) as caught:
            self.compile(projection_spec_raw=almost_limit)
        self.assertEqual(caught.exception.code, 'BOOTSTRAP_PLAN_BUDGET')
        self.specification['limits']['max_files'] = 1
        self.rejected()

    def test12_generated_relative_pth_is_existing_shared_output(self):
        for version in ('3.9.13', '3.13.12'):
            with self.subTest(version=version):
                value = copy.deepcopy(self.runtime)
                value['version'] = version
                stem = 'python39' if version == '3.9.13' else 'python313'
                value['files'] = [dict(row, path=stem + '.dll') if row['path'] == 'python313.dll'
                                  else row for row in value['files']]
                self.runtime_raw = contract.canonical(value)
                self.refresh_pins()
                proposal = self.compile()
                plan = contract.decode(self.member(proposal, 'projection_plan.json'))
                name, raw = projection.generated_pth(value)
                self.assertEqual(plan['generated_runtime_files'], {name: raw.decode('ascii')})
                self.assertEqual(raw, b'.\nLib\nDLLs\n')
                self.assertNotIn(b'import site', raw)

    def test13_bundle_exact_three_members_no_human_or_self_reference(self):
        proposal = self.compile()
        files = proposal.decoded()['files']
        self.assertEqual(set(files), {'runtime_index.json', 'projection_spec.json',
                                     'projection_plan.json', 'preparation_bundle.json'})
        bundle = contract.decode(self.member(proposal, 'preparation_bundle.json'))
        contract.validate_preparation_bundle(bundle)
        self.assertEqual(set(bundle['files']), set(files) - {'preparation_bundle.json'})
        self.assertNotIn('hc_original.txt', bundle['files'])
        for name, expected in bundle['files'].items():
            self.assertEqual(identity(self.member(proposal, name)), expected)

    def test14_inert_import_and_compile_never_publish_or_issue_authority(self):
        def forbidden(*args, **kwargs):
            raise AssertionError('UNAUTHORIZED_IO_OR_AUTHORITY')
        with inert_import_guard(), mock.patch.object(builtins, 'open', side_effect=forbidden), \
                mock.patch.object(os, 'open', side_effect=forbidden), \
                mock.patch.object(os, 'scandir', side_effect=forbidden), \
                mock.patch.object(Path, 'open', side_effect=forbidden), \
                mock.patch.object(Path, 'stat', side_effect=forbidden), \
                mock.patch.object(Path, 'lstat', side_effect=forbidden), \
                mock.patch.object(Path, 'resolve', side_effect=forbidden), \
                mock.patch.object(Path, 'mkdir', side_effect=forbidden), \
                mock.patch.object(contract, '_issue_preparation_permit', side_effect=forbidden), \
                mock.patch.object(projection, 'materialize_projection', side_effect=forbidden):
            importlib.reload(seed)
            self.assertEqual(self.compile().decoded()['status'], 'PROPOSED_NOT_APPROVED')

    def test15_session_path_budget_and_deterministic_proposal(self):
        first = self.compile()
        self.assertEqual(first.raw_bytes(), self.compile().raw_bytes())
        self.assertEqual(first.sha256, identity(first.raw_bytes())['sha256'])
        for session in ('', '../escape', None, 'a' * 65):
            with self.subTest(session=session):
                self.specification['session_id'] = session
                self.rejected()
        self.specification['session_id'] = 'synthetic_seed'
        self.specification['source_pins']['runtime_index_sha256'] = '0' * 64
        self.rejected()
        self.refresh_pins()
        self.specification['paths']['staged_product_root'] = str(Path(Path(seed.PRODUCT_ROOT).anchor) / ('x' * 219))
        self.rejected()


if __name__ == '__main__':
    unittest.main(verbosity=2)
