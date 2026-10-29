"""Pure path-role fixtures; no Mother reads, deployment, native or core entry.

The original Chinese catalog name and registered identity below are input data,
not a claim that these tests reread or execute the historical asset. Unicode
category/casefold tables belong to each interpreter: these finite longstanding
characters do not establish equivalence for every future Unicode assignment.
"""
import builtins
import copy
import hashlib
import importlib
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


PRODUCT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(PRODUCT))
BLOCKED_IMPORTS = ('ctypes', 'subprocess', 'socket', 'winreg',
    'runtime_windows.candidate_host', 'runtime_windows.host_authority',
    'runtime_windows.preflight_authority', 'runtime_windows.launcher',
    'runtime_windows.win32_backend', 'runtime_windows.assembly',
    'k0_fact_foundation', 'k1_state_derivation',
    'candidate_canonical_capability_contract', 'candidate_capability_feasibility_projection')


def inert_import_guard():
    original = builtins.__import__
    def check(name, globals=None, locals=None, fromlist=(), level=0):
        full = importlib.util.resolve_name('.' * level + name, globals['__package__']) if level else name
        names = [full] + [full + '.' + part for part in fromlist or () if part != '*']
        if any(value == blocked or value.startswith(blocked + '.')
               for value in names for blocked in BLOCKED_IMPORTS):
            raise AssertionError('FORBIDDEN_RUNTIME_IMPORT:' + full)
        return original(name, globals, locals, fromlist, level)
    return mock.patch.object(builtins, '__import__', side_effect=check)


with inert_import_guard():
    from runtime_windows import bootstrap_contract as contract
    from runtime_windows import run_projection as projection
    from runtime_windows.errors import PreparationError


ORIGINAL_CHINESE_ENTRY = {
    'path': 'runtime_binding_v1_20261024/mother/冻结复制说明.md',
    'size': 1408,
    'sha256': 'dcc4ba7d046978a5640e296f8507dffe12daa4a251d740a0c651d0d3cfc21f3c'}


def identity(raw):
    return {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def record(name, raw=b'SYNTHETIC_NOT_EXECUTED'):
    return dict(path=name, **identity(raw))


class ParentRegistryPathTests(unittest.TestCase):
    def setUp(self):
        self.candidate = {'schema': 'h56.windows-effective-source.v1', 'member_count': 1,
                          'files': [record('runtime_windows/frozen.py')]}
        self.candidate_raw = contract.canonical(self.candidate)
        self.bootstrap = {'schema': 'h56.windows-bootstrap-source.v1',
            'baseline_package_sha256': '6' * 64,
            'candidate_runtime_manifest_sha256': identity(self.candidate_raw)['sha256'],
            'member_count': 1, 'files': [record('runtime_windows/synthetic_extra.py')]}
        self.bootstrap_raw = contract.canonical(self.bootstrap)
        self.runtime = {'schema': 'h56.windows-python-source-index.v1', 'version': '3.9.13',
            'arch': 'WINDOWS_X64', 'entrypoint': 'python.exe',
            'source_reference': 'SYNTHETIC_DATA_ONLY', 'license_files': ['LICENSE.txt'],
            'files': [record(name) for name in ('python.exe', 'python39.dll',
                                               'python39.zip', 'LICENSE.txt')]}
        self.runtime_raw = contract.canonical(self.runtime)
        self.parent = {'schema': 'SYNTHETIC_PARENT_CATALOG',
            'files': self.candidate['files'] + self.bootstrap['files'] + [
                record(projection.CANDIDATE_MANIFEST, self.candidate_raw),
                record(projection.BOOTSTRAP_MANIFEST, self.bootstrap_raw),
                dict(ORIGINAL_CHINESE_ENTRY)]}
        self.parent_raw = contract.canonical(self.parent)
        anchor = Path(PRODUCT).anchor
        self.spec = {'schema': 'h56.windows-projection-spec.v1', 'session_id': 'catalog_fixture',
            'paths': {'source_product_root': str(PRODUCT),
                'staged_product_root': str(Path(anchor) / 'cat_dst'),
                'python_source_root': str(Path(anchor) / 'cat_src_py'),
                'python_root': str(Path(anchor) / 'cat_py')},
            'source_pins': {},
            'limits': {'max_files': 128, 'max_file_bytes': 1048576,
                       'max_total_bytes': 4194304, 'deadline_ms': 30000}}
        self.refresh_pins()

    def refresh_pins(self):
        self.spec['source_pins'] = {
            'current_product_manifest_sha256': identity(self.parent_raw)['sha256'],
            'candidate_runtime_manifest_sha256': identity(self.candidate_raw)['sha256'],
            'bootstrap_source_manifest_sha256': identity(self.bootstrap_raw)['sha256'],
            'runtime_index_sha256': identity(self.runtime_raw)['sha256']}

    def build(self, **changes):
        values = dict(parent_raw=self.parent_raw, candidate_raw=self.candidate_raw,
            bootstrap_raw=self.bootstrap_raw, runtime_index_raw=self.runtime_raw,
            specification=self.spec)
        values.update(changes)
        return projection.build_projection_plan(**values)

    def rejects(self, code, function, *args, **kwargs):
        with self.assertRaises(PreparationError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test01_original_catalog_name_and_identity_preserved(self):
        entry = copy.deepcopy(ORIGINAL_CHINESE_ENTRY)
        before = copy.deepcopy(entry)
        index = projection._index([entry], parent_catalog=True)
        self.assertEqual(index, {entry['path']: {'size': entry['size'], 'sha256': entry['sha256']}})
        self.assertEqual(entry, before)
        self.assertEqual(projection._parent_catalog_name(entry['path']), entry['path'].split('/'))

    def test02_full_parent_raw_retained_as_pin_not_filtered_manifest(self):
        before = copy.deepcopy(self.parent)
        plan = self.build().decoded()
        self.assertEqual(plan['source_identity']['current_product_manifest_sha256'],
                         identity(self.parent_raw)['sha256'])
        # A full registry can include Mother without selecting it for this
        # candidate-only deployment subset. The full raw identity still binds it.
        self.assertNotIn(ORIGINAL_CHINESE_ENTRY['path'], plan['product_files'])
        self.assertEqual(self.parent, before)
        self.assertIn('冻结复制说明.md', self.parent_raw.decode('utf-8'))

    def test03_parent_raw_whitespace_or_entry_change_requires_new_pin(self):
        self.rejects('PROJECTION_SOURCE_MANIFEST_PIN_MISMATCH', self.build,
                     parent_raw=self.parent_raw + b'\r\n')
        changed = copy.deepcopy(self.parent)
        changed['files'][-1]['size'] += 1
        self.rejects('PROJECTION_SOURCE_MANIFEST_PIN_MISMATCH', self.build,
                     parent_raw=contract.canonical(changed))

    def test04_selected_member_identity_mismatch_not_hidden_by_unicode_role(self):
        parent = copy.deepcopy(self.parent)
        parent['files'][0]['sha256'] = '2' * 64
        self.parent_raw = contract.canonical(parent)
        self.refresh_pins()
        self.rejects('PROJECTION_CURRENT_REGISTRY_MEMBER_MISMATCH', self.build)

    def test05_runtime_candidate_bootstrap_and_control_stay_strict(self):
        name = ORIGINAL_CHINESE_ENTRY['path']
        self.rejects('BOOTSTRAP_RELATIVE_PATH_INVALID', projection._index, [record(name)])
        runtime = copy.deepcopy(self.runtime)
        runtime['files'].append(record(name))
        self.rejects('BOOTSTRAP_RELATIVE_PATH_INVALID', projection.validate_runtime_index, runtime)
        candidate = copy.deepcopy(self.candidate)
        candidate['files'].append(record(name))
        candidate['member_count'] += 1
        self.candidate_raw = contract.canonical(candidate)
        self.refresh_pins()
        self.rejects('BOOTSTRAP_RELATIVE_PATH_INVALID', self.build)
        self.candidate_raw = contract.canonical(self.candidate)
        bootstrap = copy.deepcopy(self.bootstrap)
        bootstrap['files'].append(record(name))
        bootstrap['member_count'] += 1
        self.bootstrap_raw = contract.canonical(bootstrap)
        self.refresh_pins()
        self.rejects('BOOTSTRAP_RELATIVE_PATH_INVALID', self.build)
        bundle = {'schema': 'h56.windows-preparation-bundle.v1', 'session_id': 's',
                  'allowed_operations': ['INVENTORY'], 'files': {name: identity(b'{}')}}
        self.rejects('BOOTSTRAP_RELATIVE_PATH_INVALID', contract.validate_preparation_bundle, bundle)

    def test06_generated_member_paths_stay_strict(self):
        value = self.build().decoded()
        value['generated_product_files'] = {'冻结.json': '{}'}
        self.rejects('BOOTSTRAP_RELATIVE_PATH_INVALID', projection._validated,
                     contract.FrozenPlan(value))

    def test07_parent_absolute_unc_drive_ads_and_traversal_rejected(self):
        for name in ('/绝对.md', '//server/share.md', '\\server\\share.md', 'C:/母体.md',
                     'C:母体.md', 'dir\\母体.md', '../母体.md', 'dir/../母体.md',
                     'dir/./母体.md', 'dir//母体.md', 'dir/母体.md:stream', ''):
            with self.subTest(path=name):
                self.rejects('PROJECTION_PARENT_CATALOG_PATH_INVALID',
                             projection._index, [record(name)], parent_catalog=True)

    def test08_reserved_trailing_controls_surrogates_and_marks_rejected(self):
        for name in ('目录/CON.md', '目录/nul', 'COM1/说明.md', 'LPT9.txt',
                     'COM\u00b9.md', 'LPT\u00b2.txt', '目录./说明.md', '目录 /说明.md',
                     '目录/说明.md ', '目录/说明.md.', '目录/a\x00.md',
                     '目录/a\n.md', '目录/a\x7f.md', '目录/\ud800.md', '目录/e\u0301.md',
                     '目录/🙂.md', '目录/隐\u200b藏.md', '目录/ａ：b.md'):
            with self.subTest(path=ascii(name)):
                self.rejects('PROJECTION_PARENT_CATALOG_PATH_INVALID',
                             projection._index, [record(name)], parent_catalog=True)

    def test09_letters_numbers_and_ascii_punctuation_without_normalization(self):
        names = ('目录/冻结复制说明.md', 'Étage/é_Ω-١Ⅻ.md', '目录/文件１２３.md',
                 'plain/.gitignore')
        rows = [record(name) for name in names]
        index = projection._index(rows, parent_catalog=True)
        self.assertEqual(list(index), list(names))
        self.assertNotEqual('é.md', 'e\u0301.md')
        self.assertEqual(projection._parent_catalog_name('é.md'), ['é.md'])

    def test10_case_duplicate_collision_not_normalized_into_one_entry(self):
        for pair in (('目录/A.md', '目录/a.md'), ('Étage/说明.md', 'étage/说明.md'),
                     ('目录/ß.md', '目录/ss.md')):
            with self.subTest(pair=pair):
                self.rejects('PROJECTION_CASE_OR_DUPLICATE_MEMBER', projection._index,
                             [record(name) for name in pair], parent_catalog=True)

    def test11_casefold_file_directory_alias_rejected_for_both_roles(self):
        for parent_role, paths in ((True, ('目录/Folder', '目录/folder/说明.md')),
                                   (False, ('Folder', 'folder/child.py'))):
            with self.subTest(parent_role=parent_role):
                self.rejects('PROJECTION_FILE_DIRECTORY_COLLISION', projection._index,
                             [record(name) for name in paths], parent_catalog=parent_role)

    def test12_shared_count_size_total_and_identity_budgets(self):
        for rows, code in (([], 'PROJECTION_FILE_INDEX_BUDGET'),
                           ([record('目录/a.md')] * (projection.MAX_FILES + 1), 'PROJECTION_FILE_INDEX_BUDGET'),
                           ([dict(record('目录/a.md'), size=projection.MAX_FILE_BYTES + 1)], 'PROJECTION_FILE_IDENTITY'),
                           ([dict(record('目录/a.md'), size=True)], 'PROJECTION_FILE_IDENTITY'),
                           ([dict(record('目录/a.md'), sha256='0' * 64)], 'PROJECTION_FILE_IDENTITY')):
            with self.subTest(code=code):
                self.rejects(code, projection._index, rows, parent_catalog=True)
        rows = [dict(record('目录/f' + str(index) + '.md'), size=projection.MAX_FILE_BYTES)
                for index in range(17)]
        self.rejects('PROJECTION_TOTAL_BYTES_BUDGET', projection._index, rows, parent_catalog=True)

    def test13_parent_length_depth_and_immutable_raw_determinism(self):
        for name in ('目' * 221, '/'.join(['目录'] * 21), None, 12):
            with self.subTest(path_type=type(name).__name__):
                self.rejects('PROJECTION_PARENT_CATALOG_PATH_INVALID', projection._index,
                             [record(name)], parent_catalog=True)
        first = self.build()
        self.assertEqual(first.raw_bytes(), self.build().raw_bytes())
        before = first.raw_bytes()
        view = first.decoded()
        view['product_files'].clear()
        self.assertEqual(first.raw_bytes(), before)

    def test14_inert_import_and_build_zero_io_native_or_authority(self):
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
                mock.patch.object(contract, '_issue_preparation_permit', side_effect=forbidden):
            importlib.reload(projection)
            self.assertEqual(self.build().decoded()['schema'], projection.PLAN_SCHEMA)


if __name__ == '__main__':
    unittest.main(verbosity=2)
