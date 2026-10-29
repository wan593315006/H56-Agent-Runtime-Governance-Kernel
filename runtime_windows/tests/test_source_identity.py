"""New helper-only tests. Never import a native core, Mother or old assembly."""
import builtins
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


PRODUCT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(PRODUCT))
from runtime_windows import source_identity as subject
from runtime_windows.errors import PreparationError

COMPONENT = PRODUCT / 'runtime_binding_v1_20261024'
# Keep approved private fixtures below legacy Windows MAX_PATH, without a
# host-root alias, junction, global setting change or extended-path bypass.
FIXTURE_ROOT = PRODUCT / 'runtime_windows' / '.local'


class SourceIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
        cls.lock = subject.build_public_lock(COMPONENT)
        cls.raw = json.dumps(cls.lock, sort_keys=True, ensure_ascii=False,
                             separators=(',', ':')).encode('utf-8')

    def fixture(self):
        root = Path(tempfile.mkdtemp(prefix='si_', dir=str(FIXTURE_ROOT)))
        destination = root / 'engineering' / 'vendor'
        for name in self.lock['vendor']:
            target = destination.joinpath(*name.split('/'))
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(COMPONENT / 'engineering' / 'vendor' / name), str(target))
        return root

    def reject(self, lock, code, root=COMPONENT):
        with self.assertRaises(PreparationError) as found:
            subject.verify_public_lock(root, lock)
        self.assertEqual(found.exception.code, code)

    def test_01_real_110_file_identity_only(self):
        result = subject.verify_public_lock(COMPONENT, self.lock)
        self.assertEqual(result['status'], 'SOURCE_IDENTITY_ONLY')
        self.assertEqual(result['file_count'], 110)
        self.assertEqual(result['total_bytes'], 385567)
        self.assertEqual(result['source_commit'], subject.CORE_COMMIT)
        self.assertFalse(result['execution_authority'])
        self.assertFalse(result['external_fact_trust'])
        self.assertFalse(result['runtime_core_imported'])
        self.assertEqual(set(self.lock), {'contract_sha256', 'vendor'})

    def test_02_consumer_without_private_lock_or_old_manifest(self):
        root = self.fixture()
        self.assertFalse((root / 'offline').exists())
        self.assertFalse((root / 'SOURCE_MANIFEST.json').exists())
        reads = []
        actual = subject._read_checked

        def observe(path, size, limit):
            reads.append(path)
            return actual(path, size, limit)

        with mock.patch.object(subject, '_read_checked', side_effect=observe):
            self.assertEqual(subject.verify_public_lock(root, self.lock)['file_count'], 110)
        self.assertEqual(len(reads), 110)
        self.assertTrue(all(path.is_relative_to(root / 'engineering' / 'vendor') for path in reads))

    def test_03_strict_duplicate_keys_before_conversion(self):
        for raw in (b'{"contract_sha256":"x","contract_sha256":"y","vendor":{}}',
                    b'{"contract_sha256":"x","vendor":{"same":1,"same":2}}'):
            with self.subTest(raw=raw), self.assertRaises(PreparationError) as found:
                subject.parse_public_lock(raw)
            self.assertEqual(found.exception.code, 'DUPLICATE_JSON_KEY')

    def test_04_contract_and_fingerprint_are_fixed(self):
        changed = copy.deepcopy(self.lock)
        changed['contract_sha256'] = '0' * 64
        self.reject(changed, 'ORIGINAL_CONTRACT_IDENTITY_MISMATCH')
        changed = copy.deepcopy(self.lock)
        changed['vendor'][next(iter(changed['vendor']))]['sha256'] = '0' * 64
        self.reject(changed, 'CORE_FINGERPRINT_MISMATCH')

    def test_05_path_forms_rejected(self):
        for name in ('../escape', '/absolute', 'C:/drive', 'a\\backslash',
                     'a//double', 'a/./dot', 'a/../up', 'a/trail.', 'a/CON.txt',
                     'a/stream:ads', 'a/white space', 'a/zero\x00byte'):
            with self.subTest(path=name):
                changed = copy.deepcopy(self.lock)
                changed['vendor'][name] = changed['vendor'].pop(next(iter(changed['vendor'])))
                self.reject(changed, 'UNSAFE_VENDOR_PATH')

    def test_06_case_collision_rejected(self):
        changed = copy.deepcopy(self.lock)
        names = list(changed['vendor'])
        changed['vendor'][names[0].upper()] = changed['vendor'].pop(names[1])
        self.reject(changed, 'CASE_COLLIDING_VENDOR_PATH')

    def test_07_unknown_fields_count_and_boolean_size(self):
        changed = copy.deepcopy(self.lock)
        changed['extra'] = True
        self.reject(changed, 'PUBLIC_LOCK_EXACT_FIELDS')
        changed = copy.deepcopy(self.lock)
        changed['vendor'].pop(next(iter(changed['vendor'])))
        self.reject(changed, 'CORE_CLOSURE_COUNT')
        changed = copy.deepcopy(self.lock)
        changed['vendor'][next(iter(changed['vendor']))]['size'] = True
        self.reject(changed, 'FILE_SIZE_BUDGET')

    def test_08_missing_file_is_rejected(self):
        root = self.fixture()
        (root / 'engineering' / 'vendor' / next(iter(self.lock['vendor']))).unlink()
        self.reject(self.lock, 'EXTRA_OR_MISSING_NATIVE_SOURCE', root)

    def test_09_extra_file_and_empty_directory_rejected(self):
        root = self.fixture()
        extra = root / 'engineering' / 'vendor' / 'injected.py'
        extra.write_bytes(b'not imported')
        self.reject(self.lock, 'EXTRA_OR_MISSING_NATIVE_SOURCE', root)
        extra.unlink()
        (root / 'engineering' / 'vendor' / 'empty_extra').mkdir()
        self.reject(self.lock, 'EXTRA_OR_MISSING_NATIVE_SOURCE', root)

    def test_10_same_size_content_drift_rejected(self):
        root = self.fixture()
        target = root / 'engineering' / 'vendor' / next(iter(self.lock['vendor']))
        data = target.read_bytes()
        target.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        self.reject(self.lock, 'ORIGINAL_CORE_SOURCE_DRIFT', root)

    def test_11_lf_crlf_not_normalized(self):
        root = self.fixture()
        target = root / 'engineering' / 'vendor' / next(iter(self.lock['vendor']))
        data = target.read_bytes()
        self.assertIn(b'\n', data)
        target.write_bytes(data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
        self.assertNotEqual(target.read_bytes(), data)
        self.reject(self.lock, 'SOURCE_SIZE_MISMATCH_OR_BUDGET', root)

    def test_12_actual_hardlink_rejected(self):
        root = self.fixture()
        name = next(iter(self.lock['vendor']))
        target = root / 'engineering' / 'vendor' / name
        outside_vendor = root / 'hardlink_alias'
        try:
            os.link(str(target), str(outside_vendor))
        except OSError as exc:
            self.skipTest('private fixture hardlink unavailable: ' + type(exc).__name__)
        self.reject(self.lock, 'HARDLINK_OR_UNKNOWN_LINK_COUNT', root)

    def test_13_actual_symlink_file_rejected_if_supported(self):
        root = self.fixture()
        target = root / 'engineering' / 'vendor' / next(iter(self.lock['vendor']))
        saved = root / 'saved_bytes'
        saved.write_bytes(target.read_bytes())
        target.unlink()
        try:
            os.symlink(str(saved), str(target))
        except OSError as exc:
            self.skipTest('private fixture symlink unavailable: ' + type(exc).__name__)
        self.reject(self.lock, 'LINK_OR_REPARSE_POINT', root)

    def test_14_actual_symlink_directory_rejected_if_supported(self):
        root = self.fixture()
        destination = root / 'empty_target'
        destination.mkdir()
        target = root / 'engineering' / 'vendor' / 'linked_dir'
        try:
            os.symlink(str(destination), str(target), target_is_directory=True)
        except OSError as exc:
            self.skipTest('private fixture directory symlink unavailable: ' + type(exc).__name__)
        self.reject(self.lock, 'LINK_OR_REPARSE_POINT', root)

    def test_15_bounded_parser_rejects_invalid_or_excess_bytes(self):
        for raw in (b'{' , b'{"x":NaN}', b'\xff', b' ' * (subject.MAX_PUBLIC_LOCK_BYTES + 1)):
            with self.subTest(length=len(raw)), self.assertRaises(PreparationError):
                subject.parse_public_lock(raw)

    def test_16_private_source_hash_drift_rejected(self):
        root = Path(tempfile.mkdtemp(prefix='private_drift_', dir=str(FIXTURE_ROOT)))
        (root / 'offline').mkdir()
        (root / 'offline' / 'source-lock.json').write_bytes(b'{}')
        with self.assertRaises(PreparationError) as found:
            subject.build_public_lock(root)
        self.assertEqual(found.exception.code, 'PRIVATE_LOCK_SOURCE_IDENTITY_MISMATCH')

    def test_17_change_after_file_read_detected_by_tree_snapshot(self):
        root = self.fixture()
        actual = subject._read_checked
        injected = []

        def change_after(path, size, limit):
            raw = actual(path, size, limit)
            if not injected:
                injected.append(path)
                path.write_bytes(raw + b'x')
            return raw

        with mock.patch.object(subject, '_read_checked', side_effect=change_after):
            self.reject(self.lock, 'VENDOR_TREE_CHANGED_DURING_VERIFICATION', root)

    def test_18_import_code_performs_no_io_and_imports_no_native(self):
        path = PRODUCT / 'runtime_windows' / 'source_identity.py'
        code = compile(path.read_bytes(), str(path), 'exec')
        before = set(sys.modules)
        deny = mock.Mock(side_effect=AssertionError('unexpected import-time I/O'))
        with mock.patch.object(builtins, 'open', deny), mock.patch.object(os, 'open', deny), \
                mock.patch.object(os, 'scandir', deny), mock.patch.object(Path, 'lstat', deny), \
                mock.patch.object(Path, 'stat', deny):
            exec(code, {'__name__': 'runtime_windows._source_identity_import_test',
                        '__package__': 'runtime_windows'})
        deny.assert_not_called()
        added = set(sys.modules) - before
        self.assertFalse(any(name.startswith(('k0_', 'k1_', 'candidate_', 'assembly', 'mother'))
                             for name in added))

    def test_19_valid_roundtrip_and_unsafe_root(self):
        self.assertEqual(subject.parse_public_lock(self.raw), self.lock)
        self.reject(self.lock, 'ABSOLUTE_COMPONENT_ROOT_REQUIRED', Path('relative'))

    def test_20_policy_metadata_rejects_unknown_links_hardlinks_and_reparse(self):
        # Pure metadata policy tests, not an OS link-creation acceptance claim.
        for count, attributes, mode, code in (
                (0, 32, stat.S_IFREG, 'HARDLINK_OR_UNKNOWN_LINK_COUNT'),
                (2, 32, stat.S_IFREG, 'HARDLINK_OR_UNKNOWN_LINK_COUNT'),
                (1, 0x400, stat.S_IFREG, 'LINK_OR_REPARSE_POINT'),
                (1, 0, stat.S_IFLNK, 'LINK_OR_REPARSE_POINT')):
            value = SimpleNamespace(st_nlink=count, st_file_attributes=attributes, st_mode=mode)
            with self.subTest(nlink=count, attributes=attributes), self.assertRaises(PreparationError) as found:
                subject._check_stat(value, False, 'synthetic_metadata')
            self.assertEqual(found.exception.code, code)

    def test_21_unc_root_rejected_before_filesystem_access_on_windows(self):
        if os.name != 'nt':
            self.skipTest('Windows UNC lexical path policy applies only on Windows')
        with mock.patch.object(Path, 'lstat', side_effect=AssertionError('UNC I/O attempted')):
            self.reject(self.lock, 'NETWORK_COMPONENT_ROOT_FORBIDDEN', Path('\\\\not-accessed.invalid\\share\\component'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
