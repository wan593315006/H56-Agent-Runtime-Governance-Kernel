"""Finite source/runtime projection; explicit calls only, no import-time I/O.

The current source increment does NOT call real materialization or interpreter
inventory. Tests may exercise these routines only on newly owned synthetic
fixtures. A byte copy is not OS isolation, native dependency completeness,
Human acceptance, Mother recovery or permission for candidate computation.
"""
import hashlib
import os
from pathlib import Path
import stat
import time
import unicodedata

from .bootstrap_contract import (FrozenPlan, canonical, decode, digest, exact,
    fail, relative_name, require_preparation_permit, sha, token)
from .errors import PreparationError
from .source_identity import (_check_chain, _check_stat, _read_checked as _source_read,
    _cross_api_identity as _source_cross)


CANDIDATE_MANIFEST = 'runtime_windows/RUNTIME_SOURCE_MANIFEST.json'
BOOTSTRAP_MANIFEST = 'runtime_windows/BOOTSTRAP_SOURCE_MANIFEST.json'
PLAN_SCHEMA = 'h56.windows-run-projection-plan.v1'
MAX_FILES = 4096
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
FORBIDDEN = frozenset(('runtime_binding_v1_20261024/offline/source-lock.json',
    'runtime_binding_v1_20261024/SOURCE_MANIFEST.json'))


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _identity(raw):
    return dict(size=len(raw), sha256=_hash(raw))


def _cross_api_identity(info):
    values = list(_source_cross(info))
    # On Windows a path ending .exe can lstat as 0100777 but its fd fstat as
    # 0100666. The observed difference is filename-derived execute permissions,
    # not a different file type/object. Preserve read/write bits; only the
    # observed filename-derived 0111 execute bits differ across these APIs.
    # Same-API snapshots below remain exact, including all permission bits.
    if os.name == 'nt':
        values[2] = info.st_mode & ~0o111
    return tuple(values)


def _same_api_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns,
        info.st_ctime_ns, info.st_nlink, getattr(info, 'st_file_attributes', 0),
        getattr(info, 'st_birthtime_ns', None))


def _read_checked(path, expected_size, limit):
    """Bounded projection read with the version-bound shared identity helper.

    The original candidate helper is preserved in the previous source baseline.
    Its current successor is explicitly registered; no helper is monkeypatched.
    """
    if os.name != 'nt':
        return _source_read(path, expected_size, limit)
    _check_chain(path, include_leaf=False)
    before = path.lstat()
    _check_stat(before, False, str(path))
    if before.st_size > limit or (expected_size is not None and before.st_size != expected_size):
        fail('PROJECTION_INPUT_SIZE_OR_BUDGET')
    fd = os.open(str(path), os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    try:
        opened = os.fstat(fd)
        _check_stat(opened, False, str(path))
        if _cross_api_identity(before) != _cross_api_identity(opened):
            fail('PROJECTION_INPUT_OPEN_OBJECT_DRIFT')
        _check_chain(path, include_leaf=False)
        if _same_api_identity(path.lstat()) != _same_api_identity(before):
            fail('PROJECTION_INPUT_PATH_DRIFT')
        chunks, count, deadline = [], 0, time.monotonic() + 30
        while True:
            if time.monotonic() >= deadline:
                fail('PROJECTION_READ_TIMEOUT')
            block = os.read(fd, min(65536, limit + 1 - count))
            if not block:
                break
            count += len(block)
            if count > limit:
                fail('PROJECTION_READ_BYTES_BUDGET')
            chunks.append(block)
        if _same_api_identity(os.fstat(fd)) != _same_api_identity(opened):
            fail('PROJECTION_INPUT_FD_CHANGED')
    finally:
        os.close(fd)
    _check_chain(path, include_leaf=False)
    if _same_api_identity(path.lstat()) != _same_api_identity(before):
        fail('PROJECTION_INPUT_PATH_CHANGED_AFTER_READ')
    raw = b''.join(chunks)
    if len(raw) != before.st_size:
        fail('PROJECTION_INPUT_READ_LENGTH_DRIFT')
    return raw


def read_projection_file(path, expected_size, limit):
    """Explicit successor named read; does not alter original C1/helper code."""
    return _read_checked(path, expected_size, limit)


def _root(value):
    if type(value) is not str or not value or len(value) > 220 or '\x00' in value:
        fail('PROJECTION_ROOT_INVALID')
    path = Path(value)
    if (not path.is_absolute() or '..' in path.parts or
            value.startswith(('\\\\', '//')) or str(path) != value):
        fail('PROJECTION_ROOT_NONLOCAL_OR_NONCANONICAL')
    # Reject alternate data streams and Windows device/relative components.
    for part in path.parts[1:]:
        reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {'COM' + str(n) for n in range(1, 10)} | {'LPT' + str(n) for n in range(1, 10)}
        if (':' in part or part.endswith((' ', '.')) or
                any(ord(x) < 32 or x in '<>|?*"' for x in part) or
                part.split('.')[0].upper() in reserved):
            fail('PROJECTION_ROOT_INVALID')
    return path


def _overlap(left, right):
    a, b = os.path.normcase(str(left)), os.path.normcase(str(right))
    return a == b or a.startswith(b + os.sep) or b.startswith(a + os.sep)


def _parent_catalog_name(value):
    """Parent registry data only; never a selected/deployed member path.

    Preserve original spelling and bytes: no Unicode normalization or renaming.
    Letter/number classification and casefold use this interpreter's Unicode
    tables. Newer assigned characters can differ across Python versions; only
    explicitly dual-verified frozen inputs have cross-version evidence.
    """
    if type(value) is not str or not 1 <= len(value) <= 220:
        fail('PROJECTION_PARENT_CATALOG_PATH_INVALID')
    parts = value.split('/')
    reserved = {'CON', 'PRN', 'AUX', 'NUL'}
    reserved.update(prefix + digit for prefix in ('COM', 'LPT')
                    for digit in ('1', '2', '3', '4', '5', '6', '7', '8', '9', '\u00b9', '\u00b2', '\u00b3'))
    if len(parts) > 20:
        fail('PROJECTION_PARENT_CATALOG_PATH_INVALID')
    for part in parts:
        if (not part or part in ('.', '..') or part.endswith(('.', ' ')) or
                part.split('.')[0].upper() in reserved or
                any(character not in '._-' and unicodedata.category(character)[0] not in 'LN'
                    for character in part)):
            fail('PROJECTION_PARENT_CATALOG_PATH_INVALID')
    return parts

def _index(files, maximum=MAX_FILES, parent_catalog=False):
    if type(files) is not list or not 1 <= len(files) <= maximum:
        fail('PROJECTION_FILE_INDEX_BUDGET')
    result, folded, total = {}, set(), 0
    for item in files:
        if type(item) is not dict or not {'path', 'size', 'sha256'} <= set(item):
            fail('PROJECTION_FILE_IDENTITY_FIELDS')
        name = item['path']
        if parent_catalog:
            _parent_catalog_name(name)
        else:
            relative_name(name)
        if name.casefold() in folded:
            fail('PROJECTION_CASE_OR_DUPLICATE_MEMBER')
        folded.add(name.casefold())
        size = item['size']
        if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES or not sha(item['sha256']):
            fail('PROJECTION_FILE_IDENTITY')
        total += size
        result[name] = dict(size=size, sha256=item['sha256'])
    if total > MAX_TOTAL_BYTES:
        fail('PROJECTION_TOTAL_BYTES_BUDGET')
    for name in result:
        parts = name.split('/')
        if any('/'.join(parts[:i]).casefold() in folded for i in range(1, len(parts))):
            fail('PROJECTION_FILE_DIRECTORY_COLLISION')
    return result


def _forbidden(name):
    return (name in FORBIDDEN or name.split('/')[-1] == 'host_driver.py' or
        any(part in ('.git', '.local', '__pycache__') for part in name.split('/')))


def managed_directory_roles(session_id):
    """Fixed empty-directory producer contract; roles are not OS permissions."""
    token(session_id)
    parent = 'runtime_windows/.local'
    base = parent + '/' + session_id
    result = {parent: 'SOURCE_READ_EXECUTE', base: 'SOURCE_READ_EXECUTE'}
    for name, role in (('preparation', 'HOST_ONLY'), ('preparation_control', 'HOST_ONLY'),
            ('control', 'SOURCE_READ_EXECUTE'), ('scratch', 'SCRATCH_READ_WRITE'),
            ('scratch/runs', 'SCRATCH_READ_WRITE'), ('scratch/child_failures', 'SCRATCH_READ_WRITE'),
            ('replay_input', 'RECEIPT_READ_ONLY'), ('host_evidence', 'HOST_ONLY'),
            ('host_evidence/preflight', 'HOST_ONLY'), ('host_private', 'HOST_ONLY')):
        result[base + '/' + name] = role
    return result


def validate_runtime_index(value):
    """Declared finite distribution only; not actual native dependency proof."""
    exact(value, ('schema', 'version', 'arch', 'entrypoint', 'files',
        'source_reference', 'license_files'), 'PROJECTION_RUNTIME_INDEX_FIELDS')
    if (value['schema'] != 'h56.windows-python-source-index.v1' or
            value['version'] not in ('3.9.13', '3.13.12') or
            value['arch'] != 'WINDOWS_X64' or value['entrypoint'] != 'python.exe'):
        fail('PROJECTION_RUNTIME_VERSION_OR_ENTRY')
    if type(value['source_reference']) is not str or not 1 <= len(value['source_reference']) <= 1024:
        fail('PROJECTION_RUNTIME_SOURCE_REFERENCE')
    files = _index(value['files'])
    stem = 'python39' if value['version'] == '3.9.13' else 'python313'
    if 'python.exe' not in files or stem + '.dll' not in files:
        fail('PROJECTION_RUNTIME_EXECUTABLE_OR_DLL_MISSING')
    if any(name.split('/')[-1].casefold() == 'pyvenv.cfg' or
           name.lower().endswith('._pth') or name.lower().endswith(('.pth', '.pyc')) or
           any(p.lower() == 'site-packages' for p in name.split('/')) for name in files):
        fail('PROJECTION_UNCONTROLLED_PYTHON_CONFIGURATION')
    if not (stem + '.zip' in files or any(name.startswith('Lib/encodings/') for name in files)):
        fail('PROJECTION_STDLIB_DECLARATION_MISSING')
    licenses = value['license_files']
    if (type(licenses) is not list or not licenses or
            any(type(name) is not str or name not in files for name in licenses) or
            len(set(licenses)) != len(licenses)):
        fail('PROJECTION_RUNTIME_LICENSE_DECLARATION')
    return files


def generated_pth(value):
    files = validate_runtime_index(value)
    stem = 'python39' if value['version'] == '3.9.13' else 'python313'
    entries = ['.']
    for folder in ('Lib', 'DLLs'):
        if any(name.startswith(folder + '/') for name in files):
            entries.append(folder)
    if stem + '.zip' in files:
        entries.append(stem + '.zip')
    return stem + '._pth', ('\n'.join(entries) + '\n').encode('ascii')


def _source_manifests(parent_raw, candidate_raw, bootstrap_raw, pins):
    raws = dict(candidate_runtime_manifest_sha256=candidate_raw,
        bootstrap_source_manifest_sha256=bootstrap_raw)
    if parent_raw is not None:
        raws['current_product_manifest_sha256'] = parent_raw
    for key, raw in raws.items():
        if type(raw) is not bytes or _hash(raw) != pins[key]:
            fail('PROJECTION_SOURCE_MANIFEST_PIN_MISMATCH', key)
    candidate, bootstrap = (decode(raw) for raw in (candidate_raw, bootstrap_raw))
    parent_files = None
    if parent_raw is not None:
        parent = decode(parent_raw)
        if type(parent) is not dict or type(parent.get('files')) is not list:
            fail('PROJECTION_CURRENT_PRODUCT_REGISTRY_REQUIRED')
        parent_files = _index(parent['files'], parent_catalog=True)
    exact(candidate, ('schema', 'member_count', 'files'), 'PROJECTION_CANDIDATE_FIELDS')
    if (candidate['schema'] != 'h56.windows-effective-source.v1' or type(candidate['files']) is not list or
            type(candidate['member_count']) is not int or candidate['member_count'] != len(candidate['files'])):
        fail('PROJECTION_CANDIDATE_MANIFEST')
    candidate_files = _index(candidate['files'])
    exact(bootstrap, ('schema', 'baseline_package_sha256', 'candidate_runtime_manifest_sha256',
        'member_count', 'files'), 'PROJECTION_BOOTSTRAP_FIELDS')
    if (bootstrap['schema'] != 'h56.windows-bootstrap-source.v1' or
            not sha(bootstrap['baseline_package_sha256']) or
            bootstrap['candidate_runtime_manifest_sha256'] != pins['candidate_runtime_manifest_sha256'] or
            type(bootstrap['files']) is not list or type(bootstrap['member_count']) is not int or
            bootstrap['member_count'] != len(bootstrap['files'])):
        fail('PROJECTION_BOOTSTRAP_MANIFEST')
    bootstrap_files = _index(bootstrap['files'], 64)
    if set(bootstrap_files) & set(candidate_files):
        fail('PROJECTION_BOOTSTRAP_CANDIDATE_OVERLAP')
    for name in bootstrap_files:
        if not name.startswith('runtime_windows/') or name in (CANDIDATE_MANIFEST, BOOTSTRAP_MANIFEST):
            fail('PROJECTION_BOOTSTRAP_SOURCE_SCOPE')
    selected = dict(candidate_files, **bootstrap_files)
    selected[CANDIDATE_MANIFEST] = _identity(candidate_raw)
    selected[BOOTSTRAP_MANIFEST] = _identity(bootstrap_raw)
    for name, identity in selected.items():
        if _forbidden(name) or name == 'PACKAGE_MANIFEST.json':
            fail('PROJECTION_FORBIDDEN_SOURCE')
        if parent_files is not None and (name not in parent_files or parent_files[name] != identity):
            fail('PROJECTION_CURRENT_REGISTRY_MEMBER_MISMATCH', name)
    # The baseline hash is provenance, not a requirement to read a private old MF.
    return selected, bootstrap['baseline_package_sha256']


def build_projection_plan(parent_raw, candidate_raw, bootstrap_raw, runtime_index_raw, specification):
    """Pure builder. All reads are explicit upstream; no directory discovery."""
    exact(specification, ('schema', 'session_id', 'paths', 'source_pins', 'limits'),
        'PROJECTION_SPEC_FIELDS')
    if specification['schema'] != 'h56.windows-projection-spec.v1':
        fail('PROJECTION_SPEC_SCHEMA')
    token(specification['session_id'])
    paths, pins, limits = (specification[name] for name in ('paths', 'source_pins', 'limits'))
    exact(paths, ('source_product_root', 'staged_product_root', 'python_source_root', 'python_root'),
        'PROJECTION_PATH_FIELDS')
    roots = [_root(value) for value in paths.values()]
    if any(_overlap(left, right) for i, left in enumerate(roots) for right in roots[i + 1:]):
        fail('PROJECTION_ROOTS_OVERLAP')
    exact(pins, ('current_product_manifest_sha256', 'candidate_runtime_manifest_sha256',
        'bootstrap_source_manifest_sha256', 'runtime_index_sha256'), 'PROJECTION_PIN_FIELDS')
    if not all(sha(value) for value in pins.values()):
        fail('PROJECTION_SOURCE_PINS_UNBOUND')
    exact(limits, ('max_files', 'max_file_bytes', 'max_total_bytes', 'deadline_ms'),
        'PROJECTION_LIMIT_FIELDS')
    for key, maximum in (('max_files', MAX_FILES), ('max_file_bytes', MAX_FILE_BYTES),
            ('max_total_bytes', MAX_TOTAL_BYTES), ('deadline_ms', 600000)):
        if type(limits[key]) is not int or not 1 <= limits[key] <= maximum:
            fail('PROJECTION_LIMIT_INVALID')
    selected, baseline = _source_manifests(parent_raw, candidate_raw, bootstrap_raw, pins)
    if type(runtime_index_raw) is not bytes or _hash(runtime_index_raw) != pins['runtime_index_sha256']:
        fail('PROJECTION_RUNTIME_INDEX_PIN_MISMATCH')
    runtime_index = decode(runtime_index_raw)
    runtime = validate_runtime_index(runtime_index)
    pth_name, pth_raw = generated_pth(runtime_index)
    mutable = ['runtime_windows/.local/' + specification['session_id'] + '/' + name
        for name in ('preparation', 'preparation_control', 'control', 'scratch', 'replay_input', 'host_evidence', 'host_private')]
    provenance = dict(schema='h56.windows-projection-provenance.v1',
        grade='CANDIDATE_EXECUTION_SUBSET_ONLY', source_pins=pins,
        baseline_package_sha256=baseline,
        meaning='Not all254 files,allMother consumers,OS acceptance or candidate permission')
    provenance_raw = canonical(provenance)
    records = [dict(path=name, **identity) for name, identity in sorted(selected.items())]
    records.append(dict(path='PROJECTION_PROVENANCE.json', **_identity(provenance_raw)))
    package = dict(schema='h56.windows-projection-package.v1', files=records,
        member_count=len(records), mutable_directories=mutable,
        managed_empty_directories=managed_directory_roles(specification['session_id']),
        mutable_files=['runtime_windows/.local/' + specification['session_id'] + '/active.lock'],
        candidate_runtime_manifest_sha256=pins['candidate_runtime_manifest_sha256'],
        baseline_package_sha256=baseline)
    generated = {'PROJECTION_PROVENANCE.json': provenance_raw.decode('utf-8'),
                 'PACKAGE_MANIFEST.json': canonical(package).decode('utf-8')}
    total = sum(x['size'] for x in selected.values()) + sum(x['size'] for x in runtime.values())
    total += len(pth_raw) + sum(len(x.encode('utf-8')) for x in generated.values())
    count = len(selected) + len(runtime) + len(generated) + 1
    if count > limits['max_files'] or total > limits['max_total_bytes']:
        fail('PROJECTION_AGGREGATE_BUDGET')
    if any(x['size'] > limits['max_file_bytes'] for x in list(selected.values()) + list(runtime.values())):
        fail('PROJECTION_MEMBER_BUDGET')
    runtime_names = list(runtime) + [pth_name]
    for name in runtime_names:
        if len(str(_root(paths['python_root']).joinpath(*name.split('/')))) > 240:
            fail('PROJECTION_FINAL_RUNTIME_PATH_LENGTH')
    for name in list(selected) + list(generated) + mutable:
        if len(str(_root(paths['staged_product_root']).joinpath(*name.split('/')))) > 240:
            fail('PROJECTION_FINAL_PATH_LENGTH')
    future_names = ['runtime_windows/.local/' + specification['session_id'] + '/' + suffix
        for suffix in ('control/controller_bundle.json', 'control/preflight_evidence_index.json',
            'preparation_control/preparation_bundle.json', 'preparation_control/projection_receipt.json',
            'preparation/prelaunch_resources_receipt.json',
            'host_evidence/preflight/999_profile_storage_scope.json')]
    for name in future_names:
        if len(str(_root(paths['staged_product_root']).joinpath(*name.split('/')))) > 240:
            fail('PROJECTION_FINAL_PATH_LENGTH')
    return FrozenPlan(dict(schema=PLAN_SCHEMA, session_id=specification['session_id'],
        paths=paths, source_identity=dict(pins, baseline_package_sha256=baseline),
        limits=limits, product_files=selected, runtime_files=runtime,
        generated_product_files=generated, generated_runtime_files={pth_name: pth_raw.decode('ascii')},
        mutable_directories=mutable, mutable_files=package['mutable_files'],
        managed_empty_directories=package['managed_empty_directories'],
        runtime_version=runtime_index['version'], runtime_source_reference=runtime_index['source_reference'],
        runtime_index_raw=runtime_index_raw.decode('utf-8')))


def _validated(plan):
    if type(plan) is not FrozenPlan:
        fail('PROJECTION_FROZEN_PLAN_REQUIRED')
    value = plan.decoded()
    exact(value, ('schema', 'session_id', 'paths', 'source_identity', 'limits',
        'product_files', 'runtime_files', 'generated_product_files',
        'generated_runtime_files', 'mutable_directories', 'mutable_files',
        'managed_empty_directories',
        'runtime_version', 'runtime_source_reference', 'runtime_index_raw'), 'PROJECTION_PLAN_FIELDS')
    if value['schema'] != PLAN_SCHEMA:
        fail('PROJECTION_PLAN_SCHEMA')
    exact(value['limits'], ('max_files', 'max_file_bytes', 'max_total_bytes', 'deadline_ms'))
    for key, maximum in (('max_files', MAX_FILES), ('max_file_bytes', MAX_FILE_BYTES),
            ('max_total_bytes', MAX_TOTAL_BYTES), ('deadline_ms', 600000)):
        if type(value['limits'][key]) is not int or not 1 <= value['limits'][key] <= maximum:
            fail('PROJECTION_LIMIT_INVALID')
    # A FrozenPlan cannot bypass the pure builder's checks by adding a hash seal.
    token(value['session_id'])
    exact(value['paths'], ('source_product_root', 'staged_product_root', 'python_source_root', 'python_root'))
    roots = [_root(path) for path in value['paths'].values()]
    if any(_overlap(a, b) for i, a in enumerate(roots) for b in roots[i + 1:]):
        fail('PROJECTION_ROOTS_OVERLAP')
    for field in ('product_files', 'runtime_files'):
        identities = value[field]
        if type(identities) is not dict:
            fail('PROJECTION_PLAN_INDEX')
        _index([dict(path=name, **identity) for name, identity in identities.items()])
    for field in ('generated_product_files', 'generated_runtime_files'):
        if type(value[field]) is not dict or len(value[field]) > 4:
            fail('PROJECTION_GENERATED_FIELDS')
        for name, content in value[field].items():
            relative_name(name)
            if type(content) is not str or len(content.encode('utf-8')) > 1024 * 1024:
                fail('PROJECTION_GENERATED_BUDGET')
    if set(value['generated_product_files']) != {'PACKAGE_MANIFEST.json', 'PROJECTION_PROVENANCE.json'}:
        fail('PROJECTION_GENERATED_PRODUCT_SCOPE')
    if any(_forbidden(name) for name in value['product_files']):
        fail('PROJECTION_FORBIDDEN_SOURCE')
    # Rebuild all derived package/provenance bytes from the closed input plan.
    pins = value['source_identity']
    exact(pins, ('current_product_manifest_sha256', 'candidate_runtime_manifest_sha256',
        'bootstrap_source_manifest_sha256', 'runtime_index_sha256', 'baseline_package_sha256'))
    if not all(sha(x) for x in pins.values()):
        fail('PROJECTION_SOURCE_PINS_UNBOUND')
    if type(value['runtime_index_raw']) is not str:
        fail('PROJECTION_RUNTIME_INDEX_RAW_REQUIRED')
    runtime_raw = value['runtime_index_raw'].encode('utf-8')
    runtime_data = decode(runtime_raw)
    if (_hash(runtime_raw) != pins['runtime_index_sha256'] or
            validate_runtime_index(runtime_data) != value['runtime_files'] or
            runtime_data['version'] != value['runtime_version'] or
            runtime_data['source_reference'] != value['runtime_source_reference']):
        fail('PROJECTION_RUNTIME_INDEX_IDENTITY')
    pth_name = 'python39._pth' if value['runtime_version'] == '3.9.13' else 'python313._pth'
    if value['runtime_version'] not in ('3.9.13', '3.13.12') or set(value['generated_runtime_files']) != {pth_name}:
        fail('PROJECTION_GENERATED_RUNTIME_SCOPE')
    pth = value['generated_runtime_files'][pth_name]
    allowed = ['.']
    for folder in ('Lib', 'DLLs'):
        if any(name.startswith(folder + '/') for name in value['runtime_files']):
            allowed.append(folder)
    stem = pth_name[:-5]
    if stem + '.zip' in value['runtime_files']:
        allowed.append(stem + '.zip')
    if pth != '\n'.join(allowed) + '\n':
        fail('PROJECTION_GENERATED_PTH_CONTENT')
    expected_mutable = ['runtime_windows/.local/' + value['session_id'] + '/' + name
        for name in ('preparation', 'preparation_control', 'control', 'scratch', 'replay_input', 'host_evidence', 'host_private')]
    if value['mutable_directories'] != expected_mutable or value['mutable_files'] != [
            'runtime_windows/.local/' + value['session_id'] + '/active.lock']:
        fail('PROJECTION_MUTABLE_SCOPE')
    if value['managed_empty_directories'] != managed_directory_roles(value['session_id']):
        fail('PROJECTION_MANAGED_DIRECTORY_SCOPE')
    expected_provenance = dict(schema='h56.windows-projection-provenance.v1',
        grade='CANDIDATE_EXECUTION_SUBSET_ONLY',
        source_pins={key: val for key, val in pins.items() if key != 'baseline_package_sha256'},
        baseline_package_sha256=pins['baseline_package_sha256'],
        meaning='Not all254 files,allMother consumers,OS acceptance or candidate permission')
    if value['generated_product_files']['PROJECTION_PROVENANCE.json'] != canonical(expected_provenance).decode('utf-8'):
        fail('PROJECTION_DERIVED_PROVENANCE_MISMATCH')
    for name, content in value['generated_product_files'].items():
        if name == 'PACKAGE_MANIFEST.json':
            package = decode(content.encode('utf-8'))
            exact(package, ('schema', 'files', 'member_count', 'mutable_directories',
                'managed_empty_directories', 'mutable_files',
                'candidate_runtime_manifest_sha256', 'baseline_package_sha256'))
            expected = dict(value['product_files'])
            expected['PROJECTION_PROVENANCE.json'] = _identity(value['generated_product_files'][
                'PROJECTION_PROVENANCE.json'].encode('utf-8'))
            if (package['schema'] != 'h56.windows-projection-package.v1' or
                    package['candidate_runtime_manifest_sha256'] != pins['candidate_runtime_manifest_sha256'] or
                    package['baseline_package_sha256'] != pins['baseline_package_sha256'] or
                    _index(package.get('files')) != expected or package.get('member_count') != len(expected) or
                    package.get('mutable_directories') != value['mutable_directories'] or
                    package.get('managed_empty_directories') != value['managed_empty_directories'] or
                    package.get('mutable_files') != value['mutable_files']):
                fail('PROJECTION_DERIVED_MANIFEST_MISMATCH')
    all_files = list(value['product_files'].values()) + list(value['runtime_files'].values())
    generated = [x.encode('utf-8') for field in ('generated_product_files', 'generated_runtime_files')
        for x in value[field].values()]
    if (len(all_files) + len(generated) > value['limits']['max_files'] or
            sum(x['size'] for x in all_files) + sum(len(x) for x in generated) > value['limits']['max_total_bytes'] or
            any(x['size'] > value['limits']['max_file_bytes'] for x in all_files)):
        fail('PROJECTION_AGGREGATE_BUDGET')
    for key, names in (('staged_product_root', list(value['product_files']) +
            list(value['generated_product_files']) + value['mutable_directories'] +
            ['runtime_windows/.local/' + value['session_id'] + '/' + suffix
                for suffix in ('control/controller_bundle.json', 'control/preflight_evidence_index.json',
                    'preparation_control/preparation_bundle.json', 'preparation_control/projection_receipt.json',
                    'preparation/prelaunch_resources_receipt.json',
                    'host_evidence/preflight/999_profile_storage_scope.json')]),
            ('python_root', list(value['runtime_files']) + list(value['generated_runtime_files']))):
        if any(len(str(_root(value['paths'][key]).joinpath(*name.split('/')))) > 240 for name in names):
            fail('PROJECTION_FINAL_PATH_LENGTH')
    return value


def enforce_entry_root(plan, operation, actual_product_root):
    value = _validated(plan)
    if operation not in ('INVENTORY', 'MATERIALIZE', 'STAGED_VERIFY', 'C1_OBSERVE',
            'NEGATIVE_PROBE', 'RESOURCE_PREPARE', 'RESOURCE_READBACK'):
        fail('PROJECTION_ENTRY_OPERATION_UNKNOWN')
    key = 'source_product_root' if operation in ('INVENTORY', 'MATERIALIZE') else 'staged_product_root'
    if type(actual_product_root) is not str or actual_product_root != value['paths'][key]:
        fail('PROJECTION_ACTUAL_ENTRY_ROOT_MISMATCH')


def inventory_declared_inputs(plan, permit):
    """Read only explicit registered files. No installed-tree traversal."""
    require_preparation_permit(plan, permit, 'INVENTORY')
    value = _validated(plan)
    product_root = _root(value['paths']['source_product_root'])
    runtime_root = _root(value['paths']['python_source_root'])
    current_manifest = _read_checked(product_root / 'PACKAGE_MANIFEST.json', None, 2 * 1024 * 1024)
    if _hash(current_manifest) != value['source_identity']['current_product_manifest_sha256']:
        fail('PROJECTION_CURRENT_PRODUCT_MANIFEST_DRIFT')
    deadline, observed = time.monotonic() + value['limits']['deadline_ms'] / 1000, []
    for role, root, files in (('PRODUCT', product_root, value['product_files']),
                              ('PYTHON', runtime_root, value['runtime_files'])):
        for name, identity in sorted(files.items()):
            if time.monotonic() >= deadline:
                fail('PROJECTION_INVENTORY_TIMEOUT')
            raw = _read_checked(root.joinpath(*name.split('/')), identity['size'], value['limits']['max_file_bytes'])
            if _hash(raw) != identity['sha256']:
                fail('PROJECTION_NAMED_INPUT_DRIFT', name)
            observed.append(dict(role=role, path=name, **identity))
    return dict(schema='h56.windows-declared-input-inventory.v1', plan_sha256=plan.sha256,
        grade='NAMED_BYTES_ONLY_NOT_DEPENDENCY_COMPLETENESS', files=observed,
        native_runtime='NOT_RUN', authority_granted=False)


class ProjectionMaterializationError(PreparationError):
    """Preserve positively created paths; do not silently delete the scene."""
    def __init__(self, cause, created):
        super().__init__('PROJECTION_MATERIALIZATION_STOPPED', type(cause).__name__)
        self.created_paths = tuple(created)
        self.cause_code = cause.code if isinstance(cause, PreparationError) else type(cause).__name__


def _write_new(root, name, raw, created):
    relative_name(name)
    path = root.joinpath(*name.split('/'))
    current = root
    for part in name.split('/')[:-1]:
        current = current / part
        try:
            os.mkdir(str(current))
            created.append(str(current))
        except FileExistsError:
            _check_chain(current)
    _check_chain(path, include_leaf=False)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    created.append(str(path))
    try:
        opened = os.fstat(fd)
        _check_stat(opened, False, name)
        if _cross_api_identity(path.lstat()) != _cross_api_identity(opened):
            fail('PROJECTION_OUTPUT_HANDLE_MISMATCH')
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:offset + 65536])
            if count <= 0:
                fail('PROJECTION_OUTPUT_WRITE_STOPPED')
            offset += count
        os.fsync(fd)
        after = os.fstat(fd)
        _check_stat(after, False, name)
        _check_chain(path, include_leaf=False)
        if (_cross_api_identity(path.lstat()) != _cross_api_identity(after) or
                after.st_size != len(raw) or after.st_ino != opened.st_ino or after.st_dev != opened.st_dev):
            fail('PROJECTION_OUTPUT_PATH_CHANGED')
    finally:
        os.close(fd)
    if _read_checked(path, len(raw), max(1, len(raw))) != raw:
        fail('PROJECTION_OUTPUT_READBACK_DRIFT')


def _create_owned_directory(root, name, created):
    relative_name(name)
    current = root
    for part in name.split('/'):
        current = current / part
        _check_chain(current.parent)
        try:
            os.mkdir(str(current))
            created.append(str(current))
        except FileExistsError:
            if str(current) not in created:
                fail('PROJECTION_EXISTING_DIRECTORY_NOT_OWNED')
        _check_chain(current)


def materialize_projection(plan, permit):
    """Future approved byte copy. Never called on actual product by this increment."""
    require_preparation_permit(plan, permit, 'MATERIALIZE')
    value = _validated(plan)
    # Independently read inputs before creating any output. A MATERIALIZE permit
    # grants its bound finite reads; it does not grant a different INVENTORY call.
    deadline = time.monotonic() + value['limits']['deadline_ms'] / 1000
    for key in ('staged_product_root', 'python_root'):
        target = _root(value['paths'][key])
        _check_chain(target.parent)
        if os.path.lexists(str(target)):
            fail('PROJECTION_TARGET_EXISTS')
    product_source = _root(value['paths']['source_product_root'])
    raw = _read_checked(product_source / 'PACKAGE_MANIFEST.json', None, 2 * 1024 * 1024)
    if _hash(raw) != value['source_identity']['current_product_manifest_sha256']:
        fail('PROJECTION_CURRENT_PRODUCT_MANIFEST_DRIFT')
    candidate_raw = _read_checked(product_source.joinpath(*CANDIDATE_MANIFEST.split('/')), None, 2 * 1024 * 1024)
    bootstrap_raw = _read_checked(product_source.joinpath(*BOOTSTRAP_MANIFEST.split('/')), None, 2 * 1024 * 1024)
    selected, baseline = _source_manifests(raw, candidate_raw, bootstrap_raw, value['source_identity'])
    if selected != value['product_files'] or baseline != value['source_identity']['baseline_package_sha256']:
        fail('PROJECTION_SELECTED_SOURCE_SET_DRIFT')
    for source_key, files in (('source_product_root', value['product_files']), ('python_source_root', value['runtime_files'])):
        for name, identity in sorted(files.items()):
            if time.monotonic() >= deadline:
                fail('PROJECTION_MATERIALIZATION_TIMEOUT')
            raw = _read_checked(_root(value['paths'][source_key]).joinpath(*name.split('/')),
                identity['size'], value['limits']['max_file_bytes'])
            if _hash(raw) != identity['sha256']:
                fail('PROJECTION_NAMED_INPUT_DRIFT', name)
    created = []
    try:
        for target_key, source_key, files, generated in (
                ('staged_product_root', 'source_product_root', value['product_files'], value['generated_product_files']),
                ('python_root', 'python_source_root', value['runtime_files'], value['generated_runtime_files'])):
            target, source = _root(value['paths'][target_key]), _root(value['paths'][source_key])
            os.mkdir(str(target))
            created.append(str(target))
            _check_chain(target)
            for name, identity in sorted(files.items()):
                if time.monotonic() >= deadline:
                    fail('PROJECTION_MATERIALIZATION_TIMEOUT')
                raw = _read_checked(source.joinpath(*name.split('/')), identity['size'], value['limits']['max_file_bytes'])
                if _hash(raw) != identity['sha256']:
                    fail('PROJECTION_NAMED_INPUT_DRIFT', name)
                _write_new(target, name, raw, created)
            for name, content in sorted(generated.items()):
                _write_new(target, name, content.encode('utf-8'), created)
        product_target = _root(value['paths']['staged_product_root'])
        for name in sorted(value['managed_empty_directories'], key=lambda item: (item.count('/'), item)):
            _create_owned_directory(product_target, name, created)
        result = verify_projection(plan)
        result['created_paths'] = created
        objects = []
        for item in created:
            path, info = Path(item), Path(item).lstat()
            directory = stat.S_ISDIR(info.st_mode)
            _check_stat(info, directory, item)
            record = dict(path=item, kind='directory' if directory else 'file',
                file_identity=dict(device=info.st_dev, inode=info.st_ino,
                    links=info.st_nlink, attributes=getattr(info, 'st_file_attributes', 0)))
            role = 'SOURCE_READ_EXECUTE'
            if directory and path != product_target:
                try:
                    relative = path.relative_to(product_target).as_posix()
                except ValueError:
                    relative = None
                if relative is not None:
                    role = value['managed_empty_directories'].get(relative, role)
            record['role'] = role
            if not directory:
                record.update(_identity(_read_checked(path, info.st_size, MAX_FILE_BYTES)))
            objects.append(record)
        result['created_objects'] = objects
        return result
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise ProjectionMaterializationError(error, created) from error
        raise ProjectionMaterializationError(error, created) from error


def _verify_tree(root, expected, value, mutable_dirs=(), mutable_files=()):
    _check_chain(root)
    expected_dirs = {''}
    for name in expected:
        parts = name.split('/')
        expected_dirs.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    for name in list(mutable_dirs) + list(mutable_files):
        parts = name.split('/')
        expected_dirs.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    pending, observed, count = [(root, '')], {}, 0
    deadline = time.monotonic() + value['limits']['deadline_ms'] / 1000
    while pending:
        directory, prefix = pending.pop()
        _check_chain(directory)
        with os.scandir(str(directory)) as entries:
            for entry in entries:
                count += 1
                if count > value['limits']['max_files'] * 4 or time.monotonic() >= deadline:
                    fail('PROJECTION_VERIFY_TREE_BUDGET')
                name = prefix + '/' + entry.name if prefix else entry.name
                relative_name(name)
                path = directory / entry.name
                info = path.lstat()
                is_directory = stat.S_ISDIR(info.st_mode)
                _check_stat(info, is_directory, name)
                if is_directory:
                    if name in mutable_dirs:
                        continue  # Explicit session roles, never blanket '.local'.
                    if name not in expected_dirs:
                        fail('PROJECTION_EXTRA_DIRECTORY', name)
                    pending.append((path, name))
                else:
                    if name in mutable_files:
                        if info.st_size > 1048576:
                            fail('PROJECTION_MUTABLE_FILE_BUDGET')
                        continue
                    if name not in expected:
                        fail('PROJECTION_EXTRA_FILE', name)
                    identity = expected[name]
                    raw = _read_checked(path, identity['size'], max(value['limits']['max_file_bytes'], 1048576))
                    if _hash(raw) != identity['sha256']:
                        fail('PROJECTION_OUTPUT_HASH_DRIFT', name)
                    observed[name] = identity
    if set(observed) != set(expected):
        fail('PROJECTION_MISSING_OUTPUT')
    return observed


def verify_projection(plan):
    """Staged bytes only; never reads the original/source/Python source roots."""
    value = _validated(plan)
    product_root = _root(value['paths']['staged_product_root'])
    for name in value['managed_empty_directories']:
        try:
            _check_chain(product_root.joinpath(*name.split('/')))
        except OSError as error:
            raise PreparationError('PROJECTION_MANAGED_DIRECTORY_MISSING_OR_UNSAFE', name) from error
    expected = dict(value['product_files'])
    for name, content in value['generated_product_files'].items():
        expected[name] = _identity(content.encode('utf-8'))
    product = _verify_tree(_root(value['paths']['staged_product_root']), expected, value,
        value['mutable_directories'], value['mutable_files'])
    staged = _root(value['paths']['staged_product_root'])
    selected, baseline = _source_manifests(None,
        _read_checked(staged.joinpath(*CANDIDATE_MANIFEST.split('/')), None, 2 * 1024 * 1024),
        _read_checked(staged.joinpath(*BOOTSTRAP_MANIFEST.split('/')), None, 2 * 1024 * 1024),
        value['source_identity'])
    if selected != value['product_files'] or baseline != value['source_identity']['baseline_package_sha256']:
        fail('PROJECTION_SELECTED_SOURCE_SET_DRIFT')
    expected_runtime = dict(value['runtime_files'])
    for name, content in value['generated_runtime_files'].items():
        expected_runtime[name] = _identity(content.encode('utf-8'))
    runtime = _verify_tree(_root(value['paths']['python_root']), expected_runtime, value)
    dependencies = [dict(path=str(_root(value['paths']['python_root']).joinpath(*name.split('/'))), **identity)
        for name, identity in sorted(runtime.items())]
    return dict(schema='h56.windows-run-projection-receipt.v1', status='COPIED_BYTES_VERIFIED_ONLY',
        plan_sha256=plan.sha256, source_identity=value['source_identity'],
        product_root=value['paths']['staged_product_root'], runtime_root=value['paths']['python_root'],
        owned_roots=[value['paths']['staged_product_root'], value['paths']['python_root']],
        managed_empty_directories=value['managed_empty_directories'],
        staged_product_manifest_sha256=expected['PACKAGE_MANIFEST.json']['sha256'],
        product_files=product, dependency_closure=dict(schema='h56.windows-dependency-closure.v1', files=dependencies),
        dependency_completeness='NOT_YET_RUNTIME_OBSERVED', isolation_verified=False,
        candidate_computation='NOT_RUN', authority_granted=False)
