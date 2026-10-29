"""Five fixed local native roots, admitted only after a separate G2 release."""
import importlib
import importlib.machinery
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from .contracts import ENGINEERING, WORKSPACE, CORE_COMMIT, AssemblyError, digest, read_json, raw_hash, require_g2, safe_path

PROJECTS = {
    'k0_fact_foundation': 'k0_canonical_fact_foundation_v1',
    'k1_state_derivation': 'k1_state_derivation_foundation_v1',
    'candidate_canonical_capability_contract': 'candidate_canonical_capability_contract_v0_1',
    'candidate_capability_feasibility_projection': 'candidate_capability_feasibility_projection_v0_1',
    'unified_runtime_ontology_profile': 'unified_runtime_ontology_profile_v1_1',
}
TRUSTED_MODULES = {}


def verify_core():
    lock = read_json(safe_path(WORKSPACE, 'offline/source-lock.json'))
    if lock['contract_sha256'] != '595a39bbca6319c701d5ccbcfcf7ea35d4568681a6f77c2648b998d3b4dde9c5':
        raise AssemblyError('ORIGINAL_CONTRACT_IDENTITY_MISMATCH')
    expected = lock['vendor']
    if len(expected) != 110:
        raise AssemblyError('CORE_CLOSURE_COUNT')
    actual = set()
    root = ENGINEERING / 'vendor'
    for directory, dirs, files in os.walk(root, followlinks=False):
        here = Path(directory)
        for name in dirs:
            path = here / name
            if path.is_symlink() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
                raise AssemblyError('LINKED_NATIVE_DIRECTORY')
        actual.update((here / name).relative_to(root).as_posix() for name in files)
    if actual != set(expected):
        raise AssemblyError('EXTRA_OR_MISSING_NATIVE_SOURCE')
    for name, identity in expected.items():
        path = safe_path(ENGINEERING / 'vendor', name)
        if raw_hash(path) != identity['sha256'] or path.stat().st_size != identity['size']:
            raise AssemblyError('ORIGINAL_CORE_SOURCE_DRIFT:' + name)
    return {'source_commit': CORE_COMMIT, 'vendor_fingerprint': digest(expected), 'files': expected}


def load_core():
    require_g2()
    identity = verify_core()
    roots = {name: ENGINEERING / 'vendor/clean_core_projects' / project / 'src' for name, project in PROJECTS.items()}
    allowed_files = {str((ENGINEERING / 'vendor' / name).resolve()) for name in identity['files'] if name.endswith('.py')}
    def expected_origin(name, file):
        if not file:
            return False
        parts = name.split('.')
        base = roots[parts[0]].joinpath(*parts)
        candidates = {str(base.with_suffix('.py').resolve()), str((base / '__init__.py').resolve())}
        return str(Path(file).resolve()) in candidates & allowed_files
    def check_modules():
        for name, module in list(sys.modules.items()):
            if name.split('.')[0] in PROJECTS:
                file = getattr(module, '__file__', None)
                if not expected_origin(name, file) or TRUSTED_MODULES.get(name) is not module:
                    raise AssemblyError('PRELOADED_NATIVE_SUBSTITUTE:' + name)
    check_modules()
    for entry in sys.path:
        if not entry:
            continue
        for name, approved in roots.items():
            candidate = Path(entry) / name
            if (candidate.exists() or candidate.with_suffix('.py').exists()) and Path(entry).resolve() != approved.resolve():
                raise AssemblyError('DUPLICATE_NATIVE_ROOT:' + name)
    cache = ENGINEERING / 'vendor/.g1_no_bytecode_cache'
    if cache.exists() or cache.is_symlink():
        raise AssemblyError('NATIVE_BYTECODE_CACHE_MUST_NOT_EXIST')
    previous, previous_finders = list(sys.path), list(sys.meta_path)
    previous_cache, previous_no_write = sys.pycache_prefix, sys.dont_write_bytecode
    try:
        # -B alone does not prevent reading pyc. This nonexistent, read-only-image
        # prefix prevents use of adjacent or caller-selected prefix caches.
        sys.pycache_prefix, sys.dont_write_bytecode = str(cache), True
        sys.path[:0] = [str(p) for p in roots.values()]
        sys.meta_path[:] = [importlib.machinery.BuiltinImporter, importlib.machinery.FrozenImporter, importlib.machinery.PathFinder]
        for name, root in roots.items():
            spec = importlib.machinery.PathFinder.find_spec(name, [str(root)])
            if spec is None or spec.origin != str(root / name / '__init__.py'):
                raise AssemblyError('NATIVE_SPEC_ORIGIN_MISMATCH:' + name)
        modules = {name: importlib.import_module(name) for name in PROJECTS}
        for name, module in list(sys.modules.items()):
            if name.split('.')[0] in PROJECTS:
                if not expected_origin(name, getattr(module, '__file__', None)):
                    raise AssemblyError('IMPORTED_NATIVE_ORIGIN_MISMATCH:' + name)
                TRUSTED_MODULES[name] = module
        check_modules()
    finally:
        sys.path[:] = previous
        sys.meta_path[:] = previous_finders
        sys.pycache_prefix, sys.dont_write_bytecode = previous_cache, previous_no_write
    if verify_core() != identity:
        raise AssemblyError('NATIVE_IMPORT_SOURCE_DRIFT')
    origins = {name: str(module.__file__) for name, module in list(sys.modules.items()) if name.split('.')[0] in PROJECTS}
    return SimpleNamespace(k0=modules['k0_fact_foundation'], k1=modules['k1_state_derivation'],
        c1=modules['candidate_canonical_capability_contract'], c2=modules['candidate_capability_feasibility_projection'],
        ontology=modules['unified_runtime_ontology_profile'], identity=identity, origins=origins)
