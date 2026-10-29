"""Five fixed local native roots, admitted only after a separate G2 release."""
import importlib
import importlib.machinery
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from .contracts import ENGINEERING, WORKSPACE, CORE_COMMIT, AssemblyError, require_runtime
from ..paths import COMPONENT_ROOT, RUNTIME_ROOT
from ..source_identity import (MAX_PUBLIC_LOCK_BYTES, _read_checked,
                               parse_public_lock, verify_public_lock)

PROJECTS = {
    'k0_fact_foundation': 'k0_canonical_fact_foundation_v1',
    'k1_state_derivation': 'k1_state_derivation_foundation_v1',
    'candidate_canonical_capability_contract': 'candidate_canonical_capability_contract_v0_1',
    'candidate_capability_feasibility_projection': 'candidate_capability_feasibility_projection_v0_1',
    'unified_runtime_ontology_profile': 'unified_runtime_ontology_profile_v1_1',
}
TRUSTED_MODULES = {}


def verify_core():
    """Consume public byte identities only, never the private historical lock."""
    raw = _read_checked(RUNTIME_ROOT / 'public-source-lock.json', None, MAX_PUBLIC_LOCK_BYTES)
    lock = parse_public_lock(raw)
    identity = verify_public_lock(COMPONENT_ROOT, lock)
    return {'source_commit': identity['source_commit'],
            'vendor_fingerprint': identity['vendor_fingerprint'], 'files': lock['vendor']}


def load_core():
    require_runtime()
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
