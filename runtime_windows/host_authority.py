"""Concrete operator-pinned Controller bridge, inert until explicit bootstrap.

Pins must come out of band from the trusted local operator following an actual
Human decision. Checksums are not Human authentication. This module neither
generates approvals nor treats JSON ``approved`` flags as authority. Present
source readiness supplies no real pins, resources or accepted preflight.
"""
from dataclasses import dataclass
import hashlib
import ntpath
from pathlib import Path

from .host_contract import (BUNDLE_FILES, boundary, canonical, decode, digest, exact,
    fail, sha, token, validate_bundle, validate_acceptance, validate_resource_contract,
    validate_file_index, windows_path, _issue_permit)
from .source_identity import _read_checked, _check_chain


@dataclass(frozen=True)
class BootstrapPins:
    expected_hc_original_sha256: str
    expected_controller_bundle_sha256: str
    session_id: str
    product_root: str


def validate_bootstrap_pins(pins):
    if type(pins) is not BootstrapPins:
        fail('HOST_EXTERNAL_OPERATOR_PINS_REQUIRED')
    if not sha(pins.expected_hc_original_sha256) or not sha(pins.expected_controller_bundle_sha256):
        fail('HOST_EXTERNAL_OPERATOR_PINS_UNBOUND')
    token(pins.session_id)
    if pins.product_root != str(Path(__file__).absolute().parents[1]):
        fail('HOST_FIXED_PRODUCT_ROOT_REQUIRED')


def validate_closure(resources, environment, dependency, evidence_index, registry, control_files):
    """Pure required-object closure, separate from actual resource readback."""
    validate_resource_contract(resources)
    validate_file_index(dependency, 'h56.windows-dependency-closure.v1', 4096)
    validate_file_index(evidence_index, 'h56.windows-preflight-evidence-index.v1', 512)
    root, paths = resources['product_root'], resources['paths']
    if (environment['python_executable'] != resources['python']['executable'] or
            environment['python_sha256'] != resources['python']['sha256'] or
            environment['profile_storage_root'] != resources['profile']['storage_root'] or
            environment['observation_policy'] != resources['observation_policy'] or
            environment['variables']['SYSTEMROOT'] != resources['system_root'] or
            environment['variables']['WINDIR'] != resources['system_root']):
        fail('HOST_ENVIRONMENT_RESOURCE_BINDING')
    roots = environment['runtime_read_roots']
    if type(roots) is not list or not 1 <= len(roots) <= 16:
        fail('HOST_RUNTIME_READ_ROOTS_UNBOUND')
    normalized = [windows_path(x) for x in roots]
    if len(set(normalized)) != len(normalized):
        fail('HOST_RUNTIME_ROOT_DUPLICATE')
    required = {windows_path(ntpath.join(root, *name.split('/'))): 'file' for name in registry}
    control_targets = {windows_path(ntpath.join(paths['control_root'], name)) for name in control_files}
    for filename in control_files:
        required[windows_path(ntpath.join(paths['control_root'], filename))] = 'file'
    required[windows_path(ntpath.join(root, 'runtime_windows', 'RUNTIME_SOURCE_MANIFEST.json'))] = 'file'
    dependency_paths = set()
    for item in dependency['files']:
        path = windows_path(item['path'])
        if path in control_targets or not any(path.startswith(base + '\\') for base in normalized):
            fail('HOST_DEPENDENCY_OUTSIDE_DECLARED_RUNTIME_ROOTS')
        dependency_paths.add(path)
        required[path] = 'file'
    if windows_path(resources['python']['executable']) not in dependency_paths:
        fail('HOST_PYTHON_MISSING_FROM_DEPENDENCY_CLOSURE')
    for item in evidence_index['files']:
        path = windows_path(item['path'])
        preflight_root = windows_path(ntpath.join(paths['host_evidence_root'], 'preflight'))
        if path in control_targets or not path.startswith(preflight_root + '\\'):
            fail('HOST_PREFLIGHT_EVIDENCE_OUTSIDE_DECLARED_ROOTS')
        required[path] = 'file'
    if resources['profile']['provisioning_receipt_sha256'] not in {item['sha256'] for item in evidence_index['files']}:
        fail('HOST_PROFILE_PROVISIONING_RECEIPT_NOT_INDEXED')
    directories = [root, ntpath.join(root, 'runtime_windows'), ntpath.dirname(paths['control_root']),
        resources['profile']['storage_root'], *roots,
        *(paths[key] for key in ('control_root', 'scratch_root', 'receipt_input_root', 'host_evidence_root')),
        ntpath.join(paths['scratch_root'], 'runs'), ntpath.join(paths['scratch_root'], 'child_failures')]
    # A protected file with a writable/unchecked in-scope parent can still be
    # replaced. Declare every intervening source/runtime/control directory.
    anchors = [windows_path(root), *normalized]
    for path in tuple(required):
        parent = ntpath.dirname(path)
        while any(parent == base or parent.startswith(base + '\\') for base in anchors):
            directories.append(parent)
            if parent in anchors:
                break
            parent = ntpath.dirname(parent)
    required.update((windows_path(path), 'directory') for path in directories)
    declared = {windows_path(item['path']): item['kind'] for item in resources['acl_objects']}
    if any(declared.get(path) != kind for path, kind in required.items()):
        fail('HOST_ACL_REQUIRED_OBJECT_CLOSURE_INCOMPLETE')
    # Do not permit extra entries to turn an exact-object verifier into a scanner.
    if set(declared) != set(required):
        fail('HOST_ACL_OBJECTS_OUTSIDE_EFFECTIVE_CLOSURE')


class PinnedHumanControllerAuthority:
    """Production bridge for a separately approved local trusted operator.

    File reads/native readback occur only through explicit bootstrap/recheck;
    no default constructor or self-generated approval exists. Mutable scratch
    is shared inside one session and protected by an actual exclusive lock.
    """
    def __init__(self, pins):
        validate_bootstrap_pins(pins)  # must reject before any file/native access
        self.pins = pins
        self.root = Path(pins.product_root)
        self.control = self.root / 'runtime_windows' / '.local' / pins.session_id / 'control'
        self.configuration = self._load_and_check()
        from .host_resources import ResourceReadback
        self.reader = ResourceReadback(self.configuration['resources'],
            _issue_permit('RESOURCE_INSPECTION', digest(self.configuration['resources'])))
        self.resource_observation = self.reader.verify()

    def _load_and_check(self):
        from . import runtime_admission as admission
        _check_chain(self.control)
        original = _read_checked(self.control / 'hc_original.txt', None, 65536)
        bundle_raw = _read_checked(self.control / 'controller_bundle.json', None, 1048576)
        if (hashlib.sha256(original).hexdigest() != self.pins.expected_hc_original_sha256 or
                hashlib.sha256(bundle_raw).hexdigest() != self.pins.expected_controller_bundle_sha256):
            fail('HOST_EXTERNAL_HC_OR_BUNDLE_PIN_MISMATCH')
        bundle = decode(bundle_raw)
        validate_bundle(bundle, self.pins.session_id)
        docs, raw_docs = {}, {}
        for name in sorted(BUNDLE_FILES):
            identity = bundle['files'][name]
            raw = _read_checked(self.control / name, identity['size'], 1048576)
            if hashlib.sha256(raw).hexdigest() != identity['sha256']:
                fail('HOST_BUNDLE_MEMBER_DRIFT', name)
            raw_docs[name], docs[name] = raw, decode(raw)
        acceptance, resources = docs['host_acceptance.json'], docs['resource_contract.json']
        validate_acceptance(acceptance)
        validate_resource_contract(resources)
        if resources['session_id'] != self.pins.session_id or resources['product_root'] != self.pins.product_root:
            fail('HOST_PINNED_RESOURCE_SESSION_ROOT_MISMATCH')
        release, environment, preflight = docs['release.json'], docs['environment.json'], docs['preflight.json']
        manifest_raw = _read_checked(self.root / admission.SOURCE_PATH, None, 1048576)
        registry = admission.verify_current_sources(decode(manifest_raw))
        contract_raw = _read_checked(self.root / admission.CONTRACT_PATH, None, 1048576)
        lock_raw = _read_checked(self.root / admission.LOCK_PATH, None, 1048576)
        contract, public_lock = decode(contract_raw), admission.parse_public_lock(lock_raw)
        if (contract.get('schema') != 'h56.windows-candidate-connection.v2' or
                contract.get('launch_status') != 'PREPARED_NOT_RUNTIME_ACCEPTED' or
                contract.get('boundary') != boundary()):
            fail('HOST_SOURCE_STATE_OR_BOUNDARY_INVALID')
        if set(registry) != admission.required_runtime_paths(public_lock):
            fail('HOST_SOURCE_EFFECTIVE_CLOSURE_MISMATCH')
        admission.verify_public_lock(self.root / 'runtime_binding_v1_20261024', public_lock)
        identities = dict(runtime_source_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
            runtime_contract_sha256=hashlib.sha256(contract_raw).hexdigest(),
            public_lock_sha256=hashlib.sha256(lock_raw).hexdigest(),
            original_component_manifest_sha256=admission.ORIGINAL_MANIFEST)
        variables = environment.get('variables', {})
        child_env = dict(variables, H56W_SESSION=self.pins.session_id,
            H56W_SOURCE_SHA256=identities['runtime_source_manifest_sha256'],
            H56W_RELEASE_SHA256=hashlib.sha256(raw_docs['release.json']).hexdigest(),
            H56W_ENVIRONMENT_SHA256=hashlib.sha256(raw_docs['environment.json']).hexdigest(),
            H56W_PREFLIGHT_SHA256=hashlib.sha256(raw_docs['preflight.json']).hexdigest(),
            H56W_HOST_ACCEPTANCE_SHA256=hashlib.sha256(raw_docs['host_acceptance.json']).hexdigest())
        roots = {key: resources['paths'][key] for key in ('control_root', 'scratch_root', 'receipt_input_root')}
        for operation in acceptance['allowed_operations']:
            admission.validate_worker_documents(release, environment, preflight, acceptance,
                operation, child_env, identities, roots)
        if hashlib.sha256(raw_docs['resource_contract.json']).hexdigest() != environment['resource_contract_sha256']:
            fail('HOST_RESOURCE_CONTROL_IDENTITY')
        dependency, evidence_index = docs['dependency_closure.json'], docs['preflight_evidence_index.json']
        if (hashlib.sha256(raw_docs['dependency_closure.json']).hexdigest() != resources['python']['dependency_closure_sha256'] or
                hashlib.sha256(raw_docs['preflight_evidence_index.json']).hexdigest() != preflight['preflight_evidence_index_sha256']):
            fail('HOST_DEPENDENCY_OR_PREFLIGHT_INDEX_IDENTITY')
        validate_closure(resources, environment, dependency, evidence_index, registry,
            BUNDLE_FILES | {'hc_original.txt', 'controller_bundle.json'})
        for index in (dependency, evidence_index):
            for item in index['files']:
                raw = _read_checked(Path(item['path']), item['size'], 67108864)
                if hashlib.sha256(raw).hexdigest() != item['sha256']:
                    fail('HOST_REGISTERED_DEPENDENCY_OR_EVIDENCE_DRIFT')
        executable = resources['python']['executable']
        if hashlib.sha256(_read_checked(Path(executable), None, 2097152)).hexdigest() != resources['python']['sha256']:
            fail('HOST_PYTHON_EXECUTABLE_DRIFT')
        return dict(host_acceptance=acceptance, resources=resources,
            child_environment=child_env, source_lineage=identities, vendor=public_lock['vendor'],
            resource_contract_sha256=environment['resource_contract_sha256'])

    def active_lock(self):
        return self.reader.active_lock(_issue_permit('SESSION_CONTROL', digest(self.configuration['resources'])))

    def authorize_call(self, plan):
        """Called under the native active lock; reserve attempt before launch."""
        from .host_contract import make_candidate_plan
        configuration = self._load_and_check()
        if configuration != self.configuration:
            fail('HOST_CONTROL_OR_SOURCE_CHANGED_SINCE_BOOTSTRAP')
        data = plan.decoded()
        rebuilt = make_candidate_plan(configuration, data['operation'], data['run_id'],
            data['domain_id'], data['scenario_id'], data['source_run_id'], data['task_id'])
        if rebuilt.sha256 != plan.sha256:
            fail('HOST_UNREGISTERED_CANDIDATE_PLAN')
        self.reader.verify()
        evidence = Path(configuration['resources']['paths']['host_evidence_root'])
        _check_chain(evidence)
        ledger = evidence / 'worker_attempts.json'
        if ledger.exists():
            attempts = decode(_read_checked(ledger, None, 65536))
            if type(attempts) is not list or any(type(x) is not str for x in attempts) or len(set(attempts)) != len(attempts):
                fail('HOST_ATTEMPT_LEDGER_INVALID')
        else:
            attempts = []
        if len(attempts) >= configuration['host_acceptance']['worker_attempt_budget'] or data['run_id'] in attempts:
            fail('HOST_ATTEMPT_BUDGET_OR_RUN_ALREADY_USED')
        # The session lock serializes this fixed, private host-only ledger.
        raw = canonical(attempts + [data['run_id']]) + b'\n'
        from .source_identity import _check_stat
        if ledger.exists():
            _check_stat(ledger.lstat(), False, str(ledger))
        temporary = evidence / 'worker_attempts.pending'
        with temporary.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            import os
            os.fsync(stream.fileno())
        temporary.replace(ledger)
        if _read_checked(ledger, len(raw), 65536) != raw:
            fail('HOST_ATTEMPT_LEDGER_WRITEBACK_FAILED')
        # fsync/readback does not claim Windows directory/crash durability; the
        # later real fault/recovery tests must establish the accepted guarantee.
        return _issue_permit('CANDIDATE_WORKER', plan.sha256)
