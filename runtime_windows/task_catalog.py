"""Frozen task-input index, not a C1 catalog, fact source or runtime grant."""
import hashlib

from .assembly.contracts import canonical, digest
from .errors import PreparationError
from .paths import PRODUCT_ROOT, COMPONENT_ROOT, DATA_ROOT, RUNTIME_ROOT
from .runtime_admission import (decode, verify_current_sources, required_runtime_paths,
                                _bytes, SOURCE_PATH, LOCK_PATH, CONTRACT_PATH, ORIGINAL_MANIFEST)
from .source_identity import parse_public_lock, verify_public_lock

DOMAINS = ('DEVSECOPS', 'FINANCE_REFUND')


class FrozenTaskCatalog:
    """DATA identity only. Independent Host admission is mandatory to compute."""
    def __init__(self):
        self.cases = {}
        self.asset_manifests = {}
        self.identity = self.verify()

    def verify(self):
        public_raw = _bytes(PRODUCT_ROOT, LOCK_PATH, 65536)
        public = parse_public_lock(public_raw)
        core = verify_public_lock(COMPONENT_ROOT, public)
        manifest_raw = _bytes(PRODUCT_ROOT, SOURCE_PATH)
        registry = verify_current_sources(decode(manifest_raw))
        if set(registry) != required_runtime_paths(public):
            raise PreparationError('TASK_RUNTIME_SOURCE_CLOSURE_MISMATCH')
        relative = 'runtime_binding_v1_20261024/engineering/'
        lock_raw = _bytes(PRODUCT_ROOT, relative + 'contracts/assembly_lock.json')
        lock = decode(lock_raw)
        if set(lock['asset_sets']) != set(DOMAINS) or lock['core_lock']['vendor_fingerprint'] != core['vendor_fingerprint']:
            raise PreparationError('TASK_FROZEN_DOMAIN_CORE_MISMATCH')
        cases, asset_manifests = {}, {}
        for domain in DOMAINS:
            binding = lock['asset_sets'][domain]
            for name, expected in binding['files'].items():
                raw = _bytes(PRODUCT_ROOT, relative + binding['directory'] + '/' + name)
                if len(raw) != expected['size'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
                    raise PreparationError('TASK_FROZEN_ASSET_DRIFT')
            inputs = decode(_bytes(PRODUCT_ROOT, relative + binding['directory'] + '/inputs.json'))
            if inputs['domain_id'] != domain or len({case['scenario_id'] for case in inputs['scenarios']}) != len(inputs['scenarios']):
                raise PreparationError('TASK_FROZEN_INPUT_DOMAIN_OR_DUPLICATE')
            cases[domain] = {case['scenario_id']: digest(case) for case in inputs['scenarios']}
            asset_manifests[domain] = binding['files']['manifest.json']['sha256']
        identity = {'runtime_source_manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
                    'public_lock_sha256': hashlib.sha256(public_raw).hexdigest(),
                    'runtime_contract_sha256': registry[CONTRACT_PATH]['sha256'],
                    'original_component_manifest_sha256': ORIGINAL_MANIFEST,
                    'assembly_lock_sha256': hashlib.sha256(lock_raw).hexdigest(),
                    'domain_asset_manifest_sha256_by_domain': asset_manifests,
                    'core_fingerprint': core['vendor_fingerprint'],
                    'grade': 'DATA_IDENTITY_ONLY_NOT_RUNTIME_ACCEPTANCE'}
        if self.cases and cases != self.cases:
            raise PreparationError('TASK_FROZEN_INPUT_SOURCE_CHANGED')
        if getattr(self, 'identity', None) is not None and identity != self.identity:
            raise PreparationError('TASK_SOURCE_IDENTITY_CHANGED')
        self.cases = cases
        self.asset_manifests = asset_manifests
        return identity

    def describe(self, domain, scenario='positive'):
        if type(domain) is not str or domain not in self.cases:
            raise ValueError('UNREGISTERED_DOMAIN')
        if type(scenario) is not str or scenario not in self.cases[domain]:
            raise ValueError('UNREGISTERED_FROZEN_SCENARIO')
        return {'domain_id': domain, 'scenario_id': scenario,
                'domain_asset_manifest_sha256': self.asset_manifests[domain],
                'input_sha256': self.cases[domain][scenario], **self.identity}
