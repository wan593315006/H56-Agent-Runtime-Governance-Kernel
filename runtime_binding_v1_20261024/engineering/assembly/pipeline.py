"""The single domain-neutral native K0 -> K1 -> C1 -> C2 candidate call chain."""
from dataclasses import asdict, is_dataclass
import sys
from .contracts import ENGINEERING, AssemblyError, canonical, digest, require_g2
from .admission import admit
from .loader import load_core
from adapters.core_context import mapping_inputs, native_c2_inputs


def plain(value):
    if is_dataclass(value):
        return plain(asdict(value))
    if type(value) is dict:
        return {key: plain(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return [plain(item) for item in value]
    if value is None or type(value) in (str, int, bool):
        return value
    return {'native_type': type(value).__module__ + '.' + type(value).__qualname__}


class NativeCalls:
    def __init__(self, native):
        self.native = native
        self.events = []

    def invoke(self, label, function, *args, **kwargs):
        module = sys.modules.get(function.__module__)
        origin = getattr(module, '__file__', None)
        if origin not in self.native.origins.values():
            raise AssemblyError('UNREGISTERED_NATIVE_CALL_ORIGIN', 'NATIVE_CALL')
        from pathlib import Path
        relative = Path(origin).resolve().relative_to(ENGINEERING.resolve()).as_posix()
        event = {'label': label, 'origin': relative, 'function': function.__qualname__,
                 'arguments_hash': digest({'args': plain(args), 'kwargs': plain(kwargs)}), 'event': 'CALL'}
        self.events.append(event)
        try:
            result = function(*args, **kwargs)
        except Exception as exc:
            self.events.append({'label': label, 'event': 'RAISE', 'type': type(exc).__name__, 'message': str(exc)})
            raise
        self.events.append({'label': label, 'event': 'RETURN', 'value': plain(result)})
        return result


def compute(domain_id, scenario_id='positive', request_override=None):
    require_g2()
    stage, trace, case = 'ADMISSION', None, None
    try:
        plan = admit(domain_id, scenario_id, request_override)
        manifest, assets, case, sources = plan.decoded()
        native = load_core()
        trace = NativeCalls(native)
        call = trace.invoke
        stage = 'ONTOLOGY'
        profile = call('Ontology.load_default_profile', native.ontology.load_default_profile)
        binding = assets['runtime_ontology_binding']['value']
        if (profile.profile_id, profile.profile_version, profile.profile_hash) != (binding['profile_id'], binding['profile_version'], binding['profile_hash']):
            raise AssemblyError('RUNTIME_ONTOLOGY_VERSION_BINDING', stage)
        if not set(assets['domain_profile']['value']['semantic_bindings'].values()).issubset(set(profile.core_terms.values())):
            raise AssemblyError('DOMAIN_PROFILE_SEMANTIC_BINDING', stage)
        stage = 'FACT_HISTORY'
        observation = case['observations']
        provenance = call('K0.FactProvenance', native.k0.FactProvenance,
            source_id=observation['source_id'], object_id=observation['object_id'], object_version=observation['object_version'],
            environment_fingerprint='H56OS:ISOLATED_SYNTHETIC_TEST_ONLY:' + sources['core_lock']['vendor_fingerprint'],
            schema_version=assets['object_schema']['version'], evidence_refs=('OBS:' + digest(observation), 'ASSET:' + sources['manifest_sha256']))
        fact = call('K0.Fact.create', native.k0.Fact.create, fact_type='assertion', subject_id=observation['object_id'],
            occurred_at=observation['occurred_at'], payload={'state_projection': observation['values'],
                'source_kind': 'ISOLATED_SYNTHETIC_TEST_ONLY', 'source_binding': sources}, provenance=provenance)
        ledger = call('K0.CanonicalFactLedger', native.k0.CanonicalFactLedger)
        before = call('K0.read_history.before', ledger.read_history)
        receipt = call('K0.append', ledger.append, fact, expected_history_id=before.history_id)
        history = call('K0.read_history.after', ledger.read_history)
        stage = 'SNAPSHOT'
        versions = call('K0.VersionTuple', native.k0.VersionTuple, **assets['version_tuple']['value'])
        compiler = call('K1.StateCompiler', native.k1.StateCompiler)
        snapshot = call('K1.compile', compiler.compile, history, versions)
        stage = 'MAPPING'
        mapped = mapping_inputs(snapshot, assets, case)
        stage = 'C1'
        catalog = call('C1.Catalog.from_mapping', native.c1.CanonicalCapabilityCatalog.from_mapping, assets['catalog']['value'])
        call('C1.Catalog.verify_identity', catalog.verify_identity)
        definition = call('C1.Catalog.require_definition', catalog.require_definition, case['candidate_action']['capability_id'])
        call('C1.Definition.verify_identity', definition.verify_identity)
        stage = 'C2_CONTEXT'
        reference, assertion, context = native_c2_inputs(native, call, snapshot, assets, case, mapped, catalog, definition)
        stage = 'C2'
        evaluator = call('C2.Evaluator', native.c2.CandidateCapabilityFeasibilityEvaluator)
        projection = call('C2.project', evaluator.project, catalog=reference, assertion=assertion, context=context)
        call('C2.Projection.verify', projection.verify)
        if projection.authority_granted or projection.execution_permitted or not projection.candidate_planning_only:
            raise AssemblyError('NATIVE_CANDIDATE_BOUNDARY_DRIFT', stage)
        semantic = {'domain_id': domain_id, 'scenario_id': scenario_id, 'source_identity': sources,
            'input_bundle': case, 'manifest': manifest, 'assets': assets,
            'fact_history': plain(history), 'fact_cores': [dict(item.canonical_core(), fact_id=item.fact_id) for item in history.facts],
            'append_receipts': [plain(receipt)], 'snapshot': plain(snapshot), 'version_tuple': versions.to_dict(),
            'state': snapshot.state_by_subject(), 'snapshot_provenance': snapshot.provenance(),
            'mapping': mapped, 'c1_catalog': plain(catalog), 'c1_definition': plain(definition),
            'c2_reference': plain(reference), 'availability_assertion': plain(assertion), 'c2_context': plain(context),
            'projection': plain(projection), 'native_calls': trace.events,
            'boundary': {'candidate_planning_only': True, 'authority_granted': False, 'execution_permitted': False,
                         'business_action_calls': 0, 'formal_history_writes': 0}}
        return {'status': 'COMPUTED_CANDIDATE_ONLY', 'semantic': semantic, 'semantic_hash': digest(semantic)}
    except Exception as exc:
        return {'status': 'REJECTED', 'stage': getattr(exc, 'stage', stage), 'error_type': type(exc).__name__, 'error': str(exc),
                'domain_id': domain_id, 'scenario_id': scenario_id, 'native_calls': [] if trace is None else trace.events,
                'candidate_planning_only': True, 'authority_granted': False, 'execution_permitted': False,
                'business_action_calls': 0}
