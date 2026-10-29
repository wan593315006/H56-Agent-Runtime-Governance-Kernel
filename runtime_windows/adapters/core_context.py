"""Actual K1 state -> declared C2 inputs. Only native C2 decides feasibility."""
from ..assembly.contracts import AssemblyError, C1_COMMIT, C1_MANIFEST, digest, strict_int
from .bounded_rules import evaluate


def mapping_inputs(snapshot, assets, case):
    observation = case['observations']
    states = snapshot.state_by_subject()
    if set(states) != {observation['object_id']}:
        raise AssemblyError('SNAPSHOT_SUBJECT_MISMATCH', 'MAPPING')
    state = states[observation['object_id']]
    counter, trace, matches = [0], [], []
    for pattern in assets['mapping']['value']['patterns']:
        value = evaluate(pattern['when'], state, counter=counter)
        trace.append({'kind': 'STATE_PATTERN', 'id': pattern['id'], 'rule': pattern['when'], 'value': value})
        if value is None:
            raise AssemblyError('UNKNOWN_STATE_MAPPING', 'MAPPING')
        if value is True:
            matches.append(pattern['id'])
    if len(matches) != 1:
        raise AssemblyError('AMBIGUOUS_OR_UNMAPPED_SNAPSHOT', 'MAPPING')
    rule = assets['policy']['value']['rule']
    policy = evaluate(rule, state, counter=counter)
    if policy is not None and type(policy) is not bool:
        raise AssemblyError('POLICY_RESULT_NOT_BOOLEAN_OR_UNKNOWN', 'MAPPING')
    policy_state = 'DECLARED_UNKNOWN' if policy is None else ('DECLARED_ALLOWED' if policy else 'DECLARED_DENIED')
    trace.append({'kind': 'POLICY_INPUT', 'rule': rule, 'value': policy, 'declared_state': policy_state})
    evidence = observation['evidence']
    ids = [item['id'] for item in evidence]
    if len(ids) != len(set(ids)):
        raise AssemblyError('DUPLICATE_EVIDENCE_ID', 'MAPPING')
    declared = state['evidence_quality']
    required = assets['evidence_requirements']['value']['required_ids']
    supplied = set(ids) & set(case['candidate_action']['evidence_refs'])
    evidence_state = 'UNKNOWN' if declared in (None, 'UNKNOWN') else (
        'SUFFICIENT' if declared == 'SUFFICIENT' and set(required).issubset(supplied) else 'INSUFFICIENT')
    budget = strict_int(state['compute_budget_units'], 'COMPUTE_BUDGET')
    return {'state_pattern': matches[0], 'policy_state': policy_state, 'evidence_state': evidence_state,
            'budget_available_units': budget, 'trace': trace, 'snapshot_id': snapshot.snapshot_id,
            'history_id': snapshot.history_id, 'rule_node_count': counter[0],
            'mapping_hash': digest(assets['mapping']), 'policy_hash': digest(assets['policy']),
            'evidence_items': evidence, 'source_evidence_ids': sorted(supplied)}


def native_c2_inputs(native, call, snapshot, assets, case, mapped, catalog, definition):
    reference = {'catalog_id': catalog.catalog_id, 'catalog_version': catalog.catalog_version,
        'catalog_hash': catalog.catalog_hash, 'contract_project_id': 'CANDIDATE_CANONICAL_CAPABILITY_CONTRACT_V0_1',
        'contract_commit': C1_COMMIT, 'contract_manifest_sha256': C1_MANIFEST,
        'capability_id': definition.capability_id, 'definition_hash': definition.definition_hash}
    reference['reference_hash'] = digest(reference)
    ref = call('C2.CatalogReference.from_mapping', native.c2.CapabilityCatalogReference.from_mapping, reference)
    assertion_data = assets['availability_assertions']['value'][case['availability_key']]
    strict_int(assertion_data['minimum_budget_units'], 'MINIMUM_COMPUTE_BUDGET')
    assertion = call('C2.Assertion.from_mapping', native.c2.CapabilityAvailabilityAssertion.from_mapping, assertion_data)
    if assertion.definition_hash != definition.definition_hash or assertion.capability_id != definition.capability_id:
        raise AssemblyError('ASSERTION_DEFINITION_MISMATCH', 'C1_BINDING')
    # This is the verified native STATE:<sha256> identity, not a caller-supplied value.
    call('K1.Snapshot.verify', snapshot.verify)
    if not snapshot.snapshot_id.startswith('STATE:') or len(snapshot.snapshot_id) != 70:
        raise AssemblyError('NATIVE_SNAPSHOT_ID_FORMAT', 'C2_CONTEXT')
    declaration = assets['evaluation_declarations']['value'][case['evaluation_declaration_key']]
    if declaration['scope'] != 'SYNTHETIC_CANDIDATE_ASSUMPTION_ONLY' or declaration['execution_permission'] is not False:
        raise AssemblyError('AUTHORITY_ASSUMPTION_SCOPE', 'C2_CONTEXT')
    method = assets['method_pack']['value']
    context = {'task_kind': method['task_kind'], 'task_snapshot_hash': digest(case['candidate_action']),
        'state_pattern': mapped['state_pattern'], 'state_snapshot_hash': snapshot.snapshot_id[6:],
        'method_id': method['method_id'], 'method_hash': digest(assets['method_pack']),
        'policy_state': mapped['policy_state'], 'policy_snapshot_hash': digest({'policy': assets['policy'], 'mapping': mapped}),
        'authority_state': declaration['authority_state'], 'authority_snapshot_hash': digest(declaration),
        'budget_available_units': mapped['budget_available_units'],
        'budget_snapshot_hash': digest({'contract': assets['budget_contract'], 'snapshot_id': snapshot.snapshot_id,
                                       'available_compute_units': mapped['budget_available_units']}),
        'evidence_state': mapped['evidence_state'],
        'evidence_snapshot_hash': digest({'requirements': assets['evidence_requirements'], 'mapping_evidence': mapped['evidence_items']})}
    context['context_hash'] = digest(context)
    ctx = call('C2.Context.from_mapping', native.c2.FeasibilityContext.from_mapping, context)
    return ref, assertion, ctx
