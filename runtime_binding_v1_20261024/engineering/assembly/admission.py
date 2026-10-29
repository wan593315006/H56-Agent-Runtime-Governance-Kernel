"""Source/schema/domain admission before native import or Fact construction."""
from .contracts import (ENGINEERING, AssemblyError, AssemblyPlan, canonical, digest, exact,
                        read_json, raw_hash, safe_path, schema_check, strict_int)
from .loader import verify_core
from .unit_admission import validate_units

REFS = {'runtime_ontology_profile_ref': 'runtime_ontology_binding', 'domain_profile_ref': 'domain_profile',
    'project_profile_ref': 'project_profile', 'object_schema_ref': 'object_schema', 'fact_input_contract_ref': 'fact_contract',
    'synthetic_source_ref': 'synthetic_source', 'state_pattern_mapping_ref': 'mapping',
    'capability_catalog_ref': 'catalog', 'evidence_requirements': 'evidence_requirements',
    'budget_contract_ref': 'budget_contract', 'candidate_evaluation_declaration_ref': 'evaluation_declarations',
    'adapter_ref': 'adapter_descriptor', 'replay_contract_ref': 'replay_contract'}


def admit(domain_id, scenario_id, request_override=None):
    lock = read_json(safe_path(ENGINEERING, 'contracts/assembly_lock.json'))
    if domain_id not in lock['asset_sets']:
        raise AssemblyError('UNREGISTERED_DOMAIN')
    pinned = lock['asset_sets'][domain_id]
    directory = safe_path(ENGINEERING, pinned['directory'] + '/manifest.json').parent
    for name, identity in pinned['files'].items():
        path = safe_path(directory, name)
        if raw_hash(path) != identity['sha256'] or path.stat().st_size != identity['size']:
            raise AssemblyError('SOURCE_BOUND_ASSET_DRIFT:' + name)
    manifest = read_json(safe_path(directory, 'manifest.json'))
    schema_check(manifest, read_json(safe_path(ENGINEERING, 'contracts/domain_manifest.schema.json')))
    if manifest['domain_id'] != domain_id or manifest['asset_version'] != '1.0.0':
        raise AssemblyError('DOMAIN_OR_ASSET_VERSION_MISMATCH')
    if digest({k: v for k, v in manifest.items() if k != 'content_hash'}) != manifest['content_hash']:
        raise AssemblyError('MANIFEST_CONTENT_MISMATCH')
    core = verify_core()
    if manifest['core_lock'] != lock['core_lock'] or core['vendor_fingerprint'] != lock['core_lock']['vendor_fingerprint']:
        raise AssemblyError('MANIFEST_CORE_BINDING_MISMATCH')
    if manifest['dependency_lock'] != {'source_commit': core['source_commit'], 'vendor_fingerprint': core['vendor_fingerprint'], 'external_dependencies': []}:
        raise AssemblyError('DEPENDENCY_BINDING_MISMATCH')
    assets = read_json(safe_path(directory, 'domain_assets.json'))
    components = set(REFS.values()) | {'method_pack', 'policy', 'availability_assertions', 'version_tuple'}
    exact(assets, components, 'ASSET_COMPONENTS')
    for key, component in assets.items():
        exact(component, ('id', 'version', 'domain_id', 'value'), key)
        if component['domain_id'] != domain_id or component['version'] != '1.0.0':
            raise AssemblyError('COMPONENT_DOMAIN_OR_VERSION_MISMATCH:' + key)
        if not component['id'].startswith('ASSET:' + domain_id + ':'):
            raise AssemblyError('COMPONENT_NAMESPACE_MISMATCH:' + key)
    refs = {key: manifest[key] for key in REFS}
    if len(manifest['method_pack_refs']) != 1 or len(manifest['policy_refs']) != 1 or len(manifest['availability_assertion_refs']) != 1:
        raise AssemblyError('BOUNDED_COMPONENT_CARDINALITY')
    refs.update(method_pack_refs=manifest['method_pack_refs'][0], policy_refs=manifest['policy_refs'][0],
                availability_assertion_refs=manifest['availability_assertion_refs'][0])
    for key, ref in refs.items():
        pointer = REFS.get(key, {'method_pack_refs': 'method_pack', 'policy_refs': 'policy',
                                'availability_assertion_refs': 'availability_assertions'}.get(key))
        exact(ref, ('path', 'pointer', 'id', 'version', 'sha256'), 'ASSET_REF')
        component = assets[pointer]
        if ref != {'path': 'domain_assets.json', 'pointer': pointer, 'id': component['id'],
                    'version': component['version'], 'sha256': digest(component)}:
            raise AssemblyError('CROSS_DOMAIN_OR_RESEALED_REFERENCE:' + key)
    original_profile = read_json(safe_path(ENGINEERING, 'vendor/clean_core_projects/unified_runtime_ontology_profile_v1_1/src/unified_runtime_ontology_profile/data/UNIFIED_RUNTIME_ONTOLOGY_PROFILE_V1_1.json'))
    if assets['runtime_ontology_binding']['value'] != {key: original_profile[key] for key in ('profile_id', 'profile_version', 'profile_hash')} | {'source_commit': core['source_commit']}:
        raise AssemblyError('RUNTIME_PROFILE_VERSION_OR_SOURCE_MISMATCH')
    if assets['version_tuple']['value'] != {'compiler_version': 'K1:STATE_COMPILER:V1', 'schema_version': '1.0.0',
        'evidence_policy_version': '1.0.0', 'policy_version': '1.0.0'}:
        raise AssemblyError('K1_VERSION_TUPLE_BINDING_MISMATCH')
    method_value = assets['method_pack']['value']
    for label, prefix in (('method_id', 'METHOD:'), ('capability_id', 'CAP:'), ('task_kind', 'TASK:')):
        if not method_value[label].startswith(prefix + domain_id + ':'):
            raise AssemblyError('METHOD_CAPABILITY_TASK_NAMESPACE_MISMATCH')
    if method_value['formal_mlm_asset'] is not False or method_value['execution_enabled'] is not False:
        raise AssemblyError('METHOD_PACK_NOT_CANDIDATE_ONLY')
    definition_data = assets['catalog']['value']['definitions']
    if len(definition_data) != 1 or definition_data[0]['capability_id'] != method_value['capability_id']:
        raise AssemblyError('CATALOG_METHOD_CAPABILITY_MISMATCH')
    if definition_data[0]['source_hash'] != digest(assets['method_pack']):
        raise AssemblyError('CATALOG_METHOD_SOURCE_BINDING_MISMATCH')
    for pattern in assets['mapping']['value']['patterns']:
        if not pattern['id'].startswith('STATE:' + domain_id + ':'):
            raise AssemblyError('MAPPING_NAMESPACE_MISMATCH')
    for assertion in assets['availability_assertions']['value'].values():
        if assertion['capability_id'] != method_value['capability_id'] or assertion['definition_hash'] != definition_data[0]['definition_hash'] or assertion['allowed_method_ids'] != [method_value['method_id']]:
            raise AssemblyError('ASSERTION_METHOD_DEFINITION_BINDING_MISMATCH')
    for binding in manifest['source_bindings']:
        exact(binding, ('path', 'sha256', 'git_blob', 'origin'), 'SOURCE_BINDING')
        if binding['path'] not in ('domain_assets.json', 'inputs.json'):
            raise AssemblyError('UNREGISTERED_SOURCE_BINDING')
        expected = pinned['files'][binding['path']]
        if any(binding[field] != expected[field] for field in ('sha256', 'git_blob')) or binding['origin'] != 'G1_SYNTHETIC_ASSET_AUTHORING':
            raise AssemblyError('ASSET_SOURCE_IDENTITY_MISMATCH')
    if {b['path'] for b in manifest['source_bindings']} != {'domain_assets.json', 'inputs.json'}:
        raise AssemblyError('SOURCE_BINDING_CLOSURE')
    inputs = read_json(safe_path(directory, 'inputs.json'))
    schema_check(inputs, read_json(safe_path(ENGINEERING, 'contracts/input_bundle.schema.json')))
    if inputs['domain_id'] != domain_id or len({c['scenario_id'] for c in inputs['scenarios']}) != len(inputs['scenarios']):
        raise AssemblyError('INPUT_DOMAIN_OR_DUPLICATE_SCENARIO')
    matches = [case for case in inputs['scenarios'] if case['scenario_id'] == scenario_id]
    if len(matches) != 1:
        raise AssemblyError('UNREGISTERED_FROZEN_SCENARIO')
    case = matches[0]
    if request_override is not None and canonical(request_override) != canonical(case):
        raise AssemblyError('UNAPPROVED_OR_CROSS_DOMAIN_INPUT')
    obs, candidate = case['observations'], case['candidate_action']
    if obs['domain_id'] != domain_id or candidate['domain_id'] != domain_id or obs['source_kind'] != 'ISOLATED_SYNTHETIC_TEST_ONLY':
        raise AssemblyError('INPUT_PROVENANCE_OR_DOMAIN_MISMATCH')
    if obs['source_id'] != assets['synthetic_source']['value']['source_id']:
        raise AssemblyError('OBSERVATION_SOURCE_IDENTITY_MISMATCH')
    spec = assets['object_schema']['value']
    if obs['object_id'] != spec['object_id'] or candidate['object_id'] != obs['object_id'] or obs['object_version'] != spec['object_version']:
        raise AssemblyError('OBJECT_IDENTITY_MISMATCH')
    method = assets['method_pack']['value']
    if candidate['method_id'] != method['method_id'] or candidate['capability_id'] != method['capability_id']:
        raise AssemblyError('METHOD_OR_CAPABILITY_IDENTITY_MISMATCH')
    exact(obs['values'], spec['fields'], 'OBSERVATION_FIELDS')
    for name, field in spec['fields'].items():
        value = obs['values'][name]
        if value is None and field.get('nullable') is True:
            continue
        expected_type = {'string': str, 'strict_integer': int, 'boolean': bool}[field['type']]
        if type(value) is not expected_type or (expected_type is int and value < 0):
            raise AssemblyError('OBSERVATION_FIELD_TYPE:' + name)
        if 'enum' in field and value not in field['enum']:
            raise AssemblyError('OBSERVATION_FIELD_ENUM:' + name)
    exact(candidate['arguments'], spec['candidate_argument_bindings'], 'CANDIDATE_ARGUMENTS')
    for argument, field in spec['candidate_argument_bindings'].items():
        if type(candidate['arguments'][argument]) is not type(obs['values'][field]) or candidate['arguments'][argument] != obs['values'][field]:
            raise AssemblyError('CANDIDATE_ARGUMENT_NOT_BOUND_TO_FROZEN_REQUEST')
    strict_int(obs['values']['compute_budget_units'], 'COMPUTE_BUDGET')
    if assets['budget_contract']['value']['unit'] != 'C2_COMPUTE_UNIT':
        raise AssemblyError('BUDGET_MONEY_UNIT_CONFUSION')
    for evidence in obs['evidence']:
        exact(evidence, ('id', 'content', 'sha256'), 'EVIDENCE')
        if digest(evidence['content']) != evidence['sha256']:
            raise AssemblyError('EVIDENCE_CONTENT_DRIFT')
    if case['availability_key'] not in assets['availability_assertions']['value'] or case['evaluation_declaration_key'] not in assets['evaluation_declarations']['value']:
        raise AssemblyError('UNREGISTERED_FROZEN_DECLARATION')
    source = {'manifest_sha256': raw_hash(directory / 'manifest.json'), 'asset_files': pinned['files'],
              'core_lock': lock['core_lock'], 'input_hash': digest(case), 'domain_id': domain_id,
              'source_kind': 'ISOLATED_SYNTHETIC_TEST_ONLY', 'formal_trust': False}
    source['unit_admission'] = validate_units(domain_id, manifest, assets, ENGINEERING)
    return AssemblyPlan(domain_id, scenario_id, canonical(manifest), canonical(assets), canonical(case), canonical(source))
