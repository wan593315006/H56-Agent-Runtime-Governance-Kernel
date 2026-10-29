"""Actual successor validator source binding; internal semantics never trust."""
import re
from .contracts import (ENGINEERING, PRODUCT_ROOT, AssemblyError, digest, exact,
                        raw_hash, read_json, require_runtime, safe_path, schema_check)

CONTRACT = 'contracts/money_unit_admission.json'
SCHEMA = 'contracts/money_unit_admission.schema.json'
VALIDATOR = 'runtime_windows/assembly/unit_admission.py'
VERSION = '1.0.0'
PROOF_FAMILY = 'H56OS:INTERNAL_UNIT_ADMISSION_PROOF:WINDOWS_V1'
SOURCE_LINEAGE_FIELDS = ('runtime_source_manifest_sha256', 'runtime_contract_sha256',
                         'public_lock_sha256', 'original_component_manifest_sha256')


def reject(code):
    raise AssemblyError(code, 'ADMISSION')


def registered_contract():
    decision = require_runtime()
    registry = decision['verified_source_registry']
    for path in (ENGINEERING / CONTRACT, ENGINEERING / SCHEMA, PRODUCT_ROOT / VALIDATOR):
        name = path.relative_to(PRODUCT_ROOT).as_posix()
        if raw_hash(safe_path(PRODUCT_ROOT, name)) != registry.get(name, {}).get('sha256'):
            raise AssemblyError('MU_UNIT_SOURCE_DRIFT:' + name, 'GATE')
    contract, schema = read_json(ENGINEERING / CONTRACT), read_json(ENGINEERING / SCHEMA)
    schema_check(contract, schema, 'MU_UNIT_REGISTRY')
    if contract['contract_version'] != VERSION or schema['schema_version'] != VERSION:
        reject('MU_UNIT_CONTRACT_VERSION_OR_BINDING_MISMATCH')
    return contract, decision


def validate_unit_data(domain_id, manifest, assets, registry):
    """Pure internal DATA checks. Does not grant admission or return authority."""
    binding = registry['domain_bindings'].get(domain_id)
    if binding is None:
        reject('MU_UNIT_CONTRACT_VERSION_OR_BINDING_MISMATCH')
    component, ref = assets['object_schema'], manifest['object_schema_ref']
    expected_ref = binding['object_schema_ref']
    if any(component.get(key) != binding['object_component'][key] for key in ('id', 'version', 'domain_id')):
        reject('MU_UNIT_CONTRACT_VERSION_OR_BINDING_MISMATCH')
    if any(ref.get(key) != expected_ref[key] for key in ('path', 'pointer', 'id', 'version')):
        reject('MU_UNIT_CONTRACT_VERSION_OR_BINDING_MISMATCH')
    spec = component['value']
    if 'money_unit' not in spec:
        reject('MU_UNIT_DECLARATION_MISSING')
    declared = spec['money_unit']
    if type(declared) is not str or not declared:
        reject('MU_UNIT_DECLARATION_TYPE_INVALID')
    if declared not in registry['units']:
        reject('MU_UNIT_UNREGISTERED')
    if declared != binding['money_unit']:
        reject('MU_UNIT_DOMAIN_MISMATCH')
    unit = registry['units'][declared]
    fields, arguments = spec['fields'], spec['candidate_argument_bindings']
    if type(fields) is not dict or type(arguments) is not dict:
        reject('MU_UNIT_AMOUNT_CONTRACT_CONFLICT')
    # Validate semantics BEFORE the full immutable object digest so a resealed
    # DATA wrong-unit case actually reaches its named semantic consumer.
    if unit['monetary']:
        for name in unit['amount_fields']:
            field = fields.get(name)
            if type(field) is not dict or field.get('type') != 'strict_integer' or field.get('nullable', False) is not False or set(field) - {'type', 'nullable'}:
                reject('MU_UNIT_AMOUNT_CONTRACT_CONFLICT')
        for name in unit['currency_fields']:
            field = fields.get(name)
            if type(field) is not dict or field.get('type') != 'string' or field.get('enum') != ['CNY'] or field.get('nullable', False) is not False or set(field) - {'type', 'enum', 'nullable'}:
                reject('MU_UNIT_CURRENCY_CONTRACT_CONFLICT')
        if arguments != unit['candidate_argument_bindings']:
            reject('MU_UNIT_AMOUNT_CONTRACT_CONFLICT')
    else:
        monetary_names = set(registry['units']['INTEGER_CNY_MINOR_UNITS']['amount_fields'] + registry['units']['INTEGER_CNY_MINOR_UNITS']['currency_fields'])
        if monetary_names.intersection(fields) or {'amount_minor', 'currency'}.intersection(arguments):
            reject('MU_UNIT_NOT_APPLICABLE_CONFLICT')
        if set(fields) != set(binding['field_names']) or arguments != binding['candidate_argument_bindings']:
            reject('MU_UNIT_NOT_APPLICABLE_CONFLICT')
    budget = assets['budget_contract']['value']
    if budget.get('unit') != registry['compute_budget_unit'] or fields.get('compute_budget_units') != {'type': 'strict_integer'}:
        reject('MU_UNIT_BUDGET_DIMENSION_CONFLICT')
    definition = assets['catalog']['value']['definitions'][0]
    if definition['input_contract'] != binding['c1_input_contract_reference']:
        reject('MU_UNIT_CONTRACT_VERSION_OR_BINDING_MISMATCH')
    if digest(component) != binding['object_component_sha256'] or ref != expected_ref:
        reject('MU_UNIT_CONTRACT_VERSION_OR_BINDING_MISMATCH')
    return {'declared_unit': declared, 'resolved_unit': unit, 'binding': binding,
            'object_schema_ref': ref, 'object_component_sha256': digest(component)}


def build_internal_proof(domain_id, checked, hashes, decision):
    """Pure deterministic source metadata, not a Human or external fact claim."""
    exact(hashes, ('contract_sha256', 'schema_sha256', 'validator_sha256',
                   'asset_manifest_sha256'), 'WINDOWS_UNIT_HASHES')
    lineage = {key: decision[key] for key in SOURCE_LINEAGE_FIELDS}
    for value in tuple(hashes.values()) + tuple(lineage.values()):
        if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
            reject('MU_UNIT_SOURCE_DIGEST_INVALID')
    binding = checked['binding']
    proof = {'schema_id': PROOF_FAMILY,
             'validation_scope': 'INTERNAL_ASSET_UNIT_CONSISTENCY_ONLY',
             'external_fact_trust': False, 'authority_granted': False, 'execution_permitted': False,
             'result': 'VALIDATED_INTERNAL_CONTRACT', 'domain_id': domain_id,
             'declared_unit': checked['declared_unit'], 'resolved_unit': checked['resolved_unit'],
             'binding_id': binding['binding_id'],
             'contract_id': 'H56OS:MONEY_UNIT_ADMISSION:V1', 'contract_version': VERSION,
             **hashes, **lineage,
             'object_schema_ref': checked['object_schema_ref'],
             'object_component_sha256': checked['object_component_sha256'],
             'c1_input_contract_reference': binding['c1_input_contract_reference'],
             'c1_reference_is_not_unit_validation': True, 'compute_budget_unit': 'C2_COMPUTE_UNIT'}
    proof['proof_hash'] = digest(proof)
    return proof


def validate_units(domain_id, manifest, assets, source_root):
    registry, decision = registered_contract()
    checked = validate_unit_data(domain_id, manifest, assets, registry)
    hashes = {'contract_sha256': raw_hash(ENGINEERING / CONTRACT),
              'schema_sha256': raw_hash(ENGINEERING / SCHEMA),
              'validator_sha256': raw_hash(PRODUCT_ROOT / VALIDATOR),
              'asset_manifest_sha256': raw_hash(safe_path(source_root,
                  'assets/' + checked['binding']['directory'] + '/manifest.json'))}
    return build_internal_proof(domain_id, checked, hashes, decision)
