"""Finite internal asset-unit consistency check, never fact trust or authority.

Source pins precede this validator. DATA-only fixtures may reseal references to
exercise the named semantic checks; such fixtures are not an approved runtime.
"""
from pathlib import Path
from .contracts import (WORKSPACE, AssemblyError, canonical, digest, exact, raw_hash,
                        read_json, require_g2, safe_path, schema_check)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = 'contracts/money_unit_admission.json'
SCHEMA = 'contracts/money_unit_admission.schema.json'
VALIDATOR = 'assembly/unit_admission.py'
SOURCE = 'SOURCE_MANIFEST.json'
VERSION = '1.0.0'


def reject(code):
    raise AssemblyError(code, 'ADMISSION')


def registered_contract():
    """Current verified registry; never a DATA clone or the old parent manifest."""
    decision = require_g2()
    registry = decision['verified_source_registry']
    for name in (CONTRACT, SCHEMA, VALIDATOR):
        if raw_hash(safe_path(ROOT, name)) != registry.get('engineering/' + name, {}).get('sha256'):
            raise AssemblyError('MU_UNIT_SOURCE_DRIFT:' + name, 'GATE')
    contract, schema = read_json(ROOT / CONTRACT), read_json(ROOT / SCHEMA)
    schema_check(contract, schema, 'MU_UNIT_REGISTRY')
    if contract['contract_version'] != VERSION or schema['schema_version'] != VERSION:
        reject('MU_UNIT_CONTRACT_VERSION_OR_BINDING_MISMATCH')
    return contract, decision, decision['current_runtime_manifest_sha256']


def validate_units(domain_id, manifest, assets, source_root):
    """Shared admission entry for both domains. No K0/K1/C1/C2 is called here."""
    registry, source_manifest, source_sha = registered_contract()
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
    # Proof is deterministic INTERNAL metadata. Source kind and formal_trust
    # remain owned by the original admission source dictionary, never this proof.
    proof = {'schema_id': 'H56OS:INTERNAL_UNIT_ADMISSION_PROOF:RB_V1',
             'validation_scope': 'INTERNAL_ASSET_UNIT_CONSISTENCY_ONLY',
             'external_fact_trust': False, 'authority_granted': False, 'execution_permitted': False,
             'result': 'VALIDATED_INTERNAL_CONTRACT', 'domain_id': domain_id,
             'declared_unit': declared, 'resolved_unit': unit, 'binding_id': binding['binding_id'],
             'contract_id': registry['contract_id'], 'contract_version': registry['contract_version'],
             'contract_sha256': raw_hash(ROOT / CONTRACT), 'schema_sha256': raw_hash(ROOT / SCHEMA),
             'validator_sha256': raw_hash(ROOT / VALIDATOR), 'source_manifest_sha256': source_sha,
             'current_runtime_contract_sha256': source_manifest['current_runtime_contract_sha256'],
             'private_provenance_sha256': source_manifest['private_provenance_sha256'],
             'direct_parent_mu_manifest_sha256': source_manifest['direct_parent_mu_manifest_sha256'],
             'parent_portable_file_lock_sha256': source_manifest['parent_portable_file_lock_sha256'],
             'parent_portable_provenance_sha256': source_manifest['parent_portable_provenance_sha256'],
             'ancestor_g1_manifest_sha256': source_manifest['ancestor_g1_manifest_sha256'],
             'ancestor_g2_delivery_sha256': source_manifest['ancestor_g2_delivery_sha256'],
             'object_schema_ref': ref, 'object_component_sha256': digest(component),
             'asset_manifest_sha256': raw_hash(safe_path(source_root, 'assets/' + binding['directory'] + '/manifest.json')),
             'c1_input_contract_reference': binding['c1_input_contract_reference'],
             'c1_reference_is_not_unit_validation': True, 'compute_budget_unit': registry['compute_budget_unit']}
    proof['proof_hash'] = digest(proof)
    return proof
