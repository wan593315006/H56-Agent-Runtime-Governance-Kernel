"""Write-once run evidence, never a persistent Fact/State/Capability service."""
import re
from pathlib import Path
from .contracts import ENGINEERING, PRODUCT_ROOT, AssemblyError, canonical, digest, read_json, raw_hash, require_runtime, safe_path

from .unit_admission import PROOF_FAMILY, SOURCE_LINEAGE_FIELDS, VALIDATOR

FAMILY = 'H56OS:CANDIDATE_RECEIPT:WINDOWS_V1'


def verify_record_hash(record):
    """Integrity checksum only; resealing does not establish historical trust."""
    if type(record) is not dict or record.get('receipt_hash') != digest({k: v for k, v in record.items() if k != 'receipt_hash'}):
        raise AssemblyError('RB_RECEIPT_ENVELOPE_CONTENT_DRIFT', 'REPLAY')


def lineage(result, decision):
    """Static source lineage only; runtime observations remain unverified."""
    value = {key: decision[key] for key in SOURCE_LINEAGE_FIELDS}
    if result.get('status') == 'COMPUTED_CANDIDATE_ONLY':
        source = result.get('semantic', {}).get('source_identity', {})
        proof = source.get('unit_admission')
        if type(proof) is not dict:
            raise AssemblyError('MU_RECEIPT_LINEAGE_MISMATCH', 'REPLAY')
        expected = {'schema_id': PROOF_FAMILY,
            'contract_sha256': raw_hash(ENGINEERING / 'contracts/money_unit_admission.json'),
            'schema_sha256': raw_hash(ENGINEERING / 'contracts/money_unit_admission.schema.json'),
            'validator_sha256': raw_hash(PRODUCT_ROOT / VALIDATOR),
            'contract_id': 'H56OS:MONEY_UNIT_ADMISSION:V1', 'contract_version': '1.0.0',
            'validation_scope': 'INTERNAL_ASSET_UNIT_CONSISTENCY_ONLY',
            'result': 'VALIDATED_INTERNAL_CONTRACT', **value}
        if any(proof.get(k) != v for k, v in expected.items()) or proof.get('proof_hash') != digest({k: v for k, v in proof.items() if k != 'proof_hash'}):
            raise AssemblyError('MU_RECEIPT_LINEAGE_MISMATCH', 'REPLAY')
        if any(proof.get(k) is not False for k in ('external_fact_trust', 'authority_granted', 'execution_permitted')) or source.get('formal_trust') is not False or source.get('source_kind') != 'ISOLATED_SYNTHETIC_TEST_ONLY':
            raise AssemblyError('MU_RECEIPT_LINEAGE_MISMATCH', 'REPLAY')
        value['unit_proof_hash'] = proof['proof_hash']
    return value


def run_path(run_id, decision, must_exist=True):
    if type(run_id) is not str or not re.fullmatch('[A-Za-z0-9_-]{1,64}', run_id):
        raise AssemblyError('BOUNDED_RUN_ID_REQUIRED', 'ARCHIVE')
    root = Path(decision['scratch_root'])
    if not root.is_absolute():
        raise AssemblyError('WINDOWS_APPROVED_SCRATCH_REQUIRED', 'ARCHIVE')
    return safe_path(root, 'runs/' + run_id + '/receipt.json', must_exist=must_exist)


def receipt_input_path(run_id, decision):
    """Read a host-provisioned immutable snapshot, never mutable run output.

    The host copies exact receipt bytes only after its compute Job has closed.
    Actual AppContainer read-only ACLs are checked outside this data resolver;
    a path/hash comparison alone is not evidence of effective write denial.
    """
    if type(run_id) is not str or not re.fullmatch('[A-Za-z0-9_-]{1,64}', run_id):
        raise AssemblyError('BOUNDED_RUN_ID_REQUIRED', 'REPLAY')
    root = Path(decision['receipt_input_root'])
    scratch = Path(decision['scratch_root'])
    if (not root.is_absolute() or root == scratch or
            root in scratch.parents or scratch in root.parents):
        raise AssemblyError('WINDOWS_READ_ONLY_RECEIPT_INPUT_REQUIRED', 'REPLAY')
    return safe_path(root, run_id + '/receipt.json')


def archive(result, run_id):
    decision = require_runtime()
    binding = lineage(result, decision)
    path = run_path(run_id, decision, must_exist=False)
    if path.parent.exists():
        raise AssemblyError('RUN_ID_ALREADY_EXISTS_NO_OVERWRITE', 'ARCHIVE')
    # The approved environment supplies runs/. Never create source-side output
    # roots or recover an absent scratch mount using the original workspace.
    if not path.parent.parent.is_dir() or path.parent.parent.is_symlink():
        raise AssemblyError('RB_APPROVED_RUNS_DIRECTORY_REQUIRED', 'ARCHIVE')
    path.parent.mkdir(exist_ok=False)
    record = {'schema_id': FAMILY, 'result': result, 'result_hash': digest(result), 'lineage': binding,
              'unverified_runtime_claim': {'release_sha256': decision['release_sha256'],
                  'environment_sha256': decision['environment_sha256'],
                  'preflight_sha256': decision['preflight_sha256'],
                  'grade': 'UNVERIFIED_RECORDED_DIGESTS_NOT_REPLAYED_OR_AUTHORITY'},
              'candidate_planning_only': True, 'authority_granted': False, 'execution_permitted': False}
    record['receipt_hash'] = digest(record)
    with path.open('xb') as f:
        f.write((canonical(record) + '\n').encode('utf-8'))
    return path


def read_archive(run_id):
    decision = require_runtime('fresh_process_replay')
    record = read_json(receipt_input_path(run_id, decision))
    verify_record_hash(record)
    if set(record) != {'schema_id', 'result', 'result_hash', 'lineage', 'unverified_runtime_claim', 'receipt_hash', 'candidate_planning_only', 'authority_granted', 'execution_permitted'}:
        raise AssemblyError('RECEIPT_FIELD_DRIFT', 'REPLAY')
    observation = record['unverified_runtime_claim']
    # These claims are NOT attested historical environment evidence. Even a
    # correctly resealed receipt must pass current admission and recomputation;
    # UI/auditors must not promote this field to a verified source identity.
    if type(observation) is not dict or set(observation) != {'release_sha256', 'environment_sha256', 'preflight_sha256', 'grade'} or observation['grade'] != 'UNVERIFIED_RECORDED_DIGESTS_NOT_REPLAYED_OR_AUTHORITY':
        raise AssemblyError('RB_RECEIPT_RUNTIME_METADATA_DRIFT', 'REPLAY')
    if any(type(observation[k]) is not str or re.fullmatch('[0-9a-f]{64}', observation[k]) is None for k in ('release_sha256', 'environment_sha256', 'preflight_sha256')):
        raise AssemblyError('RB_RECEIPT_RUNTIME_METADATA_DRIFT', 'REPLAY')
    if record['schema_id'] != FAMILY or record['lineage'] != lineage(record['result'], decision):
        raise AssemblyError('MU_RECEIPT_LINEAGE_MISMATCH', 'REPLAY')
    if digest(record['result']) != record['result_hash']:
        raise AssemblyError('RECEIPT_CONTENT_DRIFT', 'REPLAY')
    if record['candidate_planning_only'] is not True or record['authority_granted'] is not False or record['execution_permitted'] is not False:
        raise AssemblyError('RECEIPT_AUTHORITY_DRIFT', 'REPLAY')
    if record['result']['status'] != 'COMPUTED_CANDIDATE_ONLY':
        raise AssemblyError('NO_COMPLETED_NATIVE_COMPUTATION_TO_REPLAY', 'REPLAY')
    return record
