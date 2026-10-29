"""Fresh-process reconstruction using approved inputs, never stored decisions."""
from .contracts import AssemblyError, digest, require_runtime
from .evidence import read_archive


def verify_recomputed(record, actual):
    """Full semantic equality, not acceptance of a stored projection or hash."""
    if actual.get('status') != 'COMPUTED_CANDIDATE_ONLY' or actual != record['result']:
        raise AssemblyError('RECOMPUTED_HISTORY_SNAPSHOT_CONTEXT_OR_PROJECTION_MISMATCH', 'REPLAY')
    return {'status': 'ACTUAL_RECOMPUTATION_MATCH', 'semantic_hash': actual['semantic_hash'],
            'authority_granted': False, 'execution_permitted': False}


def reconstruct(run_id):
    decision = require_runtime('fresh_process_replay')  # Also covers this worker's own compute.
    record = read_archive(run_id)
    semantic = record['result']['semantic']
    from ..runtime_admission import check_domain_scope
    check_domain_scope(decision, semantic['domain_id'], semantic['scenario_id'])
    from .pipeline import compute
    actual = compute(semantic['domain_id'], semantic['scenario_id'], request_override=semantic['input_bundle'])
    comparison = verify_recomputed(record, actual)
    # Dynamic transport identity stays outside the deterministic result. Return
    # the actual recomputed trace/result so the trusted host can check more than
    # a status string or semantic digest. This worker never creates a process.
    return dict(comparison, source_receipt_hash=digest(record), recomputed_result=actual)


def replay_fresh(run_id):
    """Retired worker entry: the trusted CandidateHost owns fresh launches."""
    raise AssemblyError('HOST_FRESH_PROCESS_REQUIRED', 'REPLAY')
