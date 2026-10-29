"""Fresh-process reconstruction using approved inputs, never stored decisions."""
import json
import sys
from .contracts import ENGINEERING, AssemblyError, digest, require_g2
from .evidence import read_archive
from .release_admission import child_environment, run_bounded


def verify_recomputed(record, actual):
    """Full semantic equality, not acceptance of a stored projection or hash."""
    if actual.get('status') != 'COMPUTED_CANDIDATE_ONLY' or actual != record['result']:
        raise AssemblyError('RECOMPUTED_HISTORY_SNAPSHOT_CONTEXT_OR_PROJECTION_MISMATCH', 'REPLAY')
    return {'status': 'ACTUAL_RECOMPUTATION_MATCH', 'semantic_hash': actual['semantic_hash'],
            'authority_granted': False, 'execution_permitted': False}


def reconstruct(run_id):
    require_g2('fresh_process_replay')  # Explicit grant also covers nested compute.
    record = read_archive(run_id)
    semantic = record['result']['semantic']
    from .pipeline import compute
    actual = compute(semantic['domain_id'], semantic['scenario_id'], request_override=semantic['input_bundle'])
    return verify_recomputed(record, actual)


def replay_fresh(run_id):
    decision = require_g2('fresh_process_replay')
    record = read_archive(run_id)
    # Only this exact local CLI and Python interpreter can be selected; no shell/callback/provider.
    argv = [sys.executable, '-I', '-B', '-S', str(ENGINEERING / 'cli/candidate_cli.py'), '--recompute-file', run_id]
    child = run_bounded(argv, child_environment(decision))
    if child['exit_code']:
        error = AssemblyError('FRESH_PROCESS_RECOMPUTATION_FAILED:' + child['failure_evidence']['path'], 'REPLAY')
        error.child_evidence = child['failure_evidence']
        raise error
    comparison = json.loads(child['stdout'])
    if comparison.get('status') != 'ACTUAL_RECOMPUTATION_MATCH' or comparison.get('semantic_hash') != record['result']['semantic_hash']:
        raise AssemblyError('FRESH_PROCESS_RESULT_DRIFT', 'REPLAY')
    return {'argv': argv, 'exit_code': child['exit_code'], 'child_result': comparison,
            'source_receipt_hash': digest(record), 'authority_granted': False, 'execution_permitted': False}
