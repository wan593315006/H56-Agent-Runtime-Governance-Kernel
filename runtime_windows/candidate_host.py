"""Fixed candidate compute/fresh-replay host, prepared but not runtime accepted.

No native calls at import. Explicit bootstrap needs operator-provided external
Human/bundle pins, complete accepted controls, immutable sources and actual
resource readback. Restricted workers never spawn children. This host does not
authorize or execute business actions and never mutates original K0 history.
"""
import base64
import hashlib
from pathlib import Path

from .errors import PreparationError
from .host_contract import (boundary, canonical, candidate_argv, decode, digest, exact,
    fail, make_candidate_plan, new_result, token, validate_host_result, validate_record,
    windows_path, HostEvidencePersistenceError)
from .host_authority import BootstrapPins, PinnedHumanControllerAuthority
from .source_identity import _read_checked, _check_chain, _check_stat


class CandidateHost:
    def __init__(self, authority):
        if type(authority) is not PinnedHumanControllerAuthority:
            fail('HOST_CONCRETE_PINNED_AUTHORITY_REQUIRED')
        self.authority = authority

    @classmethod
    def from_bootstrap(cls, pins=None):
        # No default pins, fake approved=True record or implicit system fallback.
        return cls(PinnedHumanControllerAuthority(pins))

    def compute(self, domain_id, scenario_id, run_id, on_started=None, task_id=None):
        plan = make_candidate_plan(self.authority.configuration, 'candidate_compute',
                                   run_id, domain_id, scenario_id, task_id=task_id)
        return self._run(plan, on_started)

    def replay(self, source_run_id, replay_id, on_started=None, task_id=None):
        plan = make_candidate_plan(self.authority.configuration, 'fresh_process_replay',
            replay_id, source_run_id=source_run_id, task_id=task_id)
        return self._run(plan, on_started)

    def _run(self, plan, on_started):
        if on_started is not None and not callable(on_started):
            fail('HOST_STARTED_CALLBACK_NOT_CALLABLE')
        # Each operation obtains a new anonymous Job/process via one backend.
        result, data = new_result(plan), plan.decoded()
        backend, cleanup, started_event, stop = None, None, None, None
        source_raw, source_record = None, None
        try:
            with self.authority.active_lock():
                permit = self.authority.authorize_call(plan)
                if data['operation'] == 'fresh_process_replay':
                    source_path = Path(data['paths']['receipt_input_root']) / data['source_run_id'] / 'receipt.json'
                    self.authority.reader.verify_receipt_readonly(source_path)
                    source_raw = _read_checked(source_path, None, 12582912)
                    source_record = decode(source_raw, 12582912)
                    validate_record(source_record, data['source_lineage'],
                                    self.authority.configuration['vendor'], require_complete=True)
                    semantic = source_record['result']['semantic']
                    scope = self.authority.configuration['host_acceptance']['domain_scenarios']
                    if semantic['domain_id'] not in scope or semantic['scenario_id'] not in scope[semantic['domain_id']]:
                        fail('HOST_REPLAY_SOURCE_OUTSIDE_ACCEPTED_SCOPE')
                try:
                    from .win32_backend import CandidateWindowsBackend
                    backend = CandidateWindowsBackend(plan, permit)
                    backend.create_job()
                    backend.create_pipes()
                    backend.create_suspended_child_in_job()
                    result['pid'] = backend.pid  # preserve even if Resume later fails
                    backend.resume()
                    result['started'] = True
                    started_event = dict(schema='h56.windows-candidate-started.v1',
                        pid=backend.pid, run_id=data['run_id'], operation=data['operation'],
                        task_id=data['task_id'],
                        runtime_source_manifest_sha256=data['source_lineage']['runtime_source_manifest_sha256'],
                        resource_contract_sha256=self.authority.configuration['resource_contract_sha256'])
                    if on_started is not None:
                        on_started(dict(started_event))
                    backend.pump()
                except Exception as error:
                    stop = _failure(error)
                finally:
                    if backend is not None:
                        result['pid'] = getattr(backend, 'pid', None)
                        try:
                            cleanup = backend.cleanup()
                        except Exception as error:
                            cleanup = dict(status='CLEANUP_NOT_VERIFIED', errors=[_failure(error)['code']])
                            if stop is None:
                                stop = dict(code='HOST_CLEANUP_FAILED', detail='Owned resource cleanup not verified')
                        capture = backend.snapshot()  # already observed bounded bytes
                        result['exit_code'] = capture['exit_code']
                        result['transport_receipt'] = _transport(plan, backend, capture, cleanup, started_event, stop,
                            self.authority.configuration['resource_contract_sha256'])
                if stop is not None:
                    raise PreparationError(stop['code'], stop['detail'])
                if cleanup != dict(status='CLOSED', errors=[]):
                    fail('HOST_CLEANUP_NOT_VERIFIED')
                output = decode(capture['raw_stdout'])
                if data['operation'] == 'candidate_compute':
                    exact(output, ('status', 'receipt'), 'HOST_COMPUTE_STDOUT_FIELDS')
                    path = Path(data['paths']['scratch_root']) / 'runs' / data['run_id'] / 'receipt.json'
                    if windows_path(output['receipt']) != windows_path(str(path)):
                        fail('HOST_WORKER_RECEIPT_PATH_MISMATCH')
                    raw = _read_checked(path, None, 12582912)
                    record = decode(raw, 12582912)
                    validate_record(record, data['source_lineage'], self.authority.configuration['vendor'])
                    if output['status'] != record['result']['status']:
                        fail('HOST_WORKER_RESULT_STATUS_MISMATCH')
                    expected_exit = 0 if output['status'] == 'COMPUTED_CANDIDATE_ONLY' else 2
                    if result['exit_code'] != expected_exit:
                        fail('HOST_WORKER_EXIT_STATUS_MISMATCH')
                    result['status'] = output['status'] if expected_exit == 0 else 'PIPELINE_REJECTED'
                    result['record'], result['receipt_ref'] = record, _reference(path, raw, data)
                    if expected_exit == 0:
                        result['projection'] = record['result']['semantic']['projection']
                        trace = record['result']['semantic']['native_calls']
                    else:
                        trace = record['result']['native_calls']
                else:
                    exact(output, ('status', 'semantic_hash', 'authority_granted', 'execution_permitted',
                        'source_receipt_hash', 'recomputed_result'), 'HOST_RECOMPUTE_STDOUT_FIELDS')
                    if (result['exit_code'] != 0 or output['status'] != 'ACTUAL_RECOMPUTATION_MATCH' or
                            output['source_receipt_hash'] != digest(source_record) or
                            output['recomputed_result'] != source_record['result'] or
                            output['semantic_hash'] != source_record['result']['semantic_hash'] or
                            output['authority_granted'] is not False or output['execution_permitted'] is not False):
                        fail('HOST_FULL_RECOMPUTATION_MISMATCH')
                    # Re-read the original immutable copy after actual computation.
                    self.authority.reader.verify_receipt_readonly(source_path)
                    if _read_checked(source_path, len(source_raw), 12582912) != source_raw:
                        fail('HOST_REPLAY_INPUT_CHANGED_DURING_COMPUTATION')
                    result.update(status='ACTUAL_RECOMPUTATION_MATCH', record=source_record,
                        receipt_ref=_reference(source_path, source_raw, data), comparison=output,
                        projection=output['recomputed_result']['semantic']['projection'])
                    trace = output['recomputed_result']['semantic']['native_calls']
                trace_path = Path(data['paths']['host_evidence_root']) / data['run_id'] / 'native_trace.json'
                trace_raw = canonical(trace) + b'\n'
                _write_once(trace_path, trace_raw, allow_new_parent=True)
                result['native_trace_ref'] = _reference(trace_path, trace_raw, data)
                validate_host_result(result, data['operation'], data['run_id'], data['task_id'],
                    data['source_run_id'], data['source_lineage'], started_event)
                if data['operation'] == 'candidate_compute' and result['status'] == 'COMPUTED_CANDIDATE_ONLY':
                    readonly = Path(data['paths']['receipt_input_root']) / data['run_id'] / 'receipt.json'
                    # Job has exited and cleanup completed before immutable copy.
                    _write_once(readonly, raw, allow_new_parent=True)
                    self.authority.reader.verify_receipt_readonly(readonly)
                    if _read_checked(readonly, len(raw), 12582912) != raw:
                        fail('HOST_IMMUTABLE_RECEIPT_COPY_IDENTITY')
            # The active-lock handle must close successfully before final success.
            result_path = Path(data['paths']['host_evidence_root']) / data['run_id'] / 'host_result.json'
            _write_once(result_path, canonical(result) + b'\n')
            return result
        except Exception as error:
            # Partly produced business data is not exposed as a valid result.
            result.update(status='HOST_FAILED' if backend is not None else 'HOST_BLOCKED',
                record=None, receipt_ref=None, native_trace_ref=None, projection=None, comparison=None,
                failure=stop or _failure(error))
            if result['transport_receipt'] is not None:
                result['transport_receipt']['stop_reason'] = result['failure']
            # Raw capture is retained even when callbacks, limits or cleanup fail.
            if backend is not None:
                try:
                    failure_path = Path(data['paths']['host_evidence_root']) / data['run_id'] / 'host_failure.json'
                    raw_failure = canonical(result) + b'\n'
                    _write_once(failure_path, raw_failure, allow_new_parent=not failure_path.parent.exists())
                    result['failure'] = dict(result['failure'], evidence=dict(
                        path=failure_path.relative_to(Path(data['paths']['product_root'])).as_posix(),
                        size=len(raw_failure), sha256=hashlib.sha256(raw_failure).hexdigest()))
                except Exception as archive_error:
                    # Do not silently return a digest-only result that discards
                    # the only captured bytes. The embedding must retain this
                    # explicit stop exception and its bounded raw_result object.
                    raise HostEvidencePersistenceError(result, archive_error) from archive_error
            return result


def _failure(error):
    return dict(code=getattr(error, 'code', type(error).__name__), detail=str(error)[:4096])


def _transport(plan, backend, capture, cleanup, started_event, stop, resource_hash):
    stdout, stderr = capture['raw_stdout'], capture['raw_stderr']
    return dict(schema='h56.windows-candidate-transport.v1', argv=candidate_argv(plan),
        pid=capture['pid'], exit_code=capture['exit_code'],
        raw_stdout_base64=base64.b64encode(stdout).decode('ascii'),
        raw_stderr_base64=base64.b64encode(stderr).decode('ascii'),
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        observed_output_bytes=capture['observed_output_bytes'], capture_prefix_truncated=capture['capture_prefix_truncated'],
        cleanup=cleanup, events=list(backend.events), stop_reason=stop,
        runtime_source_manifest_sha256=plan.decoded()['source_lineage']['runtime_source_manifest_sha256'],
        resource_contract_sha256=resource_hash, started_event=started_event)


def _reference(path, raw, data):
    relative = path.relative_to(Path(data['paths']['product_root'])).as_posix()
    return dict(path=relative, size=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                raw_base64=base64.b64encode(raw).decode('ascii'))


def _write_once(path, raw, allow_new_parent=False):
    """Only fixed registered IO descendants; no old-archive overwrite/fallback."""
    if type(raw) is not bytes or not 0 < len(raw) <= 16777216:
        fail('HOST_WRITE_ONCE_OUTPUT_BUDGET')
    if allow_new_parent:
        _check_chain(path.parent.parent)
        path.parent.mkdir(exist_ok=False)
    _check_chain(path.parent)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        import os
        os.fsync(stream.fileno())
    _check_stat(path.lstat(), False, str(path))
    if _read_checked(path, len(raw), 16777216) != raw:
        fail('HOST_WRITE_ONCE_CONTENT_DRIFT')
