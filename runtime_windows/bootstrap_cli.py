"""Fixed preparation entry, inert on import; every real operation needs pins.

Run this byte copy from its actual product root. No command creates approval.
Missing implementations are explicit BLOCKED routes, never successful stubs.
Private raw reports may contain synthetic canary/output evidence; do not publish
their output as competition artifacts without the separate public-admission scan.
"""
import argparse
import base64
import json
from pathlib import Path
import sys

if __name__ == '__main__' and __package__ in (None, ''):
    # Explicit script execution derives its one import root from this byte copy.
    # There is no original-directory/PYTHONPATH fallback.
    sys.path.insert(0, str(Path(__file__).absolute().parents[1]))
    __package__ = 'runtime_windows'

from .bootstrap_contract import (PreparationPins, canonical, decode, fail,
    relative_name, sha, token)
from .errors import PreparationError


COMMANDS = ('plan', 'inventory', 'materialize', 'verify', 'prepare', 'readback',
            'observe', 'probe', 'preflight', 'propose-controls', 'install-controls')
MAX_OUTPUT_BYTES = 16 * 1024 * 1024


def _blocked(code):
    return dict(schema='h56.windows-preparation-cli-result.v1', status='BLOCKED',
        reason=code, runtime_authorized=False, candidate_computation='NOT_RUN',
        authority_granted=False, external_services=False)


def _json_safe(value):
    if type(value) is bytes:
        return dict(encoding='base64', size=len(value), raw_base64=base64.b64encode(value).decode('ascii'))
    if type(value) is dict:
        return {name: _json_safe(item) for name, item in value.items()}
    if type(value) in (list, tuple):
        return [_json_safe(item) for item in value]
    return value


def dispatch(command, plan_name, hc_sha256, bundle_sha256, session_id):
    """Explicit future runtime route; tests exercise only missing-pin rejection."""
    if command not in COMMANDS:
        return _blocked('BOOTSTRAP_UNKNOWN_COMMAND')
    if command in ('propose-controls', 'install-controls'):
        return _blocked('BOOTSTRAP_FINAL_CONTROL_INSTALLER_NOT_IMPLEMENTED_OR_AUTHORIZED')
    if command == 'probe':
        return _blocked('BOOTSTRAP_USE_PREFLIGHT_FIXED_RAW_ARCHIVE_ROUTE')
    if not sha(hc_sha256) or not sha(bundle_sha256) or not session_id:
        return _blocked('BOOTSTRAP_EXTERNAL_HUMAN_AND_BUNDLE_PINS_REQUIRED')
    token(session_id)
    relative_name(plan_name)
    # Pins are operator inputs, never task JSON. Product root has no free option.
    root = str(Path(__file__).absolute().parents[1])
    pins = PreparationPins(hc_sha256, bundle_sha256, session_id, root)
    from .preflight_authority import PinnedPreparationAuthority
    authority = PinnedPreparationAuthority.from_pins(pins)
    if command == 'plan':
        from .run_projection import build_projection_plan, CANDIDATE_MANIFEST, BOOTSTRAP_MANIFEST
        from .source_identity import _read_checked
        spec_plan = authority.load_plan(plan_name, 'INVENTORY')
        authority.authorize(spec_plan, 'INVENTORY')
        spec = spec_plan.decoded()
        if spec.get('paths', {}).get('source_product_root') != root:
            fail('PROJECTION_ACTUAL_ENTRY_ROOT_MISMATCH')
        product = Path(root)
        plan = build_projection_plan(
            _read_checked(product / 'PACKAGE_MANIFEST.json', None, 2 * 1024 * 1024),
            _read_checked(product.joinpath(*CANDIDATE_MANIFEST.split('/')), None, 2 * 1024 * 1024),
            _read_checked(product.joinpath(*BOOTSTRAP_MANIFEST.split('/')), None, 2 * 1024 * 1024),
            authority.read_named('runtime_index.json'), spec)
        return dict(schema='h56.windows-projection-plan-proposal.v1',
            status='PROPOSED_NOT_AUTHORIZED', plan_sha256=plan.sha256,
            plan=plan.decoded(), runtime_authorized=False, candidate_computation='NOT_RUN')
    if command in ('inventory', 'materialize', 'verify'):
        from .run_projection import (inventory_declared_inputs, materialize_projection,
            verify_projection, enforce_entry_root)
        scope = 'MATERIALIZE' if command == 'materialize' else 'INVENTORY'
        plan = authority.load_plan(plan_name, scope)
        permit = authority.authorize(plan, scope)
        enforce_entry_root(plan, 'STAGED_VERIFY' if command == 'verify' else scope, root)
        if command == 'inventory':
            return inventory_declared_inputs(plan, permit)
        if command == 'materialize':
            return materialize_projection(plan, permit)
        return verify_projection(plan)
    if command in ('prepare', 'readback'):
        from .resource_prepare import prepare_resources, readback_resources, ResourcePreparationError
        scope = 'RESOURCE_PREPARE' if command == 'prepare' else 'RESOURCE_READBACK'
        plan = authority.load_plan(plan_name, scope)
        permit = authority.resource_permit(plan, scope)
        if command == 'prepare':
            try:
                return prepare_resources(plan, permit, authority.read_named('projection_receipt.json'))
            except ResourcePreparationError as error:
                return dict(schema='h56.windows-resource-cli-stop.v1', status='STOPPED',
                    reason=error.cause_code, scene=error.scene,
                    cleanup=error.cleanup_status, archive='EXPLICIT_PRIVATE_STDOUT_CAPTURE_REQUIRED',
                    runtime_authorized=False, candidate_computation='NOT_RUN')
        return readback_resources(plan, authority.read_named('preparation_receipt.json'), permit)
    if command == 'observe':
        from .launcher import run_observer
        from .launch_contract import validate_launch_request
        observation_plan = validate_launch_request(authority.load_plan(plan_name, 'C1_OBSERVE').decoded())
        bridge = authority.observation_authority(observation_plan)
        receipt = run_observer(observation_plan.decoded(), authority.expected_hc_sha256, authority=bridge)
        stopped = (receipt.get('stop_reason') is not None or receipt.get('exit_code') != 0 or
            receipt.get('cleanup', {}).get('status') != 'CLOSED')
        return dict(schema='h56.windows-single-observer-cli-raw.v1',
            status='STOPPED' if stopped else 'RAW_C1_RESULT_NOT_ACCEPTED',
            archive='EXPLICIT_PRIVATE_STDOUT_CAPTURE_REQUIRED', receipt=_json_safe(receipt),
            runtime_authorized=False, candidate_computation='NOT_RUN')
    if command == 'preflight':
        from .preflight import validate_preflight_plan, run_preflight, public_report
        plan = authority.load_plan(plan_name, 'C1_OBSERVE')
        validated = validate_preflight_plan(plan.decoded())
        return public_report(run_preflight(validated, authority))
    return _blocked('BOOTSTRAP_ROUTE_NOT_IMPLEMENTED')


def main(argv=None):
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and
            getattr(sys.flags, 'utf8_mode', 0)):
        result = _blocked('BOOTSTRAP_ISOLATED_UTF8_FLAGS_REQUIRED')
        sys.stdout.buffer.write(canonical(result) + b'\n')
        return 2
    parser = argparse.ArgumentParser(description='Explicit local preparation; no default runtime authority')
    parser.add_argument('command', choices=COMMANDS)
    parser.add_argument('--plan', default='projection_plan.json')
    parser.add_argument('--hc-sha')
    parser.add_argument('--bundle-sha')
    parser.add_argument('--session')
    args = parser.parse_args(argv)
    try:
        result = dispatch(args.command, args.plan, args.hc_sha, args.bundle_sha, args.session)
    except PreparationError as error:
        result = _blocked(error.code)
        from .run_projection import ProjectionMaterializationError
        if isinstance(error, ProjectionMaterializationError):
            result.update(created_paths=list(error.created_paths), cause_code=error.cause_code,
                cleanup='NOT_AUTOMATIC_SCENE_PRESERVED')
    raw = canonical(_json_safe(result))
    if len(raw) > MAX_OUTPUT_BYTES:
        # No false PASS or silent truncation. An embedding must preserve its
        # bounded result if this source-level transport budget proves insufficient.
        raise PreparationError('BOOTSTRAP_OUTPUT_BUDGET_SCENE_REQUIRES_PRIVATE_CAPTURE')
    sys.stdout.buffer.write(raw + b'\n')
    sys.stdout.buffer.flush()
    return 2 if result.get('status') in ('BLOCKED', 'STOPPED', 'STOPPED_ARCHIVE_FAILED') else 0


if __name__ == '__main__':
    raise SystemExit(main())
