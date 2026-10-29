"""Pure, proposal-only preparation inputs. No publication or runtime authority.

The caller supplies original UTF-8 bytes and a proposed operation list. A valid
proposal proves internal byte/schema consistency, not source authenticity,
Human approval, dependency completeness, isolation or permission to operate.
This module neither reads its own registry nor discovers any host resources.
"""
import hashlib
from pathlib import Path

from .bootstrap_contract import (FrozenPlan, canonical, decode, fail,
                                 validate_preparation_bundle)
from .run_projection import build_projection_plan


PRODUCT_ROOT = str(Path(__file__).absolute().parent.parent)
PROPOSED_OPERATIONS = frozenset(('INVENTORY', 'MATERIALIZE'))
_MEMBERS = ('runtime_index.json', 'projection_spec.json', 'projection_plan.json')


def _identity(raw):
    return {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def compile_preparation_seed(product_manifest_raw, candidate_manifest_raw,
                             bootstrap_manifest_raw, runtime_index_raw,
                             projection_spec_raw, proposed_operations):
    """Return an immutable PROPOSED_NOT_APPROVED ``FrozenPlan``.

    ``decoded()['files'][name]`` contains ``raw_utf8``, ``size`` and ``sha256``.
    Encoding that text as UTF-8 recovers the exact proposed member bytes,
    including the supplied index/spec whitespace and LF/CRLF differences.
    Generated plan/bundle bytes use the existing canonical-data contract.
    Bundle membership is precisely the three non-bundle members: no HC or
    self-hash. Operations remain proposed data, never an issued permit.
    """
    if (type(proposed_operations) is not list or not proposed_operations or
            any(type(value) is not str or value not in PROPOSED_OPERATIONS
                for value in proposed_operations) or
            len(set(proposed_operations)) != len(proposed_operations)):
        fail('PREPARATION_SEED_PROPOSED_OPERATION')

    # Strict UTF-8/duplicate-key/number/budget checks are shared, not a second
    # schema or integrity engine. Decode all supplied streams before building.
    for raw in (product_manifest_raw, candidate_manifest_raw, bootstrap_manifest_raw,
                runtime_index_raw, projection_spec_raw):
        decode(raw)
    specification = decode(projection_spec_raw)
    if (type(specification) is not dict or type(specification.get('paths')) is not dict
            or specification['paths'].get('source_product_root') != PRODUCT_ROOT):
        fail('PREPARATION_SEED_CURRENT_PRODUCT_ROOT_REQUIRED')

    # The existing builder consumes validate_runtime_index/generated_pth and
    # checks current/candidate/bootstrap/index pins, roots, paths and budgets.
    # It performs no filesystem discovery, copy, permit issuance or startup.
    plan = build_projection_plan(product_manifest_raw, candidate_manifest_raw,
                                 bootstrap_manifest_raw, runtime_index_raw, specification)
    plan_data = plan.decoded()
    member_bytes = dict(zip(_MEMBERS, (runtime_index_raw, projection_spec_raw,
                                      plan.raw_bytes())))
    bundle = {'schema': 'h56.windows-preparation-bundle.v1',
              'session_id': plan_data['session_id'],
              'allowed_operations': list(proposed_operations),
              'files': {name: _identity(raw) for name, raw in member_bytes.items()}}
    validate_preparation_bundle(bundle)
    member_bytes['preparation_bundle.json'] = canonical(bundle)

    return FrozenPlan({'schema': 'h56.windows-preparation-seed.v1',
        'status': 'PROPOSED_NOT_APPROVED', 'session_id': plan_data['session_id'],
        'proposed_operations': list(proposed_operations),
        'source_identity': plan_data['source_identity'],
        'files': {name: dict(raw_utf8=raw.decode('utf-8'), **_identity(raw))
                  for name, raw in member_bytes.items()},
        'boundary': {'proposal_only': True, 'human_approval': False,
            'human_identity_authenticated': False, 'authority_issued': False,
            'permit_issued': False, 'published': False, 'deployment_performed': False,
            'runtime_started': False, 'candidate_calculated': False,
            'execution_authority': False}})
