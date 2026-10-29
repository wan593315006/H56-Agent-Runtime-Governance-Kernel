"""Pure preparation contracts. No I/O, native imports or authority on import.

Permits identify trusted embedding decisions, not cryptographic Human identity.
Only an independently pinned bridge may issue them after the actual decision.
Preparation, raw preflight evidence and candidate acceptance are disjoint.
"""
from dataclasses import dataclass
import hashlib
import json
import re

from .errors import PreparationError


MAX_PLAN_BYTES = 2 * 1024 * 1024
PREPARATION_SCOPES = frozenset(('INVENTORY', 'MATERIALIZE', 'RESOURCE_PREPARE',
    'RESOURCE_READBACK', 'C1_OBSERVE', 'NEGATIVE_PROBE', 'INSTALL_ACCEPTED_CONTROLS'))
_SEAL = object()
_SHA = re.compile(r'^[0-9a-f]{64}$')
_TOKEN = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_PART = re.compile(r'^[A-Za-z0-9_.-]+$')
_RESERVED = frozenset(['CON', 'PRN', 'AUX', 'NUL'] +
    ['COM' + str(n) for n in range(1, 10)] + ['LPT' + str(n) for n in range(1, 10)])


def fail(code, detail=''):
    raise PreparationError(code, detail)


def sha(value):
    return type(value) is str and _SHA.fullmatch(value) is not None and value != '0' * 64


def token(value):
    if type(value) is not str or not _TOKEN.fullmatch(value):
        fail('BOOTSTRAP_TOKEN_INVALID')
    return value


def exact(value, keys, code='BOOTSTRAP_EXACT_FIELDS'):
    if type(value) is not dict or set(value) != set(keys):
        fail(code)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
            separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, UnicodeError, RecursionError):
        fail('BOOTSTRAP_CANONICAL_DATA_INVALID')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            fail('BOOTSTRAP_DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(raw, maximum=MAX_PLAN_BYTES):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        fail('BOOTSTRAP_JSON_BYTES_BUDGET')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
            parse_float=lambda value: fail('BOOTSTRAP_NONINTEGER_NUMBER'),
            parse_constant=lambda value: fail('BOOTSTRAP_NONFINITE_NUMBER'))
    except PreparationError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        fail('BOOTSTRAP_INVALID_JSON')


def relative_name(value):
    if type(value) is not str or not 1 <= len(value) <= 220:
        fail('BOOTSTRAP_RELATIVE_PATH_INVALID')
    parts = value.split('/')
    if len(parts) > 20 or any(not _PART.fullmatch(part) or part in ('.', '..') or
            part.endswith('.') or part.split('.')[0].upper() in _RESERVED
            for part in parts):
        fail('BOOTSTRAP_RELATIVE_PATH_INVALID')
    return parts


class FrozenPlan:
    """An immutable canonical-data snapshot; constructing one grants nothing."""
    __slots__ = ('_raw', 'sha256')

    def __init__(self, value):
        raw = canonical(value)
        if not 0 < len(raw) <= MAX_PLAN_BYTES:
            fail('BOOTSTRAP_PLAN_BUDGET')
        # Round-trip rejects floats and mutable/non-JSON tricks before freezing.
        decode(raw)
        object.__setattr__(self, '_raw', raw)
        object.__setattr__(self, 'sha256', hashlib.sha256(raw).hexdigest())

    def __setattr__(self, name, value):
        fail('BOOTSTRAP_PLAN_IMMUTABLE')

    def decoded(self):
        return decode(self._raw)

    def raw_bytes(self):
        return self._raw


@dataclass(frozen=True)
class PreparationPins:
    expected_hc_original_sha256: str
    expected_preparation_bundle_sha256: str
    session_id: str
    product_root: str


def validate_preparation_pins(pins, actual_product_root):
    """Pure comparison; the bridge must still read and verify original bytes."""
    if type(pins) is not PreparationPins:
        fail('BOOTSTRAP_EXTERNAL_OPERATOR_PINS_REQUIRED')
    if not sha(pins.expected_hc_original_sha256) or not sha(pins.expected_preparation_bundle_sha256):
        fail('BOOTSTRAP_EXTERNAL_PINS_UNBOUND')
    token(pins.session_id)
    if type(actual_product_root) is not str or pins.product_root != actual_product_root:
        fail('BOOTSTRAP_ACTUAL_ENTRY_ROOT_MISMATCH')


def validate_preparation_bundle(value):
    exact(value, ('schema', 'session_id', 'allowed_operations', 'files'),
        'BOOTSTRAP_BUNDLE_FIELDS')
    if value['schema'] != 'h56.windows-preparation-bundle.v1':
        fail('BOOTSTRAP_BUNDLE_SCHEMA')
    token(value['session_id'])
    operations = value['allowed_operations']
    if (type(operations) is not list or not operations or
            any(type(x) is not str or x not in PREPARATION_SCOPES for x in operations) or
            len(set(operations)) != len(operations)):
        fail('BOOTSTRAP_BUNDLE_SCOPE')
    files, folded = value['files'], set()
    if type(files) is not dict or not 1 <= len(files) <= 16:
        fail('BOOTSTRAP_BUNDLE_FILE_BUDGET')
    for name, identity in files.items():
        relative_name(name)
        if name.casefold() in folded or name in ('hc_original.txt', 'preparation_bundle.json'):
            fail('BOOTSTRAP_BUNDLE_COLLISION_OR_SELF_HASH')
        folded.add(name.casefold())
        exact(identity, ('size', 'sha256'), 'BOOTSTRAP_BUNDLE_MEMBER_FIELDS')
        if type(identity['size']) is not int or not 0 < identity['size'] <= MAX_PLAN_BYTES or not sha(identity['sha256']):
            fail('BOOTSTRAP_BUNDLE_MEMBER_IDENTITY')
    return value


class PreparationPermit:
    __slots__ = ('plan_sha256', 'scope', '_seal')

    def __init__(self, plan_sha256, scope, seal):
        if seal is not _SEAL or scope not in PREPARATION_SCOPES or not sha(plan_sha256):
            fail('OPAQUE_PREPARATION_PERMIT_REQUIRED')
        object.__setattr__(self, 'plan_sha256', plan_sha256)
        object.__setattr__(self, 'scope', scope)
        object.__setattr__(self, '_seal', seal)

    def __setattr__(self, name, value):
        fail('BOOTSTRAP_PERMIT_IMMUTABLE')


def _issue_preparation_permit(plan, scope):
    """Trusted bridge-only boundary. Not callable as an approval from task JSON."""
    if type(plan) is not FrozenPlan:
        fail('BOOTSTRAP_FROZEN_PLAN_REQUIRED')
    return PreparationPermit(plan.sha256, scope, _SEAL)


def require_preparation_permit(plan, permit, scope):
    if (type(plan) is not FrozenPlan or type(permit) is not PreparationPermit or
            permit._seal is not _SEAL or permit.scope != scope or
            permit.plan_sha256 != plan.sha256 or scope not in PREPARATION_SCOPES):
        fail('OPAQUE_PREPARATION_PERMIT_REQUIRED')


def topological_order(nodes):
    """Pure named dependency graph validation; no execution or approval."""
    if type(nodes) is not dict or not 1 <= len(nodes) <= 64:
        fail('BOOTSTRAP_DAG_BUDGET')
    pending = {}
    for name, dependencies in nodes.items():
        token(name)
        if (type(dependencies) is not list or
                any(type(x) is not str or x not in nodes for x in dependencies) or
                len(set(dependencies)) != len(dependencies)):
            fail('BOOTSTRAP_DAG_DEPENDENCY')
        pending[name] = set(dependencies)
    result = []
    while pending:
        ready = sorted(name for name, dependencies in pending.items() if not dependencies)
        if not ready:
            fail('BOOTSTRAP_DAG_CYCLE')
        result.extend(ready)
        for name in ready:
            del pending[name]
        for dependencies in pending.values():
            dependencies.difference_update(ready)
    return result
