"""Successor AST and pure DATA tests only; no runtime admission or native import."""
import ast
import builtins
import copy
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

PRODUCT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(PRODUCT))
ORIGINAL = PRODUCT / 'runtime_binding_v1_20261024' / 'engineering'
RUNTIME = PRODUCT / 'runtime_windows'
FORBIDDEN_MODULES = ('ctypes', 'assembly', 'adapters', 'mother', 'k0_fact_foundation',
                     'k1_state_derivation', 'candidate_canonical_capability_contract',
                     'candidate_capability_feasibility_projection', 'unified_runtime_ontology_profile',
                     'runtime_windows.assembly.loader', 'runtime_windows.assembly.pipeline',
                     'runtime_windows.candidate_cli', 'runtime_windows.runtime_admission',
                     'runtime_windows.launcher', 'runtime_windows.win32_backend')


def guarded_imports():
    actual = builtins.__import__

    def guarded(name, globals=None, locals=None, fromlist=(), level=0):
        full_name = importlib.util.resolve_name('.' * level + name, globals['__package__']) if level else name
        candidates = [full_name] + [full_name + '.' + value for value in fromlist or () if value != '*']
        if any(value == prefix or value.startswith(prefix + '.')
               for value in candidates for prefix in FORBIDDEN_MODULES):
            raise AssertionError('Forbidden module import: ' + full_name)
        return actual(name, globals, locals, fromlist, level)
    return mock.patch.object(builtins, '__import__', side_effect=guarded)


with guarded_imports():
    from runtime_windows.assembly import contracts, unit_admission, evidence, replay
    from runtime_windows.adapters import bounded_rules, core_context


def tree(root, name):
    return ast.parse((root / name).read_bytes(), filename=name)


def definition(root, name, function):
    return next(node for node in tree(root, name).body
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == function)


def dump(node):
    return ast.dump(node, include_attributes=False)


class GateNameOnly(ast.NodeTransformer):
    def visit_Name(self, node):
        if node.id == 'require_runtime':
            node.id = 'require_g2'
        return node


class PerimeterStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads((ORIGINAL / 'contracts/money_unit_admission.json').read_bytes())
        cls.assets = {}
        for domain, directory in (('DEVSECOPS', 'devsecops'), ('FINANCE_REFUND', 'finance_refund')):
            cls.assets[domain] = tuple(json.loads((ORIGINAL / 'assets' / directory / name).read_bytes())
                                       for name in ('manifest.json', 'domain_assets.json'))

    def test_01_original_source_pins_match_port_map(self):
        port = json.loads((RUNTIME / 'PERIMETER_PORT_MAP.json').read_bytes())
        for item in port['source_versions']:
            path = ORIGINAL.parent / item['source_relative_to_component']
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item['source_sha256'])

    def test_02_contract_and_adapter_functions_ast_unchanged(self):
        cases = {
            'assembly/contracts.py': ('AssemblyError', 'canonical', 'digest', 'raw_hash', 'exact',
                                      'strict_int', 'safe_path', '_pairs', 'read_json', 'schema_check', 'AssemblyPlan'),
            'adapters/bounded_rules.py': ('evaluate',),
            'adapters/core_context.py': ('mapping_inputs', 'native_c2_inputs'),
            'assembly/pipeline.py': ('plain', 'NativeCalls'),
            'assembly/evidence.py': ('verify_record_hash',),
            'assembly/replay.py': ('verify_recomputed',),
        }
        for filename, functions in cases.items():
            for name in functions:
                with self.subTest(file=filename, function=name):
                    self.assertEqual(dump(definition(ORIGINAL, filename, name)),
                                     dump(definition(RUNTIME, filename, name)))

    def test_03_pipeline_only_explicit_gate_name_change(self):
        original = definition(ORIGINAL, 'assembly/pipeline.py', 'compute')
        successor = definition(RUNTIME, 'assembly/pipeline.py', 'compute')
        self.assertEqual(dump(original), dump(GateNameOnly().visit(successor)))

    def test_04_admission_preserves_checks_after_new_gate(self):
        original = definition(ORIGINAL, 'assembly/admission.py', 'admit')
        successor = definition(RUNTIME, 'assembly/admission.py', 'admit')
        self.assertEqual(dump(successor.body[0]), dump(ast.parse('require_runtime()').body[0]))
        successor.body = successor.body[1:]
        self.assertEqual(dump(original), dump(successor))

    def test_05_original_unit_semantics_ast_preserved_in_pure_helper(self):
        original = definition(ORIGINAL, 'assembly/unit_admission.py', 'validate_units')
        successor = definition(RUNTIME, 'assembly/unit_admission.py', 'validate_unit_data')
        proof_index = next(i for i, node in enumerate(original.body)
                           if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'proof'
                                                                for t in node.targets))
        self.assertEqual([dump(node) for node in original.body[2:proof_index]],
                         [dump(node) for node in successor.body[1:-1]])

    def test_06_no_old_lock_manifest_root_or_generic_namespace_fallback(self):
        files = list((RUNTIME / 'assembly').glob('*.py')) + list((RUNTIME / 'adapters').glob('*.py')) + [RUNTIME / 'candidate_cli.py']
        for path in files:
            parsed = ast.parse(path.read_bytes())
            for node in ast.walk(parsed):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotIn('offline/source-lock.json', node.value)
                    self.assertNotIn('SOURCE_MANIFEST.json', node.value)
                    for old_root in ('/h56mu', '/scratch/', '/proc/', '/sys/'):
                        self.assertNotIn(old_root, node.value)
                if isinstance(node, ast.ImportFrom) and node.level == 0:
                    self.assertFalse((node.module or '').startswith(('assembly', 'adapters')))

    def test_07_two_domain_unit_data_positive(self):
        for domain, values in self.assets.items():
            with self.subTest(domain=domain):
                checked = unit_admission.validate_unit_data(domain, *values, self.registry)
                self.assertEqual(checked['declared_unit'], self.registry['domain_bindings'][domain]['money_unit'])

    def test_08_wrong_missing_unknown_unit_data_rejected(self):
        manifest, assets = self.assets['FINANCE_REFUND']
        for value, code in ((None, 'MU_UNIT_DECLARATION_MISSING'),
                            ('NOT_APPLICABLE', 'MU_UNIT_DOMAIN_MISMATCH'),
                            ('USD', 'MU_UNIT_UNREGISTERED'),
                            (False, 'MU_UNIT_DECLARATION_TYPE_INVALID')):
            changed = copy.deepcopy(assets)
            if value is None:
                del changed['object_schema']['value']['money_unit']
            else:
                changed['object_schema']['value']['money_unit'] = value
            with self.subTest(value=value), self.assertRaises(contracts.AssemblyError) as caught:
                unit_admission.validate_unit_data('FINANCE_REFUND', manifest, changed, self.registry)
            self.assertEqual(str(caught.exception), code)

    def test_09_amount_currency_budget_contract_conflicts(self):
        manifest, assets = self.assets['FINANCE_REFUND']
        for field, patch, code in (
                ('requested_amount_minor', {'type': 'boolean'}, 'MU_UNIT_AMOUNT_CONTRACT_CONFLICT'),
                ('currency', {'type': 'string', 'enum': ['USD']}, 'MU_UNIT_CURRENCY_CONTRACT_CONFLICT'),
                ('compute_budget_units', {'type': 'boolean'}, 'MU_UNIT_BUDGET_DIMENSION_CONFLICT')):
            changed = copy.deepcopy(assets)
            changed['object_schema']['value']['fields'][field] = patch
            with self.subTest(field=field), self.assertRaises(contracts.AssemblyError) as caught:
                unit_admission.validate_unit_data('FINANCE_REFUND', manifest, changed, self.registry)
            self.assertEqual(str(caught.exception), code)

    def test_10_new_proof_static_lineage_and_candidate_only_boundary(self):
        manifest, assets = self.assets['FINANCE_REFUND']
        checked = unit_admission.validate_unit_data('FINANCE_REFUND', manifest, assets, self.registry)
        hashes = {name: '1' * 64 for name in ('contract_sha256', 'schema_sha256', 'validator_sha256', 'asset_manifest_sha256')}
        decision = {name: '2' * 64 for name in unit_admission.SOURCE_LINEAGE_FIELDS}
        proof = unit_admission.build_internal_proof('FINANCE_REFUND', checked, hashes, decision)
        self.assertEqual(proof['schema_id'], 'H56OS:INTERNAL_UNIT_ADMISSION_PROOF:WINDOWS_V1')
        for name in ('external_fact_trust', 'authority_granted', 'execution_permitted'):
            self.assertIs(proof[name], False)
        self.assertFalse(any('private_provenance' in name for name in proof))
        self.assertFalse({'release_sha256', 'environment_sha256', 'preflight_sha256'} & set(proof))
        self.assertEqual(proof['proof_hash'], contracts.digest({k: v for k, v in proof.items() if k != 'proof_hash'}))
        decision['preflight_sha256'] = '3' * 64
        self.assertEqual(proof, unit_admission.build_internal_proof('FINANCE_REFUND', checked, hashes, decision))
        changed = dict(hashes, validator_sha256='4' * 64)
        self.assertNotEqual(proof['proof_hash'], unit_admission.build_internal_proof('FINANCE_REFUND', checked, changed, decision)['proof_hash'])

    def test_11_resealed_receipt_is_not_full_recomputation(self):
        result = {'status': 'COMPUTED_CANDIDATE_ONLY', 'semantic': {'projection': 'original'}, 'semantic_hash': '0' * 64}
        record = {'result': result}
        record['receipt_hash'] = contracts.digest(record)
        evidence.verify_record_hash(record)
        changed = copy.deepcopy(result)
        changed['semantic']['projection'] = 'forged'
        record['result'] = changed
        record['receipt_hash'] = contracts.digest({k: v for k, v in record.items() if k != 'receipt_hash'})
        evidence.verify_record_hash(record)
        with self.assertRaises(contracts.AssemblyError):
            replay.verify_recomputed(record, result)

    def test_12_reconstruction_is_worker_only_and_fresh_launch_belongs_to_host(self):
        node = definition(RUNTIME, 'assembly/replay.py', 'replay_fresh')
        calls = [item.func.id for item in ast.walk(node)
                 if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)]
        self.assertEqual(calls, ['AssemblyError'])
        self.assertNotIn('compute', calls)
        self.assertIn('HOST_FRESH_PROCESS_REQUIRED', dump(node))
        reconstruct = definition(RUNTIME, 'assembly/replay.py', 'reconstruct')
        for required in ('read_archive', 'compute', 'verify_recomputed', 'check_domain_scope', 'recomputed_result'):
            self.assertIn(required, dump(reconstruct))
        for forbidden in ('Popen', 'subprocess', 'run_bounded'):
            self.assertNotIn(forbidden, dump(reconstruct))
        input_resolver = definition(RUNTIME, 'assembly/evidence.py', 'receipt_input_path')
        self.assertIn('receipt_input_root', dump(input_resolver))
        read_archive = definition(RUNTIME, 'assembly/evidence.py', 'read_archive')
        self.assertIn('receipt_input_path', dump(read_archive))
        self.assertNotIn('run_path', dump(read_archive))
        entry = definition(RUNTIME, 'candidate_cli.py', 'main')
        expected = ast.parse("if not sys.flags.utf8_mode:\n    raise RuntimeError('WINDOWS_CLI_UTF8_MODE_REQUIRED')").body[0]
        self.assertEqual(dump(entry.body[0]), dump(expected))

    def test_13_pure_rule_ternary_and_limits(self):
        self.assertIsNone(bounded_rules.evaluate({'EQUALS': [{'FIELD': 'missing'}, {'CONST': True}]}, {'missing': None}))
        self.assertIs(bounded_rules.evaluate({'STRICT_INT_LE': [{'CONST': 3}, {'CONST': 5}]}, {}), True)
        with self.assertRaises(contracts.AssemblyError):
            bounded_rules.evaluate({'STRICT_INT_LE': [{'CONST': True}, {'CONST': 5}]}, {})
        with self.assertRaises(contracts.AssemblyError):
            bounded_rules.evaluate({'EXECUTE': []}, {})

    def test_14_pure_module_top_levels_do_not_call_runtime_or_file_or_native(self):
        deny = mock.Mock(side_effect=AssertionError('forbidden top-level activity'))
        modules = (contracts, unit_admission, evidence, replay, bounded_rules, core_context)
        codes = [(module, compile(Path(module.__file__).read_bytes(), module.__file__, 'exec')) for module in modules]
        with guarded_imports(), mock.patch.object(builtins, 'open', deny), \
                mock.patch.object(Path, 'read_bytes', deny), mock.patch.object(Path, 'stat', deny), \
                mock.patch.object(Path, 'lstat', deny), mock.patch.object(contracts, 'require_runtime', deny):
            for module, code in codes:
                namespace = {'__name__': module.__name__, '__package__': module.__package__}
                exec(code, namespace)
        deny.assert_not_called()

    def test_15_forbidden_modules_not_loaded(self):
        for prefix in FORBIDDEN_MODULES:
            self.assertFalse(any(name == prefix or name.startswith(prefix + '.') for name in sys.modules), prefix)


if __name__ == '__main__':
    unittest.main(verbosity=2)
