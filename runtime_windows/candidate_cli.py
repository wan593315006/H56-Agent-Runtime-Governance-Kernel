"""Fixed candidate/reconstruction worker; it cannot launch another worker."""
from pathlib import Path
import argparse
import json
import sys


def main():
    if not sys.flags.utf8_mode:
        raise RuntimeError('WINDOWS_CLI_UTF8_MODE_REQUIRED')
    product = Path(__file__).absolute().parents[1]
    cache = product / 'runtime_windows' / '.forbidden_bytecode_cache'
    if cache.exists() or cache.is_symlink():
        raise RuntimeError('CLI_BYTECODE_CACHE_MUST_NOT_EXIST')
    sys.pycache_prefix, sys.dont_write_bytecode = str(cache), True
    sys.path.insert(0, str(product))  # Exact self-contained source root, no external PYTHONPATH.
    from runtime_windows.assembly.contracts import require_runtime
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain', choices=['DEVSECOPS', 'FINANCE_REFUND'])
    parser.add_argument('--scenario', default='positive')
    parser.add_argument('--run-id')
    parser.add_argument('--replay')
    parser.add_argument('--recompute-file')
    args = parser.parse_args()
    if args.replay:
        parser.error('HOST_FRESH_PROCESS_REQUIRED: use the trusted host replay entry.')
    if args.recompute_file and (args.domain or args.run_id or args.scenario != 'positive'):
        parser.error('Do not mix compute and reconstruction arguments.')
    decision = require_runtime('fresh_process_replay' if args.recompute_file else 'candidate_compute')
    if args.recompute_file:
        from runtime_windows.assembly.replay import reconstruct
        print(json.dumps(reconstruct(args.recompute_file), ensure_ascii=False))
    elif args.domain and args.run_id:
        from runtime_windows.runtime_admission import check_domain_scope
        check_domain_scope(decision, args.domain, args.scenario)
        from runtime_windows.assembly.pipeline import compute
        from runtime_windows.assembly.evidence import archive
        result = compute(args.domain, args.scenario)
        output = archive(result, args.run_id)
        print(json.dumps({'status': result['status'], 'receipt': str(output)}, ensure_ascii=False))
        return 0 if result['status'] == 'COMPUTED_CANDIDATE_ONLY' else 2
    else:
        parser.error('Use a domain/run-id or the fixed child reconstruction mode.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
