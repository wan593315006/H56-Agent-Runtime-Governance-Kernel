# H56 Recovery Guide

This guide takes a source checkout to a working H56 demonstration. The repository itself is the portable runtime slice: it contains the application, original four-core sources, assets, public source lock, adapter and UI. There is no additional thawing or Mother-system installation step.

## Prerequisites

- Windows 10/11 and Git.
- Python 3.9.13, the primary interpreter used for candidate acceptance. Cross-interpreter comparison can be requested separately with a second interpreter.
- A short checkout path, such as `C:\h56demo`.
- The Python standard library is sufficient for the application and its offline checks. OpenCV and video-editing tools are not application dependencies.

An API credential and network access are needed only for an explicitly requested live inference run. They are not installation requirements for the offline demonstration.

## Clone and locate the actual checkout

```powershell
git -c core.autocrlf=false -c core.longpaths=true clone <repository-url> C:\h56demo
Set-Location C:\h56demo
git rev-parse HEAD
git status --porcelain
python --version
```

For a private local candidate, replace `<repository-url>` with its local repository path. The accepted candidate's local clone is created this way; no public remote is required for that check.

Start from a new destination directory. Preserve `.gitattributes` and its `* -text` rule, which prevents Git from converting registered source bytes. Prefer a short path even when long-path support is enabled. A source ZIP should be extracted to a short root without extra nesting.

`git status --porcelain` should be empty before and after the documented checks. H56's output belongs outside the checkout.

## Verify the computation identity and run

```powershell
python -B demo.py
```

The existing loader verifies `offline_qualification_v1/SOURCE_MANIFEST.json`, the public lock and each of the 139 computation members before using the cores. Expected output includes:

- `139` runtime-required members;
- six result rows with input digests and field changes;
- the frozen outcomes described in [Demo Guide](DEMO_GUIDE.md);
- `PASS_WITH_SKIPS`, with six properties passed and cross-interpreter comparison skipped.

The machine-readable `RELEASE_MANIFEST.json` identifies the larger candidate, including the current adapter and UI. The Git commit identifies the checked-out assembled version. The 139-member loader check and the whole-candidate inventory serve different scopes.

Do not modify the source manifest to suppress a mismatch. Restore the recorded file bytes from the chosen commit, or investigate a changed source version.

## Keep a six-case result

```powershell
$run = Join-Path $env:TEMP ('h56-demo-' + [guid]::NewGuid().ToString('N'))
python -B demo.py --work-dir $run --json (Join-Path $run 'report.json') --keep
```

The final `$run` directory must not exist in advance and must be outside the checkout. The JSON path must be inside that run directory; the expression above supplies an absolute path. `--keep` retains records. Without it, the driver normally cleans its own temporary run directory.

## Existing verification entry points

```powershell
python -B run_tests.py
python -B -m ui.test_release_guards
python -B -m model_ingress_v1.tests.test_ingress
python -B -m unittest model_ingress_v1.tests.test_stage_b -v
python -B -m unittest model_ingress_v1.tests.test_smoke -v
```

The product suite currently defines 30 tests and the release-guard suite nine. Use `run_tests.py` for the product suite: it supplies the explicit temporary test root required by the record tests. The adapter suites use fixed responses and local fixtures rather than paid model requests.

For the six-scenario model-to-core integration exercise:

```powershell
$a2 = Join-Path $env:TEMP ('h56-a2-' + [guid]::NewGuid().ToString('N'))
python -B -m model_ingress_v1.tests.a2_integration --all-six --root $a2
```

This uses a fixed-response model provider, with real CLI/core calculations and stored records. Its baseline is included in the test driver. It requires neither the developer's historical evidence directory nor an external project checkout. Leave identity checking enabled.

## Run the browser demonstration

```powershell
python -B ui/serve.py --no-browser
```

Open **http://127.0.0.1:8765** in the same machine's browser. The page's run button launches `demo.py --all`. Expected totals are 56 rows, 42 DECIDED, 14 REJECTED, 26 distinct inputs and 30 repeated rows. Allow the run to finish before opening its registered evidence.

Use `--port 8792` if the default port is occupied. Use the matching `127.0.0.1` URL; origin and token checks intentionally reject unrelated origins and hand-crafted requests missing the page token.

## Optional cross-interpreter check

```powershell
python -B demo.py --compare-python 'C:\path\to\second\python.exe'
```

The second interpreter is supplied by the operator. Without this option, the cross-interpreter property remains SKIP; the other properties are evaluated normally.

## Optional live model integration

The candidate retains the provider and stage-B driver used for real Nebius/NVIDIA integration. No key, private credential launcher or previously granted execution plan is included. The bundled `model_ingress_v1/stage_b_plan.json` is an inactive starting plan, scoped to R1.

To prepare a new live run:

1. Configure your own `NEBIUS_API_KEY` in the intended process environment using your local credential manager. Check presence without displaying the value. Keep credentials outside Git and outside run evidence.
2. Copy the bundled plan to a new private run directory outside the checkout. Retain the endpoint, request templates, scope and budget limits unless you are deliberately preparing a separately reviewed configuration.
3. Use the existing catalog entry point for one explicit directory query. Supply the local plan and a new external output root:

   ```powershell
   python -B -m model_ingress_v1.catalog --execute --plan '<absolute-plan-path>' --approve-origin https://api.tokenfactory.nebius.com:443 --root '<new-catalog-root>'
   ```

4. Adopt the actual catalog evidence into the local plan: confirmed model ID, catalog evidence path, model-verification state and the observed pricing fields. Use the actual current model entry; a historical price is not a current-price guarantee.
5. Record the operator's explicit run authorization and timestamp in that local plan. Its `ruling_sha256` is the SHA-256 of the UTF-8 authorization text. Set the declared gate state only when it agrees with the driver-derived conditions. The request IDs in the plan and command line must match in order and spelling.
6. Archive those exact plan bytes alongside the new run evidence. After verifying the configuration, a single R1 run uses:

   ```powershell
   python -B -m model_ingress_v1.stage_b --execute --plan '<absolute-plan-path>' --approve-origin https://api.tokenfactory.nebius.com:443 --approved-requests R1 --root '<new-run-root>'
   ```

The driver repeats preflight internally and enforces same-source plan binding. An inactive or inconsistent plan is refused before a provider is constructed. HTTP, parsing, model-selection, usage or budget failures retain their evidence and stop the remaining scope; there is no automatic retry or model substitution.

A new live request is an operator action with potential charges. The offline candidate acceptance does not activate these commands. Fixed-response checks remain available without a key.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Source/member/hash mismatch | Check the named member against the selected commit; preserve line endings and relative paths. Do not rewrite expected hashes. |
| Missing long-path member | Re-clone to a shorter root with `core.longpaths=true` and retain `* -text`. |
| Run directory already exists | Choose a new external directory; do not reuse a recorded run root. |
| JSON report rejected | Give an absolute JSON path inside this run's directory, and use `--keep` for evidence retention. |
| Record tests report a missing explicit test root | Run `python -B run_tests.py`, not unrestricted discovery. |
| Browser POST returns 403 | Use the page on its exact loopback origin and current service token. |
| `PASS_WITH_SKIPS` | Read the properties: the cross-interpreter comparison is optional and normally skipped with one interpreter. |
| Model driver returns an execution-preflight refusal | Inspect the reported plan, scope, catalog, credential-presence and budget conditions. Do not widen the scope to bypass them. |

## Candidate boundaries and preservation

The normal demonstration consumes the self-contained 139-member computation closure and the included public lock. The historical 181-member component manifest describes an earlier source-delivery layout; its excluded private provenance lock is not a dependency of these demonstrated entry points. Do not copy a private sidecar into a public checkout to satisfy that historical aggregate.

Preserve the whole candidate repository, its commit and the external run evidence. No Mother-system copy, private source lock, key file, registry repair, administrator operation or new recovery program is needed for the documented offline recovery path.
