# H56 Demo Guide

## 1. Run the six-case demonstration

From the cloned repository root:

```powershell
python -B demo.py
```

The application constructs six distinct synthetic evidence inputs and evaluates them through the original computation chain.

| Case | Input change | Expected outcome |
| --- | --- | --- |
| B06v0 | A field declares UNKNOWN and also supplies a value. | Rejected: `ENV_INPUT_REJECTED`. |
| A01v0 | `app_container=true`, `integrity_rid=4096`. | `INFEASIBLE`. |
| B05v0 | Supporting attestation removed. | `NEED_MORE_EVIDENCE`. |
| B01v0 | External prerequisite marked UNKNOWN. | `DEFER`. |
| B07v1 | Observation time changed. | `FEASIBLE`. |
| C01v0 | Baseline evidence envelope. | `FEASIBLE`. |

The output includes input digests, field-level changes, outcomes, primary native-call counts and semantic identifiers. Recorded assessments normally contain 22 native-call trace entries; the rejected input produces no assessment artifact.

The final result is `PASS_WITH_SKIPS` when only one interpreter is supplied. The skipped property is cross-interpreter comparison, not a failed evaluation.

## 2. Retain inspectable records

Choose a new output directory outside the repository. Do not create the final run directory in advance.

```powershell
$run = Join-Path $env:TEMP ('h56-demo-' + [guid]::NewGuid().ToString('N'))
python -B demo.py --work-dir $run --json (Join-Path $run 'report.json') --keep
```

Inspect `report.json`, each selected case's `in/evidence.json`, assessment artifacts, claims and append-only event journal. Use the report's evidence index to locate files. The JSON report must be inside this run's directory; use the absolute path shown above.

Without `--keep`, the driver normally removes its own temporary work directory after the run.

## 3. Use the UI

```powershell
python -B ui/serve.py --no-browser
```

Open **http://127.0.0.1:8765** and use the page's run button. This invokes `demo.py --all` in a real subprocess. Inspect the decision, rejection and evidence panels after completion.

The full run contains 56 rows: 42 DECIDED and 14 REJECTED. It covers 26 distinct input byte strings, with 30 repeated rows. All 30 repeated rows are repeats of the baseline input: 31 occurrences of that input and one occurrence each of the other 25. The UI displays row count and distinct-input coverage separately.

The service listens only on loopback. Its run endpoint checks the exact origin, a per-service token and an empty JSON request body. Evidence access checks path containment, registration and file integrity. Use the page itself; manually typing an un-tokened POST is not the normal workflow.

If port 8765 is occupied, choose another port and use the matching URL:

```powershell
python -B ui/serve.py --port 8792 --no-browser
```

## 4. Reassessment and record preservation

The driver's property exercises include a parent assessment with a deferred result and a new assessment with additional evidence and a parent reference. The old artifact and claim remain intact. A read-only view then verifies the stored result without recomputing the cores.

This is a separate deterministic reassessment exercise. It should be presented separately from a model-selected scenario's primary assessment or a live R6 business request.

## 5. Fixed-response adapter integration

```powershell
$a2 = Join-Path $env:TEMP ('h56-a2-' + [guid]::NewGuid().ToString('N'))
python -B -m model_ingress_v1.tests.a2_integration --all-six --root $a2
```

The provider supplies fixed model responses, while the adapter, input construction, CLI, original cores and assessment storage execute real code. The driver checks all six scenarios, exact exit codes, input digests and source stability before and after execution. It compares actual generated input digests with the frozen in-tree baseline constants. This is one packaged baseline, rather than a second independently supplied A0 report, and does not need a private evidence directory.

This check is labeled as fixed-response integration. It is distinct from the previously recorded real Nebius inference runs.

## 6. Model collaboration

In this demonstration, a model selects a registered scenario rather than supplying trusted environmental evidence or the final feasibility result. The adapter validates the response and maps it to controlled input construction. The original cores perform the assessment.

Real Nebius records include R1/S-C01 (`FEASIBLE`), R5/S-A01 (`INFEASIBLE`) and R7 (`NOT_APPLICABLE`, kernel not launched). The two execution batches are identified separately. For an individual frozen input, comparing the Nebius and DeepSeek assessment artifacts supplies a concrete cross-provider consistency check.

To make a new paid request, follow [Optional live model integration](RECOVERY_GUIDE.md#optional-live-model-integration). Installation and the offline demonstration do not silently call any model.

## 7. Video presentation

Use existing application footage to show an actual run. Evidence cards can make model responses, reason codes and parent references legible; label rendered evidence as a replay rather than live screen capture. Identify separate model providers, source versions and execution batches where they are combined.

The primary evaluation's 22 trace entries are separate from driver regression work. An out-of-scope request with `native_calls=null` should be described using its recorded terminal decision and unlaunched-kernel state, rather than presenting null as a measured count.
