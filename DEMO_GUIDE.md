# H56 Demo Guide

**[Watch the public demonstration on YouTube](https://youtu.be/Gxr5SzG3OMg).** The recorded walkthrough includes the offline UI, real Nebius/NVIDIA examples, linked reassessment, and four-core traces, with English narration and captions. Use the steps below to inspect or reproduce the corresponding product behavior.

## Demonstration map

For local inspection, retain the six-case run using section 2; its `$run` variable is used in the read-only examples below. The offline cases use controlled synthetic inputs and the real original cores. Recorded cloud-model examples are identified separately.

| Action or example | Expected result | Capability demonstrated | Evidence to inspect |
| --- | --- | --- | --- |
| Run C01v0 and B07v1 in the six-case demonstration | `FEASIBLE` | Candidate qualification when the supplied evidence satisfies the applicable constraints. | Matching rows in `report.json`; their input digests and registered assessment artifacts. |
| Inspect A01v0 | `INFEASIBLE` | Container and integrity constraints affect the calculated candidate result and produce specific reasons. | The A01v0 row, input change, and assessment `reason_codes`. |
| Inspect B01v0 | `DEFER` | An unknown external prerequisite is represented explicitly in the result. | The B01v0 row and its assessment. |
| Inspect B05v0 | `NEED_MORE_EVIDENCE` | Missing supporting evidence leads to an explicit request for more evidence. | The B05v0 row and its evidence/requirement fields. |
| Inspect B06v0 | `REJECTED / ENV_INPUT_REJECTED` | The input gate rejects inconsistent evidence and produces no assessment artifact. | `stop_stage=INPUT`, the rejection row, and its empty assessment-evidence list. |
| Follow the parent/child exercise in section 4 | Parent `DEFER`, child `FEASIBLE`; separate assessment IDs | New evidence supports a linked new assessment while the original record is preserved. | `chain/op/out/oq_chain/artifacts/`, `parent_decision_ref`, and properties 4 and 5. |
| Open a primary assessment's trace as shown in section 2 | 22 named entries: K0 6 / K1 4 / C1 6 / C2 6 | The selected assessment records the original four-core computation path with source and digest fields. | `mapping_trace.native_calls` inside that case's registered artifact. |
| Inspect a stored result and property 6 | `integrity_checked=True`, `native_recomputed=False` in the view-check detail | A stored assessment can be verified and presented through the read-only view. | Property 6 in `report.json`; the UI's registered-evidence view. |
| Watch the recorded Nebius R1/R5/R7 examples, or follow section 6 | R1 feasible, R5 infeasible, R7 not applicable without a kernel launch | A real cloud model proposes scenarios while the original cores compute the selected qualification results. | The video's model receipts, primary result cards, and labeled out-of-scope response. |

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

### Inspect the native-call trace

After the retained run above, keep the same PowerShell session and use its `$run` value. These commands read the stored C01v0 primary assessment; they do not launch a new evaluation.

```powershell
$report = Get-Content -LiteralPath (Join-Path $run 'report.json') -Raw | ConvertFrom-Json
$row = @($report.rows | Where-Object { $_.key -eq 'C01v0' })[0]
$artifact = @($row.evidence | Where-Object { $_.rel -match '/artifacts/' })[0]
$assessmentPath = Join-Path $run $artifact.rel
$assessment = Get-Content -LiteralPath $assessmentPath -Raw | ConvertFrom-Json
$calls = @($assessment.mapping_trace.native_calls)

$calls.Count
$calls | Group-Object { ($_.call -split '\.')[0] } | Select-Object Name, Count
$calls | Select-Object ordinal, call, status | Format-Table -AutoSize
$calls[0] | Format-List source, input_sha256, output_sha256
```

Expect 22 entries, grouped as K0 6, K1 4, C1 6 and C2 6. The artifact's top-level `mapping_trace.native_calls` contains the trace; `source_validation.recorded_native_calls` is its numeric summary. Inspect the call names, source paths and digests together. See [The four cores](ARCHITECTURE.md#the-four-cores) for interpretation of digest scope.

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

### Inspect the parent and child records

The retained run puts this exercise under `chain/op/out/oq_chain`. It uses `parent_req` and `child_req`, so these assessment IDs are distinct from the main B01v0/C01v0 row IDs. Compare the two chain records to each other.

```powershell
$chain = Join-Path $run 'chain/op/out/oq_chain'
$items = @(Get-ChildItem -LiteralPath (Join-Path $chain 'artifacts') -Filter '*.json' |
    ForEach-Object {
        [pscustomobject]@{
            Path = $_.FullName
            Record = (Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json)
        }
    })
$childItem = @($items | Where-Object { $null -ne $_.Record.parent_decision_ref })[0]
$child = $childItem.Record
$reference = $child.parent_decision_ref
$parentItem = @($items | Where-Object { $_.Record.assessment_id -eq $reference.assessment_id })[0]
$parent = $parentItem.Record

@(
    [pscustomobject]@{ Role = 'Parent'; Assessment = $parent.assessment_id; Decision = $parent.c2_projection.decision }
    [pscustomobject]@{ Role = 'Child'; Assessment = $child.assessment_id; Decision = $child.c2_projection.decision }
) | Format-Table -AutoSize

[pscustomobject]@{
    NewAssessment = ($child.assessment_id -ne $parent.assessment_id)
    ParentAssessmentMatches = ($reference.assessment_id -eq $parent.assessment_id)
    ParentDecisionMatches = ($reference.decision_id -eq $parent.decision_id)
    ParentSemanticMatches = ($reference.semantic_sha256 -eq $parent.semantic_sha256)
    ParentArtifactMatches = ($reference.artifact_sha256 -eq
        (Get-FileHash -LiteralPath $parentItem.Path -Algorithm SHA256).Hash.ToLowerInvariant())
} | Format-List

$report.properties | Where-Object { $_.id -in 4, 5, 6 } | Select-Object id, status, detail
```

Expect the parent to show `DEFER`, the child `FEASIBLE`, and all five reference checks to be `True`. Property 4 records the new-assessment/parent-link check. Property 5 records the driver's before/after byte comparison of the two previously sealed artifact/claim files. Property 6 records its read-only view check. These report properties complement the inspection of the records currently on disk.

## 5. Fixed-response adapter integration

```powershell
$a2 = Join-Path $env:TEMP ('h56-a2-' + [guid]::NewGuid().ToString('N'))
python -B -m model_ingress_v1.tests.a2_integration --all-six --root $a2
```

The provider supplies fixed model responses, while the adapter, input construction, CLI, original cores and assessment storage execute real code. The driver checks all six scenarios, exact exit codes, input digests and source stability before and after execution. It compares actual generated input digests with the frozen in-tree baseline constants. This is one packaged baseline, rather than a second independently supplied A0 report, and does not need a private evidence directory.

The candidate adapts `tests/identity.py` and `tests/a2_integration.py` for delivered inventory roots, packaged baseline lookup, and portable output. V3.4.1 also tightens credential filtering and local HTTP access in three entry scripts and their two existing test files. Among 132 distributed Python files, 124 match the development working tree, seven contain these documented adjustments, and the added standalone `verify_pack.py` checks the complete delivery. Computation-closure and registered scenario bytes are unchanged. See [Source Comparison](metadata/SOURCE_COMPARISON.json).

This check is labeled as fixed-response integration. It is distinct from the previously recorded real Nebius inference runs.

## 6. Model collaboration

In this demonstration, a model selects a registered scenario rather than supplying trusted environmental evidence or the final feasibility result. The adapter validates the response and maps it to controlled input construction. The original cores perform the assessment.

Real Nebius records include R1/S-C01 (`FEASIBLE`), R5/S-A01 (`INFEASIBLE`) and R7 (`NOT_APPLICABLE`, kernel not launched). The two execution batches are identified separately. For an individual frozen input, comparing the Nebius and DeepSeek assessment artifacts supplies a concrete cross-provider consistency check.

To make a new paid request, follow [Optional live model integration](RECOVERY_GUIDE.md#optional-live-model-integration). Installation and the offline demonstration do not silently call any model.

## 7. Video presentation

The published walkthrough is available at **[YouTube: H56 demonstration](https://youtu.be/Gxr5SzG3OMg)**. Use this same URL in the submission form's video field.

Use existing application footage to show an actual run. Evidence cards can make model responses, reason codes and parent references legible; label rendered evidence as a replay rather than live screen capture. Identify separate model providers, source versions and execution batches where they are combined.

The primary evaluation's 22 trace entries are separate from driver regression work. An out-of-scope request with `native_calls=null` should be described using its recorded terminal decision and unlaunched-kernel state, rather than presenting null as a measured count.
