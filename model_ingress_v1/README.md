# Controlled Model Ingress

This package connects a provider response to H56's original qualification CLI. It preserves a deliberate division of responsibility: the model selects a registered demonstration scenario; the adapter validates and maps that selection; the deterministic cores compute candidate eligibility from the constructed input.

## Components

| File | Role |
| --- | --- |
| `registry.json`, `registry.py` | Six registered scenarios, mappings and a restricted model-visible view. |
| `prompt.py` | The shared system prompt and user-intent message. |
| `validate.py` | Five-key response schema, types, enums, duplicate-key and authority-claim checks. |
| `provider.py` | Approved-origin HTTP provider, parameter styles, raw response and request evidence. |
| `run.py` | Adapter decision, controlled CLI invocation, credential-environment cleanup and evidence linkage. |
| `catalog.py` | One-shot catalog retrieval and verification of stored catalog bytes and source metadata. |
| `stage_b.py` | Plan preflight, ordered request scope, same-source binding, budgets and stop conditions. |
| `stage_b_plan.json` | Inactive starting plan for a separately authorized Nebius run. |
| `smoke.py` | Provider/response debugging; not the product assessment evidence chain. |
| `tests/` | Fixed-response checks and the real CLI/core integration exercise. |

## Contract

The model response has exactly `decision`, `scenario_id`, `clarification_question`, `reason` and `confidence`. SELECT requires a known scenario. NOT_APPLICABLE and NEED_CLARIFICATION end normally without starting the CLI. Invalid output is rejected before core execution.

Only scenario ID and intent description are exposed from the registry to the prompt. Expected outcomes and exit codes remain consumer/test information. Registry mappings select input-construction paths, not stored final assessments.

## Evidence and execution

Stored evidence includes the actual request body, raw response bytes, response/model identity, adapter verdict and, when executed, CLI output and a primary assessment reference. Authentication headers and key values are not evidence fields. The adapter removes the selected credential variable from the kernel-child environment.

For live stage-B runs, exact origin, model/catalog identity, explicit authorization, scope and budget are checked before sending. Declared token/cost maxima are reserved before each call and actual usage is reconciled afterward. Unknown usage halts the remaining scope. `attempts=1` is the configured policy; there is no automatic retry.

The primary assessment's native-call trace is distinct from extra driver property exercises. Adapter process counts distinguish direct observations, structural declarations and their arithmetic sum. A returned null native-call field is not converted into a measured zero.

File-bound plans are read as bytes, hashed, parsed from those same bytes, checked against the supplied object and then used for execution. This is content binding, not a cryptographic signature from an external authorizer.

## Offline reproduction

Run from the repository root:

```powershell
python -B -m model_ingress_v1.tests.test_ingress
python -B -m unittest model_ingress_v1.tests.test_stage_b -v
python -B -m unittest model_ingress_v1.tests.test_smoke -v
$a2 = Join-Path $env:TEMP ('h56-a2-' + [guid]::NewGuid().ToString('N'))
python -B -m model_ingress_v1.tests.a2_integration --all-six --root $a2
```

These use fixed model responses; A2 invokes the actual CLI, core calculations and record storage. Its existing frozen baseline is in-tree and identity collection targets this candidate's delivered directories, UI and guides.

See [Recovery Guide](../RECOVERY_GUIDE.md#optional-live-model-integration) for preparing an explicit live run with the operator's own key. The source candidate carries no credential or previously granted live execution plan.
