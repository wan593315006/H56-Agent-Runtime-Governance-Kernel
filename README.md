# H56 — General-Purpose OS Governance, Made Inspectable

H56 connects a general-purpose OS governance kernel to a runnable qualification workflow. A model can suggest a registered scenario; the original **K0 → K1 → C1 → C2** computation chain evaluates structured evidence, state and capability constraints, then produces a traceable candidate assessment.

The demonstration uses environment qualification and controlled task admission as representative applications of the underlying governance mechanisms.

## Start in one minute

Use Windows and Python 3.9.13. The offline application uses the Python standard library: no pip installation, Docker, database or API credential is required.

```powershell
git -c core.autocrlf=false -c core.longpaths=true clone <repository-url> C:\h56demo
Set-Location C:\h56demo
python -B demo.py
python -B ui/serve.py --no-browser
```

Open **http://127.0.0.1:8765**. The page launches actual evaluation processes and reads their generated records. It is not a recording.

The six-case CLI demonstration normally ends with `PASS_WITH_SKIPS`: six properties pass and the cross-interpreter property is skipped unless a second interpreter is supplied.

## What to inspect

| Input situation | Computed result |
| --- | --- |
| Inconsistent evidence fields | Input rejected |
| Container/integrity constraints violated | `INFEASIBLE` |
| Required supporting evidence absent | `NEED_MORE_EVIDENCE` |
| An external prerequisite is unknown | `DEFER` |
| Applicable constraints satisfied | `FEASIBLE` as a candidate result |

Each accepted assessment records its evidence identity, reason codes, source binding and native-call trace. A separate reassessment exercise creates a new assessment linked to an intact parent record. Candidate feasibility does not grant execution permission.

```text
Intent -> model scenario selection -> validated adapter mapping
       -> controlled evidence input -> K0 -> K1 -> C1 -> C2
       -> candidate decision + reason codes + sealed audit record
```

The scenario registry constrains this demonstration's model interface. The deterministic kernel is the reusable computation layer.

## NVIDIA and Nebius integration

Recorded runs on Nebius Token Factory used `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`:

- R1 selected S-C01; the primary assessment returned `FEASIBLE`.
- R5 selected S-A01; the primary assessment returned `INFEASIBLE`.
- R7 returned `NOT_APPLICABLE`; the adapter completed without launching the kernel.

R1 and R5/R7 were separate execution batches. The assessment inputs are synthetic fixtures; the model responses are real cloud inference responses. Each selected primary assessment recorded 22 native-call trace entries. Driver property exercises are counted separately.

No API call is needed for installation, the offline UI, or the fixed-response adapter integration check. Live inference is an explicit opt-in using the operator's own credential and a scoped run plan; see [Recovery Guide](RECOVERY_GUIDE.md#optional-live-model-integration).

## Significant updates during the hackathon

H56 builds on earlier Wuti general-purpose OS and multi-agent runtime research. During the submission period, the work added independent fact/history and state-derivation cores, capability contracts and feasibility projection, H56-specific engineering assembly, CLI/UI productization, evidence-driven reassessment and a controlled model adapter with real Nebius/NVIDIA integration.

The source histories first record K0/K1 on 25 September 2026 and C1/C2 on 4 October. H56 engineering assembly followed on 22–23 October, the delivery and UI commits on 26 October, and real model integration on 29 October. See the [architecture and development timeline](ARCHITECTURE.md#development-timeline).

## Documentation

| File | Purpose |
| --- | --- |
| [DEMO_GUIDE.md](DEMO_GUIDE.md) | Walk through the CLI, UI, model boundary and reassessment. |
| [RECOVERY_GUIDE.md](RECOVERY_GUIDE.md) | Clone, verify identities, install prerequisites, run and troubleshoot. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Understand the four cores, contracts, source provenance and evidence scope. |

The intended public documentation set is these four guides plus the owner's selected `LICENSE`. License selection remains a separate release decision; this local candidate is not a public-release approval.

## Verification and coverage

```powershell
python -B run_tests.py
python -B -m ui.test_release_guards
python -B -m model_ingress_v1.tests.test_ingress
python -B -m unittest model_ingress_v1.tests.test_stage_b -v
python -B -m unittest model_ingress_v1.tests.test_smoke -v
```

For a complete fixed-response model-to-core check, use the A2 command in the recovery guide. Its model provider is a fixture, while its CLI and core evaluations execute the real product code.

`demo.py --all` runs **56 regression rows representing 26 byte-distinct inputs**; 30 rows repeat existing inputs. They are not 56 independent capabilities. The default demonstration uses six distinct inputs.

## Source identity and candidate layout

`offline_qualification_v1/SOURCE_MANIFEST.json` binds the 139-member offline computation closure, including the original core source. `RELEASE_MANIFEST.json` describes this candidate's broader file set, including the adapter, UI and documentation. The Git commit identifies the assembled candidate.

Keep `.gitattributes` and its `* -text` rule. Preserve the registered source bytes and relative paths. The historical component/package registries retain earlier source-delivery metadata; the current user entry points are `demo.py` and `ui/serve.py`.

The public-facing candidate excludes private provenance locks, credentials, private run directories and inactive historical front doors. Those source archives remain in the private development records. The 139-member computation closure is retained unchanged.
