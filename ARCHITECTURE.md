# H56 Architecture and Development

## General-purpose OS governance

H56 presents reusable OS governance mechanisms through an environment-qualification and controlled-admission workflow. The core abstractions describe facts, history, derived state, capability contracts and candidate feasibility. Domain-specific rules enter through versioned assets and adapters.

The three qualification asset sets are `environment_policy.json`, `state_mapping.json` and `capability_catalog.json` under `offline_qualification_v1/assets/`. They define the representative environment domain. The original core implementations live under `runtime_binding_v1_20261024/engineering/vendor/clean_core_projects/`.

## Computation and consumption

```text
Evidence bytes + request
    -> input and source checks
    -> K0: canonical facts and append-only history
    -> K1: deterministic state snapshot
    -> C1: capability definitions and integrity
    -> C2: candidate feasibility projection
    -> reason codes, sealed assessment and event journal
    -> CLI / UI / read-only evidence consumer
```

The computation can produce FEASIBLE, INFEASIBLE, DEFER or NEED_MORE_EVIDENCE. Invalid evidence is rejected at its applicable gate. FEASIBLE remains a candidate outcome, with execution authority separate from qualification.

### The four cores

| Component | Role |
| --- | --- |
| K0 | Canonical fact identity and append-only history. |
| K1 | Deterministic state derivation from history and a fixed version context. |
| C1 | Immutable capability definitions, catalogs and declared constraints. |
| C2 | Context-bound capability feasibility and exclusion reasons. |

The selected primary assessment records 22 named native calls: K0 6, K1 4, C1 6 and C2 6. Trace entries contain call labels, ordinal, status, source and input/output digests. Bound-method verification entries have a narrower digest scope than full instance-state witnesses; the surrounding assessment supplies context.

The bounded rule interpreter supports nine operators and enforces limits of 32 nodes and depth 4. The current example expression has nine nodes; the interpreter limits and expression size are separate measures.

## Model adapter

```text
User intent -> provider response -> strict response validation
            -> registered scenario mapping -> controlled input construction
            -> original CLI and four-core assessment
```

The model-visible registry contains a scenario ID and intent description. Expected outcomes and CLI exits remain test/consumer data and are not placed in the model prompt. The selected scenario maps to a real input-construction path; it does not directly return a stored assessment.

The five response keys are `decision`, `scenario_id`, `clarification_question`, `reason` and `confidence`. SELECT maps to a registered scenario. NOT_APPLICABLE and NEED_CLARIFICATION are valid terminal responses that do not launch the kernel. Invalid keys, duplicate JSON keys, invalid field relationships and authority claims are rejected.

The provider pins the approved origin, does not follow redirects and retains request/response bytes separately from credentials. The stage-B driver checks model identity, catalog provenance, explicit request scope, budget and operator authorization. It reserves the declared maximum cost before sending and checks actual usage afterward. Price evidence distinguishes machine-readable catalog prices from declared prices; a cost computed from usage and rates is not a billing receipt.

For file-bound runs, the driver hashes plan bytes, reparses those same bytes, compares their normalized content with the supplied plan and executes the reparsed object. `BOUND_TO_FILE_BYTES_SAME_SOURCE` identifies this path. Earlier evidence retains the binding label of the code that produced it.

## Assessments and reassessment

An assessment joins input identity, source/asset binding, derived state, capability context, candidate decision, reasons and native-call trace. Its semantic digest covers `mapping_trace`. Assessment artifacts and claims are created as separate stored records; the event journal is append-only.

Reassessment adds a new assessment with a parent reference. The reference binds the parent's assessment ID, decision ID, semantic digest, journal event and artifact digest. The old record is preserved. The driver's property exercise demonstrates this mechanism independently of model-routing examples.

## Candidate source layout

| Path | Purpose |
| --- | --- |
| `offline_qualification_v1/` | Qualification contracts, assets, core bridge, records, CLI and focused tests. |
| `runtime_binding_v1_20261024/engineering/vendor/` | Original source-bound cores, profile and associated provenance. |
| `runtime_windows/` | Source identity and retained support contracts/helpers. |
| `model_ingress_v1/` | Provider, adapter, registry, run-plan driver and fixed-response checks. |
| `ui/`, `demo.py`, `run_tests.py` | Operator interfaces and existing verification entry points. |

The 139-member computation manifest remains byte-identical to the development source. `RELEASE_MANIFEST.json` covers the broader assembled candidate. Historical component manifests remain provenance records; their old aggregate membership is not a replacement for the current candidate inventory.

Fourteen retained engineering files are AST comparison sources and data fixtures. Inactive historical Windows front doors, private archives, credentials and private provenance locks are outside this candidate. The normal offline and model-to-core demonstration consumes the public source lock and does not restore the private lock.

Among the 131 Python files distributed in this candidate, **129 match the corresponding development working-tree files byte for byte**. Two test helpers contain candidate-specific portability adjustments:

| File | Candidate adjustment |
| --- | --- |
| `model_ingress_v1/tests/identity.py` | Inventory the delivered roots, including UI and four English guides, and omit two absent historical directories. |
| `model_ingress_v1/tests/a2_integration.py` | Use the frozen in-tree input-digest baseline and temporary output instead of a private A0 report and workstation output root. |

The frozen input digests and expected outcomes are retained. Core calculations, the registry and model request construction are unchanged. All 139 computation-closure members match the development source. Relative to the accepted V2 candidate (`a2facd8c5316e19a41fddc2a74c46d7f1d646d94`), all 131 candidate Python files are byte-identical; that is a different comparison baseline from the development working tree. [Source Comparison](metadata/SOURCE_COMPARISON.json) records the two changed file identities and both scopes.

## Development timeline

H56 builds on earlier Wuti general-purpose OS and multi-agent runtime engineering. During the submission period, it added core implementations, independent product engineering and real cloud-model collaboration.

| Date | Recorded milestone | Source-history reference |
| --- | --- | --- |
| Before the submission period | Existing tools, method access, health checks, state memory and change history. | Earlier platform research, recorded in August 2026. |
| 25 September 2026 | K0/K1 independent core projects entered their original source history. | Earlier core source-history milestone. |
| 4 October 2026 | C1 capability contracts, C2 feasibility projection and feasible capability set. | Earlier core source-history milestones. |
| 22–23 October 2026 | H56 isolated source assembly and admission integration. | Earlier engineering source-history milestones. |
| 26 October 2026 | Delivery baseline, one-command demo, test entry point, structured output and UI. | `257a1da`, `2757419`, `9a480ad`. |
| 27–29 October 2026 | Controlled model adapter and provider integration. | Development snapshots and integration records. |
| 29 October 2026 | Nebius/NVIDIA R1 followed by a separate R5/R7 run. | Recorded model responses and core assessments. |

Earlier research/core dates describe milestones in their respective source histories, rather than Git objects shipped in this candidate. The October 26 delivery history is supplied as a header extract in `metadata/SOURCE_DELIVERY_HISTORY.json`; its private historical trees are kept outside the distribution. The candidate Git history identifies the assembled release and its metadata successor. These recorded dates are development milestones, not claims about the earliest invention date.

## Runtime evidence scope

The six offline inputs are distinct synthetic fixtures. The extended run contains 56 regression rows and 26 distinct inputs. Fixed-response model tests exercise the actual adapter/CLI/core path; recorded cloud integration uses real inference. These levels are labeled separately.

Recorded Nebius runs used `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`: R1 selected S-C01 and returned FEASIBLE; R5 selected S-A01 and returned INFEASIBLE; R7 returned NOT_APPLICABLE without launching the kernel. For the same R5 input, the primary assessment artifact is byte-identical across the Nebius and earlier DeepSeek runs.

The A2 identity helper inventories its selected delivered roots, including the UI and English guides. Its digest is distinct from the full release manifest and is comparable with an older helper digest only when the member set is identical.

The local UI exposes results through loopback HTTP with an exact-origin check, per-service token and restricted run body. Evidence reads require registered paths, containment and matching bytes/digests. API keys are excluded from kernel-child environments by the adapter; no key is part of the source candidate.
