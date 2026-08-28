# ADR 0010: Chain progressive operational phases through version-pinned completion indexes

- **Status:** Proposed
- **Date:** 2026-08-20

## Context

ADR 0008 required baseline, inject, and reset receipts to exist before any phase could run. That is
not operationally possible: the inject receipt exists only after baseline completes and the reset
receipt exists only after the faulted evaluation completes. Requiring future receipts also turns
one reviewed phase selection into validation of unavailable future state.

Each phase must remain independently fail closed while preserving the same target, fault lineage,
power-state transition, and chronology when prior evidence is available. Outputs from repeated demo
runs must not collide. A phase completion marker must be written only after every payload artifact
has a concrete immutable blob version.

## Decision

Replace the delivery contract with `athena.operationalPhaseDeliveryBundle.v2`.

The bundle adds a synthetic `runId` and continues to contain exactly three digest-pinned WC-013
plans with unique attempt IDs, snapshot IDs, and idempotency keys. It contains no receipt paths or
receipt digests. Bundle validation therefore does not read or require any future receipt.

Each Job invocation supplies a separate `athena.operationalPhaseInputs.v1` document. It binds the
selected run, bundle digest, and phase to one exact version-pinned receipt reference:

- baseline: one `status` receipt and no prior phase;
- faulted: one `inject` receipt plus either the baseline completion index or an exact reviewed
  lineage digest;
- recovered: one `reset` receipt plus the faulted completion index.

Receipt and prior-index references contain a frozen synthetic blob name, immutable version, and
SHA-256 hash. An injected `VersionPinnedPhaseInputReaderPort` retrieves only that exact version and
the runner verifies the returned bytes before parsing.

The fault lineage digest covers the scenario, fault run, resource group, prefix, target VM,
complete target resource ID, and eligible web-node set after case normalization. These raw values
are used only in-process. Completion indexes store only the digest.

When a previous index is supplied, the runner requires:

- the same run and bundle digest;
- the immediately preceding phase;
- the same lineage digest;
- previous receipt completion no later than current receipt start; and
- previous confirmed after-state equal to current before-state.

The runner writes the result, snapshot, ARGUS presentation, and presentation attestation first
through `CreateOnlyArtifactWriterPort`. The port returns the exact immutable version and hash for
each artifact. Only then does the runner build
`athena.operationalPhaseCompletionIndex.v1` and call the separately injected
`CompletionIndexWriterPort`.

Every output uses this namespace:

```text
runs/<synthetic-run-id>/<phase>/demo-evaluation-result.json
runs/<synthetic-run-id>/<phase>/evidence-snapshot.json
runs/<synthetic-run-id>/<phase>/argus-presentation.json
runs/<synthetic-run-id>/<phase>/presentation-attestation.json
runs/<synthetic-run-id>/<phase>/phase-completion-index.json
```

The completion index contains only:

- run, phase, bundle/configuration digests;
- version-pinned receipt and optional prior-index references;
- previous phase index digest;
- lineage digest;
- attempt and snapshot identifiers plus the idempotency-key digest;
- receipt action, timestamps, and normalized power-state labels;
- authoritative result, snapshot, and presentation digests; and
- the names, immutable versions, and exact content hashes of the four payload artifacts.

It contains no receipt payload, evidence payload, Azure resource ID, resource group, VM name,
signature, or token claim.

## Consequences

- Baseline can run before an inject or reset receipt exists.
- A faulted phase can continue a baseline index or start from an independently reviewed lineage
  reference.
- Recovery cannot complete without the exact version-pinned faulted index.
- Repeated runs use distinct synthetic run IDs and disjoint create-only namespaces.
- The completion index is an explicit last-write completion marker. A failure before that write
  leaves no completed phase marker and requires a new reviewed run/phase identity.
- Production composition must inject the receipt/index reader, payload writer, completion-index
  writer, result/snapshot verifiers, and Key Vault-compatible presentation signer.
- No Azure storage adapter, Bicep resource, RBAC assignment, or fault/reset orchestrator is added
  by this change.

## Alternatives considered

### Keep all receipts in the bundle

Rejected because baseline would depend on future operator actions and future immutable versions.

### Re-read the inject receipt during recovery without a faulted index

Rejected because it would not prove which inject receipt produced the accepted faulted phase or
which payload versions were completed.

### Write the index in the same batch as payload artifacts

Rejected because the index cannot truthfully record immutable blob versions until the payload
writer returns them.

### Put raw lineage fields in the completion index

Rejected because downstream orchestration needs continuity proof, not Azure identifiers.

## Compatibility and rollback

The bundle schema advances from v1 to v2 and the v1 phase receipt is replaced by the v1 completion
index. Existing WC-013 and ARGUS contracts remain unchanged. Rollback restores the ADR 0008
all-receipts-up-front behavior but cannot reuse any attempt, snapshot, idempotency, run, or
create-only artifact identity already reserved.

## Validation

Deterministic tests cover baseline without future receipt/config files, baseline-to-inject and
inject-to-reset chaining, lineage-reference fault starts, target and chronology rejection,
distinct run namespaces, create-only names, immutable versions and hashes, index-last ordering,
missing prior-index rejection, missing composition ports, and payload-free logs.
