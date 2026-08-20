# Operational phase runner

The operational phase runner executes one reviewed WC-013 baseline, faulted, or recovered phase.
It reads only the receipt and prior completion information available for that phase. It does not
inject, reset, deploy, or otherwise mutate an Azure resource.

See [ADR 0010](../adr/0010-progressive-operational-phase-completion-chain.md).

## Delivery bundle v2

The read-only delivery root contains the three reviewed WC-013 plans. Future receipt files are not
part of the bundle and do not need to exist for baseline.

```text
delivery/
  operational-phase-bundle.json
  configs/
    baseline.json
    faulted.json
    recovered.json
  ...WC-007, WC-008, and public-key files referenced by the plans...
```

The bundle uses `athena.operationalPhaseDeliveryBundle.v2`:

```json
{
  "schemaVersion": "athena.operationalPhaseDeliveryBundle.v2",
  "scenarioId": "athena-web-node-fault.v1",
  "runId": "synthetic-run-001",
  "allowedPhases": ["baseline", "faulted", "recovered"],
  "syntheticPresentationKeyId": "synthetic-key://athena-argus-demo/rs256-v1",
  "configurations": {
    "baseline": {
      "phase": "baseline",
      "wc013ConfigurationFile": "configs/baseline.json",
      "wc013ConfigurationDigest": "sha256:<digest>",
      "attemptId": "attempt-<12-lowercase-hex>",
      "snapshotId": "snap-<12-lowercase-hex>",
      "idempotencyKey": "<unique-value>"
    },
    "faulted": {
      "phase": "faulted",
      "wc013ConfigurationFile": "configs/faulted.json",
      "wc013ConfigurationDigest": "sha256:<digest>",
      "attemptId": "attempt-<different-12-lowercase-hex>",
      "snapshotId": "snap-<different-12-lowercase-hex>",
      "idempotencyKey": "<different-value>"
    },
    "recovered": {
      "phase": "recovered",
      "wc013ConfigurationFile": "configs/recovered.json",
      "wc013ConfigurationDigest": "sha256:<digest>",
      "attemptId": "attempt-<different-12-lowercase-hex>",
      "snapshotId": "snap-<different-12-lowercase-hex>",
      "idempotencyKey": "<different-value>"
    }
  },
  "bundleDigest": "sha256:<canonical-bundle-digest>"
}
```

Build it through `build_operational_phase_delivery_bundle`. Do not hand-edit the final digest.
Use a new `runId`, attempt ID, snapshot ID, and idempotency key after any post-reservation failure.

## Progressive input documents

Each invocation receives `athena.operationalPhaseInputs.v1`. A reference is trusted only as the
combination of its synthetic blob name, immutable version, and exact content hash.

Receipt names are frozen:

```text
runs/<runId>/inputs/baseline/fault-receipt.json
runs/<runId>/inputs/faulted/fault-receipt.json
runs/<runId>/inputs/recovered/fault-receipt.json
```

### Baseline

Baseline requires only the version-pinned `status` receipt:

```json
{
  "schemaVersion": "athena.operationalPhaseInputs.v1",
  "runId": "synthetic-run-001",
  "bundleDigest": "sha256:<bundle-digest>",
  "phase": "baseline",
  "receipt": {
    "name": "runs/synthetic-run-001/inputs/baseline/fault-receipt.json",
    "version": "<immutable-version>",
    "contentDigest": "sha256:<exact-byte-hash>"
  }
}
```

No inject receipt, reset receipt, prior index, or future phase configuration file is read.

### Faulted

Faulted requires the inject receipt and normally the baseline completion index:

```json
{
  "schemaVersion": "athena.operationalPhaseInputs.v1",
  "runId": "synthetic-run-001",
  "bundleDigest": "sha256:<bundle-digest>",
  "phase": "faulted",
  "receipt": {
    "name": "runs/synthetic-run-001/inputs/faulted/fault-receipt.json",
    "version": "<immutable-version>",
    "contentDigest": "sha256:<exact-byte-hash>"
  },
  "previousPhaseIndex": {
    "name": "runs/synthetic-run-001/baseline/phase-completion-index.json",
    "version": "<immutable-version>",
    "contentDigest": "sha256:<exact-byte-hash>"
  }
}
```

For an independently reviewed fault start, omit `previousPhaseIndex` and supply exactly one
`lineageReferenceDigest` matching the inject receipt's canonical lineage.

### Recovered

Recovered requires the reset receipt and the exact faulted completion index:

```json
{
  "schemaVersion": "athena.operationalPhaseInputs.v1",
  "runId": "synthetic-run-001",
  "bundleDigest": "sha256:<bundle-digest>",
  "phase": "recovered",
  "receipt": {
    "name": "runs/synthetic-run-001/inputs/recovered/fault-receipt.json",
    "version": "<immutable-version>",
    "contentDigest": "sha256:<exact-byte-hash>"
  },
  "previousPhaseIndex": {
    "name": "runs/synthetic-run-001/faulted/phase-completion-index.json",
    "version": "<immutable-version>",
    "contentDigest": "sha256:<exact-byte-hash>"
  }
}
```

Missing or mismatched prior faulted indexes fail before WC-013 execution.

## Production composition

The Job composition root injects:

- `VersionPinnedPhaseInputReaderPort` to read exact receipt and prior-index versions;
- `CreateOnlyArtifactWriterPort` to create the four payload artifacts and return each immutable
  version/hash;
- `CompletionIndexWriterPort` to create the completion index after the payload write;
- trusted full-result and snapshot verifiers; and
- the existing Key Vault-compatible `PresentationSigner`.

No connection string, account key, private key, receipt payload, or arbitrary storage path is
accepted on the CLI.

```powershell
athena-context operational-phase-runner `
  --bundle $configurationRoot\operational-phase-bundle.json `
  --inputs $configurationRoot\baseline-inputs.json `
  --phase baseline
```

The standalone command fails closed until all production ports are injected.

## Run-scoped outputs and completion marker

The create-only namespace is:

```text
runs/<runId>/<phase>/demo-evaluation-result.json
runs/<runId>/<phase>/evidence-snapshot.json
runs/<runId>/<phase>/argus-presentation.json
runs/<runId>/<phase>/presentation-attestation.json
runs/<runId>/<phase>/phase-completion-index.json
```

The first four objects are created together. Their exact names, immutable versions, and byte hashes
are then placed in `athena.operationalPhaseCompletionIndex.v1`. The index is written last and also
contains the phase, attempt/snapshot identifiers, prior index digest, lineage digest, receipt
version/hash, state transition labels, and authoritative result/snapshot/presentation digests.

The index contains no raw receipt/evidence/presentation payload, Azure ID, resource group, VM name,
signature, or token claim. Downstream automation treats only a valid version-pinned index as phase
completion.

## Fail-closed checks

The phase fails before payload creation when:

- bundle, phase input, configuration, receipt, or prior-index validation fails;
- a version or exact byte hash does not match;
- phase, run, or bundle bindings differ;
- recovered has no faulted index;
- previous phase, lineage, chronology, or power-state continuity differs;
- WC-013 result identifiers differ from the selected plan;
- trusted result/snapshot verification or signing fails; or
- any required composition port is missing.

Payload writer failures create no index. Completion-index writer failures leave no completion
marker; retry requires newly reviewed create-only identities.

## Expected logging

Success output is limited to run ID, phase, snapshot identifier, result digest, presentation
digest, and completion-index content digest. Port exceptions and payload content are never copied
to stdout or stderr.
