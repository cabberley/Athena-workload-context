# Operational phase runner

The operational phase runner executes one reviewed WC-013 baseline, faulted, or recovered phase.
It reads only the receipt and prior completion information available for that phase. It does not
inject, reset, deploy, or otherwise mutate an Azure resource.

See [ADR 0010](../adr/0010-progressive-operational-phase-completion-chain.md) and [ADR 0012](../adr/0012-phase-fixed-operational-phase-jobs.md).

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

Receipt names are frozen. The trusted workload controller must create these exact immutable
`athena.demoFaultRun.v1` Blobs before the matching phase Job starts; the phase Job only reads the
exact name, version, and hash and still does not mutate workload:

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

The deployed Container Apps phase Jobs use `athena-context operational-phase-job`. That narrow
wrapper:

- reads one reviewed bundle from `/opt/athena/wc013-live/delivery/operational-phase-bundle.json`;
- writes one fixed local `athena.operationalPhaseInputs.v1` file under `/tmp/athena-operational/`;
- composes the production `VersionPinnedPhaseInputReaderPort`,
  `CreateOnlyArtifactWriterPort`, `CompletionIndexWriterPort`, trusted WC-013 result/snapshot
  verifiers, and the Key Vault-backed `PresentationSigner`; and
- then invokes the existing single-phase runner in process.

The standalone `operational-phase-runner` command still fails closed until all ports are injected.
The production job wrapper accepts no connection string, account key, private key, raw receipt
payload, alternate storage path, or shell command text. The receipt Blob itself is created earlier
by the workload-owned controller through the separate container-scoped
`workloadReceiptWriterObjectIds` capability; the Athena Job only reads the exact receipt reference
that controller produced.

Each deployed phase Job fixes its reviewed phase, bundle path, local input path, local handoff
path, and artifact container:

```powershell
athena-context operational-phase-job `
  --phase baseline `
  --bundle /opt/athena/wc013-live/delivery/operational-phase-bundle.json `
  --inputs-output /tmp/athena-operational/baseline-inputs.json `
  --handoff-output /tmp/athena-operational/baseline-handoff.json `
  --artifact-blob-endpoint https://<account>.blob.core.windows.net `
  --artifact-container operational-artifacts `
  --emit-handoff-base64
```

Container Apps requires the controller to submit a complete execution template when adding these
run-time values. The separately governed controller must first retrieve and validate the reviewed
Job template, preserve its image, command, args, identities, and reviewed bundle path exactly, and
change only the allowlisted bounded exact-reference environment values. Job-start permission must
be scoped only to that trusted controller identity; the deployed defaults are not an independent
platform-enforced immutability boundary.

| Variable | Phase use |
|---|---|
| `ATHENA_OPERATIONAL_RECEIPT_NAME` | Frozen receipt Blob name for the selected phase. |
| `ATHENA_OPERATIONAL_RECEIPT_VERSION` | Exact immutable receipt Blob version. |
| `ATHENA_OPERATIONAL_RECEIPT_DIGEST` | Exact receipt SHA-256 digest. |
| `ATHENA_OPERATIONAL_PREVIOUS_INDEX_NAME` | Exact previous completion-index Blob name for faulted or recovered. |
| `ATHENA_OPERATIONAL_PREVIOUS_INDEX_VERSION` | Exact previous completion-index Blob version. |
| `ATHENA_OPERATIONAL_PREVIOUS_INDEX_DIGEST` | Exact previous completion-index SHA-256 digest. |
| `ATHENA_OPERATIONAL_LINEAGE_REFERENCE_DIGEST` | Faulted-only independently reviewed lineage digest when no baseline index is supplied. |

Baseline supplies only the receipt triple. Faulted supplies either the previous-index triple or the
lineage digest, but never both. Recovered supplies the previous-index triple and no lineage digest.

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

When `--handoff-output` is supplied, the runner also writes
`athena.operationalPhaseReferenceHandoff.v1`. That bounded file contains only:

- scenario, run, and phase;
- the reviewed bundle digest; and
- the exact completion-index Blob name, version, and SHA-256.

The handoff is create-only on the local file system and is intended for the external operational
demo operator or another governed orchestrator. It contains no receipt payload, Azure ID, path to
the bundle, token, or raw command output.

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
digest, and completion-index content digest. The production job wrapper may also emit one
`ATHENA_OPERATIONAL_PHASE_HANDOFF_B64=` line that contains only the governed handoff JSON required
by the external phase-job controller. Port exceptions and payload content are never copied to
stdout or stderr.

## Offline validation

No deployment is required:

```powershell
python -m pytest tests/test_operational_phase_runner.py tests/test_operational_phase_job.py tests/test_wc013_deployment_assets.py -q
ruff check src tests
mypy src
az bicep build --file infra/azure-mcp/main.bicep
az bicep build --file infra/wc013-live-acceptance/main.bicep
az bicep lint --file infra/azure-mcp/main.bicep
az bicep lint --file infra/wc013-live-acceptance/main.bicep
```
