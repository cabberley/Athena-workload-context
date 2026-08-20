# Operational demo operator

The external operational demo operator runs the reviewed baseline, faulted, and recovered
demonstration end to end without giving Athena mutation authority.

See [ADR 0011](../adr/0011-external-operational-demo-operator.md).

## What it does

`athena-context operational-demo-operator` coordinates four narrow boundaries:

1. a workload-owned controller that exposes fixed `status`, `inject`, and `reset` actions;
2. a phase-job controller that starts one reviewed phase Job and polls only that exact execution;
3. a governed handoff that returns the exact completion-index Blob reference for that execution; and
4. an exact-version Blob reader that retrieves only the named version and hash.

Athena itself still performs no workload mutation. ARGUS remains presentation-only.

## Validate-only review gate

Validate the reviewed configuration locally before any live run:

```powershell
athena-context operational-demo-operator `
  --config .\operator\operational-demo-operator.json `
  --validate-only
```

Validate-only:

- parses the operator configuration, bundle, and reviewed phase plans;
- loads the presentation verification public key;
- prints a compact synthetic-safe plan; and
- prints the exact confirmation phrase required for a live run.

Validate-only must not acquire credentials, call Azure, start a subprocess, or use injected ports.

## Live execution

Use the exact confirmation phrase from validate-only:

```powershell
athena-context operational-demo-operator `
  --config .\operator\operational-demo-operator.json `
  --confirm 'ATHENA-OPERATIONAL-DEMO synthetic-run-001 sha256:<confirmation-digest>'
```

Live behavior is fixed:

1. `status` must prove the workload is healthy and running.
2. Run the baseline phase Job and verify its completion index and indexed artifacts.
3. Invoke `inject`.
4. Run the faulted phase Job and verify it the same way.
5. Always attempt `reset` once `inject` was attempted, even if inject or faulted failed
   ambiguously.
6. Run the recovered phase only after a confirmed successful reset.

Baseline failure before injection never resets. Recovery is never reported on failure.

## Reviewed operator configuration

The operator reads `athena.operationalDemoOperator.v1`:

```json
{
  "schemaVersion": "athena.operationalDemoOperator.v1",
  "scenarioId": "athena-web-node-fault.v1",
  "runId": "synthetic-run-001",
  "bundleFile": "delivery/operational-phase-bundle.json",
  "presentationPublicKeyFile": "keys/argus-presentation-public.pem",
  "workloadController": {
    "executable": "C:\\reviewed-tools\\workload-demo-controller.exe",
    "arguments": ["--governed"],
    "timeoutSeconds": 60,
    "maxOutputBytes": 32768
  },
  "phaseJobController": {
    "executable": "C:\\reviewed-tools\\phase-job-controller.exe",
    "arguments": ["--governed"],
    "timeoutSeconds": 60,
    "maxOutputBytes": 32768,
    "pollTimeoutSeconds": 900,
    "pollIntervalSeconds": 10
  },
  "artifactReader": {
    "blobEndpoint": "https://athenareplay.blob.core.windows.net",
    "containerName": "operational-artifacts",
    "managedIdentityClientId": "11111111-1111-1111-1111-111111111111"
  }
}
```

All files are relative to the configuration directory and must stay inside that boundary.
The `artifactReader.managedIdentityClientId` value is the operator identity client ID used for
token acquisition; the Bicep deployment parameter uses the corresponding object ID for container-
scoped Reader RBAC. That reader identity is distinct from the workload-controller receipt writer
capability, even when the same governed demo principal is intentionally reviewed into both arrays.

## Controller output contracts

### Workload controller

The workload controller is invoked with fixed verbs:

```text
<workload-controller> ... status --run-id <runId> --scenario-id athena-web-node-fault.v1
<workload-controller> ... inject --run-id <runId> --scenario-id athena-web-node-fault.v1
<workload-controller> ... reset  --run-id <runId> --scenario-id athena-web-node-fault.v1
```

Each verb returns `athena.operationalDemoWorkloadAction.v1` on stdout. Before reporting success
for a phase, the trusted workload-owned controller must create exactly one immutable
`athena.demoFaultRun.v1` Blob at `runs/<runId>/inputs/<phase>/fault-receipt.json`. That report
contains:

- the synthetic run and scenario;
- the bounded `athena.demoFaultRun.v1` receipt; and
- the exact version-pinned receipt Blob reference expected by the phase runner.

The controller's managed-identity object ID must be in `workloadReceiptWriterObjectIds`. Azure
RBAC cannot narrow that built-in Blob Contributor grant to the receipt prefix, so the controller
contract itself must enforce exact run-scoped names, JSON-only payloads, create-only
`If-None-Match: *`, and no overwrite/list/delete behavior. The operator verifies action, state,
chronology, target continuity, and lineage across receipts.

### Phase-job controller

The phase-job controller is invoked with fixed verbs:

```text
<phase-job-controller> ... start   --request-json <athena.operationalPhaseExecutionRequest.v1>
<phase-job-controller> ... status  --execution-id <exact-id> --run-id <runId> --phase <phase>
<phase-job-controller> ... handoff --execution-id <exact-id> --run-id <runId> --phase <phase>
```

`start` returns `athena.operationalPhaseExecution.v1`. It selects exactly one phase-specific Job.
Because Container Apps accepts start-time environment changes only through a complete execution
template, the trusted controller must retrieve and validate the reviewed template, preserve its
image, command, args, identities, and reviewed bundle path exactly, and change only the allowlisted
bounded exact-reference environment variables required by that phase. Only the controller identity
should receive Job-start permission.

`status` returns `athena.operationalPhaseExecutionStatus.v1` with one of:

- `running`
- `succeeded`
- `failed`
- `unknown`

`failed`, `unknown`, and timeout all fail closed.

`handoff` returns `athena.operationalPhaseReferenceHandoff.v1`, which contains the exact
completion-index Blob name, version ID, and SHA-256 expected by the operator.

## Phase Job requirement

The deployed phase Job uses `athena-context operational-phase-job`. It writes the fixed local
phase-input file, invokes the single-phase runner in process, writes the governed handoff file,
and may emit one base64 handoff line for the external controller:

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

The controller supplies only exact reference metadata for that phase through start-time
environment variables:

- `ATHENA_OPERATIONAL_RECEIPT_NAME`, `ATHENA_OPERATIONAL_RECEIPT_VERSION`, and
  `ATHENA_OPERATIONAL_RECEIPT_DIGEST`;
- faulted or recovered only:
  `ATHENA_OPERATIONAL_PREVIOUS_INDEX_NAME`,
  `ATHENA_OPERATIONAL_PREVIOUS_INDEX_VERSION`, and
  `ATHENA_OPERATIONAL_PREVIOUS_INDEX_DIGEST`; and
- faulted without a baseline index only: `ATHENA_OPERATIONAL_LINEAGE_REFERENCE_DIGEST`.

The handoff file contains the exact completion-index reference needed by the outer operator. When
`--emit-handoff-base64` is enabled, the Job also prints one
`ATHENA_OPERATIONAL_PHASE_HANDOFF_B64=` line that the phase-job controller may retrieve from the
exact execution logs. The operator still never lists blobs or resolves a latest version.

## Exact artifact verification

For every phase, the operator:

1. reads the exact completion index named by the handoff;
2. verifies run, phase, bundle digest, receipt binding, chronology, lineage, and digest chain;
3. reads every indexed result, snapshot, presentation, and attestation artifact by exact name,
   version, and SHA-256;
4. re-verifies the serialized WC-013 result and snapshot binding; and
5. re-projects and verifies the stored ARGUS payload and detached signature.

If any artifact or verification step is ambiguous, the operator fails closed.

## Expected output

Success output is compact and synthetic-safe:

- run ID;
- phase;
- synthetic snapshot ID;
- Athena/result/presentation/completion-index digests;
- verdict and service-state summary; and
- reset status.

The operator does not print Azure IDs, resource-group names, VM names, blob account details,
paths, tokens, command stdout/stderr, or raw boundary exceptions.

## Failure semantics

- baseline failure -> no inject, no reset;
- inject attempted -> reset always attempted in `finally`;
- faulted failure -> reset still attempted;
- reset failure -> recovery blocked;
- combined faulted/reset failure -> both failures surfaced; and
- recovered success is reported only after a confirmed successful reset plus recovered-phase
  verification.
