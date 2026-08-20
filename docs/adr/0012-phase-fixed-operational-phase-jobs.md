# ADR 0012: Deploy phase-specific operational Jobs with bounded bootstrap inputs

- **Status:** Proposed
- **Date:** 2026-08-20

## Context

ADR 0010 defines the progressive single-phase runner and ADR 0011 defines the external fail-closed
operator, but the reviewed Azure deployment still lacked a production execution composition. The
operator needs three phase-specific runtime entrypoints for baseline, faulted, and recovered that can
run inside the existing private Container Apps environment without granting Athena mutation
authority, storage keys, shared keys, or broad Azure RBAC.

The phase inputs are partly dynamic because exact receipt and completion-index Blob versions are
not known until execution time. The deployed Job templates therefore pin reviewed defaults for the
command, selected phase, bundle path, and artifact destination. Azure Container Apps start-time
overrides replace the full execution template, so those defaults are not a platform-enforced
immutability boundary by themselves. Before a phase Job starts, the workload-owned controller
invoked by the external operator must also create the exact immutable `athena.demoFaultRun.v1`
receipt blob at `runs/<runId>/inputs/<phase>/fault-receipt.json`. Azure RBAC cannot narrow a
built-in Blob data role to that Blob prefix, so strict create-only semantics must remain enforced
in the trusted controller contract and writer port rather than in ARM scope alone.

## Decision

Add three manual Container Apps Jobs to `infra/wc013-live-acceptance/main.bicep`:

- baseline
- faulted
- recovered

Each Job uses the existing reviewed delivery image, the same internal Container Apps environment,
and the same separate acceptance/evidence managed identities already approved for WC-013.

Each Job runs one fixed direct command with no shell wrapper:

```text
athena-context operational-phase-job
```

The fixed arguments pin:

- the selected phase;
- the reviewed bundle path `/opt/athena/wc013-live/delivery/operational-phase-bundle.json`;
- one fixed local phase-input file path under `/tmp/athena-operational/`;
- one fixed local handoff file path under `/tmp/athena-operational/`; and
- the exact artifact Blob endpoint and container name.

Add a narrow production bootstrap command named `operational-phase-job`. It accepts no receipt
payload, no arbitrary file path, no storage key, no connection string, and no private key. Instead
it reads only bounded environment variables that describe exact immutable references for the
selected phase:

- `ATHENA_OPERATIONAL_RECEIPT_NAME`, `_VERSION`, `_DIGEST`;
- `ATHENA_OPERATIONAL_PREVIOUS_INDEX_NAME`, `_VERSION`, `_DIGEST` when that phase requires a prior
  index; and
- `ATHENA_OPERATIONAL_LINEAGE_REFERENCE_DIGEST` only for a faulted start without a baseline index.

The bootstrap writes one local `athena.operationalPhaseInputs.v1` file, composes the production
Azure Blob exact-version reader and create-only writer, composes the Key Vault-backed signer and
trusted WC-013 verifiers, then invokes the existing single-phase runner in process.

The Job also writes the governed handoff file and may emit one
`ATHENA_OPERATIONAL_PHASE_HANDOFF_B64=` log line containing only the bounded handoff JSON so the
external phase-job controller can retrieve the exact completion-index reference from the specific
execution it started.

Keep the existing bounded `operatorArtifactReaderObjectIds` array. Grant each object ID
`Storage Blob Data Reader` only at the artifact-container scope so the external operator can
verify exact artifact versions. Add a separate bounded `workloadReceiptWriterObjectIds` array.
Grant each object ID `Storage Blob Data Contributor` only at that same artifact-container scope so
the trusted workload-owned controller can create the exact phase receipt Blob before the Job reads
it. Azure RBAC cannot scope a built-in Blob role to `runs/<runId>/inputs/<phase>/`, so the
controller must enforce the exact `athena.demoFaultRun.v1` JSON name, create-only
`If-None-Match: *`, and no-overwrite semantics in application code. The external operator
configuration still uses the corresponding managed-identity client ID for token acquisition.

## Consequences

- The reviewed Azure composition now exposes exactly three phase-specific Job names and reviewed
  default templates.
- Permission to start these Jobs must be granted only to the separately governed trusted
  phase-job controller identity.
- Container Apps requires a whole execution-template override to add run-time references. Before
  each start, the trusted controller must retrieve and validate the reviewed Job template, preserve
  its image, command, args, identities, and bundle path exactly, and change only the allowlisted
  bounded exact-reference environment variables.
- Bicep defaults reduce accidental retargeting and provide an auditable expected template; narrow
  start RBAC and controller-side template validation enforce the execution boundary.
- Athena phase Jobs still perform no workload mutation; they read exact receipt references only.
  Inject and reset remain outside Athena.
- The same governed principal may appear in both arrays for the demo, but exact-version read
  verification and receipt creation remain distinct reviewed capabilities.
- The same reviewed delivery image must now carry the operational phase bundle beneath the copied
  `wc013-live/` tree.
- Exact-version Blob reads and create-only Blob writes remain scoped to the one artifact container.
- If artifact creation succeeds but the local handoff file cannot be created or emitted, the Job
  fails closed and the outer operator must not infer success from a latest or listed Blob.

## Alternatives considered

### One generic Job with an operator-selected phase argument

Rejected because separate phase-specific defaults make review, controller validation, audit, and
least-privilege assignment clearer. Container Apps execution overrides can still replace a full
template, so separation alone is not treated as a security boundary.

### Reuse `operational-phase-runner` directly with no production bootstrap

Rejected because the standalone CLI cannot compose the Blob reader/writer, Key Vault signer,
trusted verifiers, and WC-013 runtime from bounded production inputs on its own.

### Pass receipt payloads or mutable configuration files into the Job

Rejected because that would widen the boundary from exact immutable references to arbitrary content
or paths.

## Validation

Deterministic validation covers:

- phase-input environment parsing and fail-closed behavior;
- production bootstrap wiring of Blob adapters, signer, runtime environment, and handoff output;
- exactly three phase-specific Bicep Jobs with direct reviewed defaults and no mutation verbs;
- operator Reader RBAC and workload receipt-writer RBAC at artifact-container scope from the bounded object-ID arrays; and
- targeted pytest, ruff, mypy, Bicep build, and Bicep lint without deployment.
