# ADR 0014: Isolate WC-013 evidence collection from Athena jobs

- **Status:** Proposed
- **Date:** 2026-08-28

## Context

The original WC-013 jobs attached both the Athena context identity and the Azure MCP
workload-reader identity. Container Apps managed identity is a job-level capability: any process
in the job can ask IMDS for a token for any attached user-assigned identity. Selecting the context
identity through `AZURE_CLIENT_ID` therefore did not prevent Athena code from requesting a token
for the Reader identity and bypassing the private MCP boundary.

The existing trusted-ingestion signer also acquired the evidence-identity token in the Athena
process. Removing only the environment variable would not remove that capability.

## Decision

Split every WC-013 run into two separately authorized Container Apps Jobs:

1. An **isolated evidence collector** has only the MCP/evidence identity. It invokes the exact
   private Azure MCP endpoint through the existing sealed transport and reviewed tool allowlist,
   reserves the attempt in the replay table, acquires and verifies its own trusted-ingestion token,
   signs the exact collector attempt with the pinned Key Vault key, and writes one immutable
   `athena.wc013CollectedEvidence.v2` artifact.
2. The **Athena acceptance or phase job** has only the context identity. It reads the collector
   artifact by exact Blob name, immutable version, and SHA-256 from an
   `athena.wc013CollectedEvidenceHandoff.v2`, revalidates the signed identity, request, response
   envelope, scope, freshness, plan binding, WC-008 assertion digest, sealed transport digest, and
   collector artifact signature, and then performs the existing evaluation and snapshot signing.

Collector Jobs can be read and started only by a distinct managed-identity controller through a
custom role containing `Microsoft.App/jobs/read`, `Microsoft.App/jobs/start/action`, and
`Microsoft.App/jobs/executions/read`. The controller retrieves the deployed Job, validates its
single evidence identity and exact reviewed configuration/template, and invokes the ARM start
action with that exact validated template as the complete execution body. This removes the
validation/start race: a concurrent change to the stored Job template cannot alter the execution
body already pinned by the controller. The controller exposes no caller-supplied template or mutable
field. Human operators and the Athena/evidence runtime identities receive no collector Job start
assignment. The deployment owns this controller user-assigned identity and its one GitHub OIDC
federated credential. The trust is limited to issuer
`https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`, and subject
`repo:cabberley/Athena-workload-context:environment:athena-live`. A manually dispatched workflow
runs only from protected `main` in the protected `athena-live` environment, accepts only the three
phase names, loads the selected exact contract from deployment outputs, and executes the repository
controller after `azure/login`; it has no client secret or image/template override.

Collector artifacts use a dedicated immutable Blob container. The evidence identity has
create/read capability only on that collector container and replay table. The context identity has
read capability on the collector container and retains create capability only on the separate
operational output container. The evidence identity is not attached to any Athena evaluation job;
the context identity is not attached to any collector job.

The collector and evaluator continue using the existing versioned Key Vault key and
domain-separated signature preimages. This preserves the published evidence and snapshot
contracts while moving evidence-token acquisition to the only component allowed to hold the
workload-reader identity.

## Security and operational consequences

- Athena processes cannot select the workload-reader identity through IMDS.
- Evidence still originates through the private authenticated Azure MCP endpoint and exact
  allowlist; the collector has no direct workload SDK path.
- A handoff is accepted only when its plan digest and attempt ID match the reviewed plan and the
  referenced immutable Blob version matches the exact SHA-256. Its transport binding must match
  the currently prepared WC-008 configuration and the signature-bound artifact.
- Tampered envelopes, records, identity evidence, signatures, scopes, stale observations, or
  mismatched plans fail closed before publication.
- The trusted controller must run the matching collector Job first and pass its base64 handoff
  unchanged to the corresponding Athena job.
- The dedicated collected-evidence Blob transfer cap is 8 MiB. It covers the 1 MiB raw response,
  its validated projected records, per-record provenance overhead, and fixed request, identity,
  transport, and attestation fields without broadening the 1 MiB default artifact contract.
- Existing deployments must grant the Azure MCP and trusted-ingestion application roles to the
  evidence identity. The context identity no longer needs the Azure MCP application role.

## Alternatives considered

### Keep both identities and rely on `AZURE_CLIENT_ID`

Rejected. `AZURE_CLIENT_ID` selects a default credential but does not prevent explicit selection
of another attached identity through IMDS.

### Remove collector identity evidence

Rejected. That would weaken provenance and would no longer prove the exact MCP identity bound to
the response.

### Add an online attestation proxy

Deferred. A separately authenticated long-running proxy could preserve a single synchronous call,
but it adds another ingress, service lifecycle, and Entra resource application. The version-pinned
job handoff is smaller and reuses the existing private Blob and controller boundaries.

## Compatibility and migration

The WC-007, WC-008, evidence snapshot, and evaluation result contracts are unchanged. Deployment
automation must sequence collector then evaluator and pass
`ATHENA_WC013_COLLECTED_EVIDENCE_HANDOFF_B64`. Existing combined jobs must be redeployed so the
evidence identity is detached before further execution. Collector start automation must use the
`athena-context wc013-collector-controller` path and a reviewed
`athena.wc013CollectorStartContract.v1`; direct human Job-start access is not supported.

## Validation

- Static Bicep tests prove collector and evaluator jobs have disjoint identity sets and storage
  roles, and that collector start permission is assigned only to the controller role.
- Deterministic tests cover exact deployed-template validation, exact-template-pinned start requests,
  plan/transport-bound handoff loading, cross-endpoint relabel rejection, exact immutable Blob
  reads, artifact-capacity boundaries, tampered envelope rejection, and evidence-only collector
  credential selection.
- WC-013, operational phase, full pytest, Ruff, mypy, and Bicep build/lint validation must pass.
