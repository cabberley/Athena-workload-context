# ADR 0003: Compose the initial WC-013 live gate as a one-shot job

- **Status:** Proposed
- **Date:** 2026-08-19

## Context

The live gate must execute beside the private Azure MCP deployment. The default Context API has no
production evaluation composition or durable authoritative state, so an HTTP harness cannot run.
Creating a long-running API and persistence layer solely for the first acceptance run adds a larger
security and deployment surface.

The gate must retain WC-007 authority, WC-008 endpoint/identity/scope, WC-009 validation, separate
context/evidence identities, durable replay protection, and non-exportable RSA signing.

## Decision

Use a one-shot Container Apps Job that directly composes the existing `ContextService`,
`DemoEvaluationService`, private MCP transport, and WC-009 client.

The job imports only an exact `PublishedManifestView`, active `DemoEvaluationApproval`,
publisher/context-reader identities, and exact workload grants. That bundle has a canonical digest
and a separate human trust decision. It cannot create, approve, publish, supersede, or alter
authority. The existing ContextService transaction performs the evaluation authority checks and
commit.

Use `DefaultAzureCredential` with explicit managed-identity client IDs, one exact versioned Key
Vault RSA key for ingestion and snapshot signatures, independent Entra token verification, and an
Azure Table batch that atomically reserves attempt and request identities.

The private MCP transport first calls the reviewed `group_resource_list` inventory tool. For every
projected `Microsoft.Compute/virtualMachines` record, it then calls the separately reviewed
read-only `compute_vm_get` tool exactly once in deterministic resource-ID order, reusing the same
initialized MCP session. Arguments are derived only from the authorized resource-group scope and
the exact inventory resource ID: `subscription`, `resource-group`, `vm-name`, and
`instance-view: true`.

The enrichment shares the collection item, response-byte, and absolute timeout bounds. Only one
exact instance-view `PowerState/running`, `PowerState/stopped`, or `PowerState/deallocated` status
code is normalized. Missing, duplicate, conflicting, unclassified, out-of-scope, partial,
oversized, timed-out, or malformed VM responses produce `unknown`. Provisioning state, Resource
Health, display text, and model-view power fields are not evidence of runtime state.

## Consequences

- No Context API Container App is required for the initial gate.
- Authority/configuration files are non-secret but must be reviewed, digest-pinned, and deployed
  read-only.
- The context identity has no workload Reader role; Azure evidence still comes only through the
  sealed private MCP adapter.
- Replay reservations survive job/process restarts. A failed post-reservation run requires new
  reviewed attempt and snapshot IDs.
- The WC-008 allowlist adds only `compute_vm_get`; the existing resource-group Reader assignment
  already covers the required VM instance-view read, so no RBAC or scope broadening is introduced.
- Non-VM inventory records retain their existing projection and `unknown` operational state.
- The in-memory authority store is acceptable only for this single evaluation. A long-running API,
  concurrent writers, or reusable evaluation service requires durable Context API persistence with
  equivalent conditional transactions.

## Alternatives considered

1. **Call the default Context API.** Rejected because it intentionally exposes no evaluation route
   or authority.
2. **Deploy a minimal Context API first.** Rejected for the initial gate because it also requires a
   durable authority/evaluation persistence adapter and expands the deployment surface.
3. **Bypass ContextService and assemble a snapshot in the CLI.** Rejected because it would duplicate
   WC-013 logic and lose WC-007 approval/grant and atomic commit invariants.

## Validation

- Configuration tests reject changed authority/assertion digests, identities, scopes, profiles,
  approvals, and public keys.
- Adapter tests cover exact Key Vault RS256 input, public-key fingerprint resolution, Entra
  evidence-identity verification, and atomic replay reservations.
- The one-shot composition test runs the existing services end to end without a Context API HTTP
  endpoint.
- Runtime-state tests cover all supported power states, wrapper variants, deterministic per-VM
  calls, scope enforcement, partial and timeout behavior, response-byte exhaustion, malformed and
  conflicting statuses, and exact allowlist drift.
- Targeted WC-013 and demo-evaluation tests, Ruff, and mypy must pass.
