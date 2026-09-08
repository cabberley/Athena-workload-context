# ADR 0018: Durable context-store concurrency and trust boundaries

## Status

Accepted for implementation.

## Context

WC-007 established the governed Context API lifecycle with an in-memory adapter. That adapter
is deterministic for tests, but loses state at process restart and cannot coordinate multiple
Context API replicas. Published manifest history, publication provenance, idempotency receipts,
and audit history must remain protected within the customer subscription.

The Context API remains Athena's only authoritative writer. Context MCP, Context Studio, policy
workers, and presentation components consume authorized API results and must not receive direct
context-store write access. The context identity remains separate from the private Azure MCP
evidence identity and receives no workload Reader role.

## Decision

`AzureTableContextStore` implements the existing `ContextStorePort` for the governed manifest
lifecycle. It uses a deployment-provisioned, dedicated Azure Table and one dedicated partition
for one exact configured workload. The adapter authenticates only with the Context API managed
identity through the existing managed-identity-only credential factory. It does not create tables,
use connection strings, accept caller credentials, or access workload resources.

All lifecycle rows share the partition so one Azure Table transactional batch can atomically
create or conditionally replace the draft, immutable published version, immutable supersession
record, audit event, and idempotency receipt. A generation metadata row is conditionally updated
with its ETag in every mutating batch. This supplies cross-process optimistic concurrency and
preserves the Context API's single-writer transaction semantics: a losing replica writes no
partial state and receives a typed persistence conflict.

Published manifests and supersessions are create-only rows. A new version is published instead
of changing an existing version, and supersession remains an explicit separate record. Drafts
alone use conditional replacement with the expected revision and the enclosing generation ETag.
The service continues to authorize after resolving a draft or an exact manifest version, so an
explicit workload grant cannot read a different workload. Runtime readers resolve only an exact
`manifest_id` and `manifest_version` through the Context API.

The adapter is explicitly workload-scoped. Workload identifiers use the Context API's route-safe
ASCII identifier contract. It rejects another workload's draft, published,
supersession, audit, or receipt records on both persistence and lookup; it also rejects a
persisted foreign record as integrity/configuration failure. This keeps the single-partition
atomicity model honest and prevents a general grant from extending an adapter instance beyond its
deployment-selected workload.

Each entity contains a canonical-record SHA-256 digest. Audit events additionally link the prior
event digest and include a canonical digest over their sequence, ID, predecessor, and provenance.
The state row also atomically commits a partition anchor: the full entity count, a digest of the
sorted non-state row keys, kinds, and record digests, and the audit tail sequence and digest.
It includes the commit generation in that canonical digest. The store verifies all record digests,
the complete audit chain, and the state anchor on every load; the API verifies the chain before
returning a workload's history. A deleted final audit event or immutable state row consequently
fails closed instead of appearing as a shorter valid history. Invalid row keys, schema versions,
entity kinds, ETags, oversized records, record digest failures, audit gaps, audit-chain failures,
or state-anchor mismatches fail closed. The partition scan is capped at 4,096 entities and
individual serialized records at a 60 KiB UTF-16LE-byte bound (without a BOM), within the Azure
Table `Edm.String` property bound. Untrusted lifecycle identifier components are never used
directly as row keys. Each row key has a kind prefix and a domain-separated SHA-256 digest over a
canonical structured component list; original logical IDs remain in `recordJson`, and load-time
derivation verifies the same key. This avoids Azure-disallowed characters and ambiguity between
kinds or component boundaries while keeping route-safe logical IDs opaque in storage.
The state anchor canonically includes the configured workload ID, so its bootstrap continuity root
cannot be reused under a different workload configuration.

The existing `InMemoryContextStore` stays an explicit deterministic test adapter and implements
the same port, optimistic revision checks, create-only publication behavior, and audit-chain
construction. The production ASGI composition root refuses to start unless all durable-store
settings are supplied; it never selects the in-memory adapter. It also requires an exact Entra
tenant GUID and API audience, constructs a tenant-v2-JWKS RS256 verifier, validates issuer,
audience, expiry/not-before/issued-at, tenant, subject, and object ID. Delegated tokens require the
exact deployment-owned scope in their signed `scp`; `idtyp=user` is accepted when configured but
is not required. Signed Entra agent-identity facet claims map to an agent rather than a human.
App-only tokens require `idtyp=app`, one consistent signed application client ID, and no delegated
scope. The lower-case object ID maps deterministically to the resulting human, agent, or service
actor. It requires a
bounded, non-empty deployment-owned JSON role-grant list whose entries are all explicit grants for
the configured workload; caller headers never supply identity or grants. Existing human-only
approval/publication/supersession checks therefore remain effective. There is no historic
production data migration because the prior in-memory state is process-local and non-durable;
deployment migration is an explicit cutover that starts the durable store empty and replays only
reviewed Context API commands.

An empty Azure Table partition is permitted only for the explicit first-initialization operation.
The production root always loads and verifies the committed partition at startup; an empty
partition or a missing state row fails closed. A controlled deployment runs
`apps/context-api/bootstrap.py` once under the Context API managed identity before starting API
replicas. That process calls `initialize_empty_partition`, creates the generation-one state-row
continuity root, and exits. The operation refuses a non-empty partition and is not reachable
through API startup or a Context API mutation. Normal startup rejects the obsolete
`ATHENA_CONTEXT_STORE_BOOTSTRAP_ENABLED` setting, preventing a retained replica configuration from
turning later partition deletion into an automatic history reset.

## Alternatives considered

- **Keep process-local memory:** rejected because restart loses authoritative state and replicas
  cannot coordinate.
- **Share one Table partition across workloads:** rejected because the 4,096-row bound becomes a
  migration trap and an adapter could accidentally serve a foreign workload. Each durable adapter
  is configured for exactly one workload and keeps all of that workload's lifecycle rows in its
  atomic partition. Cross-workload transaction semantics are intentionally not invented.
- **Use Blob snapshots:** rejected because conditional lifecycle mutations and strongly
  transactional multi-row writes are less direct than Azure Table batches.
- **Give all Athena components Table write access:** rejected because it bypasses Context API
  lifecycle validation, human publication approval, authorization, and provenance.

## Security and operational consequences

- Azure RBAC grants the dedicated Context API identity only the minimum data-plane role required
  on the dedicated context table. No client, agent, evidence identity, or presentation identity
  receives Table write access.
- The Table is a protected customer-boundary data store. Private networking, diagnostic policy,
  retention, and RBAC assignment are deployment responsibilities; the adapter intentionally
  does not broaden identity or network configuration.
- The audit chain is tamper-evident, not independently immutable against a principal that can
  both alter all rows and recompute the chain. Least-privilege write access and exported,
  independently retained audit checkpoints are required before treating it as protection from a
  subscription administrator.
- The continuity root detects deletion of the complete partition during normal operation, but an
  actor able to restore a fully self-consistent old Table snapshot can still roll history back.
  That remains within the fully privileged rewrite limitation; detection requires an external
  monotonic anchor or independently retained checkpoint. Administrator-grade immutability is a
  separate production release gate and is not claimed by this adapter.
- A full-partition bounded scan favors correctness over availability. Capacity growth beyond the
  bound fails closed. The adapter logs the operational alert event
  `athena_context_store_capacity_warning` at 3,584 rows (87.5% of capacity), carrying the workload
  ID, entity count, capacity, and required migration action. Deployments must route that event to
  operational alerting. Before the hard limit, an approved archival/cutover gate is required:
  freeze writers, verify and independently retain the source state-anchor checkpoint, and preserve
  the source partition read-only. No archival process may delete or prune active-chain rows.
  A future per-workload shard adapter must explicitly bind a successor continuity record to that
  checkpoint and provide an exact-version resolver before accepting writes; this adapter neither
  replays history nor invents cross-partition transactions. Demo-evaluation approvals, findings,
  receipts, and artifacts are outside `ContextStorePort`; they are not silently migrated by this
  adapter, and the production Context API root does not compose demo evaluation on it.

## Compatibility, migration, and rollback

The durable adapter is a drop-in `ContextStorePort` implementation for the Context API lifecycle;
the service contracts and existing in-memory tests remain valid. Controlled deployment injects
the durable adapter at the Context API composition root after the dedicated Table and managed
identity RBAC are provisioned. Rollback is safe before cutover by continuing to run the
in-memory test adapter only; after authoritative durable publication begins, recovery restores
the protected Table and never reconstructs or mutates published versions from local memory.
