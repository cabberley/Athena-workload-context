# ADR 0021: Bounded change ingestion data boundaries

- **Status:** Accepted for implementation
- **Date:** 2026-09-06

## Context

WC-025 needs timely evidence of Azure changes that could affect approved Athena workload
resources. Broad subscription Activity Log export would ingest unrelated customer operations,
provide unnecessary access to non-workload data, and blur the boundary between a notification and
evidence. Azure Resource Graph change history adds useful changed-property and snapshot metadata,
but it can query at broad subscription scope unless both the generated query and identity scope
are constrained.

## Decision

Use a global resource-group Event Grid system topic whose only source is
`rg-athena-demo-workload`. It delivers resource write, delete, and action notifications with
successful, failed, and cancelled outcomes to one duplicate-detecting Service Bus queue. The Event
Grid data filter and the worker both require the target resource to exactly match the
deployment-owned approved-resource list; membership in the resource group alone is insufficient.

Event Grid does not deliver through a Service Bus private endpoint. Therefore the namespace keeps
a public endpoint only for identity-authenticated trusted-service delivery: its firewall default is
deny, its trusted-service bypass is enabled, and the dedicated Event Grid user-assigned identity
has Data Sender on exactly this queue. The two Athena workers access the namespace only through
the private endpoint and hold no shared identity with Event Grid. This is a documented, bounded
ingress exception; it is not anonymous or unrestricted public queue access.

The Service Bus private DNS zone may exist before the namespace, but its VNet link is explicitly
sequenced after the namespace and queue, private endpoint, and private DNS zone group. This
prevents ARM from linking an empty Service Bus private zone that could temporarily override
Service Bus name resolution for the VNet.

Run a separate scheduled worker under a separate managed identity. Its Azure Resource Graph
adapter generates the only permitted `resourcechanges` query: one subscription, the exact
resource group, exact approved resource IDs, a maximum 15-minute window, ascending timestamp
order, and at most 101 rows. Its REST request explicitly requests the Resource Graph `ObjectArray`
format. The worker accepts at most 100 records and fails closed if the extra record, a
continuation token, or a truncation indicator shows the query is incomplete. Resource Graph
remains configuration-change evidence only: action notification evidence is not inferred from
change history. An update with a positive `changesCount` is also rejected until exactly that many
changed-property details are available, so an incomplete early observation can never claim the
source ID and suppress its enriched retry. Its custom role is assigned only at that resource group
and permits only Resource Graph and resource-change reads. Neither worker receives workload
Reader, Activity Log export permissions, or authority to change workload resources.

Both paths normalize a versioned contract containing operation, result, changed-property
references, actor reference, UTC occurrence time, correlation ID, deployment source, policy
context, before/after references, source digest, source-specific deterministic delivery key, and
cross-source change key. Identity and value strings that could contain personal or customer data
are represented only by SHA-256 references. Raw events, property values, and arbitrary query
results are not retained.

Each accepted record becomes a canonical, detached-RS256-signed artifact at a deterministic
create-only Blob name. Before source-message settlement or query success counting, the worker
also writes a deterministic create-only persistence-handoff artifact containing the exact
version-pinned evidence reference. Duplicate evidence and handoff names are read only by their
known deterministic name, bounded, metadata-and-digest verified, RS256-verified against the exact
versioned Key Vault key, and accepted only when every source-derived normalized field is identical
to the retry. The retry's later `receivedAt` observation is deliberately excluded from replay
equivalence; the original signed artifact and its original receipt time remain authoritative when
the exact version-pinned receipt is reconstructed. Blob enumeration and unverified latest-content
recovery are prohibited.
The root deployment reads the existing evidence account's `blobServices/default` configuration and
fails through an explicit deployment gate unless `properties.isVersioningEnabled == true`; the
worker deployment depends on that gate. This prevents either worker from creating an artifact whose
otherwise-successful upload has no immutable version receipt for durable replay recovery.
A malformed, stale, unordered, incomplete, or out-of-scope record is rejected before
persistence. Every Event Grid batch is fully normalized and validated before its first record is
persisted, preventing partial writes before a malformed later record is dead-lettered.

## Consequences

- Change notification and richer query evidence remain separate provenance records while sharing a
  correlation-safe change key; the system does not claim they are equivalent evidence.
- A short query overlap safely replays records because a completed handoff reconstructs the
  original evidence version rather than treating duplicate creation as an implicit success.
- Private worker access to Service Bus, authenticated trusted-service Event Grid ingress, managed
  identities, container-scoped evidence writes, and key-scoped Key Vault Crypto User
  (`12338af0-0e69-4776-bea7-57ae8d297424`) assignments avoid keys, connection strings, and broad
  data-plane access. The workers are not assigned Key Vault Crypto Officer
  (`14b46e9e-c2b7-41b4-b07b-48a6ebf60603`), which would unnecessarily permit key and rotation-policy
  management.
- The query worker cannot backfill arbitrary historical or subscription-wide changes. Missed
  evidence outside the bounded window is explicitly unavailable rather than silently inferred.

## Alternatives considered

### Export the subscription Activity Log

Rejected because it would collect unrelated resource changes and create a broad, persistent
customer-data boundary.

### Rely only on Event Grid notifications

Rejected because resource notifications do not consistently provide changed properties,
before/after snapshots, or change-actor context.

### Let the context identity query Azure Resource Graph

Rejected because it would give the Athena context plane direct workload evidence access, violating
the separated-identity boundary.

## Validation

Deterministic unit tests prove exact resource scope rejection, canonical event and query
normalization, actor/value redaction, bounded query construction, stale and malformed evidence
rejection, create-only idempotency, signed artifact provenance, and version-pinned persistence
handoffs. Bicep static validation proves a resource-group system topic, private queue endpoint,
separate worker identities, narrow custom read role, exact Event Grid event types, and no Activity
Log export resource.
