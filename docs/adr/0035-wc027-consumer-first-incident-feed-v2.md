# ADR 0035: Add a consumer-first incident enrichment feed

- **Status:** Accepted
- **Date:** 2026-09-12

## Context

IncidentState v1, `current.json`, and `active.json` are exact-shape lifecycle contracts consumed by
Python, the presentation gateway, and the browser. Adding enrichment fields would break those
readers. A second mutable `current-v2.json` would also create four independently committed mutable
heads whose state cannot be updated atomically.

The v1 active index removes resolved incidents, so an active-only enrichment feed cannot support
resolved guidance pages or notification deep links.

## Decision

Keep IncidentState v1 and `incidents/active.json` as the only lifecycle authority. Add a derivative
WC-027 feed with:

- one immutable `IncidentEnrichmentFeedPointer.v2` per exact occurrence/enrichment;
- a separate pointer attestation;
- one mutable signed `IncidentFeedIndex.v2` containing `active` and bounded `recentlyResolved`
  collections; and
- no `current-v2.json`.

The immutable pointer binds the complete `IncidentOccurrenceReceipt` reference set—state,
state-attestation, pointer, and pointer-attestation—plus one exact
`IncidentEnrichmentAssetReference`. Lifecycle and update time are derived from the canonical v1
state; callers cannot relabel them. Its path is:

```text
incidents/<incident-id>/versions/<state-result-digest>/enrichments/<enrichment-id>/
  feed-pointer.json
  feed-pointer-attestation.json
```

The v2 index entries carry only routing/join fields and exact version-pinned pointer/attestation
references. They do not duplicate state, findings, report, guidance, or enrichment content.

### Producer reconstruction registry

The producer maintains a private Azure Table registry with one latest prepared entry per incident.
Each row stores the complete signed feed pointer and pointer attestation, not an unsigned lifecycle
claim. The registry is not a consumer API or lifecycle authority.

Before building an index, the producer verifies every retained row against the configured feed
signing key. Every v1-active incident must have one matching active registry row with the exact
state digest and update time derived from its v1 pointer. An active registry row that disappears
from v1 blocks publication until a verified resolved successor replaces it. This permits gradual
bootstrap without ever publishing a partial active mirror.

Every active or retention-eligible resolved row must also match the incident's independently
verified v1 `current.json` snapshot and its reconstructed `IncidentOccurrenceReceipt`. The
producer compares lifecycle, state result digest, update time, occurrence digest, and all four
version-pinned v1 source references. Missing, malformed, or mismatched current-occurrence
authority blocks the complete v2 projection. This makes the signed v1 current occurrence—not the
mutable Table row—the per-incident latest-occurrence authority and prevents a principal with
registry-only write access from replaying an older, correctly signed resolved row. Protection
against rollback by a principal that can also replace the signed v1 current head remains a
separate storage-integrity concern.

Resolved rows expire seven days after their authoritative state update. The producer reads expired
rows into the bounded projection, validates them against current-occurrence authority, and only
then passes the projection's opaque prune plan to the Table adapter for ETag-conditional deletes.
The adapter does not accept raw records for cleanup. This order prevents an expired replay from
being silently deleted before detection while ensuring expired history cannot permanently exhaust
the bounded registry. The complete eligible set supplies the exact resolved total; only the newest
64 entries are exposed in the public index.

The index publisher reads the current v1 occurrence for every retained registry row before signing
a candidate, revalidates every entry in a concurrent winner before accepting it, and performs
expiry cleanup only after a verified index commit or verified-winner reconciliation. A concurrent
registry addition does not invalidate an already committed candidate, but no entry already present
in that candidate can be older than its current v1 occurrence. If a signed concurrent winner fails
that check, the publisher uses the winner's ETag to replace it with a verified candidate whose
publication timestamp is at least one millisecond newer; it never treats the invalid winner's
timestamp as authority. The publisher reads the signed v1 source again after per-entry occurrence
validation and immediately before acceptance, so an active-set change during validation restarts
the bounded publication attempt rather than accepting the older mirror.

The registry keeps a reserved capacity metadata row in the same partition. New incident rows are
created in one Azure Table transaction with an ETag-conditional retained-count increment. Expiry
cleanup similarly deletes bounded batches while conditionally decrementing the same row. A stale
capacity ETag rejects the whole transaction, so concurrent writers cannot admit more than 4,096
retained incidents or let the metadata diverge from the rows. Startup creates missing metadata
from one bounded partition snapshot and immediately revalidates the count; mixed-version writers
or any mismatch fail closed.

`IncidentFeedIndex.v2` has separate maximum-64 active and recently-resolved collections within a
128-KiB bound. Active
entries are uniquely ordered by incident ID. Recently resolved entries contain the latest retained
occurrence per incident and are ordered by updated time descending, incident ID, and state digest.
The index declares a resolved-retention start and rejects entries outside its signed interval.
Any history truncation carries an explicit omitted count. The index also binds the v1 active-index
digest from which the derivative view was produced.

### Index publication transaction

The publisher reads and verifies `incidents/active.json` and its attestation directly; Blob
enumeration is never a lifecycle input. It then reads the bounded registry snapshot, verifies every
retained feed pointer and attestation from the registry's exact Blob versions, and refuses to
publish unless the active projection exactly matches the signed v1 index.

Each publication uploads the digest-addressed index attestation before conditionally writing
`incidents/feed-v2.json`. Blob versioning makes the successful feed-v2 write an immutable,
version-pinned index asset while the stable blob name remains the only discovery head. The stable
head is created with `If-None-Match` or replaced with `If-Match` against the observed ETag, so an
attestation-only partial upload is undiscoverable.

After a lost CAS or uncertain response, the publisher rereads and fully verifies the stable head.
It accepts an exact retry or a winner bound to the same or a newer currently signed v1 authority;
it never overwrites a newer winner. A same-timestamp, non-equivalent index fails closed.

## Consumer-first rollout

1. Land these contracts.
2. Add exact-version gateway reads and separate report/guidance/enrichment/feed trust anchors.
3. Add dormant browser verification and rendering.
4. Publish v2 pointers/index only after the winning v1 active-index CAS.
5. Activate the browser and later switch notifications from v1 to v2. Never dual-send user-visible
   notifications.

### Production-domain publication chain

The domain integration boundary consumes only a successfully verified
`IncidentEnrichmentPublicationReceipt`. Before any feed write it re-reads the authoritative v1
current occurrence by incident ID and requires exact equality for the occurrence, transition,
state result digest, current-pointer digest, lifecycle, update time, and enrichment binding.
The verified receipt carries the actual report, guidance, and enrichment signing key IDs so feed
key separation cannot be asserted from caller-supplied substitutes.

It then:

1. constructs and signs the immutable feed pointer with a feed key that is distinct from the
   report, guidance, and enrichment signing authorities;
2. creates or recovers the pointer and attestation at their exact derived names without Blob
   enumeration;
3. builds and validates the registry record, calls `IncidentFeedRegistryPort.put()`, and confirms
   the exact record is durably readable, accepting an uncertain-write replay only when the retained
   record is byte-equivalent; the Azure Table adapter translates transport-response loss into this
   domain recovery path; and
4. invokes `IncidentFeedIndexPublicationService.publish()` only after registry durability is
   proven, returning success only when the exact pointer entry is present in the committed or
   reconciled index.

The immutable pointer timestamp is bound to the verified enrichment-publication receipt, while the
mutable index publication timestamp is supplied for each index attempt. They have separate retry
lifecycles, so a caller may retry with a fresher index timestamp without changing the pointer bytes.
If a valid concurrent index winner omits a newly admitted resolved entry, the orchestrator keeps
the already published pointer bytes and retries only the index with a timestamp strictly newer
than that winner. A same-timestamp CAS conflict also advances only the index timestamp within the
bounded retry loop.

Registry admission orders successors by exact signed v1 current-occurrence authority, not by
`IncidentState.updatedAt`. The adapter validates the incoming record against that authority, then
ETag-conditionally replaces a retained row that no longer matches it. This permits valid
active-to-resolved successors whose state update time is equal to or lower than the prior row while
still rejecting stale replays and non-equivalent records claiming the same current authority. The
Table adapter directly re-reads the known v1 current head before and after its conditional write;
it never discovers authority through Blob enumeration.

The chain emits no notification. Runtime wiring may enqueue Notification v2 only after receiving
the successful domain receipt, so pointer-only, registry-only, and failed-index states remain
undiscoverable and silent.

Before v2 activation, v1 behavior remains unchanged. After activation, invalid, missing, stale, or
unavailable v2 enrichment does not silently become successful v1 guidance. The UI may still show
independently verified v1 lifecycle with an explicit guidance-unavailable state.

## Invariants

- v2 cannot create, resolve, or hide a v1 incident;
- there is one mutable v2 discovery head and no v2 current pointer;
- every v2 pointer references exact Blob versions and content digests;
- active and recently-resolved collections cannot contain the same incident;
- resolved occurrences remain discoverable after v1 active-index removal;
- the gateway derives its immutable allowlist from verified references, never prefixes;
- notification v2 is queued only after its exact immutable pointer is in the v2 index; and
- `noAutoRemediation=true` remains invariant.

## Consequences

- v1 readers remain byte-for-byte compatible.
- CAS failure can leave immutable v2 artifacts, but they are undiscoverable until a signed index
  commit succeeds.
- A later shadow producer needs reconciliation for crashes between v1 CAS, immutable v2 writes,
  and v2 index CAS.
- The browser needs an exact-version reader; the generic 1-MiB presentation reader must not be
  globally widened for 8-MiB correlation reports.

## Alternatives considered

- **Extend v1 pointers/index:** rejected because exact-key readers would break.
- **Add active-v2 and current-v2 peers:** rejected because independently committed mutable heads
  split lifecycle and enrichment state.
- **Active-only v2 index:** rejected because resolved occurrences and deep links disappear.
- **Silent v2-to-v1 fallback:** rejected because it hides rollout and verification failures.

## Validation

- Exact occurrence/enrichment pointer binding and signature validation.
- Active/recent-resolved ordering, uniqueness, retention, and cross-set exclusion.
- Version/path/content/signature substitution failures.
- Strict unknown-field rejection and byte bounds.
- Existing IncidentState/feed/index v1 contracts remain unchanged.
