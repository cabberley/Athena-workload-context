# ADR 0035: Add a consumer-first incident enrichment feed

- **Status:** Proposed
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

`IncidentFeedIndex.v2` has separate maximum-64 active and recently-resolved collections within a
128-KiB bound. Active
entries are uniquely ordered by incident ID. Recently resolved entries contain the latest retained
occurrence per incident and are ordered by updated time descending, incident ID, and state digest.
The index declares a resolved-retention start and rejects entries outside its signed interval.
Any history truncation carries an explicit omitted count. The index also binds the v1 active-index
digest from which the derivative view was produced.

## Consumer-first rollout

1. Land these contracts.
2. Add exact-version gateway reads and separate report/guidance/enrichment/feed trust anchors.
3. Add dormant browser verification and rendering.
4. Publish v2 pointers/index only after the winning v1 active-index CAS.
5. Activate the browser and later switch notifications from v1 to v2. Never dual-send user-visible
   notifications.

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
