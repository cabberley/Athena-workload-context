# ADR 0033: Return version-pinned WC-016 incident occurrences

- **Status:** Proposed
- **Date:** 2026-09-12

## Context

WC-027 correlation and enrichment bind one exact signed IncidentState v1 occurrence. The current
WC-016 publisher writes immutable state, state attestation, pointer, and pointer attestation blobs,
but its publication receipt discards Azure Blob version IDs. A later process therefore cannot read
and verify those exact versions without relying on mutable current paths or Blob listing.

State and pointer signatures also use different preimages:

- state signs canonical JSON excluding `resultDigest`, without a trailing newline;
- pointer signs complete `IncidentFeedPointer.canonical_bytes()`, including its trailing newline.

These rules must be shared by writers and historical readers.

## Decision

Add `IncidentOccurrenceReceipt.v1` as a separate additive contract. It contains version-pinned
references to:

- `state.json`;
- `attestation.json`;
- immutable `pointer.json`; and
- `pointer-attestation.json`.

All names are beneath:

```text
incidents/<incident-id>/versions/<state-result-digest-hex>/
```

The directory suffix is the semantic `IncidentState.resultDigest`, not the content digest of
`state.json`. Each `VersionPinnedBlobReference` independently carries the content digest and Blob
version.

The contract adds shared `incident_state_signature_preimage` and
`incident_pointer_signature_preimage` helpers. The receipt builder re-parses every model and
requires exact state/pointer IDs, paths, semantic/content digests, preimages, publication time, and
attestation relationships before creating a deterministic receipt ID/digest.

The receipt is an unsigned, version-pinned locator that binds one exact artifact set at
construction time. It does **not** independently establish signature trust or prove that the
mutable `current.json` and `active.json` CAS operations committed. A later implementation PR may
return this receipt through `IncidentPublicationReceipt` only after both CAS operations are
coherent. Retry/no-op paths must recover and return the same receipt rather than discard it.

## Consequences

- IncidentState v1, feed v1, active index v1, and browser contracts remain unchanged.
- A future historical reader can perform exact-version reads without listing or latest-version
  fallback. Every read must verify the returned Blob version and content digest, rederive the state
  and pointer preimages, and verify both attestations against configured trust anchors.
- The implementation must preserve logical v1 signing IDs separately from the exact configured Key
  Vault key URI/fingerprint.
- Upload recovery must return non-empty version IDs for successful writes or exactly matched
  existing blobs and fail closed on ambiguous/conflicting content.
- WC-027 publication remains blocked until the implementation returns/durably hands off the
  receipt after coherent CAS publication.

## Alternatives considered

- **Add version fields to IncidentFeedPointer v1:** rejected because v1 readers enforce exact keys.
- **Read current blobs:** rejected because current paths can advance to another occurrence.
- **List versions by digest:** rejected because listing broadens access and introduces ambiguity.
- **Treat four references as publication proof:** rejected because immutable uploads can survive a
  losing or interrupted CAS.

## Validation

- Deterministic receipt IDs/digests and strict round trips.
- Exact path and state-result-digest semantics.
- Independent content-digest substitution failures.
- State and pointer preimage parity with existing WC-016 signing.
- Publication-time chronology.
- Existing WC-016 eventing and WC-027 incident-subject tests remain unchanged.
