# ADR 0027: Bind WC-027 guidance to an exact signed incident occurrence

- **Status:** Proposed
- **Date:** 2026-09-11

## Context

WC-026 correlates an evidence-derived health transition, but its request does not identify the
exact WC-016 incident state occurrence that later guidance will enrich. Reusing only an incident
revision or affected resource could attach a valid correlation report to another recurrence,
transition, or signed state.

Changing the stable WC-026 request v2 would also couple a completed correlation contract to the
later guidance rollout and break existing readers before guidance is available.

## Decision

WC-027 introduces `IncidentCorrelationSubject.v1`. It embeds the exact WC-016 `IncidentState` and
`IncidentStateAttestation`, explicit incident, transition, resource, state-digest, and revision
values, and version-pinned immutable references for both signed-state artifacts. A separate
`IncidentCorrelationSubjectAttestation.v1` signs that complete occurrence preimage, so the
guidance-specific revision cannot be relabelled around an older valid incident state. The subject
validates:

- incident ID derivation from the canonical affected resource;
- exact incident, transition, revision, and state-digest identity;
- state and attestation result-digest equality;
- exact incident/version Blob paths;
- Blob content digests against canonical state and attestation bytes; and
- deterministic subject ID and digest.

WC-027 also introduces `IncidentBoundCorrelationRequest.v1`, an outer envelope containing the
subject and an unchanged WC-026 `CorrelationRequest.v2`. It explicitly binds the WC-026 transition
digest, affected resource, and incident revision across both contracts. It rejects stale prior
occurrences whose last signed update predates the selected health transition, state timestamps
newer than the correlation trusted time, and active/resolved lifecycle claims incompatible with the
selected health state. `IncidentBoundCorrelationRequestAttestation.v1` signs the complete
subject/request association with a separate domain-specific preimage, preventing a valid subject
from being paired with another correlation request or relabelled revision. The wrapper also uses a
deterministic request ID and binding digest.

The subject contract does not verify the detached signature or read Blob storage. A later atomic
production service must read the exact versions, validate all three signatures and pointer authority,
and then correlate and generate guidance without exposing a reusable trusted capability.

## Consequences

- WC-026 v2 remains readable and unchanged.
- Guidance can bind to one exact incident state and transition through the embedded signed state.
- Incident state and attestation references remain outside the WC-026 evidence inventory; the
  WC-027 outer envelope owns that additional authority boundary.
- Producers must retain immutable WC-016 state and attestation versions before requesting guidance.
- This prerequisite adds no guidance text, live-page changes, notifications, or remediation.

## Alternatives considered

- **Advance WC-026 request directly to v3:** rejected because WC-026 is complete and the new
  authority is guidance-specific.
- **Carry only incident ID and revision:** rejected because those values do not authenticate the
  exact signed state occurrence.
- **Carry only a current pointer:** rejected because a mutable pointer can advance between
  correlation and guidance.

## Validation

- Contract tests cover deterministic round trips and digest-bound IDs.
- State, attestation, resource, revision, time, Blob name, and content-digest substitutions fail.
- Strict extra fields fail.
- Existing WC-026 contract and WC-005 golden-proof suites remain green.
