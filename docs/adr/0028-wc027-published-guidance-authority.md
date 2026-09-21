# ADR 0028: Publish immutable WC-027 guidance authority

- **Status:** Accepted
- **Date:** 2026-09-11

ADR 0029 advances the pre-runtime guidance authority wire contracts to v2 so runbook references
carry immutable versions and content digests.

## Context

WC-027 guidance may cite manual options and runbooks only when they are part of exact published
workload context and applicable to the affected role, cause, path, action, and confidence. The
existing `ManualFailoverRunbookControl` does not carry that complete applicability, review-expiry,
URI-policy, or execution-authorization boundary.

Adding fields to the existing WC-026 publication authority would break strict request v2 readers
and change completed context and correlation digests.

## Decision

WC-027 introduces an outer immutable `PublishedGuidanceAuthority.v2` and a signed
`PublishedGuidanceAuthorityBinding.v2`.

The authority binds the exact published context identity and authority reference plus zero or more
deterministic runbook guidance options. Each option carries:

- exact manifest/profile/clause/owner provenance;
- cause, role, path, action, and minimum-confidence applicability;
- a safe HTTPS or approved opaque runbook reference;
- control health, review time, review expiry; and
- `executionAuthorizationRequired=true`.

A zero-option authority is valid only with signed deterministic no-runbook reasons. Until a future manifest-authoring prerequisite introduces a
fully applicable operator-guidance control, legacy `manualFailoverRunbook` controls are not
promoted and guidance must select a structured `noRunbook` outcome.

The binding wraps the merged WC-027 incident-bound request and exact WC-026 report without changing
either contract. It validates the report as published runtime output, binds an immutable authority
Blob named `guidance-authority/{authorityId}/authority.json`, checks context identity, and records
either:

- one exact effective, unexpired, applicable selected option; or
- one explicit no-runbook reason.

No-runbook selection is rejected when any effective, unexpired, applicable option exists, and its
reason must match the signed authority omissions or deterministic option failures. All freshness
checks use one binding evaluation time that cannot predate the correlation report and must remain
inside the request validity window.

Prescriptive manual or rollback actions require Confirmed confidence, no material Medium-or-higher
competing hypothesis, and no explicit competing-cause contradiction. Every
binding carries a domain-separated detached-signature preimage digest.

Production publication accepts only canonical, bounded
`GuidanceAuthorityPublicationRequest.v1` messages. The request signs the exact incident-bound
correlation request, current signed `IncidentOccurrenceReceipt`, requested actions, evaluation
time, and expiry using a dedicated publication-request authority. The publisher verifies the
request and every nested lifecycle/subject/correlation-binding signature before writing guidance
assets, re-reads the signed current occurrence and active index, and recomputes correlation rather
than trusting a caller-supplied report.

The initial production publisher emits only the deterministic zero-option authority with
`noMatchingControl`. It first create-or-recovers the immutable authority Blob, then signs and
immediately verifies the binding, then create-or-recovers the binding Blob. Existing paths are
accepted only when their exact canonical bytes, digest, content type, and version-pinned readback
match.

Activation is a separate signed `PublishedGuidanceAuthorityActivation.v1` CAS row keyed by
incident ID. It binds the exact occurrence, request, binding digest, version-pinned binding
reference, activation time, and expiry. A retry may reuse the same activation; a different
activation for the same occurrence, an ETag conflict, a changed lifecycle authority, changed
correlation result, or a superseding activation fails closed. The enrichment runtime verifies the
current activation before correlation or any external write, closing replay of an older valid
binding.

Publication-request signing and guidance-binding signing are distinct from lifecycle,
correlation-binding, report, guidance, enrichment, feed, and notification authorities. Stable
logical `keyId` values appear in signed artifacts; exact versioned Key Vault URIs are deployment
configuration only. The lifecycle pointer and active-index `keyId` are checked against the
configured logical lifecycle ID, while lifecycle attestations and cryptographic verification are
checked against the separately configured versioned Key Vault URI.

The publisher configuration is rejected unless its authority Blob endpoint/container and
activation Table endpoint/name/partition exactly match the embedded feed runtime's read
locations. The publisher deployment derives those destinations from that runtime configuration.
Its authority writer has only Blob create permission, its activation writer has only Table entity
read/add/update permission, and its binding signer has only exact-key sign permission.

## Consequences

- WC-026 request/report and WC-027 incident-subject contracts remain unchanged.
- No runbook is safer and valid when authority is absent, stale, unhealthy, inapplicable, or too
  weakly supported.
- Renderers may open only validated HTTPS references. Opaque references remain display-only.
- Athena still does not execute runbooks or remediation.
- Manifest authoring must later add an applicable operator-guidance control before production
  authorities can contain selectable options.
- Readiness remains an operational assertion. Shipping the publisher and feed runtime does not
  set `wc027PublisherReady` or `wc027FeedV2ProducerReady`; both remain false until exact deployed
  Job/configuration/RBAC and publisher-to-producer queue wiring are proven. Setting them true
  enables bounded runtime acceptance and is not itself proof of end-to-end behavior.

## Alternatives considered

- **Extend `PublishedContextAuthority`:** rejected because it would break WC-026 request v2.
- **Use legacy failover controls directly:** rejected because they lack cause, role, path, action,
  expiry, and authorization applicability.
- **Allow generated fallback runbooks:** rejected because observed or generated text is not
  published human-owned intent.

## Validation

- Contract tests cover safe and unsafe references, applicability and confidence rules, option
  health and expiry, context/Blob/report cross-binding, selected-option legality, draft rejection,
  and valid zero-option/no-runbook authority.
- WC-027 subject, WC-026 contract, and WC-005 golden-proof tests remain green.
- Adversarial publisher tests cover invalid signatures with zero publication I/O, stale and
  mismatched occurrence authority, deterministic retries, conflicting activation, changed
  authority before activation/enqueue, strict request bytes, logical/physical key separation,
  and activation expiry/currentness.
