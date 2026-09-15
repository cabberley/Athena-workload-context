# ADR 0028: Publish immutable WC-027 guidance authority

- **Status:** Accepted
- **Date:** 2026-09-11
- **Last updated:** 2026-09-15

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

The publication request is now produced by a separate production runtime rather than by the
authority publisher or a caller-side submit command. That producer consumes only the exact
canonical signed `IncidentBoundCorrelationRequest.v1` from a private session-enabled queue. Before
any output Blob or Service Bus write it verifies the nested incident-state, incident-subject, and
incident-bound request signatures against exact pinned key versions; reads the current signed
occurrence, pointer, and active index from the lifecycle authority; rejects draft context; and
reads the exact version-pinned `PublishedContextAuthority` bytes to prove the manifest, resolved
profile, dependency graph, context payload, publication record, and audit-head binding.

`evaluatedAt` is derived deterministically from stable signed inputs: the maximum of the
correlation request `trustedAsOf`, current occurrence `publishedAt`, and published-context
authority `publishedAt`. It is never derived from wall-clock time. Expiry is the earlier of five
minutes after that stable time or the nested correlation expiry. The producer signs with a
dedicated request-signing identity, normalizes the detached signature with the same guidance
signing rules as the publisher, and immediately verifies it using a separate exact-key public-key
reader identity.

Before enqueue, the producer create-or-recovers the exact canonical request in an isolated
immutable Blob outbox. Its logical path is keyed only by the signed occurrence ID, so an identical
retry recovers the same version while a different request for the same occurrence conflicts
closed. The writer has create-only permission; a separate reader has exact read permission with
Blob listing denied. Immediately before persistence and enqueue, the producer requires more than
the reviewed 90-second downstream budget: the publisher's 30-second KEDA polling interval plus a
60-second startup and processing allowance. After persistence, the producer re-reads the signed
lifecycle authority and the exact immutable context authority. It then establishes the sender,
resamples the trusted clock, and calculates TTL immediately before message construction and send.
Only then does a distinct Service Bus sender identity send the canonical request to
`wc027-guidance-authority-requests`, using
`requestId` as `MessageId`, incident ID as `SessionId`, a bounded TTL, and occurrence, incident,
context-authority, request, outbox, and delivery-budget binding metadata. Service Bus duplicate
detection and immutable outbox recovery make an uncertain send safely retryable with
byte-identical identity.

The publisher accepts exactly one configured request submitter identity, which must be the
producer's dedicated sender and must not overlap any publisher, signer, reader, or runtime identity.
Every other request-producer identity is disjoint from the complete enrichment-runtime deployment
identity set and from every identity attached to the publisher Job. The sender-to-submitter
authorization is the only cross-component identity handoff and does not attach the sender identity
to the publisher Job.
Before publication, a separate publisher outbox-reader identity validates the complete broker
metadata and exact-reads the referenced Blob version, requiring byte-for-byte equality with the
canonical signed request. A correctly signed request without durable outbox evidence therefore
cannot activate guidance authority. The publisher also requires the same configured delivery
budget and rejects requests that no longer retain its 60-second startup and processing allowance.
Service Bus failures from the enrichment trigger send or input completion are retryable; the worker
abandons only under a valid delivery/session lock, and immutable activation replay prevents a
duplicate activation after an uncertain send.

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

The request producer, authority publisher, and enrichment/feed producer are separate runtime Jobs.
The request producer does not create or activate `PublishedGuidanceAuthorityBinding.v2`, does not
trigger enrichment, does not execute actions, and does not fabricate correlation or occurrence
evidence. The authority publisher remains the only component that creates and activates the
binding.

Root readiness accepts those Jobs only by canonical absolute ARM IDs in the current subscription
and reviewed foundation resource group. Structural parsing is followed by normalized equality
with each loaded Job `.id`, closing malformed prefixes, provider/type aliases, suffixes, duplicate
separators, encoded/query/fragment forms, and cross-scope substitution.

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
  set `wc027RequestProducerReady`, `wc027PublisherReady`, or
  `wc027FeedV2ProducerReady`; all remain false until exact deployed Job/configuration/RBAC evidence
  and end-to-end behavior are proven. Readiness requires user-assigned-only identity mode, exactly
  one reviewed container, and the complete environment, command, resource, probe, replica, scaler,
  registry, volume, secret, and managed-identity lifecycle surfaces to match.

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
- Adversarial publication-request producer tests cover invalid nested signatures and key versions,
  draft or stale inputs with zero output I/O, current occurrence and immutable context-authority
  mismatch, separate signer verification failure, occurrence-keyed immutable outbox conflict,
  retry after uncertain enqueue, exact replay/concurrency identity, broker metadata, strict
  configuration and identity separation, required Blob versioning, digest-pinned non-root image,
  least-privilege Bicep/RBAC, and the separate root readiness gate.
