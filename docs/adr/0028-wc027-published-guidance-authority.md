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
`GuidanceAuthorityPublicationRequest.v2` messages. The request signs the exact incident-bound
correlation request, current signed `IncidentOccurrenceReceipt`, requested actions, evaluation
time, expiry, and absolute `finishBefore` using a dedicated publication-request authority. The
reader still verifies the original v1 shape without synthesizing signed fields, but legacy
broker-only requests cannot bypass the mandatory immutable-outbox proof and must be reissued by
the governed producer. The publisher verifies the request and every nested
lifecycle/subject/correlation-binding signature before writing guidance assets, re-reads the
signed current occurrence and active index, and recomputes correlation rather than trusting a
caller-supplied report.

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
authority `publishedAt`. It is never derived from wall-clock time. Request expiry is the earlier
of five minutes after that stable time or the latest instant whose complete downstream
`finishBefore` extension remains within the nested correlation expiry. A correlation window that
cannot cover the reviewed producer minimum and downstream phases fails closed. The producer signs
with a dedicated request-signing identity, normalizes the detached signature with the same
guidance signing rules as the publisher, and immediately verifies it using a separate exact-key
public-key reader identity.

Before enqueue, the producer create-or-recovers the exact canonical request in an isolated
immutable Blob outbox. Its logical path is keyed only by the signed occurrence ID, so an identical
retry recovers the same version while a different request for the same occurrence conflicts
closed. The writer has create-only permission; a separate reader has exact read permission with
Blob listing denied. Immediately before persistence and enqueue, the producer preserves the
reviewed 150-second upstream minimum: 30 seconds each for publisher KEDA polling, cold start, and
Service Bus setup plus 60 seconds for publisher processing. The exact minimum is accepted; anything
below it fails before the corresponding persistence or send action. After persistence, the
producer re-reads the signed lifecycle authority and the exact immutable context authority. It
then establishes the sender, resamples the trusted clock, and calculates the request-hop TTL as
`floor(finishBefore - now - downstreamMargin)`. The request signature binds `finishBefore`, and
the activation must copy that deadline unchanged. Only then does a distinct Service Bus sender
identity send the canonical request to
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
cannot activate guidance authority. The publisher and feed runtime require the same signed and
configured delivery budget. After publisher KEDA polling, cold start, and Service Bus setup, a new
publication must retain the exact 60-second processing phase. The signed activation establishes an
independent feed-delivery timeline with one signed absolute `finishBefore` deadline derived from
request expiry, the 300-second recovery allowance, complete 150-second feed phase, and 30-second
jitter margin without exceeding the nested correlation expiry. The activation is the durable
trigger outbox and binds the immutable binding reference, deterministic trigger message ID,
`triggerDeliveryPending=true`, `finishBefore`, and delivery budget. The publisher requires a fresh
trusted-clock deadline guard immediately before each immutable authority write, immutable binding
write, activation CAS, and trigger send, then submits the trigger after CAS with
`floor(finishBefore - now - feedProcessingMargin)`, and completes its input only after submission
returns. Definite or uncertain submission failure is retryable; replay exact-reads the same
committed activation and immutable binding, resubmits the same message identity, and performs no
second CAS—even after request expiry. The feed checks the processing reserve at start and a fresh
irreversible-write margin directly before each enrichment artifact create/recover, feed pointer
and attestation create/recover, registry transaction, feed-index attestation/index CAS,
activation-materialization CAS, expiry-prune transaction, and notification send.

The activation Table row stores a separate ETag-protected trigger-delivery status. CAS creates
`pending`, and confirmed or uncertain trigger submission leaves it `pending` so publisher replay
can resend the same duplicate-detected message. After the feed pointer, attestation, registry
record, and feed index are durably materialized, a separately authorized runtime identity
conditionally changes only the same activation row to `materialized`. That identity has entity
read/update permission only—no add or delete. The update occurs only after the deterministic
notification is durably enqueued, so notification or marker uncertainty keeps recovery live.
Publisher replay treats `materialized` as complete and does not resend. Original v1 rows omit the
new delivery fields and may omit the transport status entirely; pre-v2 transitional v1 rows may
carry those fields plus the previously published `submitted` value. Both forms normalize to
recoverable `pending` during reads and retain their original signed bytes. Original v1 uses signed
`expiresAt`; extended v1 and new v2 use signed `finishBefore`. All operational checks cap either
form at nested correlation expiry, preventing upgrade-time permanent rejection without allowing
work beyond trusted correlation authority. The immutable occurrence-keyed request slot is not
renewable: a different activation for the same occurrence remains conflict-closed even after
expiry, and a new signed occurrence is required before guidance/feed state can change.
The publisher dead-letters that permanent occurrence conflict and irreversible effective-deadline
exhaustion with one lock-aware terminal disposition, while transient source, ETag, and transport
failures retain the existing abandon/recovery behavior.

The initial production publisher emits only the deterministic zero-option authority with
`noMatchingControl`. It first create-or-recovers the immutable authority Blob, then signs and
immediately verifies the binding, then create-or-recovers the binding Blob. Existing paths are
accepted only when their exact canonical bytes, digest, content type, and version-pinned readback
match.

New activation is a separate signed `PublishedGuidanceAuthorityActivation.v2` CAS row keyed by
incident ID. It binds the exact occurrence, request, binding digest, version-pinned binding
reference, deterministic trigger message ID, complete delivery budget, activation time, original
request expiry, and independently bounded `finishBefore`. A retry
may reuse the same activation; a different activation for the same occurrence, an ETag conflict,
a changed lifecycle authority, changed correlation result, or a superseding activation fails
closed. The enrichment runtime verifies the current activation, trigger metadata, and exact feed
processing budget before correlation or any external write, closing replay of an older valid
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
and reviewed foundation resource group. Complete syntactic parsing closes malformed prefixes,
provider/type aliases, suffixes, duplicate separators, encoded/query/fragment forms, and
cross-scope substitution. A guarded nested deployment resolves each expected ID with ARM
`reference(..., 'Full').id`; readiness requires exact equality with that server-returned ID before
validating the referenced Job's complete configuration and identity surfaces.

The publisher configuration is rejected unless its authority Blob endpoint/container and
activation Table endpoint/name/partition exactly match the embedded feed runtime's read
locations. The publisher deployment derives those destinations from that runtime configuration.
Its authority writer has only Blob create permission, its activation writer has only Table entity
read/add/update permission, and its binding signer has only exact-key sign permission.
The publisher validates the ACR ID canonically and scopes its image-pull module to the exact parsed
registry subscription and resource group. It detects the registry permission mode and selects
`AcrPull` only for legacy RBAC registries or `Container Registry Repository Reader` for
ABAC-repository-permissions registries. Every ABAC Repository Reader assignment uses condition
version `2.0` and the documented request repository-name attribute with
`StringEqualsIgnoreCase` against the one exact repository derived from the digest-pinned image.
ABAC assignment identity includes that repository; legacy `AcrPull` retains the
registry/principal/role seed and null condition fields. The module outputs, publisher
configuration, and readiness evidence carry the same explicit `anonymousPullEnabled=false`
readback, canonical repository, and condition bytes as PR #102. A digest pull cannot prove the
managed identity when anonymous access is enabled, so the readiness probe performs live
management-plane registry and user-assigned-identity readbacks before and after the pull using the
unchanged operator context and an isolated managed-identity CLI profile. The live identity
resource must return the exact resource, client, and principal IDs used for the scan, Docker login,
publisher configuration, and Job registry binding.

Root readiness additionally requires the authoritative PR #103 effective-assignment proof across the
tenant root management-group hierarchy. Every descendant subscription is enumerated, direct group
membership is traversed recursively twice without the eventual transitive-membership index, and
the two closures must converge. Full role definitions are then resolved for every direct,
inherited, group-derived, and active time-bound/PIM assignment in every subscription. For each
service principal and recursively discovered group, the scanner follows the bounded, canonical
`roleAssignmentScheduleInstances` pages for the exact principal. Eligibility without an active
assignment schedule is not effective. Persistent role-assignment schedule mirrors are reconciled
through their canonical origin role-assignment ID and must match the underlying reviewed grant.
Any extra pull grant or escalation path—including
`roleAssignments/write`, role-assignment or eligibility schedule-request writes, role-management
policy administration, tenant access elevation, role-definition mutation, ACR credential
administration, quarantine reads or mutation, task execution/administration, update-policy
mutation, quarantined-artifact writes, custom roles, or a sibling registry in another
subscription—fails closed. The scanner verifies
every referenced registry's live permission mode, and the proof exact-matches each reviewed
assignment's principal, registry scope, role, condition version, and canonical repository
condition; legacy `AcrPull` accepts null condition fields only. The bounded publisher probe repeats
the complete scan after the pull and requires an identical evidence digest. The digest covers a
canonical completeness map for classic assignments, active PIM schedule instances, transitive
groups, sibling registries, escalation paths, exact readbacks, and enforced pagination budgets,
plus the exact numeric page, call, group, subscription, assignment, and schedule-instance limits.
Classic assignments use explicit bounded `roleAssignments@2022-04-01` REST pagination, so the
published API-call budget counts service pages rather than wrapper-command invocations. Consumers
require the exact case-sensitive property sets and summary sets derived from the three reviewed
assignments. PR #102 consumes this proof after rebase rather than owning another ACR classifier.
Request and feed
deployments also emit exact non-secret ACR binding JSON, and root readiness binds those two
reviewed assignments plus the publisher assignment to their live Job identities, deployment RBAC
sets, registries, and images instead of trusting labels or counts. Evidence older than five
minutes, generated after the trusted deployment evaluation instant, or lacking a final post-pull
scan is rejected. This allows the required later rebase and its governed legacy-assignment
migration to reconcile without semantic divergence. When PR #99's collector contract v10 becomes
the integration base, PR #103 consumes it only through shared `MonitoringCollectorContract`
construction/imports and the tests that pin `collectorContractDigest`. The rebase uses canonical
helpers, recomputes current digest-based fixtures, preserves PR #99's exact schema/version checks,
and leaves historical v9 fixtures unchanged. PR #99-owned Resource Health IaC and the reviewed
operation tuple remain outside this branch. None of that work changes or aliases this ACR evidence
contract.

## Consequences

- WC-026 request/report and WC-027 incident-subject contracts remain unchanged.
- New publication requests and activations use v2 shapes for the signed deadline and delivery
  fields. Original v1 signatures remain verifiable; v1 activation rows remain readable and
  materializable without rewriting their immutable payloads.
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
