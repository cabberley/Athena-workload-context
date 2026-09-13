# ADR 0038: Trigger WC-027 enrichment from the signed guidance binding

- **Status:** Proposed
- **Date:** 2026-09-13

## Context

ADRs 0032 and 0035 define the enrichment and feed-v2 publication services, but neither defines a
durable runtime trigger. The process-local `VerifiedCorrelationReport` receipt cannot cross a
queue or restart boundary. Accepting a bare incident ID, Blob prefix, unsigned report, or unsigned
set of references would let a caller choose authority outside the contracts already verified by
the publication service. Blob enumeration is also prohibited as lifecycle discovery.

Notification v2 must remain silent until the exact enrichment pointer is durably admitted to the
registry and present in the committed or reconciled signed feed-v2 index.

## Decision

The runtime accepts only canonical bytes of the existing signed
`PublishedGuidanceAuthorityBinding.v2` as its Service Bus message body. The broker metadata binds:

- `messageId` to the deterministic guidance binding ID;
- `sessionId` to the incident ID; and
- application properties to the exact schema version and binding digest.

The binding is the narrowest existing contract that carries:

- the signed incident subject and incident-bound correlation request;
- the exact version-pinned correlation evidence and published context authority;
- the deterministic correlation report;
- the exact version-pinned guidance authority; and
- the signed guidance selection and evaluation time.

The worker does not trust the queued report as a reusable verified result. It creates one
production `CorrelationService`, rereads every exact version-pinned correlation input, verifies
the configured authorities, and recomputes the report synchronously. The same service instance
then supplies the process-local verification receipt to
`IncidentEnrichmentPublicationService`.

Before publication, the worker independently reads the signed v1 current occurrence and active
index and reconstructs `IncidentPublicationReceipt`. The runtime then executes:

1. correlation recomputation and validation;
2. six-stage enrichment create-or-recover publication;
3. immutable feed pointer and attestation publication;
4. exact registry admission and durable reread;
5. signed feed-v2 index compare-and-swap or verified-winner reconciliation; and
6. Notification v2 construction and enqueue.

Notification enqueue is unreachable until step 5 returns an
`IncidentEnrichmentFeedPublicationReceipt`. Retries repeat the whole sequence, relying on exact
byte recovery, registry equivalence, feed-index reconciliation, deterministic notification IDs,
and Service Bus duplicate detection. Missing current authority is retried. Stale, mismatched,
non-canonical, or untrusted bindings fail closed.

The deployment uses separate managed identities for the four correlation source readers, the
incident reader, enrichment/feed writer, feed registry writer, public-key reader, broker, and each
report, guidance, enrichment, feed, and notification signer. The five producer signing keys and
identities must be pairwise distinct. Storage, Table, Key Vault, Service Bus, and Container Apps
traffic remains on the existing private endpoint/DNS boundary.

`wc027FeedV2ProducerReady` remains false by default. Setting it true also requires the exact
deployed `Microsoft.App/jobs` resource ID, the deployed configuration digest, the WC-016 runtime,
completed external source RBAC, and healthy retry/reconciliation evidence.

## Consequences

- No unsigned incident ID or Blob listing can trigger enrichment.
- A queued report cannot bypass production correlation verification.
- Partial enrichment, pointer, registry, or feed-index writes are recoverable without an early
  notification.
- The producer can be deployed dormant while Notification v2 remains disabled.
- The repository still has no automatic publisher for
  `PublishedGuidanceAuthorityBinding.v2`. Until the separately governed guidance-authority
  publisher submits this exact signed contract, operators may use the bounded submit CLI only with
  an already-authoritative binding. The runtime does not mint or weaken that authority.

## Alternatives considered

- **Queue an incident ID:** rejected because it is unsigned and does not pin correlation or
  guidance authority.
- **Queue `VerifiedCorrelationReport`:** rejected because its HMAC receipt is intentionally
  process-local.
- **Discover pending enrichments by Blob listing:** rejected because Blob enumeration is not
  lifecycle authority.
- **Enqueue notification from the WC-016 orchestrator and wait for feed lag:** rejected because it
  permits notification orchestration to race the producer rather than making feed success the
  causal gate.

## Validation

- Deterministic ordering tests prove correlation, enrichment, feed commit, then notification.
- Missing and stale authority tests prove zero writes and zero notification.
- Partial feed writes recover on retry.
- Feed-index failure never reaches notification.
- Bicep validation asserts sessions, duplicate detection, identity separation, scoped RBAC, and
  the deployment-evidence gate.
