# WC-027 guidance publication-request producer

**Operational date:** Tuesday, September 15, 2026

## Purpose

This is the first production runtime in the governed WC-027 authority chain:

```text
canonical signed IncidentBoundCorrelationRequest.v1
  -> verify nested signatures and published-runtime context
  -> read current signed lifecycle occurrence and active index
  -> verify exact immutable PublishedContextAuthority bytes
  -> deterministically build, sign, and self-verify GuidanceAuthorityPublicationRequest.v1
  -> create-or-recover immutable occurrence-keyed outbox evidence
  -> revalidate current lifecycle and context authority
  -> enqueue canonical request to wc027-guidance-authority-requests
```

It is deliberately separate from the guidance-authority publisher. It never creates or activates
`PublishedGuidanceAuthorityBinding.v2`, never triggers enrichment, never executes an action, and
never fabricates correlation or occurrence evidence. `noAutoRemediation` remains true throughout
the input and output broker bindings.

## Input contract and queue

The private input queue is `wc027-guidance-publication-inputs`. It is session-enabled and
duplicate-detecting. The body must be the exact canonical JSON bytes of
`athena.wc027IncidentBoundCorrelationRequest.v1`.

Required metadata:

| Field | Required value |
|---|---|
| Content type | `application/json` |
| Message ID | signed incident-bound `requestId` |
| Session ID | signed incident ID |
| `schemaVersion` | `athena.wc027IncidentBoundCorrelationRequest.v1` |
| `bindingDigest` | signed incident-bound request digest |
| `incidentSubjectDigest` | signed subject digest |
| `correlationRequestDigest` | nested correlation request digest |
| `contextAuthorityDigest` | nested published-context authority digest |
| `noAutoRemediation` | `true` |

Only explicitly supplied upstream identities receive sender access to this queue. The repository
does not expose a direct authority-request submit command: production requests must carry verified
immutable outbox evidence and arrive through the dedicated request-producer sender identity.

## Verification and deterministic request construction

Before any output write, the worker:

1. parses exact canonical bytes and rejects unknown or noncanonical input;
2. rejects stale correlation requests and all draft-preview context;
3. verifies the incident-state and incident-subject signatures against the configured exact
   lifecycle key version;
4. verifies the incident-bound request signature against the exact correlation-binding key
   version;
5. reads the current signed incident pointer, state, occurrence receipt, and active index from
   `incident-assets` and requires logical and physical key bindings, exact occurrence equality,
   and active-index coherence;
6. reads the exact version-pinned `PublishedContextAuthority` from `context-authority` and requires
   canonical bytes, reference digest, manifest/profile/dependency/context payload, publication
   record, and audit-head equality; and
7. derives `evaluatedAt` as the maximum signed publication/trust time and bounds request expiry to
   the earlier of five minutes or the latest instant whose derived `finishBefore` does not exceed
   the nested correlation expiry.

The request-signing identity has exact-key sign-only RBAC. A distinct identity reads the exact
public key and immediately verifies the normalized detached signature before any outbox write.

## Immutable outbox and enqueue

The producer persists:

```text
guidance-publication-requests/{occurrenceId}/request.json
```

in the isolated `wc027-guidance-request-outbox` container. The create-only writer cannot read,
list, overwrite, tag, move, or delete. A separate recovery reader has exact Blob read permission
with `Blob.List` denied. The deployment fails closed unless Blob versioning is already enabled on
the outbox account, because create and recovery both require one exact version ID.

The occurrence-keyed path means:

- identical retries recover the same exact request and version;
- a different requested action set, expiry, key, or any other request bytes for the same signed
  occurrence fail closed; and
- concurrent workers converge on one request identity.

Immediately before persistence and again immediately before enqueue, the worker consults its
trusted clock and preserves the reviewed 150-second upstream minimum: 30 seconds each for
publisher KEDA polling, cold start, and managed-identity Service Bus setup plus 60 seconds for
publisher processing. A request below the boundary is abandoned without reserving or writing its
occurrence-keyed outbox path. If revalidation or producer sender setup consumes the budget, the
persisted request is not sent and the input is abandoned. A request with exactly 150 seconds
remaining is eligible to persist and send. If the signed correlation window cannot cover that
minimum plus the complete downstream `finishBefore` extension, production fails closed without an
outbox write. After persistence, the worker revalidates lifecycle and context authority,
establishes the managed-identity Service Bus sender, resamples the trusted clock, and only then
constructs/sends the message. The signed request carries one absolute `finishBefore` deadline,
which the activation must copy unchanged and which can never outlive the nested correlation
expiry. The request hop uses
`floor(finishBefore - now - downstreamMargin)`, where the downstream margin reserves publisher
processing, the full feed phase, and delivery jitter. Sender creation cannot complete the input
delivery. The request is sent to the existing
`wc027-guidance-authority-requests` queue with a distinct sender identity:

| Field | Value |
|---|---|
| Message ID | deterministic `requestId` |
| Session ID | signed incident ID |
| TTL | `floor(finishBefore - now - downstreamMargin)`, bounded by the ten-minute request queue |
| Body | exact canonical request bytes |
| Metadata | request, occurrence, incident-state, context-authority, version-pinned outbox, exact 30/30/30/60/150-second publisher and feed phase sets, the 300-second trigger-recovery allowance, the preserved 150-second upstream minimum, and `noAutoRemediation=true` |

If send completion is uncertain, the input delivery is abandoned. A retry recovers identical
outbox bytes and sends the same `MessageId`; Service Bus duplicate detection safely suppresses a
prior successful send. Budget exhaustion is retryable without output I/O; once the signed input is
actually stale, the same delivery is rejected rather than completed. Producer completion,
abandon, and rejection settlement is lock-aware and bounded to one attempt. Message-lock loss,
already-settled messages, and Service Bus or transport settlement uncertainty return a deterministic
result (`already-settled`, `message-lock-lost`, `session-lock-lost`, or `unconfirmed`) instead of
crashing the Job. An uncertain completion is never followed by abandon or dead-letter.
The authority publisher uses the same one-disposition rule for completion and rejection
settlement.
The runtime minimum is `azure-servicebus>=7.14.3`, and the reviewed lock resolves `7.14.3`.
Regression tests assert both versions and the SDK inheritance contract:
`MessageAlreadySettled` is a `ValueError`, while message/session lock-loss exceptions are
`ServiceBusError` subclasses.

## Deployment and identities

`infra/wc027-guidance-publication-request-producer/main.bicep` deploys:

- the minimal private input queue and receiver RBAC;
- the dedicated output sender identity and exact publisher queue handoff;
- exact no-list readers for `incident-assets`, `context-authority`, and request outbox recovery;
- create-only outbox writer RBAC;
- one shared upstream exact-public-key reader for the incident and correlation-binding keys;
- separate exact-key request signer and request public-key reader identities;
- ACR pull for the event-trigger identity, deployed at the exact validated subscription and
  resource group parsed from `registryResourceId`; ABAC-mode Repository Reader assignments use
  condition version `2.0` and the shared canonical exact repository-name expression derived from
  the digest-pinned image, while legacy registries retain unconditioned `AcrPull`;
- generated non-secret strict configuration and deterministic RBAC evidence; and
- a publisher handoff containing the existing output queue, sender identity, exact request key
  binding, producer Job resource ID, and configuration digest.

The module derives the complete identity boundary from the embedded enrichment-runtime
configuration and its deployment binding. None of the receiver, sender, source reader, outbox
reader/writer, upstream trust reader, request signer, or request verifier identities may intersect
that runtime boundary. Resource IDs are normalized before uniqueness and overlap checks so casing
aliases cannot bypass the separation.

The strict producer, publisher, and enrichment/feed configurations carry the same reviewed
delivery budget. Broker metadata binds every phase. After publisher cold start and Service Bus
setup, the publisher requires the exact 60-second processing phase before creating authority and
the reviewed CAS margin immediately before commit. A fresh trusted-clock guard also runs directly
before each immutable authority write, immutable binding write, activation CAS, and trigger send.
The signed activation establishes one independent `finishBefore` deadline derived
deterministically from request expiry, the 300-second recovery allowance, the 150-second feed
phase, and a 30-second delivery-jitter margin, while remaining at or before the nested correlation
expiry. It is the durable trigger outbox and binds the immutable binding reference, deterministic
trigger `MessageId`, `triggerDeliveryPending=true`, all budget components, and `finishBefore`.
After CAS, the publisher submits that exact message to the duplicate-detecting feed queue. A
definite or uncertain send failure abandons the publisher request; replay may continue after the
request itself expires, reads the same activation and exact binding version, and resubmits the same
`MessageId` without another CAS. Each trigger TTL is
`floor(finishBefore - now - feedProcessingMargin)`. An uncertain CAS that actually committed is
recovered in the same way. The publisher completes its input only after trigger submission
returns. The feed checks the processing reserve at start and threads one trusted-clock guard down
to every irreversible operation: each enrichment artifact create/recover, feed pointer and
attestation create/recover, registry capacity/update transaction, feed-index attestation and index
CAS, activation-materialization CAS, expiry-prune transaction, and notification send.

The activation Table row separately stores a CAS-protected delivery status. New activations remain
`pending` after confirmed or uncertain trigger submission so publisher replay can resend the
identical duplicate-detected message until the feed is durably materialized. Only the feed runtime,
after the exact feed pointer, attestation, registry record, and feed index are present and the
deterministic notification has been durably enqueued, may conditionally update the same activation
row to `materialized`. A later publisher-input retry that reads `materialized` completes without
another trigger send. If notification or marker persistence is uncertain, the row remains
recoverable and the same feed and notification identities replay idempotently. The runtime
identity has only Table entity read/update permission for this marker—no add, delete, or table
administration.
Rows written by the previously published implementation with `triggerDeliveryStatus=submitted`
are read as recoverable `pending` rows, so the upgrade neither dead-letters nor strands existing
activations before the feed proves materialization. Previously signed requests whose stored
`finishBefore` exceeded their nested correlation expiry are accepted only through the same trusted
signature path; all operational TTL, freshness, and write checks use the earlier nested expiry as
their effective deadline. The occurrence-keyed outbox remains authoritative: after that effective
deadline, a different request cannot renew the same occurrence. A new signed incident occurrence
is required, preserving immutable request and feed-registry identity.

Publisher settlement distinguishes permanent from transient outcomes. A different immutable
activation for the same occurrence, or an exhausted effective trigger-recovery deadline, is
lock-aware dead-lettered once as `AthenaWc027GuidanceAuthorityTerminal`. ETag races, source
unavailability, and transport uncertainty remain retryable and are abandoned once under the
existing one-disposition settlement rule.

Deploy the authority publisher first with the dedicated producer sender identity as the only
value in `requestSubmitterIdentityResourceIds`; the queue-owning publisher module grants that
singleton queue-scoped sender role. Give the publisher a separate no-list outbox-reader identity
and the same versioning-enabled outbox storage account. Its outputs expose the exact request queue
resource ID plus logical key ID, versioned Key Vault URI, fingerprint, key resource ID, and outbox
location. Pass those values unchanged to the request-producer module, then use
`publisherHandoffJson` and both generated configuration digests as the reviewed cross-deployment
handoff.

The image is built from
`apps/guidance-publication-request-producer/Dockerfile`, pins both Dockerfile frontend and Python
base image digests, installs the hashed dependency lock, and runs as UID/GID `10001`.

## Readiness

Keep all three gates false after code delivery:

```text
wc027RequestProducerReady=false
wc027PublisherReady=false
wc027FeedV2ProducerReady=false
```

The root live acceptance template checks the exact deployed request-producer Job,
user-assigned-only identity mode, exactly one reviewed container, digest-pinned image,
command/arguments, both environment values, resources, empty probe/init-container/volume/secret
and managed-identity lifecycle surfaces, complete replica and scaler settings, queue names,
registry identity, generated configuration, attached identities, configuration digest, and
deterministic RBAC evidence. It derives the request-producer, publisher-owned, delegated-runtime,
and runtime deployment identity sets and rejects every request-producer intersection. When both
jobs are asserted ready, it allows only the producer sender to appear as the publisher's separately
modeled request submitter and requires the publisher's queue plus logical/physical request-key
binding to match the producer. The complete feed-v2 chain cannot be marked ready unless both jobs
are ready.

Request-producer, authority-publisher, and feed-producer Job IDs must be canonical absolute ARM
IDs in the root deployment subscription and `foundationResourceGroupName`. Readiness rejects
prefix/provider/type aliases, missing components, child or suffix IDs, duplicate separators,
and query/fragment/encoding forms. A guarded nested deployment resolves each ID through
`reference(expectedId, '2025-01-01', 'Full').id`; readiness requires exact equality with that
server-returned ID before inspecting the referenced Job's configuration surfaces.

The authority publisher validates `registryResourceId` as one canonical
`Microsoft.ContainerRegistry/registries` ID. Both the existing registry reference and the
publisher ACR-pull module use the parsed subscription and resource-group scope, including reviewed
cross-subscription or cross-resource-group registries. The module reads the registry's
`roleAssignmentMode`: `LegacyRegistryPermissions` receives `AcrPull`, while
`AbacRepositoryPermissions` receives `Container Registry Repository Reader`. The deterministic
role-assignment GUID is seeded with the registry ID, managed-identity principal object ID, and
selected role-definition ID; ABAC mode additionally binds the derived repository name. The
assignment declares `principalType: ServicePrincipal`. Module outputs, publisher configuration,
and pull-readiness evidence carry the same repository, condition version, and condition bytes.
Legacy mode carries null condition fields. The later PR #102 integration rebase owns migration of
the prior unconditioned Repository Reader assignment and can reconcile this identical shared
module without semantic divergence.

Before setting publisher readiness, run
`infra/wc027-guidance-authority-publisher/Test-AcrDigestPullReadiness.ps1` on an Azure host that can
use the publisher's user-assigned identity. The script logs in with that identity using the
registry mode already server-validated by Bicep, performs an actual pull of the exact digest-pinned
image, verifies the resulting
`RepoDigest`, and retries only within the reviewed attempt/delay bounds for RBAC propagation.
Pass its compact JSON output unchanged as `wc027PublisherImagePullEvidenceJson`; the root gate
matches the registry, image, identity, mode, role, and bounded success evidence to the deployed
publisher configuration.

The publisher independently exact-reads every referenced outbox Blob version before invoking its
existing publication/activation service. Broker metadata without matching durable request bytes is
rejected.

Before setting `wc027RequestProducerReady=true`, confirm the deployed input submitter allowlist and
that the publisher request queue grants `Azure Service Bus Data Sender` only to the dedicated
request-producer sender identity used in the generated configuration.

## Failure handling

- Invalid canonical bytes, metadata, signature, key binding, draft context, freshness, occurrence,
  or context authority: dead-letter as `AthenaWc027GuidanceRequestRejected` with zero output I/O.
- Different request in an existing occurrence slot: dead-letter as
  `AthenaWc027GuidanceRequestConflict`.
- Current authority temporarily unavailable or changed, Blob uncertainty, Key Vault transport
  failure, insufficient pre-persistence lifetime, expiry during revalidation, or Service Bus
  uncertainty: abandon and retry.
- Producer completion/abandon settlement lock loss, already-settled state, or transport failure:
  contain the settlement error and return deferred/uncertain; redelivery recovers the same outbox
  bytes and deterministic broker identity.
- Publisher trigger-send or input-completion `ServiceBusError`: abandon only while the delivery or
  session lock remains valid. A retry reuses the same immutable request/activation identity and
  cannot create a second activation.
- Signer output that fails separate public-key verification: reject before persistence.

Never delete immutable outbox evidence to retry and never bypass the publisher activation path.
