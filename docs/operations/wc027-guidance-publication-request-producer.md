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
7. derives `evaluatedAt` as the maximum signed publication/trust time and bounds expiry to the
   earlier of five minutes or the nested correlation expiry.

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

After persistence, the worker revalidates lifecycle and context authority, then sends to the
existing `wc027-guidance-authority-requests` queue with a distinct sender identity:

| Field | Value |
|---|---|
| Message ID | deterministic `requestId` |
| Session ID | signed incident ID |
| TTL | remaining bounded request lifetime, at most five minutes |
| Body | exact canonical request bytes |
| Metadata | request, occurrence, incident-state, context-authority, and version-pinned outbox bindings plus `noAutoRemediation=true` |

If send completion is uncertain, the input delivery is abandoned. A retry recovers identical
outbox bytes and sends the same `MessageId`; Service Bus duplicate detection safely suppresses a
prior successful send.

## Deployment and identities

`infra/wc027-guidance-publication-request-producer/main.bicep` deploys:

- the minimal private input queue and receiver RBAC;
- the dedicated output sender identity and exact publisher queue handoff;
- exact no-list readers for `incident-assets`, `context-authority`, and request outbox recovery;
- create-only outbox writer RBAC;
- one shared upstream exact-public-key reader for the incident and correlation-binding keys;
- separate exact-key request signer and request public-key reader identities;
- ACR pull for the event-trigger identity;
- generated non-secret strict configuration and deterministic RBAC evidence; and
- a publisher handoff containing the existing output queue, sender identity, exact request key
  binding, producer Job resource ID, and configuration digest.

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

The root live acceptance template checks the exact deployed request-producer Job, digest-pinned
image, command, scaler, queue names, registry identity, generated configuration, attached
identities, configuration digest, and deterministic RBAC evidence. When both jobs are asserted
ready, it requires the publisher's queue plus logical/physical request-key binding to match the
producer. The complete feed-v2 chain cannot be marked ready unless both jobs are ready.

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
  failure, or Service Bus uncertainty: abandon and retry.
- Signer output that fails separate public-key verification: reject before persistence.

Never delete immutable outbox evidence to retry and never bypass the publisher activation path.
