# WC-027 enrichment and feed-v2 producer

## Purpose

This runtime turns one already-signed `PublishedGuidanceAuthorityBinding.v2` into the complete
WC-027 publication chain:

```text
signed binding
  -> verify signed current activation
  -> recompute and verify correlation
  -> enrichment report/guidance/manifest assets
  -> immutable feed pointer and attestation
  -> private registry admission
  -> signed incidents/feed-v2.json CAS
  -> Notification v2 enqueue
```

It never enumerates Blob storage and never accepts a bare incident ID, unsigned report, or
caller-selected asset prefix.

## Trigger contract

The Service Bus message body is the exact canonical JSON for
`athena.wc027PublishedGuidanceAuthorityBinding.v2`.

Required broker metadata:

| Field | Required value |
|---|---|
| Content type | `application/json` |
| Message ID | `bindingId` |
| Session ID | signed incident ID |
| `schemaVersion` | `athena.wc027PublishedGuidanceAuthorityBinding.v2` |
| `bindingDigest` | exact signed binding digest |

Submit an already-authoritative binding:

```powershell
athena-context wc027-enrichment-feed-submit `
  --binding .\published-guidance-binding.json `
  --service-bus-namespace <private-namespace>.servicebus.windows.net `
  --trigger-queue wc027-enrichment-feed-requests `
  --managed-identity-client-id <caller-managed-identity-client-id>
```

The submit command validates strict canonical JSON but does not create or approve guidance
authority. Production automation must obtain the binding from the separately governed publisher.

## Runtime configuration

The Container Apps Job receives non-secret JSON through
`ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON`. The module **generates** this JSON in Bicep from the
referenced resources - it is never accepted as an arbitrary parameter. Client IDs, principal IDs,
attached identity resource IDs, storage blob/table endpoints, container/table names, and versioned
Key Vault key URIs are all derived from the referenced user-assigned identities, storage account,
Service Bus namespace, and Key Vault keys. The strict configuration contains:

- private Service Bus namespace, trigger queue, notification queue, and broker identity;
- private read-only v1 lifecycle Blob source plus a distinct private enrichment/feed-v2
  Blob source with separate producer reader and writer identities;
- private Table endpoint, feed registry table/partition, and registry identity;
- four distinct exact-version correlation Blob source domains and reader identities:
  `wc024-monitoring/`, `change-evidence/`, `context-authority/`, and
  `monitoring-intent/`;
- exact guidance-authority Blob source;
- signed current guidance-activation Table source;
- the reviewed WC-028 v8 `MonitoringCollectorContract`, its exact canonical SHA-256 digest, and
  the exact deployed acquisition-authority digest accepted by production correlation;
- a deployment binding containing the exact resource IDs of every identity attached to the Job
  and the deterministic RBAC evidence ID generated from the deployed assignments;
- exact versioned Key Vault IDs, fingerprints, identity client IDs, and identity resource IDs for
  incident,
  correlation-binding, guidance-binding, monitoring collection, change evidence, monitoring
  intent, report, guidance, enrichment, feed, and notification trust domains; and
- the private presentation URL.

The parser rejects unknown fields, malformed endpoints, noncanonical identity IDs, reused
correlation reader identities/storage domains, and reused producer signing keys or identities.

## Deployment

`infra/wc027-enrichment-feed-runtime/main.bicep` deploys:

- one session-enabled, duplicate-detecting `wc027-enrichment-feed-requests` queue;
- one event-triggered Container Apps Job in the existing internal managed environment;
- exact trigger submitter, queue receiver, and Notification v2 queue sender roles;
- a distinct private `wc027-enrichment-feed-v2` container that isolates the enrichment and
  feed-v2 artifacts from the v1 incident lifecycle assets;
- a custom least-privilege data-plane role granting only blob create/read/write (no delete), with
  an ABAC condition that explicitly denies the `Blob.List` sub-operation, assigned to the v2
  writer identity;
- read-only `Storage Blob Data Reader` for the producer read-back identity on the v2 container and
  for the v1 incident-assets identity on `incident-assets`, each with the same explicit
  `Blob.List` denial (the producer never writes, deletes, or lists v1 lifecycle assets);
- a separately authorized presentation/gateway reader on the v2 container, also denied listing;
- feed registry Table contributor;
- Key Vault public-key reader;
- one exact-key Crypto User assignment for each report, guidance, enrichment, feed, and
  notification signer; and
- ACR pull for the broker identity.

Supply the referenced resource IDs/names (user-assigned identities, replay storage account,
correlation source storage account, Service Bus namespace, and Key Vault keys); the module derives
every runtime value from them. Supply the phase-two WC-024
`monitoringAcquisitionCollectorContract` output, its independently computed canonical digest, and
the exact deployed WC-028 acquisition-authority digest. Legacy v3 contracts are parse-only and
must be recollected and republished as v8 before this runtime can start. Supply
`runtimeConfigurationDigest` as the externally computed `sha256:<lowercase-hex>` digest of the
module's generated `deployedRuntimeConfigurationJson` output.
Record the `deployedRuntimeConfigurationDigest`, `attachedIdentityResourceIds`, and
`bindingEvidenceDigest` outputs, plus
`deployedMonitoringCollectorContractDigest` and
`deployedMonitoringAcquisitionAuthorityDigest`, with the Job resource ID for the root readiness
gate.

## Guidance-authority publisher

`infra/wc027-guidance-authority-publisher/main.bicep` deploys the separately governed production
publisher:

- a private, session-enabled, duplicate-detecting
  `wc027-guidance-authority-requests` queue;
- the existing `wc027-enrichment-feed-requests` trigger queue;
- an immutable `wc027-guidance-authority` Blob container;
- the `Wc027GuidanceActivation` Table;
- one event-triggered Container Apps Job with distinct broker, authority reader/writer,
  activation writer, request-trust reader, binding-trust reader, and binding-signer identities;
- a create-only authority Blob identity plus a separate exact-version readback identity;
- Table entity read/add/update RBAC for activation CAS with no entity-delete permission;
- exact-key public-key read/verify RBAC and exact-key sign-only binding RBAC; and
- generated strict configuration in
  `ATHENA_WC027_GUIDANCE_AUTHORITY_PUBLISHER_CONFIG_JSON`.

The request-signing key and binding-signing key are dedicated trust domains. Signed request,
binding, and activation artifacts contain stable logical key IDs; the generated deployment
configuration separately carries exact versioned Key Vault URIs. Lifecycle pointer/index
`keyId` checks use the logical lifecycle ID; lifecycle attestation verification uses the physical
versioned Key Vault URI.

Submit one canonical, already-signed publication request:

```powershell
athena-context wc027-guidance-authority-submit `
  --request .\guidance-authority-publication-request.json `
  --service-bus-namespace <private-namespace>.servicebus.windows.net `
  --request-queue wc027-guidance-authority-requests `
  --managed-identity-client-id <authorized-submitter-identity-client-id>
```

The publisher verifies the outer request and nested lifecycle, subject, and correlation-binding
signatures; confirms the exact current signed occurrence and active index; recomputes correlation;
create-or-recovers the deterministic authority and binding; signs and verifies binding and
activation; revalidates source authority before CAS and enqueue; and sends the same deterministic
binding ID to the feed queue. The initial implementation intentionally publishes only a
zero-option `noMatchingControl` authority.

All correlation source readers and upstream authority keys remain separately governed resources.
The module grants each configured reader only its exact container with `Blob.List` denied, and
grants the trust-reader identity only exact-key read/verify data actions on the configured
verification keys. Publisher authority and activation destinations are derived from the embedded
runtime configuration, and startup fails closed if either location differs from the runtime read
location. Do not grant workload Reader to the producer identities.

The job must be attached to every identity named in the runtime configuration. The Bicep module
rejects duplicate attached identity IDs/client IDs. Its image must be digest-pinned.

## Activation gate

Keep:

```text
wc027PublisherReady=false
wc027FeedV2ProducerReady=false
```

until all of the following are evidenced:

1. the publisher and producer Jobs and their exact generated configurations are deployed;
2. the trigger and notification queues are private and RBAC-only;
3. every source reader can read only its configured exact container;
4. each signing identity can use only its dedicated exact key;
5. a partial-write retry reaches the same immutable assets and registry row;
6. feed-v2 CAS reconciliation commits the exact entry; and
7. a stale or non-current binding is rejected by activation verification; and
8. the producer and publisher carry the same non-placeholder v8 collector-contract and
   acquisition-authority digests in their generated configuration and deployed Job tags; and
9. Notification v2 is observed only after the feed entry is verifiable.

Code delivery does not flip either readiness flag. To assert publisher readiness, supply
`wc027PublisherJobResourceId`, `wc027PublisherConfigurationDigest`, and
`wc027PublisherConfigurationJson`, and `wc027PublisherImage` from the deployed publisher module.
The root template reads the existing Job and fails closed unless the exact digest-pinned image,
command/arguments, scaler and registry identity, configuration value and digest tag, embedded
producer-runtime digest, attached identities, and deterministic RBAC binding evidence match.

To assert producer readiness, supply
`wc027EnrichmentFeedProducerJobResourceId` with the exact deployed `Microsoft.App/jobs` resource
ID, `wc027EnrichmentFeedProducerConfigurationDigest` and
`wc027EnrichmentFeedProducerConfigurationJson` from the producer module output. The root
deployment derives the expected attached identity resource IDs and RBAC evidence ID from that
exact deployed configuration; it does not accept independent identity arrays or evidence values.
It reads the existing Job and fails closed unless the deployed configuration value and digest
tag, monitoring contract and authority digest tags, derived broker identity, exact attached
user-assigned identities, and RBAC evidence tag all match, the publisher carries the same
monitoring trust values, the publisher is ready, and the WC-016 runtime is enabled.

## Failure and retry

- Transient absence of current occurrence/active-index authority: abandon and retry.
- Noncanonical, expired, signature-invalid, occurrence-mismatched, or replay-conflicting
  publication request: dead-letter as `AthenaWc027GuidanceAuthorityRejected` without publishing.
- Blob uncertainty, activation ETag conflict, or Service Bus uncertainty: abandon and retry.
  Immutable authority/binding bytes and the same activation are recovered only when exact.
- A changed signed occurrence, active index, correlation result, or activation between validation
  and enqueue fails closed. Never overwrite a different activation for the same occurrence.
- Blob/Table transport uncertainty, partial create, registry uncertainty, or feed CAS conflict:
  abandon and retry; existing bytes/records are accepted only when exact.
- Noncanonical, stale, mismatched, or untrusted signed binding: dead-letter as
  `AthenaWc027EnrichmentRejected`.
- Notification enqueue uncertainty: abandon the trigger. A retry reconstructs and verifies the
  feed and emits the same deterministic Notification v2 ID; Service Bus duplicate detection
  suppresses a prior successful enqueue.

Never delete partial immutable assets to retry. They are undiscoverable until the signed feed-v2
head includes the exact pointer.
