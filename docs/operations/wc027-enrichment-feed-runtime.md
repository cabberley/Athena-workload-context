# WC-027 enrichment and feed-v2 producer

## Purpose

This runtime turns one already-signed `PublishedGuidanceAuthorityBinding.v2` into the complete
WC-027 publication chain:

```text
signed binding
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
`ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON`. The strict configuration contains:

- private Service Bus namespace, trigger queue, notification queue, and broker identity;
- private incident Blob endpoint plus separate reader and writer identities;
- private Table endpoint, feed registry table/partition, and registry identity;
- four distinct exact-version correlation Blob source domains and reader identities:
  `wc024-monitoring/`, `change-evidence/`, `context-authority/`, and
  `monitoring-intent/`;
- exact guidance-authority Blob source;
- the reviewed `MonitoringCollectorContract`;
- exact versioned Key Vault IDs, logical key IDs, fingerprints, and identities for incident,
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
- incident Blob reader/writer roles;
- feed registry Table contributor;
- Key Vault public-key reader;
- one exact-key Crypto User assignment for each report, guidance, enrichment, feed, and
  notification signer; and
- ACR pull for the broker identity.

Supply `runtimeConfigurationDigest` as the externally computed `sha256:<lowercase-hex>` digest of
the exact UTF-8 `runtimeConfigurationJson`. Record the module's
`deployedRuntimeConfigurationDigest` output with the Job resource ID.

All correlation source readers and upstream authority keys are separately governed resources.
Grant each configured reader only `Storage Blob Data Reader` on its exact container. Grant the
configured change and monitoring-intent verifier only the exact Key Vault crypto verification
scope needed by those existing contracts. Do not grant workload Reader to the producer identities.

The job must be attached to every identity named in the runtime configuration. The Bicep module
rejects duplicate attached identity IDs/client IDs. Its image must be digest-pinned.

## Activation gate

Keep:

```text
wc027FeedV2ProducerReady=false
```

until all of the following are evidenced:

1. the producer Job and exact runtime configuration are deployed;
2. the trigger and notification queues are private and RBAC-only;
3. every source reader can read only its configured exact container;
4. each signing identity can use only its dedicated exact key;
5. a partial-write retry reaches the same immutable assets and registry row;
6. feed-v2 CAS reconciliation commits the exact entry; and
7. Notification v2 is observed only after the feed entry is verifiable.

When enabling the gate, also supply
`wc027EnrichmentFeedProducerJobResourceId` with the exact deployed
`Microsoft.App/jobs` resource ID and
`wc027EnrichmentFeedProducerConfigurationDigest` from the producer module output, plus the exact
`wc027EnrichmentFeedProducerConfigurationJson`. The root deployment reads the existing Job and
fails if its configuration environment value or digest tag differs, or if the WC-016 runtime is
not enabled.

## Failure and retry

- Missing current occurrence or active-index authority: abandon and retry.
- Blob/Table transport uncertainty, partial create, registry uncertainty, or feed CAS conflict:
  abandon and retry; existing bytes/records are accepted only when exact.
- Noncanonical, stale, mismatched, or untrusted signed binding: dead-letter as
  `AthenaWc027EnrichmentRejected`.
- Notification enqueue uncertainty: abandon the trigger. A retry reconstructs and verifies the
  feed and emits the same deterministic Notification v2 ID; Service Bus duplicate detection
  suppresses a prior successful enqueue.

Never delete partial immutable assets to retry. They are undiscoverable until the signed feed-v2
head includes the exact pointer.

## Remaining upstream contract gap

No merged production component currently publishes
`PublishedGuidanceAuthorityBinding.v2` into the trigger queue. This runtime deliberately does not
invent that authority. Keep the activation gate false until the separately governed publisher is
implemented or an operator supplies an already-signed, exact binding through the submit command.
