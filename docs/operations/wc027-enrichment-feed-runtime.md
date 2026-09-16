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
- the reviewed `MonitoringCollectorContract`;
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
- the empty private `wc027-guidance-authority` source container needed to establish the producer
  reader boundary before the separately governed publisher receives create-only access;
- Key Vault public-key reader;
- one custom exact-key sign-and-verify role for each report, guidance, enrichment, feed, and
  notification signer, with no key read, encrypt, decrypt, wrap, unwrap, release, update, or
  delete actions; and
- ACR pull for the broker identity.

Supply the referenced resource IDs/names (user-assigned identities, replay storage account,
correlation source storage account, Service Bus namespace, and Key Vault keys); the module derives
every runtime value from them. Supply `runtimeConfigurationDigest` as the externally computed
`sha256:<lowercase-hex>` digest of the module's generated `deployedRuntimeConfigurationJson` output.
Record the `producerImage`, `deployedRuntimeConfigurationDigest`,
`attachedIdentityResourceIds`, `bindingEvidenceDigest`, exact queue IDs, and exact
container/table IDs with the Job resource ID for the root readiness gate. The producer root
creates no guidance-authority bytes and grants no authority writer role.

Deployment verification derives an exact assignment-ID-to-principal, scope, role-definition, and
condition mapping for every RBAC assignment emitted by both WC-027 roots. Each custom role is also
bound to exact per-assignment `actions`, `notActions`, `dataActions`, and `notDataActions` sets, so
a sign-only role cannot replace a verification role and a verification role cannot replace the
binding signer. Principal swaps and any extra, missing, differently conditioned, or permission-
swapped assignment fail closed. Every assignment whose resolved role permissions include Blob read
— including the custom feed-v2 writer role — must retain condition version `2.0` and the exact
canonical no-`Blob.List` expression; absent, altered, or duplicated condition forms fail closed.
Effective RBAC includes every transitive Microsoft Entra group membership and each group’s direct,
descendant, and inherited assignments; incomplete membership or assignment pagination fails
closed. It also requires the producer trigger, publisher request, and notification outbox queues
to be `Active`, non-forwarding, explicitly non-auto-deleting, and to match their exact
stage-specific session, duplicate-detection window, TTL, lock, delivery-count, capacity, batching,
partitioning, and message-size profiles.

The deployment output validator parses the generated producer JSON through
`Wc027EnrichmentFeedProductionConfiguration` and the publisher JSON through
`Wc027GuidanceAuthorityPublisherConfiguration` before accepting any partial output projection.
Both Python and WC-013 Bicep readiness also require scaler metadata to contain exactly
`namespace`, `queueName`, `messageCount`, `cloud`, and `isSessionsEnabled`; legacy
`activationMessageCount` and every other extra field fail closed.

Every configured Key Vault trust anchor is read back by its exact versioned `kid`. Verification
reads the current key by vault and name and requires that same response's `kid` to equal the
reviewed version exactly. It then requires RSA public material, the reviewed 3072-bit size (and
never less than 2048 bits), canonical base64url modulus and exponent, exact `sign`/`verify` key
operations, and an SPKI DER SHA-256 fingerprint equal to the configured `keyFingerprint`. Missing
public material, EC keys, version drift, wrong fingerprints, or extra/missing key operations fail
before readiness.

The guidance-authority storage account must have Blob versioning enabled. Each reviewed
`athena.wc029DeploymentPlan.v6` records a digest-chained authority checkpoint. One
version-inclusive listing supplies exact case-sensitive names, version IDs, ETags, and lengths.
Every newly observed exact version is downloaded, SHA-256 hashed, and validated as the canonical
published authority or binding contract. Prior versions and digests must remain byte-identical;
overwrites, deletions, orphan authorities, bindings that reference the wrong authority version, or
any other non-append-only change fail closed. A fresh producer deployment must prove the container
absent and then create an empty versioned container. Every pre-existing producer container,
including an empty one, requires prior same-stage evidence. Publisher recovery, producer upgrade,
and live acceptance review an append-only successor of the receipt-carried checkpoint rather than
requiring equality with the original deployment snapshot.

For a producer upgrade or publisher recovery, pass the independently reviewed prior same-stage
handoff and receipt. The new plan reads each reviewed artifact once, verifies the exact historical
deployment scope and predecessor-receipt lineage, and carries its post-deployment checkpoint
forward; it cannot approve out-of-band content merely by observing it again. If fresh producer
deployment succeeds before RBAC/readback convergence, the same reviewed plan can use the bounded,
read-only `--resume-succeeded-deployment` path to re-attest the exact deployment and empty
versioned container before issuing the missing receipt; it never creates or deletes resources.

Upgrades from the earlier built-in Key Vault Crypto User assignments use a separate reviewed
same-principal migration list. Supply each of the five exact legacy deterministic assignment IDs
with `--legacy-crypto-user-migration-assignment` during producer planning. Planning requires the
listed assignments to be present and exact; controlled operator revocation must remove them before
`apply`, and producer/publisher/live-acceptance verification independently confirms that none of
the five deterministic legacy IDs remains. The orchestrator never deletes them.

For WC-029 deployment, do not deploy this root as an untracked side step. Use the governed
foundation -> producer -> publisher -> live-acceptance sequence in
[`wc029-deployment-live-validation.md`](wc029-deployment-live-validation.md). The orchestration
tool binds this root to the exact WC-013 foundation outputs, verifies that its generated
configuration digest hashes the deployed JSON, proves the referenced identities, versioned keys,
feed/activation storage, and empty private guidance-authority container exist, and emits the only
producer handoff plus reviewed deployment receipt accepted by the publisher and final WC-013
gate. The publisher root must consume the exact producer configuration, correlation-storage
boundary, and guidance-binding key resource from that handoff, while independently verifying the
receipt digest and its referenced plan, rather than accepting independently selected replacements.

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
- publisher ACR pull deployed in the exact registry resource group derived from
  `registryResourceId` (`rg-athena-platform-dev` in the fixed topology), rather than in the runtime
  resource group;
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

The merged production publisher does publish the resulting exact
`PublishedGuidanceAuthorityBinding.v2` to `wc027-enrichment-feed-requests`: the worker consumes the
signed publication request, creates and verifies the binding and activation, and uses the
publisher broker identity to send the canonical binding to the producer trigger queue. There is
still no automatic production component that constructs and submits
`GuidanceAuthorityPublicationRequest.v1`. The command above is the bounded operator invocation
boundary for an already-authoritative signed request.

The WC-029 deployment orchestrator validates the exact shared trigger queue plus the publisher
broker's sender assignment, but it does not mint, sign, or submit a publication request and does
not claim that a runtime invocation occurred. Its final deployment handoff records
`runtimeInvocationValidated=false`; end-to-end acceptance requires the separate bounded invocation
and signed readback evidence described in the WC-029 runbook.

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

## Deployment activation and runtime acceptance

Keep:

```text
wc027PublisherReady=false
wc027FeedV2ProducerReady=false
```

until the deployment-wiring conditions are evidenced:

1. the publisher and producer Jobs and their exact generated configurations are deployed;
2. the trigger and notification queues are private and RBAC-only;
3. every source reader can read only its configured exact container;
4. each signing identity can use only its dedicated exact key; and
5. the publisher broker has the exact sender assignment on the producer trigger queue.

After those checks, the WC-029 deployment activation stage may set both flags true to enable one
bounded runtime invocation. The flags mean **deployment wiring is ready**; they do not mean
end-to-end behavior has completed. WC-029 runtime acceptance still requires:

1. a partial-write retry reaching the same immutable assets and registry row;
2. feed-v2 CAS reconciliation committing the exact entry;
3. a stale or non-current binding being rejected by activation verification; and
4. Notification v2 being observed only after the feed entry is verifiable.

Code delivery alone does not flip either readiness flag. To assert publisher deployment
readiness, supply
`wc027PublisherJobResourceId`, `wc027PublisherConfigurationDigest`, and
`wc027PublisherConfigurationJson`, and `wc027PublisherImage` from the deployed publisher module.
The root template reads the existing Job and fails closed unless the exact digest-pinned image,
command/arguments, scaler and registry identity, configuration value and digest tag, embedded
producer-runtime digest, attached identities, and deterministic RBAC binding evidence match.

To assert producer readiness, supply
`wc027EnrichmentFeedProducerJobResourceId` with the exact deployed `Microsoft.App/jobs` resource
ID, `wc027EnrichmentFeedProducerConfigurationDigest` and
`wc027EnrichmentFeedProducerConfigurationJson`, and
`wc027EnrichmentFeedProducerImage` from the producer module output. The root
deployment derives the expected attached identity resource IDs and RBAC evidence ID from that
exact deployed configuration; it does not accept independent identity arrays or evidence values.
It reads the existing Job and fails closed unless provisioning state, managed environment, image,
single container, command, arguments, scaler, registry, deployed configuration value and digest
tag, derived broker identity, exact attached user-assigned identities, and RBAC evidence tag all
match. Init containers, volumes, probes, secret-backed environment or registry/scaler
authentication, workload profiles, alternate triggers, and unreviewed identity settings are
rejected. The publisher must be ready and the WC-016 runtime must be enabled.

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
- Publisher deployment recovery, publisher retry, and later producer upgrades may encounter the
  already-created publisher sender assignment on `wc027-enrichment-feed-requests`. Producer
  verification enumerates the complete direct assignment set at that queue. It accepts only current
  producer assignments, the deterministic current publisher assignment, and up to four exact
  retired queue assignment/principal pairs explicitly approved with
  `--rotation-transition-assignment <assignment-id> <retired-principal-id>`. The same reviewed
  transition model covers every other
  deterministic assignment affected by identity rotation, including notification and publisher
  queues, exact keys, Blob containers, Tables, and ACR. Planning proves every approved retired
  assignment is present for the exact reviewed retired principal and conforms to an approved
  role/condition profile; controlled operator revocation then removes the stale grant.
  Post-deployment readiness rejects that retired principal. When a same-name UAMI recreation
  deterministically reuses the assignment ID, it is accepted only for the exact current principal,
  role, scope, type, condition, and custom permissions. The orchestrator performs no automatic RBAC
  deletion and allows no broad publisher exemption.

Never delete partial immutable assets to retry. They are undiscoverable until the signed feed-v2
head includes the exact pointer.
