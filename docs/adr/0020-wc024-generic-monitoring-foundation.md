# ADR 0020: Isolate generic monitoring evidence from context and presentation runtimes

- **Status:** Proposed
- **Date:** 2026-09-06
- **Amended:** 2026-09-16

## Context

WC-024 establishes a reusable monitoring substrate for the reviewed demo workload. It must collect
generic AMA and VM Insights telemetry, VNet flow logs, Traffic Analytics evidence, and later
Connection Monitor results without allowing a Context API, Context MCP, presentation, or
correlation process to acquire broad monitoring access. Monitoring configuration must not derive
endpoint paths, thresholds, or other desired state from an unpublished context. Read-only
reconciliation established that the workload already has an AMA deployment, an
`athena-hackathon-law` workspace, `athena-hackathon-linux-dce`,
`athena-hackathon-linux-dcr`, and an `athena-linux-dcr` VM association. The DCR contains the
required `Custom-AthenaJson` to `Custom-AthenaApp_CL` custom log flow. At reconciliation, the
workspace was actively ingesting Heartbeat, Perf, InsightsMetrics, Syslog, AthenaApp_CL, and
NTANetAnalytics within minutes. All 11 workload VMs had successful AzureMonitorLinuxAgent
deployment and the `athena-linux-dcr` DCR association. This is a cutover baseline, not a
substitute for post-change verification.
The adopted workspace's reconciliation baseline is 30-day retention,
`workspaceCapping.dailyQuotaGb` of `-1`, and `features.disableLocalAuth` set to `true`; the DCE
and workspace have existing tags that are not generic WC-024 tags.

The legacy `athenahackathonflowwhtco` account contains retained flow-log evidence. Replacing it in
place would risk evidence loss and would couple cleanup to a new foundation deployment. Its active
flow logs operate with Shared Key disabled.

## Decision

WC-024 adopts the existing `athena-hackathon-law`, `athena-hackathon-linux-dce`, and
`athena-hackathon-linux-dcr` resources through parameterized defaults rather than creating
parallel resources. The DCR is declared only as an existing resource: WC-024 does not PUT it,
which preserves its `Custom-AthenaJson` to `Custom-AthenaApp_CL` data flow and all existing tags.
The existing `rg-athena-demo-monitoring` resource group is likewise a deployment scope rather than
a resource PUT, so the foundation cannot replace its established tags.
The existing `athena-linux-dcr` DCR association is read without being rewritten for the exact,
case-insensitively distinct set of 11 named, already AMA-enabled VMs:
`athena-hackathon-client-01`, `athena-hackathon-ecp-01` through
`athena-hackathon-ecp-03`, `athena-hackathon-iris-01`,
`athena-hackathon-mid-01` and `athena-hackathon-mid-02`,
`athena-hackathon-sqlvm-01`, and `athena-hackathon-web-01` through
`athena-hackathon-web-03`. A dedicated prerequisite
validation deployment reads each association's `dataCollectionRuleId`, compares it to the adopted
DCR resource ID, and must complete before any DCE association PUT can occur. WC-024 does not rewrite
the existing DCR binding. Deployment fails closed if any association is missing or does not reference
the reviewed DCR. The template instead creates a
distinct `configurationAccessEndpoint` association on each approved VM whose properties contain
only the adopted private DCE ID. It neither installs AMA nor creates a duplicate DCR association.

WC-024 adds two isolated Azure Monitor Private Link Scopes, monitoring-owned replacement storage,
private endpoints, separate workload and collector private DNS boundaries, and one collector-only
managed identity. AMPLS creation is a separate one-time bootstrap deployment with explicit Open
access modes. Its wrapper processes each scope independently: an exact existing Open scope with no
exclusions is retained, a missing scope is created, and any other lookup failure or existing state
fails closed. The steady-state foundation always declares both scopes as existing, links the same reviewed
LAW and DCE to each, fails closed if either is absent, and never PUTs Open access modes. Therefore
the phase-two PrivateOnly update is persistent and an ordinary later foundation deployment cannot
reopen either scope. It validates all 11 adopted DCR associations before deploying either AMPLS
private endpoint and private DNS zone group. Each DNS boundary is populated through its local
private-endpoint zone group before being linked to its sole VNet. This prevents empty private zones
from overriding Azure Monitor DNS and prevents collector Blob/Key Vault records from being exposed
to the workload network. Public access remains unchanged by default, and both new AMPLS resources
remain open during the initial adoption deployment. LAW/DCE public
access and AMPLS private-only access can be enabled only by the separate reviewed
`set-private-access.ps1` operation after its connectivity, DNS, and ingestion confirmations attest
that the 11 agents, their adopted DCR associations, and their separate DCE associations
remain healthy and Heartbeat, Perf, InsightsMetrics, Syslog, AthenaApp_CL, and NTANetAnalytics
are actively ingesting. This two-phase ordering avoids a telemetry outage while AMA transitions to
private connectivity. The cutover is a serialized operator action that reads each AMPLS, requires
an empty per-private-endpoint exclusion set, performs the documented create-or-update operation
while preserving exact tags, and immediately verifies that only the default query and ingestion
modes changed. It
then uses the supported narrow Azure CLI update surfaces for the DCE and LAW public-network
settings. The script reads all four resources back and fails unless the intended private settings
are effective. The AMPLS API exposes no supported ETag condition, so concurrent cutover execution
is prohibited operationally.
Collector private DNS resources are managed in `rg-athena-demo-monitoring`; the isolated workload
Azure Monitor/Blob zones are managed in `rg-athena-demo-workload`. Both are fixed deployment
scopes rather than caller-selected resource groups.

The deployment pins the workload scope to `rg-athena-demo-workload`, the exact reviewed
`athena-hackathon-vnet` resource ID in the deployment subscription, and the reviewed 11-VM list.
It also pins the workload-local private-endpoint subnet and the dedicated collector VNet, runtime
subnet, and private-endpoint subnet. A prerequisite validation module requires all IDs to be in the
deployment subscription, verifies each subnet parent, requires distinct collector subnets, and
rejects a shared workload/collector VNet. Non-registration links are created only between each
private DNS boundary and its corresponding VNet. Before private cutover, the operator validates
that both runtimes resolve their local managed zones. DNS and ingestion evidence is supplied only
to the explicit cutover script after endpoint records and links exist.

The reviewed demo workload and existing shared WC-013 MCP network have overlapping address spaces,
and the shared MCP identity already has workload Reader authority. WC-024 therefore does not peer
or DNS-link that runtime. Connectivity is a separate deployment under
`infra/wc024-monitoring-connectivity`: it creates a dedicated `10.45.0.0/24` WC-024 collector VNet
in `rg-athena-demo-monitoring`, with separate runtime and private-endpoint subnets and no peering to
the workload. The workload uses its existing `snet-paas-private-endpoints` subnet for a
workload-local AMPLS endpoint. The collector VNet receives a separate AMPLS endpoint plus the
evidence Blob and Key Vault endpoints. Identically named Azure Monitor/Blob zones live in separate
resource groups and link to only their corresponding VNet; the Key Vault zone exists only in the
collector boundary. This avoids ambiguous routes, shared DNS records, and a network path from the
workload to collector evidence or signing resources.

The subscription deployment `location` applies only to WC-024-created monitoring resources. The
adoption module reads the actual LAW and DCE locations and fails closed unless they are in the same
Azure region, which is required for the DCE logs-ingestion endpoint. The DCE association module
also fails closed unless every approved VM is in the adopted DCE region, which is required for its
configuration-access endpoint. Traffic Analytics receives the adopted workspace location. The root deployment is pinned to
`australiaeast`, matching the reviewed workload and monitoring VNets; a caller cannot select a
different private-endpoint or flow-log-storage region.

The collector receives no subscription- or resource-group-level Reader role. The existing narrow
WC-016 signal-reader role is assigned at each exact reviewed VM and is validated to contain only
VM instance-view and Azure Monitor metrics reads. Built-in Reader is assigned only at the exact
DCR and DCE, both AMPLS resources, both exact DCR-association children on each approved VM, and
the canonical VNet flow-log child. No current or future Connection Monitor is preauthorized.

The collector receives no Log Analytics Data Reader assignment at the adopted workspace. Current
resource-context access is granted only at each exact reviewed VM through the registered
control-plane actions for Heartbeat, Perf, InsightsMetrics, Syslog, and VMConnection. The adopted
workspace must retain `features.enableLogAccessUsingOnlyResourcePermissions=true`, use the
`PerGB2018` SKU, and expose each supported table on the `Analytics` plan. Every query includes and
returns the exact `_ResourceId`, requests `Prefer: include-permissions=true`, and persists the
permissions payload.

Traffic Analytics, `AzureNetworkAnalytics_CL`, and Connection Monitor workspace tables remain
available to separately authorized platform consumers, but the signed collector treats them as
unsupported and unavailable because this foundation does not provide a dedicated or ABAC-isolated
workspace/table boundary. It issues zero table and IP Flow calls for those controls. Context API,
Context MCP, presentation, and correlation identities remain absent from monitoring read
assignments.

A separate RBAC attestor UAMI receives only role-assignment, role-definition, deny-assignment,
active PIM schedule-instance, managed-identity attachment/federated-credential, Storage account
authorization-mode, and Key Vault authorization-mode reads at the subscription, plus Microsoft Graph
`Application.Read.All`, the least-privileged application permission for reading a service
principal's transitive `memberOf` relationship. It receives no workload or monitoring data-plane
role. Contract publication is deliberately two-phase so this identity and the collector
assignments exist before they are measured. The foundation deployment outputs an immutable
`athena.wc024MonitoringRbacBootstrapHandoff.v1`, including the exact Graph app-role assignment and
membership request paths, the unfiltered managed-identity attachment requests, a subscription-wide
all-principal role-assignment request, and keeps acquisition-contract readiness false. The attestor role includes the exact `Microsoft.Management/getEntities/action` needed for the
hierarchy request. The attestor
then performs two stable subscription-scope assignment reads for the collector and Athena Context
principals using the exact equivalent of `az role assignment list --all --include-inherited
--include-groups --assignee-object-id`. Those flags bind assignments at parent management groups,
the subscription, and arbitrary descendants, plus transitive group assignments, so an unexpected
grant cannot hide behind a fixed set of `atScope()` queries. A separate unfiltered
subscription-wide read uses `--all --include-inherited` to derive every principal authorized to
write monitoring evidence or sign receipts. The inventory permits
only the collector principal, requires Storage Shared Key to remain disabled, requires OAuth to
remain the default, and requires the signing vault to retain RBAC authorization with no access
policies.

The same two reads enumerate each UAMI's complete `listAssociatedResources` result and every
federated identity credential, then read each associated Container Apps Job's complete UAMI map.
The collector and attestor must each be attached to exactly one separate, contract-bound Job and
must have no federated credential. The collector Job may contain only the collector and explicit
runtime-support UAMI. Its collector identity lifecycle must be `All`, while the support identity
lifecycle must be `None`, making the support UAMI platform-only and unavailable to init or main
containers. The attestor Job may contain only the attestor with lifecycle `All`, and Athena Context
must be absent from both. The attestor
separately captures both service principals' transitive group IDs from Microsoft Graph using the
exact casted requests with `$count=true`, `$select=id`, and `ConsistencyLevel: eventual`. It also
performs two complete `Microsoft.Management/getEntities` reads, binds the subscription entity's
ordered parent edges through the tenant-root management group, and performs stable assignment
reads at every ancestor and at the subscription. Any missing or non-adjacent ancestor, unstable
hierarchy/assignment page, inherited management-group or tenant-root grant, or applicable deny
fails closed.
Published v8 contracts
retain their short-lived v3 inventory for parse-only compatibility. Current v4 inventory binds the
subscription-wide queries, complete protected-scope set, full roles,
conditions, applicable denies, runtime attachments, exclusive writer/signer derivation, transitive
groups, resource authorization modes, Blob versioning, the container immutability-policy
readback, independently timed first/second raw page sets, and stable repeated reads. V2 and v3
remain parseable only for historical inspection.

The collector no longer receives `Storage Blob Data Contributor` or
`Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write`. Phase one creates the
same deterministic `Athena WC028 Monitoring Evidence Create-Only Writer` role consumed by the
stacked runtime: exact known-name Blob read plus `blobs/add/action`, with a role-assignment
condition that denies `Blob.List` and restricts read/add to the three reviewed immutable
monitoring-persistence path shapes. Incremental deployment cannot remove the
superseded built-in assignment, so phase one requires a non-zero
`athena.wc028LegacyCollectorRbacCleanup.v3` evidence digest proving the old assignment and role
definitions are absent before the handoff can be published.

`publish-monitoring-contract.bicep` is the only phase-two publication entry point. It accepts the
name of the successful phase-one subscription deployment and retrieves the authoritative handoff
directly from that deployment's outputs; callers cannot substitute a handoff object. Phase one
also binds a nonzero reviewer principal, the exact versioned
`athenarbacevidencekv/monitoring-rbac-inventory-review` key, and a separate verifier UAMI with only
public-key read access to that key. Phase one creates the deterministic keys/get-only custom role
and exact-key assignment; the signed inventory proves that the verifier has exactly that one
grant, no transitive groups, no federated credential, and no persistent associated resource. The
reviewer must be distinct from the verifier, collector, Athena Context, and attestor principals.
Phase one gives the complete `collectorContractInputs` object a
deterministic binding ID and includes that ID plus its exact subscription deployment ID in the
handoff identity. Phase two requires a detached RS256 signature over the bootstrap handoff,
deployment ID, server template hash, complete-input binding ID, cleanup evidence, canonical
inventory, and immutable source-manifest digests. Its
AzureCLI deployment script runs as the verifier UAMI, resolves the exact Key Vault JWK, rejects
caller-supplied modulus or fingerprint substitutions, recomputes the inventory digest, verifies
the RSA-2048-or-stronger SPKI fingerprint and signature, and emits a validation digest; a nonempty
signature or caller-supplied digest/key alone cannot publish a contract.

After cryptographic review succeeds, phase two recomputes the handoff identity, rejects duplicate,
missing, extra, or out-of-subscription target scopes, verifies the Graph and attachment collection
contracts, physical identity separation, principal evidence, exact collector grants,
role-definition set, the exact Blob-list deny condition, exclusive writer/signer evidence, Blob
versioning, public-access and immutability readback, the deterministic storage-readiness
binding/digest, and the runtime-support identity's exact direct four-action management-plane
storage reader grant, complete role definition, principal evidence, and deny/PIM posture,
stable snapshots, source reference, and
the inventory lifetime against the deployment's own timestamp before it emits the generic and
WC-028 v9 collector contracts. Current publication deliberately rejects any active PIM instance,
Athena context grant, additional writer or signer, federated credential, unauthorized runtime
attachment, insecure Storage or Key Vault authorization mode, conditioned deny, or deny that
effectively applies to the collector. An
`All Principals` deny is allowed only when its direct or transitive-group exclusion is present in
the attested principal set, matching the Python contract's fail-closed semantics.

The same phase-one deployment creates the Athena-owned identity-proof authority required before
any collector source I/O. It uses a secure tenant-scoped
`api://<tenant-id>/athena-monitoring-identity-proof` identifier URI, v1 access tokens, one
application-only `Athena.MonitoringAcquisition.ProveIdentity` role, and one direct assignment to
the collector UAMI. No secret or credential is created. The phase-one handoff and v9 contract bind
the application, enterprise application, role, assignment, assigned principal, and audience IDs,
and the application explicitly requests the `idtyp` access-token claim, so an unprovisioned or
substituted proof authority cannot be published.

The collector uses a dedicated non-exportable Key Vault RSA signing key and a versioned,
retention-controlled `monitoring-evidence` Blob container. The checked-in contract binds the
versioned `signingKeyResourceId` Key Vault key URI, reviewed workload resource group, reviewed
workload VNet, and exact 11 VM names. Its Pydantic contract follows the WC-013 pattern: a
reviewed, canonical collector contract identifies the allowed generic signal kinds and read
operations; each `athena.wc024MonitoringEvidenceHandoff.v1` references an exact Blob version and
digest and binds it with a domain-separated RS256 attestation. Consumers must validate the reviewed
contract digest, immutable reference, signing key URI, signature, scope, and freshness at trusted
`as_of` before using evidence; keys retired or expired at `as_of` fail closed.

The existing VNet-scope
`athena-hackathon-vnet-rg-athena-demo-workload-flowlog` is adopted and updated in place to use
the monitoring-owned storage with Traffic Analytics enabled. `athenahackathonflowwhtco` remains
retained and its existing blobs are never deleted. An explicit, bounded migration surface can
disable redundant subnet and NIC flow logs only after a reviewed canonical-VNet cutover
confirmation. Each redundant flow-log name and target must appear in a checked-in exact
reviewed allowlist, and WC-024 currently ships with an empty allowlist. The module rejects
unpaired values, unreviewed name/target pairs, the canonical VNet flow log, VNet targets, and an
unconfirmed cutover; it also reads each existing flow log and refuses to disable it unless its
current target matches the reviewed pair. Disabled redundant logs are pointed at replacement
storage and have Traffic Analytics disabled, so future writes do not continue to use the legacy
account. No flow log is implicitly deleted.

Connection Monitor is a capability boundary only. WC-024 creates no monitor definitions and
rejects attempts to enable them. A future published-intent reconciliation may introduce exact,
reviewed endpoint paths in a separate change.

## Operator runbook

1. Run `bootstrap-ampls.ps1` once after reviewing its what-if. The wrapper refuses an already
   existing scope and deploys explicit Open access modes. Every foundation deployment thereafter
   adopts that scope as existing; there is no steady-state creation parameter or Open-mode PUT.
2. Review, validate, and deploy the separate monitoring-connectivity template. Confirm the
   dedicated collector VNet contains only the WC-024 runtime and private-endpoint subnets. Provide
   its output IDs and the existing workload private-endpoint subnet ID to the foundation.
3. Only after validating populated DNS records, all DCE-only associations, connectivity, and the
   stated ingestion baseline, run `set-private-access.ps1` with all three explicit confirmations.
   The steady-state template has no public-access mutation path and cannot reopen an adopted
   PrivateOnly AMPLS.
4. Select a separately governed reviewer principal and versioned RSA key in the fixed review vault
   and key name. Preprovision a separate otherwise-unassigned verifier UAMI; phase one grants it
   only `keys/get` on that exact key. Predeploy the exact dormant collector and RBAC-attestor
   Container Apps Jobs plus the separate runtime-support UAMI; configure collector=`All`,
   support=`None`, and attestor=`All`, and do not run either Job yet. Run the
   reviewed v3 legacy-collector cleanup against every deterministic superseded assignment and role
   definition, retain its non-zero `cleanupEvidenceDigest`, and deploy `main.bicep` with those
   three resource IDs, that digest, the reviewer public material, and no pre-existing
   effective-RBAC inventory. Capture the exact
   `monitoringRbacBootstrapHandoff` output and confirm
   `monitoringAcquisitionContractPublicationReady=false`.
5. Use only the handoff attestor identity. Twice, list collector and Athena Context assignments
   with the exact `--all --include-inherited --include-groups --assignee-object-id` semantics,
   list all subscription and inherited assignments without a principal filter for the exclusive
   writer/signer derivation, enumerate the collector, attestor, and reviewer-key verifier UAMIs'
   associated resources, federated credentials, transitive groups, and effective assignments
   through the exact handoff paths, read Storage and Key Vault
   authorization modes, Blob-service versioning, the evidence container, and its default
   immutability policy; preserve every role definition, deny assignment, active PIM instance,
   Graph transitive-group response, page, target digest, and completion time in one short-lived v4
   inventory. The verifier must have exactly one direct keys/get-only grant and no persistent
   attachment. Evaluate denies against every exact `effectiveRbacTargetScopeIds` entry. The target
   deployment currently requires empty PIM, Athena Context grant, and effective collector or
   verifier deny sets.
6. Have the separate reviewer validate the phase-one deployment ID and server template hash,
   complete contract-input binding ID, immutable source artifact, canonical `inventoryDigest`,
   exact runtime attachments, absence of federated credentials, and exclusive data-plane
   derivation, then sign the domain-separated attestation preimage with the pinned key.
7. Deploy `publish-monitoring-contract.bicep` with the exact successful phase-one deployment name,
   the same two runtime Job IDs and runtime-support UAMI ID, fresh inventory, canonical digest,
   and detached reviewer attestation. Capture its v9 acquisition contract and publication
   handoff. Any identity, Graph
   permission, scope, duplicate target, grant, attachment, federated credential, writer/signer,
   authorization mode, Blob-list condition, versioning, immutability, cleanup, stable-read, source,
   freshness, canonical-digest, key-anchor, or signature mismatch keeps publication fail-closed.

The exact target list includes the subscription, all three relevant resource groups, the workload
VNet, the Network Watcher, the Log Analytics workspace and every reviewed table resource, every
collector Reader/signal/resource-log/resource-health scope, the evidence storage account and Blob
service/container, and the signing vault/key. This is intentionally broader than the collector's
grants. The subscription-wide principal queries detect direct or group-derived grants on arbitrary
descendants, while the protected-scope list binds deny evaluation and prevents any acquisition or
resource-read scope from being omitted.

## Consequences

- Workspace query and ingestion, DCE, and Key Vault have public access disabled and use private
  endpoints/private-link infrastructure once the explicit private-access cutover operation
  is supplied; the initial adoption deployment leaves LAW/DCE public settings unchanged. The
  Azure Monitor private endpoint uses all five
  required zones: `privatelink.monitor.azure.com`, `privatelink.oms.opinsights.azure.com`,
  `privatelink.ods.opinsights.azure.com`, `privatelink.agentsvc.azure-automation.net`, and the
  corresponding isolated `privatelink.blob.core.windows.net` zones. The Key Vault zone and evidence
  storage endpoint exist only in the collector DNS/network boundary. Operators must validate DNS
  and endpoint connectivity in both runtimes before private cutover.
- Storage uses Microsoft Entra authorization, TLS 1.2, versioning, soft-delete retention,
  cool-tier/deletion lifecycle, and an unlocked evidence-container immutability policy. Standard
  ZRS does not use archive tiering and Shared Key access remains disabled. The retained legacy
  flow-log account demonstrates that Network Watcher can ingest with Shared Key disabled, so the
  replacement account must not weaken this control based on a presumed platform dependency. The
  migration validation must instead confirm Network Watcher trusted-service authorization and
  end-to-end network reachability and ingestion to replacement storage. Shared Key may be enabled
  only if a reviewed subscription validation or what-if, or an authoritative platform constraint,
  proves that ingestion otherwise cannot work. The storage account keeps public network access
  enabled solely to activate the storage firewall's selected-networks mode, with default deny and
  the `AzureServices` trusted-service bypass required for Network Watcher flow-log writes. No
  Athena identity is granted `listKeys` or a shared-key data-plane route, and no IP or virtual
  network firewall allow rules are configured.
- A collector is a seam, not a deployed job: the reviewed deployment output must be captured in a
  signed handoff artifact before a runtime is introduced. This preserves the WC-013 deployment
  review and exact version-pinned handoff model.
- Generic monitoring data remains distinct from declared workload context. Thresholds and endpoint
  paths wait for an exact published manifest and an approved monitoring proposal.

## Validation

Deterministic contract tests reject incomplete allowlists, unexpected fields, nondeterministic Blob
names, and attestation digests that do not bind the exact immutable reference. Static Bicep tests
assert adoption of the existing LAW/DCE/DCR and association, custom-log preservation boundary,
the exact distinct 11-VM preserved-association validation boundary, reviewed workload RG/VNet
pinning, its completion before any DCE-only association PUT, the gated private-ingestion
confirmation,
the DCR-association adoption and DCE-only `configurationAccessEndpoint` association boundary,
private networking, collector runtime topology validation, and DNS links, populated-zone-before-VNet-link
ordering, persistent private-access ordering and mutable-state preservation, versioned signing
key binding, lifecycle/retention, collector-only RBAC, canonical VNet Traffic Analytics, explicit
allowlisted legacy-flow-log migration with existing-target verification, the two-phase
RBAC-attestor handoff and freshness gate, and the absence of Connection Monitor definitions or
unpublished-intent configuration. Local Bicep build validates the root, publication, and example
parameter templates without contacting Azure.
