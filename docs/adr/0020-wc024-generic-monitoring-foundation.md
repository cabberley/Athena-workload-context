# ADR 0020: Isolate generic monitoring evidence from context and presentation runtimes

- **Status:** Proposed
- **Date:** 2026-09-06

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
case-insensitively distinct set of 11 named, already AMA-enabled VMs. A dedicated prerequisite
validation deployment reads each association's `dataCollectionRuleId`, compares it to the adopted
DCR resource ID, and must complete before any DCE association PUT can occur. WC-024 does not rewrite
the existing DCR binding. Deployment fails closed if any association is missing or does not reference
the reviewed DCR. The template instead creates a
distinct `configurationAccessEndpoint` association on each approved VM whose properties contain
only the adopted private DCE ID. It neither installs AMA nor creates a duplicate DCR association.

WC-024 adds an Azure Monitor Private Link Scope, monitoring-owned replacement storage, private
endpoints, required private DNS zones and workload- and collector-runtime-VNet links, and one
collector-only managed identity. The AMPLS is created in Open mode only when the explicit,
reviewed `createPrivateLinkScope` phase-one input is true. Its default is false: later deployments
declare the scope as existing, fail closed if it is absent, and do not PUT its access mode. Therefore
the phase-two PrivateOnly update is persistent and an ordinary later deployment cannot reopen the
scope. The template rejects a request to create an Open scope in the private-only cutover phase. It
validates all 11 adopted DCR associations before deploying the AMPLS private endpoint
and its private DNS zone group. Private DNS zone creation is separated from workload-VNet linking:
the deployment creates or adopts unlinked zones, populates them through the private-endpoint zone
groups, and only then links the zones to the workload VNet. This prevents empty private zones from
overriding Azure Monitor DNS before the AMPLS records exist. Public access remains unchanged by
default, and the new AMPLS remains open during the initial adoption deployment. LAW/DCE public
access and AMPLS private-only access can be enabled only in a subsequent reviewed deployment after
the private-ingestion cutover confirmation attests that the 11 agents, their adopted DCR associations, and
their separate DCE associations
remain healthy and Heartbeat, Perf, InsightsMetrics, Syslog, AthenaApp_CL, and NTANetAnalytics
are actively ingesting. This two-phase ordering avoids a telemetry outage while AMA transitions to
private connectivity. The phase-two PUT obtains the adopted LAW and DCE values from the
adoption module rather than applying generic tags or replacement defaults: it preserves LAW tags,
SKU, retention, daily quota, and the exact workspace feature object (including `disableLocalAuth`
and `enableLogAccessUsingOnlyResourcePermissions`), and preserves DCE tags plus description and
kind when those optional values exist on the adopted resource. It also
replays the AMPLS's exact tags and any per-private-endpoint access-mode exclusions. Therefore the
only intended phase-two changes are the LAW/DCE public-network settings and AMPLS default access
modes. Private DNS resources are managed
in one reviewed, deployment-subscription resource group; deployment fails if that resource group
is unavailable instead of silently relying on unverified links.

The deployment explicitly declares the private-endpoint VNet and subnet and the isolated
collector-runtime VNet and subnet. A prerequisite validation module requires all of these IDs to
be in the deployment subscription and verifies that each subnet belongs to its declared VNet. When
either the workload VNet or collector VNet differs from the private-endpoint VNet, a reviewed
routing/peering confirmation is required. Separate non-registration links are created for all six
private zones on the collector VNet when it differs from the workload VNet. Before the private-ingestion cutover, after private endpoints, private DNS zones, and VNet
links exist, the operator must also attest that workload and collector runtimes resolve the
managed private zones (or approved forwarding). The first adoption deployment can therefore
create the DNS and endpoint prerequisites without pre-attesting records that cannot exist yet.
This does not infer peering, routes, or custom DNS behavior from resource IDs: missing cutover
topology or DNS evidence fails closed.

The subscription deployment `location` applies only to WC-024-created monitoring resources. The
adoption module reads the actual LAW and DCE locations and fails closed unless they are in the same
Azure region, which is required for the DCE logs-ingestion endpoint. The DCE association module
also fails closed unless every approved VM is in the adopted DCE region, which is required for its
configuration-access endpoint. Traffic Analytics receives the adopted workspace location, while the
gated phase-two PUTs use each adopted resource's own location. Consequently, a subscription
deployment in a different region cannot relocate or misconfigure the adopted LAW or DCE.

The custom **Athena WC024 Isolated Monitoring Evidence Reader** role is assigned only to that
collector identity and only at the monitoring, approved workload, and Network Watcher resource
groups, all in the deployment subscription. Its workspace permissions name only Heartbeat, Perf,
InsightsMetrics, Syslog, VMComputer, VMConnection, VMBoundPort, VMProcess, NTANetAnalytics,
NWConnectionMonitorDestinationListenerResult, NWConnectionMonitorDNSResult,
NWConnectionMonitorPathResult, and NWConnectionMonitorTestResult query tables; it also has the
exact DCR, DCE, flow-log, Connection Monitor, and Azure Monitor metrics read operations required
by the collector. Context API, Context MCP, presentation, and correlation identities are neither
parameters nor role-assignment principals in the foundation.

The collector uses a dedicated non-exportable Key Vault RSA signing key and a versioned,
retention-controlled `monitoring-evidence` Blob container. Its Pydantic contract follows the
WC-013 pattern: a reviewed, canonical collector contract identifies the allowed generic signal
kinds and read operations; each `athena.wc024MonitoringEvidenceHandoff.v1` references an exact
Blob version and digest and binds it with a domain-separated RS256 attestation. Consumers must
validate the reviewed contract digest, immutable reference, signature, scope, and freshness before
using evidence.

The existing VNet-scope
`athena-hackathon-vnet-rg-athena-demo-workload-flowlog` is adopted and updated in place to use
the monitoring-owned storage with Traffic Analytics enabled. `athenahackathonflowwhtco` remains
retained and its existing blobs are never deleted. An explicit, bounded migration surface can
disable redundant subnet and NIC flow logs only after a reviewed canonical-VNet cutover
confirmation. Each redundant flow-log name and target is supplied as a paired reviewed parameter;
the module rejects unpaired values, the canonical VNet flow log, VNet targets, and an unconfirmed
cutover. Disabled redundant logs are pointed at replacement storage and have Traffic Analytics
disabled, so future writes do not continue to use the legacy account. No flow log is implicitly
deleted.

Connection Monitor is a capability boundary only. WC-024 creates no monitor definitions and
rejects attempts to enable them. A future published-intent reconciliation may introduce exact,
reviewed endpoint paths in a separate change.

## Operator runbook

1. For the reviewed first phase-one deployment only, set `createPrivateLinkScope` to `true`; keep
   `privateMonitoringIngestionCutoverConfirmed` false. All later deployments leave
   `createPrivateLinkScope` false, which adopts the scope as an existing resource and preserves
   its access mode.
2. Provide the workload, private-endpoint, and collector runtime VNet/subnet IDs. Where a runtime
   is not in the private-endpoint VNet, record reviewed routing or peering evidence and set the
   corresponding connectivity confirmation. For the first adoption deployment, leave the DNS
   resolution confirmations false until the private endpoints, zones, and VNet links exist. For
   the private-ingestion cutover deployment, record private DNS resolution evidence for both
   runtimes and set both confirmations true. The deployment deliberately rejects omitted or
   inconsistent cutover assertions.
3. Only after validating the populated DNS records, all DCE-only associations, connectivity, and
   the stated ingestion baseline, set the private-ingestion confirmation for phase two. Review
   validate and what-if output for deletes, public exposure, and role broadening. There is no
   phase-two parameter that reopens an adopted PrivateOnly AMPLS.

## Consequences

- Workspace query and ingestion, DCE, and Key Vault have public access disabled and use private
  endpoints/private-link infrastructure once the explicit private-ingestion cutover confirmation
  is supplied; the initial adoption deployment leaves LAW/DCE public settings unchanged. The
  Azure Monitor private endpoint uses all five
  required zones: `privatelink.monitor.azure.com`, `privatelink.oms.opinsights.azure.com`,
  `privatelink.ods.opinsights.azure.com`, `privatelink.agentsvc.azure-automation.net`, and the
  same `privatelink.blob.core.windows.net` zone also attached to the storage endpoint. WC-024
  explicitly manages non-registration workload-VNet links and, when distinct, collector-runtime
  VNet links for these zones and `privatelink.vaultcore.azure.net`. Operators must validate
  routing/peering and custom DNS forwarding before private cutover; resource IDs alone are not
  evidence that these paths work.
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
the exact distinct 11-VM preserved-association validation boundary, its completion before any
DCE-only association PUT, the gated private-ingestion confirmation,
the DCR-association adoption and DCE-only `configurationAccessEndpoint` association boundary,
private networking, collector runtime topology validation, and DNS links, populated-zone-before-VNet-link
ordering, persistent private-access ordering and mutable-state preservation, lifecycle/retention, collector-only
RBAC, canonical VNet Traffic Analytics, explicit legacy-flow-log migration, and the absence of
Connection Monitor definitions or unpublished-intent configuration. Local Bicep build validates
the root template and example parameters without contacting Azure.
