# ADR 0037: Gate WC-029 monitoring guest prerequisites and broad Activity Log export

- **Status:** Proposed
- **Date:** 2026-09-13

## Context

WC-024 already deployed the generic monitoring foundation and adopted the eleven Linux VMs, Azure
Monitor Agent (AMA), DCR/DCE associations, VNet flow log, Traffic Analytics, monitoring-owned
storage, private endpoints, and narrow collector identity. Read-only WC-029 reconciliation found
that AMA and the required DCR streams are present, while `DependencyAgentLinux`,
`NetworkWatcherAgentLinux`, Connection Monitor definitions, and the WC-025 resource-group event
route are not deployed. The canonical VNet flow log writes to monitoring-owned
`athenademomonchab01`; eighteen older subnet/NIC flow logs still write to retained legacy
`athenahackathonflowwhtco`.

Connection Monitor paths must come from exact published monitoring intent. Subscription Activity
Log export would collect unrelated operations and is not an acceptable substitute for the bounded
WC-025 Event Grid route.

## Decision

Add a separate subscription-scope WC-029 prerequisite root. It pins the reviewed subscription,
region, resource groups, eleven VMs, DCR/DCE/workspace, canonical flow log, replacement storage,
and Blob private endpoint. Read-only deployment validations fail closed unless:

- every VM has one successful AMA extension and the exact DCR and DCE associations;
- the adopted DCR retains Perf, InsightsMetrics, Syslog, bounded Athena JSON, the reviewed CPU,
  memory, disk, network, and `VmInsights` counters, and the exact workspace destination;
- the VM Insights workspace solution exists;
- the canonical VNet flow log is enabled for the workload VNet, uses JSON v2 and at least 30 days'
  retention, writes to monitoring-owned storage, and sends 10-minute Traffic Analytics to the
  adopted workspace; and
- replacement storage retains Microsoft Entra authorization, disabled shared keys/public Blob
  access, default-deny networking with only the Azure-services flow-log ingress exception,
  versioning, soft delete, lifecycle policy, and an approved Blob private endpoint.

The only optional mutations are guest prerequisite extensions. Both use the pinned Azure Verified
Module `br/public:avm/res/compute/virtual-machine/extension:0.1.0`. Dependency Agent is gated for
all approved Linux VMs and is configured for AMA. Network Watcher Agent is separately gated and
requires a distinct non-empty subset of approved source VMs. Both gates default off in the checked-in
environment parameter artifact. No Connection Monitor definition is created.

Both the WC-029 root and WC-025 root expose an `@allowed([false])` subscription Activity Log export
parameter. There is no diagnostic-setting resource. Enabling broad export requires a separate ADR,
data-governance approval, isolated destination and retention design, and a reviewed IaC change.
The authoritative near-real-time change route remains the WC-025 resource-group Event Grid system
topic with exact resource filters and separated delivery/ingestion/query/purge identities.

A read-only PowerShell verifier checks the same baseline plus retained legacy flow-log sources,
absence of subscription diagnostic export, and optional Dependency Agent, Network Watcher Agent,
and bounded change-route readiness. It never changes Azure context or resources.

## Alternatives considered

- **Create Connection Monitor paths in this slice:** rejected because no exact published-intent path
  authority or approved source-VM set exists.
- **Export the subscription Activity Log:** rejected because it persists unrelated subscription
  operations and broadens the customer-data boundary.
- **Replace the adopted DCR:** rejected because its current custom log flow and tags must be
  preserved; read-only validation is sufficient.
- **Use raw extension resources:** rejected because the AVM virtual-machine extension module is
  compatible with the bounded guest-prerequisite deployment.

## Consequences

- The prepared template can be validated and reviewed without changing live Azure because both
  extension deployment gates are false.
- VM dependency mapping remains unavailable until an operator approves and enables Dependency
  Agent installation.
- Connection Monitor remains unavailable until published intent selects exact paths and source VMs;
  then the source-agent gate can be enabled before a separate definition deployment.
- Existing legacy flow-log blobs and active legacy writers are not deleted or silently migrated.
  Their eventual disablement continues to use the explicit WC-024 cutover gate.
- WC-025 cannot be deployed from the synthetic example. Exact digest-pinned image, four existing
  separated identities, private runtime network IDs, approved resource IDs, evidence store, and
  versioned signing key are still required in a reviewed environment parameter artifact.

## Validation

Bicep build and parameter build cover the WC-029 root and synthetic WC-025 example. Static tests
assert exact scope, DCR/AMA coverage, pinned AVM usage, disabled mutation gates, Network Watcher and
storage controls, no Connection Monitor or subscription diagnostic-setting resource, identity
separation, and read-only validation commands.
