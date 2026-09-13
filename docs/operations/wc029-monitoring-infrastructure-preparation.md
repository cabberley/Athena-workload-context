# WC-029 monitoring infrastructure preparation

This slice is preparation only. It does not authorize or perform an Azure deployment.

## Exact prepared boundary

- Subscription `a6add389-9978-47ac-ab1e-a09212e321d4`, `australiaeast`.
- Workload resource group `rg-athena-demo-workload`; monitoring resource group
  `rg-athena-demo-monitoring`; Network Watcher remains in `NetworkWatcherRG`.
- Existing AMA, `athena-linux-dcr`, `configurationAccessEndpoint`, VM Insights solution, and exact
  eleven-VM coverage are read and validated, not replaced.
- Optional `DependencyAgentLinux` and `NetworkWatcherAgentLinux` installs use pinned AVM 0.1.0.
  Both deployment gates are false in `infra/wc029-monitoring-prerequisites/main.preparation.bicepparam`.
- The canonical VNet flow log, 10-minute Traffic Analytics, monitoring-owned
  `athenademomonchab01`, its lifecycle policy, and private Blob endpoint are validated.
- `athenahackathonflowwhtco` remains a legacy evidence source. This slice neither deletes its blobs
  nor disables its eighteen currently retained subnet/NIC flow-log writers.
- Connection Monitor definitions remain disabled until exact published intent supplies paths and
  approved source VMs.
- Subscription Activity Log export is hard-disabled in both WC-029 and WC-025 IaC. WC-025's
  resource-group Event Grid route remains the only prepared event-driven change path.

## Build and read-only validation

```powershell
az bicep build --file infra/wc029-monitoring-prerequisites/main.bicep
az bicep build-params --file infra/wc029-monitoring-prerequisites/main.preparation.bicepparam
az bicep build --file infra/wc025-change-ingestion/main.bicep
az bicep build-params --file infra/wc025-change-ingestion/main.example.bicepparam

# GET/list operations only; does not call account set, deployment create, or any update command.
./infra/wc029-monitoring-prerequisites/Test-MonitoringReadiness.ps1
```

The checked-in WC-029 parameter file keeps every mutation gate off. Before an operator enables an
extension family, create a separately reviewed immutable parameter artifact, run subscription
validate and full-payload what-if, and apply the zero-delete/public-exposure/RBAC gates from the
main WC-029 runbook.

Use `-RequireDependencyAgent`, `-RequireConnectionMonitorAgent`, or
`-RequireChangeEventRoute` only after the corresponding deployment is expected. A missing
prerequisite then fails closed.

## Known blockers, not inferred values

1. No exact published-intent Connection Monitor path set or approved source-VM subset exists, so no
   monitor definition or Network Watcher Agent deployment is enabled.
2. WC-025 lacks a reviewed environment parameter artifact containing the digest-pinned worker
   image, four dedicated identity names, exact approved resource IDs, private runtime network IDs,
   evidence store, and versioned signing key. The checked-in example is synthetic and cannot be
   deployment approval.
3. Dependency Agent is not installed on the eleven VMs. VM Insights guest metrics remain available,
   but process/dependency mapping requires a reviewed extension rollout and post-deployment table
   evidence.
4. The eighteen redundant legacy flow logs cannot be disabled until canonical replacement writes,
   Traffic Analytics ingestion, retention evidence, and operator cutover approval are captured.
5. Subscription Activity Log export remains prohibited. If Azure constraints later make it
   necessary, that requires a separate approved design and IaC change; changing a parameter cannot
   enable it.
