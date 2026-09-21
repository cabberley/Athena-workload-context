# WC-028 monitoring acquisition runtime

This deployment runs the receipt-bearing WC-028 acquisition coordinator as one manually triggered,
identity-isolated Container Apps Job with a freshly reviewed configuration per execution:

```text
athena-context wc028-monitoring-acquisition-job
```

The job attaches the existing WC-024 monitoring collector identity plus a separate runtime-support
identity. The support identity is used only for ACR pull and monitoring-intent public-key reads; it
has no workload or monitoring-data permission. The reviewed runtime configuration is supplied as a
Container Apps secret and is accepted only when its exact raw bytes match
`acquisitionRuntimeConfigurationDigest`.

## Required existing boundaries

- the private Container Apps managed environment and digest-pinned runtime image;
- the WC-024 collector identity, versioned `monitoring-evidence-signing` key, storage account,
  immutable `monitoring-evidence` container, and current measured RBAC inventory;
- exact deployment-time WC-024 storage readback proving Blob versioning, no public container
  access, and the reviewed immutability policy state, retention, and disabled protected-append
  exceptions;
- the separate runtime-support identity plus fresh hierarchy-complete effective-RBAC evidence
  proving that it has only direct `AcrPull` and exact monitoring-intent key-read access;
- the exact versioned monitoring-intent signing key whose public material is required for local
  signature verification;
- the exact workload resource group named by the acquisition authority.

Monitoring bundles are written only to:

```text
wc024-monitoring/{collectionId}/evidence.json
wc024-monitoring/commits/{replayKey}/recovery.json
wc024-monitoring/commits/{replayKey}/manifest.json
```

Every start probes the deterministic manifest, recovery-state, and evidence names before requiring
current runtime-support RBAC freshness. If evidence appears after an initial state miss, the reader
performs bounded manifest/state reconciliation before declaring a true orphan. A valid manifest
recovers the committed handoff and exact correlation request directly. A collector-signed recovery
state can recreate missing evidence and finish the same handoff, request, and manifest without
Azure source reacquisition.

Recovery state v2 is signed with the exact collector key before the first durable write. Its
signature binds the complete replay-v3 execution, cleanup, incident revision, request window,
prepared bundle, and the originally accepted support-inventory digest and lifetime. Rehashing any
field without a new valid collector signature is rejected. Evidence without that signed state is
rejected until PR #99 exposes the same complete recovery binding in the signed acquisition receipt.
Current support-RBAC freshness is required only when no durable recovery artifact exists and the Job
will perform new support-key, identity, or monitoring-source I/O. A caller failure leaves no commit
marker. The current contract does not execute or persist supporting change controls.

## Runtime configuration

`acquisitionRuntimeConfigurationJson` uses
`athena.wc028MonitoringAcquisitionJobConfiguration.v4`. It embeds the exact signed monitoring
intent and references, published runtime binding, acquisition authority v5, collector contract v8,
and approved change scope. It also binds:

- the WC-024 collector resource, client, and principal identities;
- the separate runtime-support resource, client, and principal identities;
- the exact registry and monitoring-intent key scopes, the two permitted role IDs, and fresh
  hierarchy-complete runtime-support effective-RBAC evidence covering every intervening ARM scope
  (including the containing Key Vault and leaf key), direct and inherited assignments, transitive
  groups, active PIM schedules, conditions, and deny assignments;
- the separate Athena context resource and principal identities;
- the monitoring-evidence storage endpoint and container;
- the non-zero storage-readiness digest and exact versioning/immutability readback;
- the resource-context Log Analytics workspace, exact VM scopes, and measured effective RBAC
  inventory;
- the monitoring-intent and collector signing-key trust anchors; and
- the active-context and acquisition-authority digests; and
- a non-zero one-execution ID plus deterministic persistence replay key. Refreshing the current
  support inventory does not change the stable recovery path; the collector-signed recovery state
  retains the original inventory digest and execution-time validity window.

Every physical monitoring-intent Key Vault request is wrapped at the HTTP transport boundary.
Trusted time and runtime-support RBAC are revalidated immediately before and after each attempt,
including authentication challenges and SDK retries. The resolver's second key read receives a new
guard interval; expiry during the first read prevents construction or execution of that second read.
The Azure SystemDefined all-principals deny sentinel is applied only when it is the sole deny
principal. Exclusions are evaluated first, unsupported conditions fail closed only when they could
affect a required support operation, and nil GUIDs remain invalid everywhere else.

The runtime delegates managed-identity acquisition to the hardened production adapter. That
adapter verifies the collector identity through the Athena-owned proof audience, carries the
collector effective-RBAC inventory window into every acquisition execution, and checks live trusted
time immediately before and after every Azure source call and physical HTTP request. Historical
acquisition receipt v5 remains unchanged: it signs and verifies logical exchanges only and does not
accept a `wireAttempts` extension or reinterpret `maxAcquisitionCalls` as a physical-request budget.
The draft remains hard-gated until PR #99 publishes explicit successor receipt and authority schema
versions for those mandatory wire-attempt and call-budget semantics. The adapter creates every Azure
source client from the same verified
`ManagedIdentityCredential`, binds resource-context Log Analytics request v3 and permission evidence
to the authority-selected VM scope, and persists the selected incident in acquisition receipt v5
and correlation request v4.

Traffic Analytics and Connection Monitor workspace-table acquisition are explicitly unsupported in
the current contract. Those controls produce deterministic unavailable coverage with zero Logs or
IP Flow calls and no IP Flow RBAC.

> **Provisional stack boundary:** the published collector contract v8 currently required by this
> draft still encodes `Storage Blob Data Contributor` and `blobs/write`. It cannot truthfully
> describe the narrow role below after cleanup. Do not deploy this draft until PR #99 publishes the
> corresponding conditioned read-plus-add collector contract/bootstrap and effective-RBAC
> revision, a reviewed storage-protection contract, and the collector-signed persistence replay
> binding. PR #99 must also replace its current subscription-descendant-only inventory with
> ancestor-complete evidence that can detect inherited management-group or tenant-root grants.
> This branch must then be restacked on that exact head. Runtime startup remains unconditionally
> blocked in this draft; merely changing the shared current-schema constant cannot make an
> intermediate successor deployable. The final restack may replace the runtime gate only while
> pinning the exact reviewed successor schema and its authority-bound collector-contract digest.
> The Bicep
> `pr99RuntimeDependenciesReady` parameter is constrained to `false`; its deployment-time failure
> is referenced by every RBAC module and the Container Apps Job, so this draft cannot grant roles or
> create a runnable Job.

## Upgrade cleanup gate

An incremental deployment does not delete role assignments created by an older runtime template.
Before deploying this version over an existing WC-028 runtime, run
`remove-obsolete-collector-rbac.ps1` with the previous registry, workload resource group,
change-evidence container, monitoring-evidence container, monitoring-intent key, exact historical
Network Watcher, and exact collector resource/principal pair. The script deletes only the six exact
legacy collector assignment targets, including Network Watcher IP Flow and the broad
monitoring-evidence contributor assignment. Before mutation it runs a separate complete custom-role
enumeration at each exact known historical assignable scope, without a name or GUID filter. Each
historical custom role must resolve uniquely by its exact trusted role name, permissions, empty
deny lists, and single assignable scope. Duplicate, renamed, or body-mismatched candidates fail
closed. A missing role is accepted only as an explicit per-target absence proof from that complete
known-scope enumeration.

For every assignment target, the script performs a separate complete subscription assignment
enumeration for the exact collector principal. Found custom roles are matched using the actual
`roleDefinitionId` returned by Azure together with the exact principal and target scope; the two
built-in targets use their published fixed role IDs. Each assignment must be found uniquely and
deleted by its returned Azure resource ID or be explicitly proved absent by that independent query.
Fresh per-target role and assignment queries prove post-cleanup absence rather than reusing any
pre-delete lookup. The cleanup evidence records the resolution and absence proof for every target
before emitting `cleanupEvidenceDigest`.

No real deployment-derived ARM `guid()` result was found in the reviewed repository, session, or
read-only Azure evidence. The earlier local UUIDv5/SHA-1 helper did not implement ARM's
MD5/UUIDv3-style `guid()` behavior and has been removed. The cleanup script does not calculate role
IDs, record invented GUID vectors, or treat a reconstructed-ID miss as evidence of absence. A
renamed role with the exact historical permissions and assignable scope is surfaced for manual
review rather than deleted automatically.

The cleanup uses only supported exact lookups: `az resource show --ids` for the reviewed
`NetworkWatcherRG/NetworkWatcher_australiaeast` resource and `az group show --name` for the
resource-group name parsed from the canonical workload resource-group ID. Both calls remain bound to
the supplied subscription, and their returned ID, name, `australiaeast` location, and `Succeeded`
provisioning state must match before any cleanup command runs. Executable tests exercise the
installed Azure CLI command parser plus malformed and cross-subscription script preflight paths
without permitting a live mutation.

Pass that digest as both `legacyCollectorRbacCleanupDigest` and the matching field in runtime
configuration v4. All-zero cleanup evidence is rejected. Measure and embed fresh collector and
runtime-support effective-RBAC inventories only after cleanup. The Job is
manual with no replica retry, so every execution requires a newly reviewed configuration, cleanup
evidence binding, execution ID, and replay key.

## Planned least privilege

After the PR #99 dependency gate is replaced during the final restack, the deployment is designed to
add only:

- `AcrPull` for the runtime-support identity on the existing registry;
- the `Athena WC028 Runtime Support Monitoring Intent Key Reader` role, permitting only public-key
  material and metadata reads for the runtime-support identity on the exact monitoring-intent
  signing key; and
- exact known-name Blob reads plus add-only Blob creation for the collector on the existing
  `monitoring-evidence` container. The assignment condition explicitly denies the `Blob.List`
  suboperation.

The storage-readiness module must first read back the exact WC-024 storage account, Blob service,
container, and immutability policy. Its validated digest is passed into the evidence-writer RBAC
module name and the Job environment. The module computes an ARM `guid()` binding from the live
resource IDs and protection values and requires it to equal the binding embedded in the same parsed
runtime configuration. A mismatched versioning, public-access, policy-state, retention,
protected-append, binding-ID, or readiness-digest claim prevents role assignment and Job deployment.
Runtime recomputes the SHA-256 readiness digest and requires a fresh storage-readiness verifier to
return the exact same validated contract immediately before any durable writer call. This draft
deliberately wires a verifier that fails closed because current PR #99 has not yet published the
required storage contract or narrow runtime read authorization.

No local ARM `guid()` implementation remains. Runtime treats the non-nil readback binding as an
opaque deployment-produced value already checked by the Bicep module's native `guid()` call. It
independently recomputes the SHA-256 readiness digest from the exact resource IDs and protection
values and requires a fresh live verifier result before durable creation. Neither RBAC cleanup nor
runtime readiness relies on a locally reconstructed ARM GUID.

It adds no built-in Reader, Contributor, Owner, Blob overwrite/delete/list, diagnostic-setting,
alert-rule, or Connection Monitor mutation permission. Existing WC-024 grants continue to
authorize the collector's exact VM resource-context Logs and Resource Graph HealthResources reads,
measured RBAC attestation, and signing-key use.

## Local validation

```powershell
az bicep build --file infra/wc028-monitoring-acquisition/main.bicep --stdout
python -m pytest tests/test_wc028_monitoring_acquisition_infra.py `
  tests/test_wc028_monitoring_acquisition_runtime.py
```
