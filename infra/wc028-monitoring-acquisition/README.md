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
- the separate runtime-support identity;
- the exact versioned monitoring-intent signing key whose public material is required for local
  signature verification;
- the exact workload resource group named by the acquisition authority.

Monitoring bundles are written only to:

```text
wc024-monitoring/{collectionId}/evidence.json
wc024-monitoring/commits/{replayKey}/manifest.json
```

The runtime writes or recovers the exact known evidence name, yields it for correlation request
construction, then publishes the deterministic persistence manifest last as the logical atomic
commit marker. The evidence name is derived from the reviewed replay key, so a retry cannot commit
different acquisition bytes under the same execution identity. A caller failure leaves no commit
marker. The current contract does not execute or persist supporting change controls.

## Runtime configuration

`acquisitionRuntimeConfigurationJson` uses
`athena.wc028MonitoringAcquisitionJobConfiguration.v2`. It embeds the exact signed monitoring
intent and references, published runtime binding, acquisition authority v5, collector contract v8,
and approved change scope. It also binds:

- the WC-024 collector resource, client, and principal identities;
- the separate runtime-support resource, client, and principal identities;
- the separate Athena context resource and principal identities;
- the monitoring-evidence storage endpoint and container;
- the resource-context Log Analytics workspace, exact VM scopes, and measured effective RBAC
  inventory;
- the monitoring-intent and collector signing-key trust anchors; and
- the active-context and acquisition-authority digests; and
- a one-execution ID plus deterministic persistence replay key.

The runtime delegates managed-identity acquisition to the hardened production adapter. That
adapter verifies the collector identity through the Athena-owned proof audience, creates every
Azure source client from the same verified `ManagedIdentityCredential`, binds resource-context Log
Analytics request v3 and permission evidence to the authority-selected VM scope, and persists the
selected incident in acquisition receipt v5 and correlation request v4.

Traffic Analytics and Connection Monitor workspace-table acquisition are explicitly unsupported in
the current contract. Those controls produce deterministic unavailable coverage with zero Logs or
IP Flow calls and no IP Flow RBAC.

> **Provisional stack boundary:** the published collector contract v8 currently required by this
> draft still encodes `Storage Blob Data Contributor` and `blobs/write`. It cannot truthfully
> describe the narrow role below after cleanup. Do not deploy this draft until PR #99 publishes the
> corresponding collector-contract and effective-RBAC revision and this branch is restacked on that
> head.

## Upgrade cleanup gate

An incremental deployment does not delete role assignments created by an older runtime template.
Before deploying this version over an existing WC-028 runtime, run
`remove-obsolete-collector-rbac.ps1` with the previous registry, workload resource group,
change-evidence container, monitoring-evidence container, monitoring-intent key, and exact collector
resource/principal pair. The script deletes only the five exact legacy collector assignments,
including the broad monitoring-evidence contributor assignment, removes the two obsolete custom
role definitions, verifies those bindings are absent, and emits `cleanupEvidenceDigest`.

Pass that digest as both `legacyCollectorRbacCleanupDigest` and the matching field in runtime
configuration v2. Measure and embed a fresh effective-RBAC inventory only after cleanup. The Job is
manual with no replica retry, so every execution requires a newly reviewed configuration, cleanup
evidence binding, execution ID, and replay key.

## Least privilege

The deployment adds only:

- `AcrPull` for the runtime-support identity on the existing registry;
- public-key read access for the runtime-support identity on the exact monitoring-intent signing
  key; and
- exact known-name Blob reads plus add-only Blob creation for the collector on the existing
  `monitoring-evidence` container. The assignment condition explicitly denies the `Blob.List`
  suboperation.

It adds no built-in Reader, Contributor, Owner, Blob overwrite/delete/list, diagnostic-setting,
alert-rule, or Connection Monitor mutation permission. Existing WC-024 grants continue to
authorize the collector's exact VM resource-context Logs and Resource Health reads, measured RBAC
attestation, and signing-key use.

## Local validation

```powershell
az bicep build --file infra/wc028-monitoring-acquisition/main.bicep --stdout
python -m pytest tests/test_wc028_monitoring_acquisition_infra.py `
  tests/test_wc028_monitoring_acquisition_runtime.py
```
