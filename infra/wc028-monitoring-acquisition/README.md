# WC-028 monitoring acquisition runtime

This deployment runs the receipt-bearing WC-028 acquisition coordinator as one scheduled,
identity-isolated Container Apps Job:

```text
athena-context wc028-monitoring-acquisition-job
```

The job attaches only the existing WC-024 monitoring collector identity. The reviewed runtime
configuration is supplied as a Container Apps secret and is accepted only when its exact raw bytes
match `acquisitionRuntimeConfigurationDigest`.

## Required existing boundaries

- the private Container Apps managed environment and digest-pinned runtime image;
- the WC-024 collector identity, versioned `monitoring-evidence-signing` key, storage account, and
  immutable `monitoring-evidence` container;
- the WC-025 versioned `change-evidence` container; and
- the exact workload resource group and Network Watcher named by the acquisition authority.

Monitoring bundles are written only to:

```text
wc024-monitoring/{collectionId}/evidence.json
```

Normalized change artifacts are written to the distinct WC-025 `change-evidence` container. Both
writers use known-name, create-only conditional uploads and recover an existing Blob only when its
bounded bytes and SHA-256 digest are identical.

## Runtime configuration

`acquisitionRuntimeConfigurationJson` uses
`athena.wc028MonitoringAcquisitionJobConfiguration.v1`. It embeds the exact signed monitoring
intent and references, published runtime binding, acquisition authority v2, collector contract v3,
and approved change scope. It also binds:

- the WC-024 collector resource, client, and principal identities;
- the separate Athena context resource and principal identities;
- the monitoring and change-evidence storage endpoints and containers;
- the Log Analytics workspace and Network Watcher;
- the monitoring-intent and collector signing-key trust anchors; and
- the active-context and acquisition-authority digests.

For `Heartbeat` and `VMConnection`, a signed query may return a second result table to prove that a
zero aggregate came from positive input and complete ingestion. The table must contain exactly one
row and these columns in order:

```text
rawInputRowCount, ingestionCompleteThrough
```

Without that proof, a zero remains unavailable rather than being treated as healthy evidence.

## Least privilege

The deployment adds only:

- `AcrPull` on the existing registry;
- Activity Log and Resource Graph change-history reads at the approved workload resource group;
- the IP Flow Verify diagnostic action on the exact Network Watcher; and
- known-Blob read/write data actions on the exact WC-025 `change-evidence` container.

It adds no built-in Reader, Contributor, Owner, list, delete, diagnostic-setting, alert-rule, or
Connection Monitor mutation permission. Existing WC-024 grants continue to authorize the
collector's narrow monitoring reads, monitoring evidence writes, and signing-key use.

## Local validation

```powershell
az bicep build --file infra/wc028-monitoring-acquisition/main.bicep --stdout
python -m pytest tests/test_wc028_monitoring_acquisition_infra.py `
  tests/test_wc028_monitoring_acquisition_runtime.py
```
