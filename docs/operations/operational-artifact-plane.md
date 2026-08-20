# Operational artifact plane prerequisite

This prerequisite adds storage plus narrow create-only and exact-version read adapters. It does not
run phases, choose Blob names, project presentation data, or orchestrate retries.

## Azure resources

The existing WC-013 replay StorageV2 account also hosts one Blob container:

- normal client endpoint: `https://<account>.blob.core.windows.net`;
- private endpoint subresource: `blob`;
- private DNS zone: `privatelink.blob.core.windows.net`;
- container: the `artifactContainerName` Bicep parameter;
- immutable version retention: the explicit `artifactRetentionDays` Bicep parameter; and
- identity: the existing acceptance identity with `Storage Blob Data Contributor` scoped to the
  container resource ID only;
- workload receipt writers: the managed identity object IDs supplied as
  `workloadReceiptWriterObjectIds`, each with `Storage Blob Data Contributor` at that same exact
  container so the trusted workload controller can create the phase receipt Blob before the Job
  reads it; and
- operator readers: the managed identity object IDs supplied as
  `operatorArtifactReaderObjectIds`, each with `Storage Blob Data Reader` at the same exact
  container for exact-version verification only.

The account keeps `allowSharedKeyAccess: false`, OAuth as the default, public Blob access disabled,
and public network access disabled. The private endpoint uses the existing private-endpoint subnet
and VNet link. Clients use the normal Blob hostname; DNS resolves it to the private endpoint.

The retention policy is unlocked. It protects Blob versions from modification or deletion during
the configured period, but an authorized management-plane administrator can still change an
unlocked policy. Locking it is a separate irreversible governance action and is not automated here.
Azure RBAC cannot scope built-in Blob data roles to `runs/<runId>/inputs/<phase>/`. The stricter
create-only boundary for workload receipts is therefore enforced in the trusted controller and
`CreateOnlyArtifactWriterPort`: it may create only exact `athena.demoFaultRun.v1` JSON Blobs at
`runs/<runId>/inputs/<phase>/fault-receipt.json` and must send `If-None-Match: *` so duplicates
fail closed rather than overwrite.

## Python capability

`CreateOnlyArtifactWriterPort` exposes one operation:

```python
create(request: ArtifactWriteRequest) -> ArtifactWriteReceipt
```

The request accepts:

- a bounded lowercase relative Blob path;
- non-empty immutable `bytes`, up to one MiB;
- exactly `application/json`; and
- fixed `payload_sha256`, optional `artifact_sha256`, and optional `semantic_sha256` metadata.

The adapter recomputes `payload_sha256`, uses the explicitly selected managed identity, and uploads
one block Blob with `MatchConditions.IfMissing` (`If-None-Match: *`). It never retries as an
overwrite. The port has no read, list, overwrite, or delete method.

The receipt contains the exact Blob version ID and hash. Downstream code must use the version ID,
not an unversioned Blob name, when it later verifies or presents an artifact.

`VersionPinnedArtifactReaderPort` exposes one operation:

```python
read(request: ArtifactReadRequest) -> ArtifactReadResult
```

The request requires the exact Blob name, exact opaque version ID, and expected payload SHA-256.
The adapter requests at most one MiB plus one byte, requires exact `application/json`, verifies the
response version ID and `payload_sha256` metadata, recomputes the SHA-256 over the returned bytes,
and validates UTF-8 JSON before returning. Missing versions, missing metadata, oversize responses,
and any mismatch fail closed. It never lists Blobs or resolves a latest version.

The built-in Reader role includes read and list data actions. The no-list rule is enforced by the
port surface, not by Azure RBAC. Likewise, the built-in Contributor role granted to
`workloadReceiptWriterObjectIds` is broader than create-only and cannot be constrained to the
receipt prefix in Azure RBAC. The trusted workload controller therefore enforces exact names, JSON
payloads, and `If-None-Match: *` itself. Each separate operator identity is read-only at Azure
scope; the acceptance identity may use the same adapter but retains its existing Contributor
permissions.

## Bicep inputs and outputs

The WC-013 entrypoint adds:

| Name | Direction | Purpose |
|---|---|---|
| `artifactContainerName` | input | The single immutable artifact container. |
| `artifactRetentionDays` | input | Explicit unlocked WORM retention period. |
| `operatorArtifactReaderObjectIds` | input | Entra object IDs of the separate operator reader managed identities used for exact-version verification. |
| `workloadReceiptWriterObjectIds` | input | Entra object IDs of the trusted workload-controller managed identities that create exact run-scoped receipt Blobs. |
| `artifactBlobEndpoint` | output | Private-resolved normal Blob HTTPS endpoint. |
| `artifactContainerName` | output | Exact container name. |
| `artifactContainerResourceId` | output | Exact Azure RBAC scope. |
| `artifactRetentionDays` | output | Deployed retention value. |

The example parameter file uses 30 days only as a synthetic reviewed example. Operators must select
and review the required retention value before any deployment.

## Offline validation

No deployment is required:

```powershell
python -m pytest tests/test_artifact_writer.py tests/test_artifact_reader.py tests/test_operational_phase_job.py tests/test_wc013_deployment_assets.py -q
ruff check src tests
mypy src
az bicep build --file infra/azure-mcp/main.bicep
az bicep build --file infra/wc013-live-acceptance/main.bicep
az bicep lint --file infra/azure-mcp/main.bicep
az bicep lint --file infra/wc013-live-acceptance/main.bicep
```
