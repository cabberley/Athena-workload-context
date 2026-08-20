# Operational artifact plane prerequisite

This prerequisite adds storage and a create-only adapter only. It does not run phases, choose Blob
names, project presentation data, or orchestrate retries.

## Azure resources

The existing WC-013 replay StorageV2 account also hosts one Blob container:

- normal client endpoint: `https://<account>.blob.core.windows.net`;
- private endpoint subresource: `blob`;
- private DNS zone: `privatelink.blob.core.windows.net`;
- container: the `artifactContainerName` Bicep parameter;
- immutable version retention: the explicit `artifactRetentionDays` Bicep parameter; and
- identity: the existing acceptance identity with `Storage Blob Data Contributor` scoped to the
  container resource ID only.

The account keeps `allowSharedKeyAccess: false`, OAuth as the default, public Blob access disabled,
and public network access disabled. The private endpoint uses the existing private-endpoint subnet
and VNet link. Clients use the normal Blob hostname; DNS resolves it to the private endpoint.

The retention policy is unlocked. It protects Blob versions from modification or deletion during
the configured period, but an authorized management-plane administrator can still change an
unlocked policy. Locking it is a separate irreversible governance action and is not automated here.

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

## Bicep inputs and outputs

The WC-013 entrypoint adds:

| Name | Direction | Purpose |
|---|---|---|
| `artifactContainerName` | input | The single immutable artifact container. |
| `artifactRetentionDays` | input | Explicit unlocked WORM retention period. |
| `artifactBlobEndpoint` | output | Private-resolved normal Blob HTTPS endpoint. |
| `artifactContainerName` | output | Exact container name. |
| `artifactContainerResourceId` | output | Exact Azure RBAC scope. |
| `artifactRetentionDays` | output | Deployed retention value. |

The example parameter file uses 30 days only as a synthetic reviewed example. Operators must select
and review the required retention value before any deployment.

## Offline validation

No deployment is required:

```powershell
python -m pytest tests/test_artifact_writer.py tests/test_wc013_deployment_assets.py -q
ruff check src tests
mypy src
az bicep build --file infra/azure-mcp/main.bicep
az bicep build --file infra/wc013-live-acceptance/main.bicep
```
