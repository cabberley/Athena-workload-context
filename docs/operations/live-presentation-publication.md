# Live presentation publication

This runbook connects the verified operational demonstration to the private presentation web.
See [ADR 0016](../adr/0016-live-workload-presentation-publication.md).

## Security boundary

- `operational-artifacts` remains the immutable, version-pinned verification plane.
- `presentation-assets` is private, has no public access, and is intentionally non-WORM so only
  `runtime-manifest.json` can be replaced.
- Storage account Blob versioning remains enabled.
- No account key, connection string, SAS, public container, CORS rule, or browser Azure credential
  is used.
- Operator object IDs receive Blob Data Reader on `operational-artifacts` and Blob Data
  Contributor only on `presentation-assets`.
- The presentation identity receives ACR pull and Blob Data Reader only on
  `presentation-assets`. It must not receive access to `operational-artifacts`, workload Reader,
  Key Vault, Table, MCP, or Job control.

## Exact operator configuration

Add this optional section to the reviewed `athena.operationalDemoOperator.v1` file:

```json
{
  "presentationPublisher": {
    "blobEndpoint": "https://<storage-account>.blob.core.windows.net",
    "containerName": "presentation-assets",
    "managedIdentityClientId": "<operator-managed-identity-client-id>"
  }
}
```

`blobEndpoint` must be one credential-free HTTPS Blob origin. `containerName` must be exactly
`presentation-assets`. The client ID is the managed identity used by the external operator; its
corresponding object ID must appear in `operatorArtifactReaderObjectIds`.

Omitting the section preserves the previous verify-only operator behavior.

## Publication sequence

After status, injection, reset, and all three recovered phase checks succeed, the operator:

1. confirms all three signed receipts target the same case-insensitive resource group;
2. confirms the presentation public key matches key ID
   `synthetic-key://athena-argus-demo/rs256-v1` and SPKI fingerprint
   `sha256:9323d86eb7d1fffccc409a89795e04ef71db7c9b011dad9c2f3e3fcf6e81784a`;
3. create-writes the exact verified payload and attestation bytes to:
   `live/runs/<runId>/<phase>/argus-presentation.json` and
   `live/runs/<runId>/<phase>/presentation-attestation.json`;
4. records each exact content SHA-256 in strict `athena.presentationWeb.runtime.v2`; and
5. overwrites `runtime-manifest.json` in one final Blob PUT.

The pointer-last sequence is the atomic publication boundary. A failed asset write leaves the
previous pointer unchanged. Retrying the same run is safe only when any existing immutable asset
has the exact expected bytes, content type, and digest; a mismatch fails closed.

If any publication action fails, the command exits non-zero with
`presentation publication failed closed; reset succeeded`. Do not interpret the successful reset
as successful publication.

## Gateway behavior

The presentation Container App includes the digest-pinned WC-013 delivery image as a sidecar:

```text
athena-context presentation-asset-gateway
  --blob-endpoint https://<storage-account>.blob.core.windows.net
  --container presentation-assets
  --managed-identity-client-id <presentation-identity-client-id>
  --port 8081
```

It listens only inside the Container App replica. NGINX proxies the exact
`/runtime-manifest.json` path and `/live/` prefix to `127.0.0.1:8081`. The gateway permits only
GET and HEAD for the current manifest, currently allowlisted live assets, and `/healthz`. It never
lists, writes, redirects, returns credentials, or accepts arbitrary Blob paths.

## No-run, stale, and failure behavior

- No `runtime-manifest.json`: the gateway returns a generic unavailable JSON response and the
  browser renders no lifecycle.
- Invalid current manifest, missing asset, wrong content type, oversized content, metadata hash
  mismatch, or content digest mismatch: the gateway returns a generic unavailable response.
- Failed new run before pointer replacement: the previous complete run remains current.
- An older complete pointer is not silently relabelled as current evidence. The UI separately
  exposes its verified evaluation UTC time and later publication UTC time, alongside the run ID
  and target resource group, so operators can identify staleness. The manifest rejects publication
  times earlier than the recovered evaluation.
- Browser key, signature, lifecycle, or target-resource-group binding failure: the complete
  lifecycle is withheld.

## Deployment and validation

Set `presentationAssetContainerName` to `presentation-assets` or use its default. Build both the
presentation image and WC-013 delivery image, resolve their ACR RepoDigests, update the reviewed
parameters, and run:

```powershell
az bicep build --file infra/wc013-live-acceptance/main.bicep --stdout > $null
pytest tests/test_presentation_asset_gateway.py `
  tests/test_presentation_asset_store.py `
  tests/test_operational_demo_operator.py `
  tests/test_presentation_deployment.py `
  tests/test_wc013_deployment_assets.py

Push-Location apps/presentation-web
npm run typecheck
npm run lint
npm test -- --run
npm run build
Pop-Location
```

From the linked VNet, verify `/healthz`, then `/runtime-manifest.json`. Do not bypass a no-run or
unavailable response by copying assets into the NGINX image or granting broader storage access.
