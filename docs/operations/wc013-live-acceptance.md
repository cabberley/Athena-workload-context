# WC-013 live acceptance

The initial gate is a one-shot Container Apps Job in the same private managed environment as the
Azure MCP Container App. It does not require a separately deployed Context API HTTP composition.
The CLI composes the existing `ContextService`, `DemoEvaluationService`,
`ManagedIdentityPrivateMcpInvoker`, `PrivateMcpEvidenceTransport`, and
`Wc009EvidenceClientAdapter` in process.

This is safe only because the job imports a bounded, human-approved, digest-pinned WC-007 authority
bundle and performs no manifest, approval, grant, or key-trust mutation. The imported
`PublishedManifestView`, active `DemoEvaluationApproval`, publisher/context-reader identities, and
exact workload-scoped grants are loaded into the existing transactional ContextService store.
ContextService still re-resolves context, approval, grants, key authority, scope, freshness, and
identity before and after collection and owns the only evaluation commit.

The production path uses:

- `DefaultAzureCredential` with the exact context identity for the private Azure MCP call, Key Vault
  signing/key resolution, and replay-table transaction;
- a separate explicitly selected evidence identity token for the retained MCP collector identity
  proof;
- independent Entra JWKS, issuer, audience, time, tenant, object-id, and client-id verification;
- one exact versioned Key Vault RSA key for trusted-ingestion and snapshot RS256 signatures; and
- one Azure Table transaction that atomically reserves both attempt ID and request digest.
- one private immutable Blob container prepared for later bounded operational artifacts.

No bearer token, client secret, storage key, connection string, or private key is accepted in
configuration or persisted in evidence.

WC-008 deliberately configures the MCP app with `external: true` while the Container Apps
environment remains `internal: true` with `publicNetworkAccess: Disabled`. In this combination,
external ingress means reachable through the environment's private static IP from the linked VNet;
it does not create an internet-reachable endpoint. A private DNS zone named for the environment
`defaultDomain` is linked to that VNet, and its wildcard A record maps the normal non-`.internal`
Container App FQDN to the environment `staticIp`. See
`docs/adr/0004-vnet-scoped-container-app-ingress.md`.

## Reviewed input files

`wc013-source.json` is produced by `athena-context wc013-config-template` and references:

1. the exact WC-008 deployment facts and separate human operator approval;
2. a `wc013-authority-source.json` containing:
   - `published_context`: exact active `PublishedManifestView`;
   - `evaluation_approval`: exact active `DemoEvaluationApproval`;
   - `publisher` and `context_reader` actors;
   - at least one exact workload-scoped publisher grant and reader grant;
3. the exact WC-007 selection and `DemoEvaluationCommand`;
4. separate context/evidence managed-identity client IDs;
5. the private Azure MCP audience;
6. collector trust and the exact versioned Key Vault key/public PEM; and
7. the Azure Table endpoint, table name, and acceptance partition key.

The authority source is an export, not a proposal or publication command. The renderer computes its
canonical digest, creates a separate human trust record, and refuses to overwrite output.

```powershell
athena-context wc013-config-template |
  Set-Content -Encoding utf8 .\wc013-source.json

athena-context wc013-render-config `
  --input .\wc013-source.json `
  --output-directory .\wc013-live
```

Download only the public half of the exact key version:

```powershell
az keyvault key download `
  --id 'https://<vault>.vault.azure.net/keys/<name>/<version>' `
  --encoding PEM `
  --file .\wc013-signing-public-key.pem
```

## Offline validation

This performs no credential or network operation:

```powershell
athena-context wc013-live-acceptance `
  --config .\wc013-live\wc013-live-acceptance.json `
  --validate-only
```

It validates both pinned human approvals, WC-007 selection/digests/profile, active unsuperseded
shape, exact workload grants, WC-008 endpoint/identity/scope, separate identities, trusted key
fingerprint, and all bounded files.

The rendered WC-008 assertion must pin `internal_environment: true`,
`public_network_access: Disabled`, `external_ingress: true`, and `allow_insecure: false`. An older
assertion that records `external_ingress: false` no longer represents the deployable topology and
must be re-rendered and separately approved.

## One-shot execution

Run the generated environment file as the Job startup script, then:

```powershell
athena-context wc013-live-acceptance `
  --config $env:ATHENA_WC013_LIVE_CONFIG `
  --snapshot-output .\evidence-snapshot.json
```

The output is created exclusively, canonicalized, and marked read-only only after the complete
result, snapshot attestation, collector identity signature, scope, freshness, and authority checks
pass. A failed run creates no snapshot. Reusing either the attempt ID or request digest is rejected
durably; an operator must issue new reviewed IDs after a failed post-reservation run.

## Exact runtime environment variables

Generated `wc013-runtime.ps1` sets:

| Variable | Exact purpose |
|---|---|
| `AZURE_CLIENT_ID` | WC-008 context managed-identity client ID. |
| `ATHENA_WC013_LIVE` | `1` for the opt-in pytest gate. |
| `ATHENA_WC013_LIVE_CONFIG` | Absolute path to `wc013-live-acceptance.json`. |
| `ATHENA_WC013_MANIFEST_ID` | Exact WC-007 manifest ID. |
| `ATHENA_WC013_MANIFEST_VERSION` | Exact active version. |
| `ATHENA_WC013_PROFILE_ID` | Exact resolved profile ID. |
| `ATHENA_WC013_WC007_AUTHORITY_FILE` | Bounded rendered authority bundle. |
| `ATHENA_WC013_WC007_AUTHORITY_APPROVAL_FILE` | Separate human approval of the authority digest. |
| `ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST` | Exact `sha256:<64 lowercase hex>` digest. |
| `ATHENA_WC013_WC008_DEPLOYMENT_ASSERTION_FILE` | Bounded WC-008 assertion JSON. |
| `ATHENA_WC013_WC008_OPERATOR_APPROVAL_FILE` | Separate human WC-008 approval JSON. |
| `ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST` | Exact WC-008 digest. |
| `ATHENA_WC013_CONTEXT_IDENTITY_CLIENT_ID` | Exact context identity client ID. |
| `ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID` | Exact evidence identity client ID. |
| `ATHENA_WC013_AZURE_MCP_AUDIENCE` | Private Azure MCP Entra audience. |
| `ATHENA_WC013_REPLAY_TABLE_ENDPOINT` | Private HTTPS Azure Table endpoint. |
| `ATHENA_WC013_REPLAY_TABLE_NAME` | Pre-created replay table. |
| `ATHENA_WC013_REPLAY_PARTITION_KEY` | Dedicated acceptance-run namespace. |

The plan also contains the non-secret Key Vault key ID, public-key metadata, collector trust, replay
configuration, idempotency key, exact command, and relative input-file paths.

## Deployment assets and prerequisites

`infra/wc013-live-acceptance/main.bicep` is the subscription-scope composition for this gate. It
creates a dedicated hosting resource group, reuses `infra/azure-mcp/main.bicep` and its pinned
Azure MCP 2.0.5 implementation, and adds a private-endpoint subnet, private DNS zones, a private
Key Vault, private Azure Table and Blob endpoints, one immutable artifact container, and a manual
Container Apps Job in the same internal managed environment.

The composition uses pinned Azure Verified Modules for the Key Vault
(`avm/res/key-vault/vault:0.14.0`), Storage account
(`avm/res/storage/storage-account:0.33.0`), and Container Apps Job
(`avm/res/app/job:0.7.2`). The existing native Azure MCP implementation remains visible because its
reviewed image, command line, VNet-scoped ingress, private DNS, and cross-resource-group Reader
assignment are security-critical.

It creates exactly two runtime identities:

1. the MCP/evidence identity has the single Reader role at the supplied synthetic demo workload
   resource-group scope; and
2. the separate acceptance-job context identity is attached to the Job and has no workload Reader
   or workspace-log role.

The job selects the acceptance identity with `AZURE_CLIENT_ID`; it attaches the MCP/evidence
identity only so the in-process adapter can acquire the separate collector token. The Key Vault
role is scoped to the one RSA key, `Storage Table Data Contributor` is scoped to the one replay
table, and `Storage Blob Data Contributor` is scoped to the one immutable artifact container.
Shared keys, connection strings, secrets, and private key export are disabled or unused.

### Required existing Entra resources

Azure Resource Manager Bicep intentionally does not create Entra applications or directory
application-role assignments. Supply these non-secret IDs and audiences as Bicep parameters before
the infrastructure deployment:

- `azureMcpResourceApplicationClientId` and `azureMcpAudience`: an existing Azure MCP resource
  application whose Application ID URI equals the configured audience and which exposes the
  reviewed `Mcp.Tools.ReadWrite.All` application role.
- `trustedIngestionResourceApplicationClientId` and `trustedIngestionAudience`: an existing
  trusted-ingestion resource application whose Application ID URI equals the configured ingestion
audience, accepts v1 access tokens, and exposes an application role usable with `.default`.

After the first deployment has produced the two managed-identity principal IDs, but before any Job
execution, an Entra administrator must grant the Azure MCP application role only to
`acceptanceJobIdentityPrincipalId` and the trusted-ingestion application role only to
`evidenceIdentityPrincipalId`. The trusted-ingestion token must retain the exact configured
`api://...` audience, rather than only a client-ID GUID audience. No client secret is created or
accepted.

The deployment identity needs resource deployment rights in the hosting resource group, role
assignment rights at the supplied demo resource-group and ACR scopes, and permission to create the
key-scoped and table-scoped data-plane role assignments. The supplied existing ACR resource ID is
also assigned `AcrPull` for the acceptance identity. Review the subscription what-if for deletes,
public exposure, and all role assignments before creating a deployment.

### Build the runner and deployment configuration image

The root `Dockerfile` packages this repository with its normal `pyproject.toml` installation and
runs the `athena-context wc013-live-acceptance` CLI as a non-root user. It deliberately contains no
operator configuration. `Dockerfile.wc013-delivery` is the second, required image layer: it copies
only the reviewed rendered files and the public PEM into the fixed paths used by the Job.

Build and push a digest-pinned runner image first. Use it as the bootstrap `acceptanceImage`; the
Job is manual and must not be started at this stage.

```powershell
docker build --file Dockerfile --tag <registry>/athena/wc013-runner:<reviewed-tag> .
docker push <registry>/athena/wc013-runner:<reviewed-tag>
```

Build the Bicep templates before a what-if or deployment:

```powershell
az bicep build --file infra/azure-mcp/main.bicep
az bicep build --file infra/wc013-live-acceptance/main.bicep
```

Copy `infra/wc013-live-acceptance/main.example.bicepparam` to an operator-owned parameter file.
It contains only synthetic non-secret values. Set the globally unique Key Vault and Storage account
names, exact target demo resource-group scope, existing ACR server/resource ID, existing Entra app
IDs/audiences, and the runner image digest. For the bootstrap deployment, leave the two
`wc007PinnedAuthorityDigest` and `wc008PinnedAssertionDigest` values as nonmatching placeholders.
They prevent an accidental execution until the reviewed renderer output is available.

```powershell
az deployment sub what-if `
  --name wc013-bootstrap `
  --location <region> `
  --template-file infra/wc013-live-acceptance/main.bicep `
  --parameters <operator-wc013.bicepparam>

az deployment sub create `
  --name wc013-bootstrap `
  --location <region> `
  --template-file infra/wc013-live-acceptance/main.bicep `
  --parameters <operator-wc013.bicepparam>

az deployment sub show --name wc013-bootstrap --query properties.outputs -o json
```

Map the first deployment outputs directly into `wc013-source.json`: use the MCP endpoint, managed
environment and Container App resource IDs, both identity resource/principal/client IDs, the one
Reader scope, `azureMcpAudience`, `replayTableEndpoint`, `replayTableName`, and
`signingKeyUriWithVersion`. Use the output key URI, not an unversioned name, to download the public
PEM. The configured trusted-ingestion application ID and audience remain operator-supplied Bicep
outputs for the collector trust section.

Download the exact public key, then render the reviewed files into a staging directory:

```powershell
az keyvault key download `
  --id <signingKeyUriWithVersion> `
  --encoding PEM `
  --file <staging-directory>/wc013-signing-public-key.pem

athena-context wc013-render-config `
  --input <staging-directory>/wc013-source.json `
  --output-directory <staging-directory>/wc013-live

Set-Location <staging-directory>
docker build `
  --file <repository-root>/Dockerfile.wc013-delivery `
  --build-arg ATHENA_WC013_RUNNER_IMAGE=<runner-image-by-digest> `
  --tag <registry>/athena/wc013-live:<reviewed-tag> `
  .
docker push <registry>/athena/wc013-live:<reviewed-tag>
```

The staging directory must contain `wc013-live/` and `wc013-signing-public-key.pem` only as
reviewed non-secret delivery artifacts. Do not add authority data, PEM files, or any runtime files
to Bicep parameters, outputs, Container Apps secrets, or source control.

Update the operator parameter file with the configuration delivery image digest and the exact
`pinned authority digest` and `pinned assertion digest` printed by the renderer. Re-run what-if,
then redeploy the same Bicep entrypoint. This updates the manual Job with its reviewed image and
non-secret environment pins. Re-read the Key Vault version output after each resource deployment;
if a new key version was intentionally produced, download that public key and rerender before
starting the Job.

```powershell
az deployment sub what-if `
  --name wc013-ready `
  --location <region> `
  --template-file infra/wc013-live-acceptance/main.bicep `
  --parameters <operator-wc013.bicepparam>

az deployment sub create `
  --name wc013-ready `
  --location <region> `
  --template-file infra/wc013-live-acceptance/main.bicep `
  --parameters <operator-wc013.bicepparam>

az containerapp job start `
  --name <acceptanceJobName> `
  --resource-group <foundationResourceGroupName>
```

The relevant final outputs are `azureMcpInternalEndpoint`, `azureMcpAudience`,
`azureMcpContainerAppResourceId`, `managedEnvironmentResourceId`, all evidence and acceptance
identity IDs, `keyVaultUri`, `signingKeyName`, `signingKeyUriWithVersion`,
`replayStorageAccountResourceId`, `replayTableEndpoint`, `replayTableName`,
`replayTableResourceId`, `artifactBlobEndpoint`, `artifactContainerName`,
`artifactContainerResourceId`, `artifactRetentionDays`, `acceptanceJobName`, and
`acceptanceJobResourceId`.

No Context API Container App, internet-reachable environment endpoint, client secret, storage
account key, or exported private key is required for this initial one-shot gate.

The equivalent live pytest gate is:

```powershell
$env:ATHENA_WC013_LIVE = '1'
$env:ATHENA_WC013_LIVE_CONFIG = (
  Resolve-Path .\wc013-live\wc013-live-acceptance.json
)
python -m pytest tests/test_wc013_live.py -m live
```

The second live test retains the direct unauthenticated Azure MCP `tools/list` 401/403 check.

## Recorded initial acceptance

The initial live gate completed successfully on 2026-08-19:

- Container Apps Job execution:
  `athena-wc013-live-acceptance-6b9olif`
- Runner image digest:
  `sha256:44407e4cda6f8d5c413f583e95a75565aa7dc3ddd2f216197a4dbd17d0ef2b67`
- Delivery image digest:
  `sha256:5cfbcc0f50aef45f07e45d5a12210f7497fe6a8e4fadda08d1a1443996e94110`
- Manifest/profile:
  `wl-athena-demo-live-inventory` / `production`
- Attempt/snapshot:
  `attempt-63719e874a0b` / `snap-77139bba9a02`
- Snapshot artifact and semantic digest:
  `sha256:0647e9609cc2b3096c1d722ab7e56dd7b866f8320783ddeebdf2e3273abd9ab6`
- WC-007 authority digest:
  `sha256:5bdf54958a5e83b38129740c8ab0b4d8d05500eb5b126373d942f3baf8aec016`
- WC-008 assertion digest:
  `sha256:93c36c4615c35b5a19616ea471f376d9596ab81c415827b02cd0d9b65c70ef21`
- Evidence records: 15 projected resources from
  `rg-athena-demo-workload`.

The recorded WC-008 assertion digest above is historical evidence for that completed run. Do not
reuse it after reconciling the deployment to VNet-scoped `external_ingress: true`; render and
approve a new assertion for the next execution.

Independent verification recomputed both immutable snapshot digests and verified the Key Vault
RSA snapshot attestation and trusted-ingestion signature against the pinned public key. Live RBAC
verification also confirmed Reader only on the demo resource group for the evidence identity, and
only AcrPull, Key Vault Crypto User, and Storage Table Data Contributor at their exact resource
scopes for the acceptance identity.

## Recorded VNet-scoped re-attestation

The reconciled VNet-scoped composition completed successfully on 2026-08-20:

- Container Apps Job execution:
  `athena-wc013-live-acceptance-1mmei91`
- Runner image digest:
  `sha256:4ded30d50ee849d33d32597bfe88fc3b32af02a5b4a6376c749be586b407c095`
- Delivery image digest:
  `sha256:946f6b4e7008f4af80c4d66bbc28f5a4c29972dcd0e65e58452fd09a4451ba13`
- VNet-accessible private MCP endpoint:
  `https://athena-wc013-live-mcp.delightfulmeadow-2f7be892.australiaeast.azurecontainerapps.io`
- Attempt/snapshot:
  `attempt-c2fb3624108e` / `snap-7b4f7b57e673`
- Snapshot artifact and semantic digest:
  `sha256:5137142b745beb4e5c75db1c42f8178b4716fec265aa479796e324c4568c8f2c`
- WC-007 authority digest:
  `sha256:d90b488ecf17915eeb1fe8944ad4ce0e81637c01a160e1d9ecce8a62fc9a2500`
- WC-008 assertion digest:
  `sha256:dd19d5ce778225ed3840ce1f7bf47bfeab561ac3af91e93b162de7b3ffce8183`
- Evidence records: 15 projected resources from
  `rg-athena-demo-workload`.

Independent verification confirmed both RSA signatures, the exact managed-identity claims,
authorized resource-group scope, successful MCP attempt, and immutable snapshot digests. An
authenticated MCP initialize request from the VNet jumpbox returned HTTP 200 while the Container
Apps environment remained internal with public network access disabled.
