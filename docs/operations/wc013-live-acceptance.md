# WC-013 live acceptance

The initial gate uses two manual Container Apps Jobs in the same private managed environment as
the Azure MCP Container App. An isolated collector job invokes Azure MCP and publishes a signed,
version-pinned evidence artifact. A separate context-only Athena job consumes that exact artifact
and composes the existing `ContextService` and `DemoEvaluationService`. It does not require a
separately deployed Context API HTTP composition.

This is safe only because the job imports a bounded, human-approved, digest-pinned WC-007 authority
bundle and performs no manifest, approval, grant, or key-trust mutation. The imported
`PublishedManifestView`, active `DemoEvaluationApproval`, publisher/context-reader identities, and
exact workload-scoped grants are loaded into the existing transactional ContextService store.
ContextService still re-resolves context, approval, grants, key authority, scope, freshness, and
identity before and after collection and owns the only evaluation commit.

The production path uses:

- `DefaultAzureCredential` with the exact evidence identity only inside the isolated collector for
  the private Azure MCP call, replay-table transaction, collector token, and ingestion signature;
- `DefaultAzureCredential` with the exact context identity only inside Athena for collector
  artifact reads, Key Vault key resolution, snapshot/presentation signing, and operational output
  writes;
- independent Entra JWKS, issuer, audience, time, tenant, object-id, and client-id verification;
- one exact versioned Key Vault RSA key for trusted-ingestion and snapshot RS256 signatures; and
- one Azure Table transaction that atomically reserves both attempt ID and request digest;
- one private immutable collector container for version-pinned evidence handoffs; and
- a separate private immutable Blob container for bounded operational artifacts.

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

## Collector and evaluation execution

The following command is the fixed entry point inside each collector Job. Operators must not run
it with the evidence identity or invoke the Job start action directly:

```powershell
athena-context wc013-evidence-collector-job `
  --config $env:ATHENA_WC013_LIVE_CONFIG `
  --artifact-blob-endpoint $env:ATHENA_WC013_EVIDENCE_BLOB_ENDPOINT `
  --artifact-container $env:ATHENA_WC013_EVIDENCE_CONTAINER `
  --emit-handoff-base64
```

Copy the emitted `ATHENA_WC013_COLLECTED_EVIDENCE_HANDOFF_B64` value unchanged into the
context-only job environment, then run:

```powershell
athena-context wc013-live-acceptance `
  --config $env:ATHENA_WC013_LIVE_CONFIG `
  --evidence-blob-endpoint $env:ATHENA_WC013_EVIDENCE_BLOB_ENDPOINT `
  --evidence-container $env:ATHENA_WC013_EVIDENCE_CONTAINER `
  --snapshot-output .\evidence-snapshot.json
```

The collector writes one create-only `athena.wc013CollectedEvidence.v2` object under the reviewed
attempt ID and emits only an `athena.wc013CollectedEvidenceHandoff.v2` containing its exact Blob
name, immutable version, SHA-256, plan digest, attempt ID, WC-008 assertion digest, and sealed
transport digest. The artifact has a separate Key Vault RSA attestation over those bindings and
the complete collected payload. The Athena job reads that exact version and creates the final
snapshot only after the complete result, artifact attestation, collector identity signature,
source envelope, scope, freshness, transport, and authority checks pass. The dedicated 8 MiB
collector-artifact cap accommodates the 1 MiB raw MCP response, its projected records, and bounded
provenance/attestation overhead without changing the default 1 MiB operational-artifact limit. A
failed run creates no snapshot. Reusing either the attempt ID or request digest is rejected
durably; an operator must issue new reviewed IDs after a failed post-reservation run.

The three-phase operational demonstration reuses this execution path without the direct
`--snapshot-output` file. Its deployed `athena-context operational-phase-job` wrapper writes one
fixed local phase-input file, composes the production Blob reader/writer and Key Vault signer,
invokes the [operational phase runner](operational-phase-runner.md) for one digest-pinned
baseline, faulted, or recovered plan, then writes a governed handoff file for the outer
[operational demo operator](operational-demo-operator.md). Fault injection and reset remain
outside Athena and are represented only by separately delivered receipts.

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
| `ATHENA_WC013_COLLECTED_EVIDENCE_HANDOFF_B64` | Exact base64 collector handoff supplied only to the context-only evaluator job. |

The collector job separately receives `AZURE_CLIENT_ID` and
`ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID` set to the evidence identity plus the pinned WC-007 and
WC-008 digests. The private MCP audience and replay configuration remain in the reviewed plan; the
Athena evaluator receives no evidence-identity selector.

The plan also contains the non-secret Key Vault key ID, public-key metadata, collector trust, replay
configuration, idempotency key, exact command, and relative input-file paths.

## Deployment assets and prerequisites

`infra/wc013-live-acceptance/main.bicep` is the subscription-scope composition for this gate. It
reuses the private Azure MCP foundation and existing internal managed environment and adds private
Key Vault, Table, and Blob dependencies, immutable collector and operational artifact containers,
four collector Jobs, one acceptance Job, three phase-fixed Jobs, and the private presentation
Container App. No public IP or public Container Apps environment is introduced.

The composition pins Azure Verified Modules for Key Vault
(`avm/res/key-vault/vault:0.14.0`), Storage
(`avm/res/storage/storage-account:0.33.0`), Jobs (`avm/res/app/job:0.7.2`), the presentation
Container App (`avm/res/app/container-app:0.23.0`), and both new user-assigned identities
(`avm/res/managed-identity/user-assigned-identity:0.6.0`). The security-critical native Azure MCP,
private DNS, cross-resource-group RBAC, and fixed collector/evaluator Job definitions remain
visible and unchanged in capability.

The identities remain disjoint:

1. the MCP/evidence identity is attached only to collector Jobs and alone has workload Reader;
2. the context identity is attached only to acceptance and phase Jobs and has no workload Reader;
3. the presentation identity is attached only to the presentation app for ACR authentication and
   receives only `AcrPull` at the existing registry;
4. the deployment-owned collector-controller identity is not attached to any runtime and receives
   only the custom collector Job read/start/execution-read role on the four fixed collector Jobs;
5. the operator reader principal remains read-only on the operational artifact container; and
6. the workload identity in `workloadReceiptWriterObjectIds` writes exact run-scoped receipts and
   is neither an operator reader nor an Athena runtime.

The deployment creates the controller identity and a single GitHub federated credential with
issuer `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`, and
subject `repo:cabberley/Athena-workload-context:environment:athena-live`. The Bicep composition
rejects any overlap between its principal ID and the runtime, presentation, operator, or workload
principals. No client secret is created. The `collectorControllerPrincipalId` deployment parameter
no longer exists.

The collector identity has Key Vault sign/verify on the one key, Table Contributor on the replay
table, and Blob Contributor on only the collected-evidence container. The context identity has
key sign/verify, collected-evidence Reader, and operational-artifact Contributor. The presentation
and controller identities receive none of those data-plane roles and receive no MCP, workload, or
broad ARM role. The operator and workload arrays remain normalized and deployment fails if they
overlap or contain either Athena runtime identity.

The presentation app uses a digest-pinned image and one 0.25-vCPU/0.5-GiB replica in
`athena-wc013-live-mcp-env`. Its ingress is external to the Container Apps environment only so it
is reachable from the linked VNet; the environment remains `internal: true` with
`publicNetworkAccess: Disabled`, making the HTTPS FQDN private to the VNet/jumpbox. HTTP redirects
to HTTPS and the container listens as non-root on port 8080. NGINX returns `/healthz`, preserves
JSON bytes and MIME, excludes missing JSON from SPA fallback, sends the reviewed security headers,
disables caching for HTML/reviewed JSON, and caches only content-addressed assets as immutable.

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
execution, an Entra administrator must grant both the Azure MCP application role and the
trusted-ingestion application role only to `evidenceIdentityPrincipalId`. Remove any earlier Azure
MCP application-role grant from `acceptanceJobIdentityPrincipalId`. The trusted-ingestion token
must retain the exact configured `api://...` audience, rather than only a client-ID GUID audience.
No client secret is created or accepted.

The deployment identity needs resource deployment rights in the hosting resource group, role
assignment rights at the supplied demo resource-group and ACR scopes, and permission to create the
key-scoped and table-scoped data-plane role assignments and the narrowly assignable custom
collector-controller role. The supplied existing ACR receives separate `AcrPull` assignments for
the evidence, context, and presentation identities; no broader registry role is assigned. Review
the subscription what-if for deletes, public exposure, and all
role assignments before creating a deployment.

### Build the runner, presentation, and deployment configuration images

The root `Dockerfile` packages this repository with its normal `pyproject.toml` installation and
runs the `athena-context wc013-live-acceptance` CLI as a non-root user. It deliberately contains no
operator configuration. `Dockerfile.wc013-delivery` is the second, required image layer: it copies
the reviewed `wc013-live/` tree and the public PEM into the fixed paths used by the Jobs. For the
operational demonstration, that same `wc013-live/` tree must also contain the reviewed phase bundle
at `wc013-live/delivery/operational-phase-bundle.json`.

Build and push a digest-pinned runner image first. Use it as the bootstrap `acceptanceImage`; the
Job is manual and must not be started at this stage.

```powershell
docker build --file Dockerfile --tag <registry>/athena/wc013-runner:<reviewed-tag> .
docker push <registry>/athena/wc013-runner:<reviewed-tag>
```

Build the presentation from its dedicated context. ACR remote build uses the same multi-stage,
digest-pinned Dockerfile without requiring a local Docker daemon:

```powershell
az acr build `
  --registry athenademoa6add389 `
  --image athena/presentation-web:<reviewed-tag> `
  --file apps/presentation-web/Dockerfile `
  apps/presentation-web

$presentationDigest = az acr repository show `
  --name athenademoa6add389 `
  --image athena/presentation-web:<reviewed-tag> `
  --query digest `
  --output tsv
```

Replace `.azure/wc013.parameters.json` `presentationImage` with
`athenademoa6add389.azurecr.io/athena/presentation-web@$presentationDigest`. Until then it contains
an all-zero digest that is syntactically valid but cannot resolve, so preparation cannot
accidentally create a runnable app. Keep the current `acceptanceImage` value until the runner and
delivery build step intentionally replaces it.

Build the Bicep templates before a what-if or deployment:

```powershell
az bicep build --file infra/azure-mcp/main.bicep
az bicep build --file infra/wc013-live-acceptance/main.bicep
az bicep lint --file infra/azure-mcp/main.bicep
az bicep lint --file infra/wc013-live-acceptance/main.bicep
```

`infra/wc013-live-acceptance/main.example.bicepparam` remains the synthetic example. The approved
redeployment uses `.azure/wc013.parameters.json`: operator Reader object ID
`51425b07-8512-4c49-a763-23a09c347f0b`, workload receipt-writer object ID
`48bedd25-5a4d-4d5b-babd-56d259a41b0d`, and the confirmed subscription, location, resource names,
ACR, Entra applications, and audiences. The controller principal is deployment-owned and is not a
parameter. Review the two arrays independently and never reuse either principal for a runtime,
presentation, or controller identity. Before any deployment, replace the all-zero presentation
digest. Before any Job start, also replace bootstrap authority/assertion pins and the runner/delivery
image with current reviewed renderer/build output.

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
```

Copy the reviewed operational phase delivery bundle into
`<staging-directory>/wc013-live/delivery/` before the image build. That subtree must contain
`operational-phase-bundle.json`, `configs/`, and every WC-007, WC-008, and public-key file
referenced by the reviewed phase plans.

```powershell
Set-Location <staging-directory>
docker build `
  --file <repository-root>/Dockerfile.wc013-delivery `
  --build-arg ATHENA_WC013_RUNNER_IMAGE=<runner-image-by-digest> `
  --tag <registry>/athena/wc013-live:<reviewed-tag> `
  .
docker push <registry>/athena/wc013-live:<reviewed-tag>
```

The staging directory must contain `wc013-live/` (including the reviewed `delivery/` subtree)
and `wc013-signing-public-key.pem` only as reviewed non-secret delivery artifacts. Do not add
authority data, PEM files, or any runtime files to Bicep parameters, outputs, Container Apps
secrets, or source control.

Update the operator parameter file with the configuration delivery image digest and the exact
`pinned authority digest` and `pinned assertion digest` printed by the renderer. Re-run what-if,
then redeploy the same Bicep entrypoint. This updates the manual Jobs with their reviewed image
and non-secret environment pins. Re-read the Key Vault version output after each resource
deployment; if a new key version was intentionally produced, download that public key and rerender
before starting any Job.

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

# After merge, protected-environment approval, deployment, and output review only:
gh workflow run wc013-collector-controller.yml `
  --ref main `
  -f phase=baseline
```

Before dispatch, configure the protected GitHub environment `athena-live` to allow deployments only
from `main`, require its human reviewers, and add non-secret environment variables
`AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID`, and `WC013_COLLECTOR_CONTROLLER_CLIENT_ID`. Set the last
value from the reviewed `collectorControllerIdentityClientId` deployment output. The federated
credential subject is environment-bound, so a branch or job without `environment: athena-live`
cannot exchange a token. The workflow grants only `contents: read` and `id-token: write`, uses
`azure/login` without a secret, verifies the Azure CLI service-principal client ID, and accepts only
`baseline`, `faulted`, or `recovered`. It selects the corresponding fixed contract from the
`wc013-ready` deployment output; no image, command, args, environment, or template input exists.

The controller first retrieves the deployed Job, rejects any identity, registry, image, command,
argument, environment, resource, init-container, volume, trigger, retry, or timeout difference,
then calls the ARM start action with that exact validated template as the complete execution body.
This prevents a Job-template write between validation and start from changing the execution. Its API
and CLI expose no caller-supplied execution-template or mutable field. Direct
`az containerapp job start` use for collector Jobs is prohibited.

Retrieve the collector handoff from its bounded log line. Start `acceptanceJobName` only through a
complete execution-template override that preserves the deployed image, command, arguments,
single context identity, and configuration path and adds only
`ATHENA_WC013_COLLECTED_EVIDENCE_HANDOFF_B64`.

Do not grant human operator identities direct start permission on the three operational phase
Jobs. Container Apps start-time environment changes require a complete execution-template
override. The separately governed phase-job controller must validate the deployed reviewed
template, preserve its image, command, args, identities, and bundle path exactly, and modify only
the allowlisted bounded receipt, prior-index, lineage, and collected-evidence handoff variables.

The relevant final outputs include the MCP endpoint/environment, evidence and context identity IDs,
Key Vault key, replay/artifact endpoints and scopes, all acceptance/phase/collector Job names and
IDs, and `evidenceCollectorStartContracts`. Controller outputs are
`collectorControllerRoleDefinitionId`, `collectorControllerIdentityClientId`,
`collectorControllerIdentityPrincipalId`, and `collectorControllerIdentityResourceId`.
Presentation outputs are `presentationContainerAppName`, `presentationContainerAppResourceId`,
`presentationFqdn`, `presentationHttpsUrl`, and all three presentation identity IDs. Use the fully
qualified `presentationHttpsUrl` only from the linked VNet/jumpbox and verify `/healthz`, JSON MIME,
exact bytes, no-cache and immutable-cache boundaries, CSP, nosniff, referrer, permissions, and frame
headers before acceptance.

No Context API Container App, internet-reachable environment endpoint, client secret, storage
account key, or exported private key is required for this initial one-shot gate.

The equivalent live pytest gate is:

```powershell
$env:ATHENA_WC013_LIVE = '1'
$env:ATHENA_WC013_LIVE_CONFIG = (
  Resolve-Path .\wc013-live\wc013-live-acceptance.json
)
$env:ATHENA_WC013_EVIDENCE_BLOB_ENDPOINT = 'https://<account>.blob.core.windows.net'
$env:ATHENA_WC013_EVIDENCE_CONTAINER = 'collected-evidence'
$env:ATHENA_WC013_COLLECTED_EVIDENCE_HANDOFF_B64 = '<collector-handoff>'
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
scopes for the acceptance identity. This was a pre-ADR-0014 combined-job execution and does not
demonstrate the current isolated collector/evaluator identity boundary.

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
Apps environment remained internal with public network access disabled. This was also a
pre-ADR-0014 combined-job execution; a new live run must use the split collector/evaluator flow.
