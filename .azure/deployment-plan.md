# Azure Deployment Plan

> **Status:** Validated

Generated: 2026-08-31T12:28:07+10:00

Updated: 2026-09-02T00:58:02Z for the live workload presentation connection.

The follow-on deployment adds a private `presentation-assets` container, operator-only
publication of the fully verified lifecycle, a managed-identity read-only gateway sidecar, and
same-origin delivery to the presentation browser. The browser displays the exact target resource
group and separate verified evaluation/publication times only after signature, digest, lifecycle,
key, and resource-group binding checks pass.

---

## 1. Project Overview

**Goal:** Redeploy the merged Athena architecture into the existing WC-013 Azure footprint,
including isolated evidence collectors, governed collector execution, context-only evaluation
jobs, and the standalone verified presentation web application.

**Path:** Add Components and update the existing development operational demonstration.

---

## 2. Requirements

| Attribute | Value |
|-----------|-------|
| Classification | Development operational demonstration |
| Scale | Small |
| Budget | Cost-Optimized |
| Subscription | AG-CI-CE-chabberl (`a6add389-9978-47ac-ab1e-a09212e321d4`) |
| Location | `australiaeast` |
| Presentation access | Private HTTPS from the existing jumpbox/VNet only |

The user reconfirmed the subscription, location, and private presentation access model on
2026-08-31.

---

## 3. Components Detected

| Component | Type | Technology | Path |
|-----------|------|------------|------|
| Private Azure MCP | Internal service | Azure Container Apps | `infra/azure-mcp/` |
| Isolated evidence collectors | Four manual jobs | Python 3.14 / Container Apps Jobs | `src/athena_context/wc013_evidence_collector.py` |
| Governed collector controller | Control-plane client | Digest-pinned Python 3.14 container / GitHub OIDC | `src/athena_context/wc013_collector_controller.py` |
| WC-013 evaluation | One manual job | Python 3.14 / Container Apps Jobs | `src/athena_context/live_acceptance.py` |
| Operational phases | Three manual jobs | Python 3.14 / Container Apps Jobs | `src/athena_context/operational_phase_job.py` |
| Immutable evidence plane | Storage | Private Blob and Table endpoints | `infra/wc013-live-acceptance/` |
| Signing boundary | Key service | Azure Key Vault RS256 | `infra/wc013-live-acceptance/` |
| Presentation app | Frontend | React, TypeScript, Vite | `apps/presentation-web/` |

---

## 4. Recipe Selection

**Selected:** Bicep with Azure CLI and ACR remote builds.

**Rationale:**

- The deployment already uses reviewed subscription-scope Bicep and an existing private
  Container Apps environment.
- Updating the deployment in place avoids replacing the VNet, Key Vault, Storage account,
  private endpoints, identities, or Azure MCP endpoint.
- `az deployment sub what-if` provides an explicit delete and RBAC review before deployment.
- `az acr build` avoids relying on a local Docker daemon and returns digest-addressable images.

---

## 5. Architecture

**Stack:** Private Container Apps, managed identities, immutable private Blob artifacts, Key Vault
signing, and a private static presentation container.

### Service Mapping

| Component | Azure Service | SKU / mode |
|-----------|---------------|------------|
| Private Azure MCP | Existing Container App | Internal environment, pinned image |
| Evidence collection | Four Container Apps Jobs | Manual, 0.5 vCPU / 1 GiB |
| Athena evaluation | Existing acceptance Job, updated | Manual, context identity only |
| Operational lifecycle | Existing three phase Jobs, updated | Manual, context identity only |
| Presentation | New private Container App | 0.25 vCPU / 0.5 GiB, minimum one replica |
| Presentation hosting | NGINX unprivileged container | Same-origin JSON, HTTPS ingress, CSP headers |
| Operational artifacts | Existing StorageV2 account | OAuth only, versioned immutable containers |
| Signing | Existing Key Vault key | Managed identity, RS256 |
| Container images | Existing Basic ACR | Digest-pinned runner, delivery, controller, and presentation images |

### Identity and trust boundaries

- The MCP/evidence identity is attached only to collector Jobs and retains workload Reader only
  on `rg-athena-demo-workload`.
- The context identity is attached only to evaluation/phase Jobs and has no workload Reader role.
- The workload receipt writer becomes the existing workload-managed identity
  `athena-hackathon-workload-id` (`48bedd25-5a4d-4d5b-babd-56d259a41b0d`), not the operator reader.
- The operator artifact reader remains `51425b07-8512-4c49-a763-23a09c347f0b`.
- A new collector-controller identity is created with only the custom collector Job
  read/start/execution-read role. It is not attached to any Athena runtime and has no deployment
  read permission or broad Reader role. It receives only one additional `AcrPull` assignment on
  the existing ACR for the exact controller image.
- A GitHub OIDC federated credential binds that controller identity to the protected
  `cabberley/Athena-workload-context` deployment environment so collector starts execute reviewed
  controller code without a client secret. The workflow checks out the immutable dispatch SHA,
  then uses a networkless, digest-pinned minimal Python verifier container to reject duplicate keys
  recursively and emit one canonical bounded selection before Azure login. Only then may `jq` read
  that selection and independently verify that the requested phase maps to its exact Job suffix,
  collector name, fixed configuration path, and acceptance ACR repository. The workflow pulls the
  exact reviewed controller RepoDigest and executes only that image with a one-shot ARM token piped
  through stdin. No repository Python or dependencies execute through the hosted runner Python,
  and the workflow never reads mutable deployment outputs.
- A new presentation identity receives only `AcrPull`; the presentation container receives no
  Blob, Key Vault, MCP, workload, or ARM role.
- The presentation browser makes same-origin requests only and validates content hashes,
  RFC 8785 digests, RS256 signatures, key fingerprint, and lifecycle consistency before rendering.
- The unavoidable execution substrate is GitHub's hosted `ubuntu-24.04` runner and its pinned-action
  plumbing (`azure/login`, Azure CLI, curl, jq, SHA-256, Docker client/daemon) plus the pinned
  verifier image. No controller code or unpinned Python runs directly on the host; exact image and
  contract digests, strict canonical selection, and ephemeral token pipes bound the residual trust.

### Network boundary

- The presentation Container App is deployed into
  `athena-wc013-live-mcp-env`.
- Ingress is enabled for the environment-internal address only; no public endpoint is introduced.
- The existing private Container Apps DNS zone makes the FQDN resolvable from the WC-013 jumpbox.
- NGINX serves immutable JSON bytes and sends CSP including `frame-ancestors 'none'`.

### Deployment sequence

1. Add presentation container packaging, Bicep resources, controller identity federation, and
   deployment parameter updates.
2. Build the runner, controller, and presentation images in ACR; publish the final delivery
   image only as `athena/wc013-live@sha256:<64 lowercase hex>`, and replace both rejected
   controller/presentation placeholders before any ARM validation or what-if.
3. Run Bicep build/lint, repository tests, application tests, policy checks, ARM validation, and
   full what-if. Placeholder parameters must fail closed.
4. Deploy the bootstrap infrastructure without starting a Job.
5. Verify and migrate Entra application-role assignments so MCP and trusted-ingestion roles are
   assigned only to the evidence identity.
6. Download the exact Key Vault public key, rerender the reviewed WC-013 configuration and phase
   bundle, build the delivery image, and update exact image/digest parameters.
7. Run a second validation/what-if and deploy the ready configuration under a unique
   timestamp/source-commit deployment name that is never reused.
8. Capture and review the exact deployment ID, correlation ID, template hash, controller image,
   and collector contracts; commit their byte-pinned artifact and exact workflow choice before
   enabling starts.
9. Verify identities, scoped RBAC, collector/evaluator job templates, immutable containers, private
   DNS, image digests, and presentation headers/content from the jumpbox.

---

## 6. Provisioning Limit Checklist

| Resource Type | Number to Deploy | Total After Deployment | Limit / Quota | Notes |
|---------------|------------------|------------------------|---------------|-------|
| `Microsoft.App/managedEnvironments` | 0 | 2 | 50 | `az quota`: `ManagedEnvironmentCount`, 48 available |
| Container Apps consumption cores | 0.25 steady; 0.5 per sequential job | 0.75 steady; 1.25 during one job | 100 | Existing environment usage 0.5; 99.5 available |
| `Microsoft.App/jobs` | 4 new, 4 updated | 15 regional Jobs | No numeric count quota exposed | Current regional count 11; core quota is the governing capacity |
| `Microsoft.App/containerApps` | 1 new, 1 updated | 6 regional apps | Governed by environment/core quota | Current regional count 5 |
| User-assigned managed identities | 2 new | 10 regional identities | 80 create operations per 20 seconds per subscription/region | Current regional count 8; deployment creates two |
| ACR image storage | 3 new image manifests | Under 1 GiB expected | 10 GiB included; 40 TiB maximum | Current use 721,060,375 bytes |
| Storage accounts | 0 | Existing account unchanged | Existing account capacity | Adds one immutable Blob container only |
| Private endpoints | 0 | Existing endpoints unchanged | 65,536 per VNet | Existing Blob, Table, and Key Vault endpoints reused |
| Public IP addresses | 0 | No change | Existing network quota | Presentation remains private |

**Status:** All planned resources are within available limits.

---

## 7. Execution Checklist

### Phase 1: Planning

- [x] Analyze merged workspace
- [x] Gather deployment requirements
- [x] Confirm subscription and location with user
- [x] Confirm private presentation access model
- [x] Inventory current Azure resources
- [x] Invoke `azure-quotas` and validate capacity
- [x] Select Bicep recipe
- [x] Plan architecture and trust boundaries
- [x] User approved this plan

### Phase 2: Preparation

- [x] Add private presentation container packaging and CSP configuration
- [x] Add presentation Container App and dedicated pull identity to Bicep
- [x] Add governed controller identity and GitHub OIDC federation
- [x] Bind workflow code to dispatch SHA and remove runtime deployment reads
- [x] Add fail-closed reviewed deployment-contract artifact selection
- [x] Package controller code/dependencies in a fixed-entrypoint digest-pinned image
- [x] Replace host Python with verified ACR image execution and one-shot stdin ARM token
- [x] Grant the OIDC controller identity only registry-scoped `AcrPull` in addition to Job actions
- [x] Hard-reject all-zero controller and presentation image digests in Bicep
- [x] Restrict the acceptance image to the supplied ACR and exact `athena/wc013-live` RepoDigest
- [x] Bind every workflow phase to its exact Job suffix, collector name, and configuration path
  before controller Docker launch
- [x] Reject duplicate keys recursively before `jq`, Azure login, or controller image execution
- [x] Correct operator reader, workload receipt writer, and controller parameters
- [x] Add/update deterministic deployment tests and documentation
- [x] Run local preparation tests, audits, container checks, Bicep build/lint, validator, and diff check
- [x] Build digest-pinned runner, controller, presentation, and delivery images
- [x] Reuse the reviewed WC-013 configuration and phase bundle with unchanged key/endpoint identities
- [x] Replace the rejected controller and presentation digests before ARM validation
- [x] Update plan status to `Ready for Validation`

### Phase 3: Validation

- [x] Invoke `azure-validate`
- [x] All validation checks pass
  - [x] 1. Core Validation (CLI, auth, build, validate, what-if) - run the Bicep `validate-deployment` script
  - [x] 2. Linting (optional)
  - [x] 3. Azure Policy Validation
- [x] Run all repository, Python, frontend, and security checks
- [x] Run ARM validation and structured what-if
- [x] Confirm zero unexpected deletes or public exposure
- [x] Populate current validation proof
- [x] Update plan status to `Validated`

### Phase 4: Deployment

- [x] Invoke `azure-deploy`
- [x] Deploy bootstrap infrastructure
- [x] Verify/migrate Entra application-role assignments
- [x] Deploy ready digest-pinned configuration under a unique immutable-style name
- [ ] Review and commit the deployment-bound collector contract artifact/workflow choice
- [x] Verify live RBAC and managed-identity separation
- [x] Verify private presentation endpoint from the jumpbox
- [x] Report the fully qualified private HTTPS URL
- [ ] Update plan status to `Deployed` after operational lifecycle verification

---

## 8. Validation Proof

| Check | Command Run | Result | Timestamp |
|-------|-------------|--------|-----------|
| Repository validation | `scripts/check.ps1` | Passed: repository validator, deterministic assets, Ruff, mypy, 709 tests; 2 live tests skipped | 2026-09-01T08:17:11+10:00 |
| Athena web | `npm run lint`; `npm run typecheck`; `npm test -- --run --silent`; `npm run build` | Passed: 20 tests and production build | 2026-09-01T08:17:11+10:00 |
| Presentation web | `npm run lint`; `npm run typecheck`; `npm test -- --run --silent`; `npm run build` | Passed: 27 tests and production build | 2026-09-01T08:17:11+10:00 |
| Bicep build and lint | `az bicep build`; `az bicep lint` for `infra/wc013-live-acceptance/main.bicep` | Passed | 2026-09-01T08:17:11+10:00 |
| ARM validation | `az deployment sub validate` in `australiaeast` with `.azure/wc013.parameters.json` | Passed against subscription `a6add389-9978-47ac-ab1e-a09212e321d4` | 2026-09-01T08:17:11+10:00 |
| Azure Policy | Azure Policy assignment review plus ARM subscription validation | Passed; the internal VNet-integrated Container Apps design satisfies the applicable ACA network policy and no deny policy blocked validation | 2026-09-01T08:17:11+10:00 |
| Structured what-if | `az deployment sub what-if --result-format FullResourcePayloads` | 8 create, 11 modify, 0 delete, 27 ignore, 5 no-change, 4 runtime-expression unsupported | 2026-09-01T08:17:11+10:00 |
| Private exposure review | Reviewed presentation app and managed-environment payloads | Passed: app ingress is environment-external on port 8080, while the environment remains `internal: true`, `publicNetworkAccess: Disabled`, and VNet integrated | 2026-09-01T08:17:11+10:00 |
| Collector-name correction | Shortened all four Container Apps Job resource names to satisfy Azure's 32-character limit and updated the immutable phase bindings | Passed: Bicep build/lint and targeted contract/deployment tests | 2026-09-01T10:02:13+10:00 |
| Post-correction repository validation | `scripts/check.ps1` | Passed: 709 tests; 2 live tests skipped | 2026-09-01T10:02:13+10:00 |
| Post-correction ARM validation | Bicep validation plus structured `az deployment sub what-if --result-format FullResourcePayloads` | Passed: 0 deletes; private environment remains `internal: true` with `publicNetworkAccess: Disabled` | 2026-09-01T10:02:13+10:00 |
| Collector endpoint correction | Canonicalized the generated Blob origin before embedding it in collector templates; reran `scripts/check.ps1`, Bicep build, ARM validation, and structured what-if | Passed: 709 tests, 0 deletes, and exact compatibility with the digest-pinned controller contract | 2026-09-01T13:51:32+10:00 |
| Collector output parity | Bound both the deployed Job template and emitted reviewed contract to the same canonical Blob origin; added a regression assertion and reran the complete repository and ARM gates | Passed: 709 tests, ARM validation, and 0 authoritative what-if deletes | 2026-09-01T14:10:07+10:00 |
| Independent-review hardening | Enforced exact lowercase 64-hex controller/presentation RepoDigests, bound the presentation registry server to its ACR resource ID, and made selected contract output canonical | Passed: GPT-5.4 findings resolved, 709 tests, ARM validation, and 0 authoritative what-if deletes | 2026-09-01T14:50:25+10:00 |
| Canonical round-trip gate | Rejected any reviewed contract whose validated model would rewrite its pinned canonical bytes | Passed: independent follow-up finding resolved, 710 tests, ARM validation, and 0 authoritative what-if deletes | 2026-09-01T15:08:32+10:00 |
| Live presentation repository gate | `scripts/check.ps1` from merged commit `c734dadd` | Passed: repository validator, deterministic assets, Ruff, mypy, 727 tests; 2 live tests skipped | 2026-09-02T01:12:56Z |
| Current live images | ACR remote builds and exact RepoDigest checks | Passed: presentation `sha256:998393cc...`, runner `sha256:0037340a...`, delivery `sha256:02c314ca...`, controller `sha256:a300b1ff...`; application images derive from merged commit `0620492968a1` | 2026-09-02T04:55:00Z |
| Live presentation ARM validation | Authoritative `azure-validate` Bicep workflow with `.azure/wc013.parameters.json` | Passed against subscription `a6add389-9978-47ac-ab1e-a09212e321d4` in `australiaeast` | 2026-09-02T01:12:56Z |
| Live presentation Azure Policy | Reviewed all three enforced subscription assignments and completed ARM validation | Passed: shared-key prevention is preserved and no assigned deny policy blocked the deployment | 2026-09-02T01:12:56Z |
| Live presentation structured what-if | `az deployment sub what-if --result-format FullResourcePayloads --no-pretty-print` | Passed: 8 no-change, 16 modify, 31 ignore, 4 unsupported, and 0 actual deletes | 2026-09-02T01:12:56Z |
| Live signing-key correction | Full repository gate; presentation typecheck/lint/tests/build; Bicep build/lint; `az deployment sub validate`; structured full-payload what-if | Passed: 727 tests with 2 intentional skips, 32 presentation tests, ARM validation, 9 no-change, 15 modify, 31 ignore, 4 unsupported, and 0 deletes | 2026-09-02T04:24:00Z |
| Current controller provenance | ACR build `cr2d`; targeted controller/deployment tests; strict selector for all operational phases; `az deployment sub validate`; structured full-payload what-if | Passed: controller `sha256:a300b1ff...` built from merged commit `0620492968a1`; ARM validation and 0 deletes | 2026-09-02T04:55:00Z |
| GitHub OIDC subject correction | Live workflow-dispatch token inspection; `scripts/check.ps1`; Bicep build/lint; `az deployment sub validate`; structured full-payload what-if | Passed: 727 tests with 2 intentional skips, ARM validation, 8 no-change, 16 modify, 31 ignore, 4 unsupported, and 0 deletes; the validated template will update Entra federation to GitHub's immutable owner/repository-ID subject `repo:cabberley@26394346/Athena-workload-context@1334641162:environment:athena-live` | 2026-09-02T06:07:00Z |
| Fresh operational delivery | Generated run `synthetic-run-20260902212858-a7a67f6d`; ACR build `cr2f`; full repository gate; targeted contract/deployment tests; Bicep build/lint; ARM validation; structured full-payload what-if | Passed: delivery image `sha256:fbd1e678...` contains the fresh baseline/faulted/recovered configurations and pins authority digest `sha256:062b5a14...`; 729 tests with 2 intentional skips, targeted tests, ARM validation, 10 no-change, 14 modify, 31 ignore, 4 unsupported, and 0 deletes | 2026-09-02T21:55:00Z |
| Live presentation independent review | GPT-5.4 code and architecture reviews | Passed after adding retry-safe immutable publication and enforcing publication/evaluation chronology | 2026-09-02T01:12:56Z |

**Validated by:** GitHub Copilot CLI using the authoritative `azure-validate` workflow

**Validation timestamp:** 2026-09-02T21:55:00Z

### Role Assignment Verification

- **Status:** Verified
- **Identities checked:** acceptance/context, isolated evidence collector, collector controller,
  presentation, operator artifact reader, and workload receipt writer
- **Roles confirmed:** key-scoped Key Vault Crypto User; table-scoped Storage Table Data
  Contributor; operator Blob Data Reader on `operational-artifacts`; operator Blob Data
  Contributor only on `presentation-assets`; presentation Blob Data Reader only on
  `presentation-assets`; registry-scoped AcrPull; and the custom collector-controller role
  limited to Job read/start/execution-read operations
- **Issues:** None. Data-plane roles are scoped to the exact key, table, blob container, registry,
  or collector Job resources. The presentation identity has no access to operational artifacts,
  workload resources, Key Vault, MCP, Table storage, or Job control, and no generic subscription
  or resource-group Contributor role is used.

### Deployment Verification

- **Deployment:** `wc013-ready-20260902T050729Z-0620492968a1`
- **Deployment proof:** correlation ID `9e37ca1e-4d60-436a-aa17-071dd5201a80`;
  template hash `5355939670410545896`; source commit
  `0620492968a123f5b380c62bc3ebfa9bbeab5cd5`
- **Reviewed contract:** artifact digest
  `sha256:4bed6560e142193a43132872fd038075ce339a6cc7740a0e43ed7f2a3f06aa14`;
  merged in [#42](https://github.com/cabberley/Athena-workload-context/pull/42)
- **Presentation:** `https://athena-wc013-live-presentation.delightfulmeadow-2f7be892.australiaeast.azurecontainerapps.io`
- **Jumpbox result:** private DNS resolved to `10.42.0.62`; `/healthz` returned
  `200 healthy`; CSP, `frame-ancestors 'none'`, `DENY`, and `nosniff` headers were present
- **Container Apps:** presentation and all four isolated collector Jobs are `Succeeded` and
  use the reviewed immutable ACR digests
- **Entra:** evidence identity has both Azure MCP and trusted-ingestion application roles;
  context identity has neither, completing collector/evaluator separation
- **GitHub OIDC:** `athena-live` has required reviewer protection, a `main` branch policy,
  and all three Azure variables. Azure still has the legacy name-only subject until this
  validated correction is deployed and read back.
- **Live RBAC:** verified exact key/table/container/registry/Job scopes for the context,
  evidence, controller, presentation, operator, and workload identities

---

## 9. Files to Generate or Update

| File | Purpose | Status |
|------|---------|--------|
| `.azure/deployment-plan.md` | Deployment source of truth | Validated; operational verification pending |
| `.azure/wc013.parameters.json` | Current non-secret deployment inputs | Deployed with current immutable digests |
| `apps/presentation-web/Dockerfile` | Reproducible static web image | Prepared |
| `Dockerfile.wc013-controller` | Immutable fixed-entrypoint controller image | Prepared |
| `scripts/strict_select_wc013_contract.py` | Pre-login duplicate-free canonical contract selector | Prepared |
| `apps/presentation-web/nginx.conf` | Same-origin MIME, caching, and CSP headers | Prepared |
| `infra/wc013-live-acceptance/main.bicep` | Controller/presentation composition | Prepared |
| `infra/wc013-live-acceptance/modules/presentation-web.bicep` | Private web app and identity | Prepared |
| `.github/workflows/wc013-collector-controller.yml` | Immutable-SHA, artifact-bound OIDC collector start | Active for the reviewed deployment |
| Deployment tests/docs | Deterministic architecture and runbook coverage | Deployment contract pending merge |

---

## 10. Next Steps

> Current: Fresh operational delivery authority binding validated; final deployment pending

1. Deploy and merge the fresh authority-bound reviewed contract.
2. Run the baseline, faulted, and recovered collectors through the protected workflow at their
   matching lifecycle points.
3. Publish and verify the signed runtime-v2 presentation from the jumpbox.
