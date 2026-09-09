# Azure Deployment Plan

> **Status:** Deployed — WC-024 phase-one monitoring foundation

Generated: 2026-08-31T12:28:07+10:00

Updated: 2026-09-02T00:58:02Z for the live workload presentation connection.

The follow-on deployment adds a private `presentation-assets` container, operator-only
publication of the fully verified lifecycle, a managed-identity read-only gateway sidecar, and
same-origin delivery to the presentation browser. The browser displays the exact target resource
group and separate verified evaluation/publication times only after signature, digest, lifecycle,
key, and resource-group binding checks pass.

WC-016 security remediation is staged separately. Incremental ARM deployment does not remove the
previous detector, normalizer, orchestrator, notification Jobs, queues, identities, or role
assignments. The first deployment therefore keeps `wc016RuntimeEnabled=false` and
`wc016LegacyCleanupConfirmed=false` while creating only the hardened v2 identities and the
dedicated incident key, `incident-assets` container, and detector state table. WC-016 runtime RBAC,
queues, and Jobs remain absent. The hardened Jobs have distinct `-v2` names and cannot update the
legacy Jobs or inherit their principals.

Before activation, run `scripts/audit-remove-wc016-legacy-runtime.ps1` in its default read-only
mode, review the exact allowlist, then run it with `-Apply`. The confirmation parameter may become
`true` only when the apply report has `zeroResidualReadback=true`. After cleanup, export and pin the
deployed public key in both verification layers, rebuild and digest-pin all affected images, and
complete repository, Bicep, ARM validation, and what-if checks. Only then may the reviewed second
deployment set both `wc016LegacyCleanupConfirmed=true` and `wc016RuntimeEnabled=true`. There is no
lifecycle-trust fallback.

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
- The presentation identity receives `AcrPull` plus Blob Data Reader on only
  `presentation-assets` and `incident-assets`; it receives no Blob write, Key Vault, MCP, workload,
  or ARM role.
- WC-016 uses dedicated detector, orchestrator, and notification identities. Detector and
  orchestrator live reads are limited to VM instance view and Azure Monitor metrics in the exact
  approved workload resource group, with application allowlists binding exact resource IDs.
- The notification dispatcher calls an Entra-authorized Logic App request trigger with a managed
  identity token. SAS authentication is disabled, so no callback secret is stored in the Job.
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
- [x] Update plan status to `Deployed` after operational lifecycle verification

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
| Collector clock precision correction | ACR builds `cr2j` and `cr2k`; targeted collector/deployment tests; Bicep build/lint; ARM validation; structured full-payload what-if; one-off live baseline collector execution | Passed: delivery image `sha256:fd679e08...` truncates the system clock to UTC millisecond precision; 30 targeted tests passed, ARM validation and zero deletes passed, and live execution `athena-wc013-live-base-col-fme7hiq` succeeded | 2026-09-02T22:16:00Z |
| Fresh post-diagnostic operational run | Generated run `synthetic-run-20260903000955-7872b649`; ACR delivery build; full repository gate; Bicep build/lint; ARM validation; structured full-payload what-if | Passed: delivery image `sha256:14dfeae0...` contains unused phase attempt IDs and pins authority digest `sha256:bccc445a...`; 730 tests with 2 intentional skips, ARM validation, and zero deletes | 2026-09-03T00:20:00Z |
| Hour-fresh operational release | Generated run `synthetic-run-20260903010325-4fcc3e1c`; ACR runner and delivery builds; full repository gate; Bicep build/lint; ARM validation; structured full-payload what-if | Passed: delivery image `sha256:706a7c0e...` uses corrected clocks, diagnostic error provenance, and a 3600-second evidence freshness bound; 730 tests with 2 intentional skips, ARM validation, and zero deletes | 2026-09-03T01:15:00Z |
| Independent-review controller correction | GPT-5.4 review; current-source controller ACR build; targeted operator/controller/deployment tests; Bicep build/lint; ARM validation; structured full-payload what-if | Passed: publication errors remain redacted, controller `sha256:be16f069...` contains the exact ARM normalization/start-body fixes, targeted tests passed, ARM validation passed, and zero deletes | 2026-09-03T02:15:00Z |
| Live presentation independent review | GPT-5.4 code and architecture reviews | Passed after adding retry-safe immutable publication and enforcing publication/evaluation chronology | 2026-09-02T01:12:56Z |
| WC-016 runtime repository gate | `scripts/check.ps1`; targeted WC-016/deployment tests; presentation typecheck, lint, tests, and build | Passed: 767 tests with 2 intentional live skips after image-pin updates; Ruff and mypy passed across 81 source files; 35 presentation tests and production build passed | 2026-09-04T18:49:00Z |
| WC-016 immutable images | Interactive ACR builds `cr2x`, `cr2y`, `cr30`, `cr31`, `cr32`, and `cr33` using `chabberl@microsoft.com` | Passed: presentation `sha256:c73c0551...`, delivery `sha256:cdc8e1c2...`, detector `sha256:a934a034...`, normalizer `sha256:ec6762e2...`, orchestrator `sha256:e6354c3f...` | 2026-09-04T18:39:43Z |
| WC-016 Bicep and ARM validation | Bicep build/lint and `az deployment sub validate` using `.azure/wc013.parameters.json` | Passed against subscription `a6add389-9978-47ac-ab1e-a09212e321d4` in `australiaeast` | 2026-09-04T18:40:00Z |
| WC-016 policy and structured what-if | Reviewed all three enforced policy assignments; `az deployment sub what-if --result-format FullResourcePayloads --no-pretty-print` | Passed: 16 create, 15 modify, 31 ignore, 9 no-change, 9 unsupported, and 0 deletes; private networking and shared-key prevention remain enforced | 2026-09-04T18:40:00Z |
| WC-016 interactive deployment | `az deployment sub create` using `athena-wc016-20260904-202738`, `athena-wc016-fix-20260904-210957`, and `athena-wc016-notify-20260904-221117` | Passed under `chabberl@microsoft.com`; private Service Bus, detector/normalizer/orchestrator/notification Jobs, scoped identities/RBAC, presentation revision, Teams Logic App, and Teams connection provisioned | 2026-09-04T22:17:29Z |
| WC-016 bounded live web failure | Stopped and restarted `athena-hackathon-web-01`; observed detector and orchestrator executions; queried the signed incident feed from the jumpbox | Passed: webpage reported `webServerFailure`, `active`, `warning`, `web-tier`, then `resolved`, `normal`, `none`; VM restored to `PowerState/running` | 2026-09-04T21:34:38Z |
| WC-016 runtime precision correction | Live failure exposed non-canonical microsecond timestamps; rounded the runtime clock to UTC milliseconds; ACR builds `cr34` and `cr35` | Passed: active and resolved incident publications succeeded with final runtime digest `sha256:6a6038a1...`; targeted local test rerun was blocked by workstation PyPI TLS, while Python compilation, ACR build, Bicep build, ARM validation, zero-delete what-if, and live execution passed | 2026-09-04T22:11:17Z |
| WC-016 Teams notification bridge | Authorized `teams`; deployed `athena-wc016-teams-notifier` and private Job `athena-wc013-live-w16-notify`; consumed queued active/resolved messages | Passed: connector `Connected`, two dispatcher executions succeeded, logs reported `WC-016 notification delivered`, and outbox active/dead-letter counts are zero | 2026-09-04T22:17:29Z |
| Hardened WC-016 repository and review gate | Local repository validation, Ruff, mypy, 785 Python tests with 2 intentional skips, both web application gates, Bicep build/lint, PowerShell parsing, privileged image builds, GitHub PR #57 checks, and independent code/security reviews | Passed: PR #57 merged as `b858c962`; no merge-blocking correctness or security findings remain | 2026-09-05T12:51:38Z |
| Hardened WC-016 stage-one Azure preflight | Authoritative `azure-validate` Bicep workflow plus structured full-payload subscription what-if using `.azure/wc013.parameters.json` | Passed against `AG-CI-CE-chabberl` (`a6add389-9978-47ac-ab1e-a09212e321d4`) in `australiaeast`: 3 create, 15 modify, 45 ignore, 9 no-change, 4 unsupported, and 0 resource deletes; runtime and cleanup gates remain disabled | 2026-09-05T12:51:38Z |
| Hardened WC-016 stage-one deployment | `az deployment sub create` deployment `athena-wc016-hardening-stage1-20260905-125430` | Passed under `chabberl@microsoft.com`; correlation ID `bbbd5caa-bc1e-4d56-9759-a6a8572a21d5`; provisioned the three v2 identities, dedicated incident key, `incident-assets`, `Wc016DetectorState`, and `Wc016NotificationState` while assigning zero runtime roles and creating zero v2 Jobs | 2026-09-05T13:03:00Z |
| Exact WC-016 legacy cleanup | `scripts/audit-remove-wc016-legacy-runtime.ps1 -Apply` with the three recorded legacy principal IDs | Passed: report digest `sha256:ffae8cf126747d6933ca312769a91dff268d5a1376a593b3976e3e698840b4aa`; zero residual resources, expected/unexpected roles, or evidence sender roles; zero protected-resource or protected-role changes; zero operation errors | 2026-09-05T22:35:00Z |
| Deployed incident trust pin | One-shot private Container Apps Job execution `athena-wc013-live-acceptance-5xoa591` using temporary key-scoped Reader access, followed by immediate removal of both temporary assignments | Passed: exported Key Vault version `d3b5590af01e45f0b7747a2632498ecb`; PEM, JWK, TypeScript, and parameter fingerprint all bind to `sha256:7e0b51de2b9968f6f1ae9df0ee981154dc8fe9ee463055031b556ee075351964`; no temporary key-reader assignment remains | 2026-09-05T22:40:00Z |
| Hardened WC-016 activation images | Interactive ACR builds `cr36`, `cr37`, `cr38`, `cr39`, `cr3b`, and `cr3c` using `chabberl@microsoft.com` | Passed: detector `sha256:8367751e...`, final orchestrator `sha256:720b84f2...`, presentation `sha256:e0116228...`, current-code runner `sha256:74d62c6c...`, and full delivery/gateway `sha256:fb9503b3...`; all deployment inputs are immutable RepoDigests | 2026-09-06T01:40:11Z |
| Hardened WC-016 stage-two validation | `scripts/check.ps1`; both frontend test/typecheck/lint/build/audit gates; Bicep build/lint; `az deployment sub validate`; structured full-payload what-if | Passed: 787 Python tests with 2 intentional live skips, 38 presentation tests, 20 Context Studio tests, zero npm vulnerabilities, ARM validation, 10 create, 20 modify, 33 ignore, 14 no-change, 10 unsupported, and 0 deletes | 2026-09-05T22:59:48Z |
| Hardened WC-016 activation deployment | Subscription deployments `athena-wc016-hardening-stage2-20260905-234823`, `athena-wc016-gateway-fix-20260906-000655`, `athena-wc016-notify-fix-20260906-014328`, and `athena-wc016-auth-policy-fix-20260906-015616` | Passed under `chabberl@microsoft.com`; correlation IDs `6ba2b100-...`, `f37baee8-...`, `a637f7c5-...`, and `ae3e4aea-...`; four v2 Jobs, two session queues, exact data-plane RBAC, current signed-feed gateway, and Entra-authenticated Teams callback are deployed | 2026-09-06T02:03:02Z |
| Hardened signed-feed verification | Private jumpbox GETs to `/healthz`, `/incidents/active.json`, and `/trust/incident-public-key.jwk.json` | Passed: HTTP 200, fresh signed empty index, and exact deployed fingerprint `sha256:7e0b51de...` in both index and browser trust asset | 2026-09-06T00:13:17Z |
| Hardened bounded web-failure lifecycle | Stopped and restarted only `athena-hackathon-web-01`, retaining `web-02` and `web-03` running; inspected signed feed from the jumpbox | Passed: active `webServerFailure` with `warning`, `web-tier`, and `required`, followed by signed empty active index after recovery; all three web VMs restored to `PowerState/running` | 2026-09-06T02:13:21Z |
| Hardened Teams notification delivery | Private notification dispatcher plus Teams message search for the bounded active/resolved transitions | Passed: active and resolved dispatcher logs reported `WC-016 notification delivered`; matching Notes-to-Self messages were present at `2026-09-06T02:09:55Z` and `2026-09-06T02:13:54Z`; active and dead-letter counts are zero after removal of only the two recorded pre-fix test messages | 2026-09-06T05:29:58Z |

**Validated by:** GitHub Copilot CLI using the authoritative `azure-validate` workflow

**Validation timestamp:** 2026-09-05T22:59:48Z

### Role Assignment Verification

- **Status:** Verified
- **Identities checked:** acceptance/context, isolated evidence collector, collector controller,
  presentation, WC-016 v2 detector, WC-016 v2 orchestrator/feed-heartbeat, WC-016 v2 notification
  dispatcher, operator artifact reader, and workload receipt writer
- **Roles confirmed:** key-scoped Key Vault Crypto User; table-scoped Storage Table Data
  Contributor; operator Blob Data Reader on `operational-artifacts`; operator Blob Data
  Contributor only on `presentation-assets`; presentation Blob Data Reader only on
  `presentation-assets`; queue-scoped Service Bus Data Sender/Receiver; registry-scoped AcrPull;
  the custom collector-controller role limited to Job read/start/execution-read operations, and
  the WC-016 custom signal-reader role limited to VM instance view and Azure Monitor metric reads
  in the exact workload resource group
- **Issues:** None. Data-plane roles are scoped to the exact key, table, blob container, registry,
  or collector Job resources. The presentation identity has no access to operational artifacts,
  workload resources, Key Vault, MCP, Table storage, or Job control, and no generic subscription
  or resource-group Contributor role is used.

### Deployment Verification

- **Deployment:** `wc013-ready-20260903T025500Z-c9a420be0cbb`
- **Deployment proof:** correlation ID `6d1a2892-6384-46a8-9a78-d18f647d54d4`;
  template hash `8373313941976686749`; source commit
  `c9a420be0cbbf2596f179c5e80dbb164a0637609`
- **Reviewed contract:** artifact digest
  `sha256:0868d2d4a2d8e6bc48eaef802b0203ecc58d3c0cd02fb13497aa06407f5b9ef4`;
  merged in pull request `#45`
- **Presentation:** `https://athena-wc013-live-presentation.delightfulmeadow-2f7be892.australiaeast.azurecontainerapps.io`
- **Jumpbox result:** private DNS resolved to `10.42.0.62`; `/healthz` returned
  `200 healthy`; CSP, `frame-ancestors 'none'`, `DENY`, and `nosniff` headers were present
- **Container Apps:** presentation and all four isolated collector Jobs are `Succeeded` and
  use the reviewed immutable ACR digests
- **Operational lifecycle:** run `synthetic-run-20260903010325-4fcc3e1c` completed baseline,
  faulted, and recovered evaluations against `rg-athena-demo-workload`; all three workload VMs
  were restored to `PowerState/running`
- **Runtime publication:** runtime-v2 manifest and all six phase payload/attestation assets were
  published to `presentation-assets` and verified from the jumpbox
- **Entra:** evidence identity has both Azure MCP and trusted-ingestion application roles;
  context identity has neither, completing collector/evaluator separation
- **GitHub OIDC:** `athena-live` has required reviewer protection, a `main` branch policy,
  and all three Azure variables. Azure still has the legacy name-only subject until this
  validated correction is deployed and read back.
- **Live RBAC:** verified exact key/table/container/registry/Job scopes for the context,
  evidence, controller, presentation, operator, and workload identities
- **WC-016 live RBAC:** v2 detector has only AcrPull, exact workload signal reader, detector-table
  contributor, and reassessment sender; v2 orchestrator/feed-heartbeat has only AcrPull, exact
  workload signal reader, incident-key Crypto User, `incident-assets` Blob contributor,
  reassessment receiver, and notification sender; v2 notification dispatcher has only AcrPull,
  notification-table contributor, and notification receiver; presentation has read-only access to
  `presentation-assets` and `incident-assets`
- **Dynamic incident loop:** verified fresh signed empty-index heartbeats plus active and resolved
  web-server states from the jumpbox; detector, heartbeat, orchestrator, and dispatcher executions
  succeeded and the signed feed returned HTTP 200
- **Teams notifications:** the Logic App callback uses its returned `2019-05-01` API version and an
  exact `https://management.azure.com` audience claim; active and resolved messages were delivered
  to Notes to Self and both queue active/dead-letter counts are zero

---

## 9. Files to Generate or Update

| File | Purpose | Status |
|------|---------|--------|
| `.azure/deployment-plan.md` | Deployment source of truth | Deployed and operationally verified |
| `.azure/wc013.parameters.json` | Current non-secret deployment inputs | Deployed with current immutable digests |
| `apps/presentation-web/Dockerfile` | Reproducible static web image | Prepared |
| `Dockerfile.wc013-controller` | Immutable fixed-entrypoint controller image | Prepared |
| `scripts/strict_select_wc013_contract.py` | Pre-login duplicate-free canonical contract selector | Prepared |
| `apps/presentation-web/nginx.conf` | Same-origin MIME, caching, and CSP headers | Prepared |
| `infra/wc013-live-acceptance/main.bicep` | Controller/presentation composition | Prepared |
| `infra/wc013-live-acceptance/modules/presentation-web.bicep` | Private web app and identity | Prepared |
| `.github/workflows/wc013-collector-controller.yml` | Immutable-SHA, artifact-bound OIDC collector start | Active for the reviewed deployment |
| Deployment tests/docs | Deterministic architecture and runbook coverage | Merged and deployed |

---

## 10. Next Steps

> Current: Operational demonstration deployed and verified.

1. Preserve the approved enterprise-claim workaround for collector execution until the repository
   is hosted in an allowed GitHub enterprise or an Azure-hosted managed-identity runner is adopted.

---

## 11. WC-024 Monitoring Foundation Deployment

### Scope

Deploy WC-024 into the previously approved Azure scope:

- Subscription: `AG-CI-CE-chabberl`
  (`a6add389-9978-47ac-ab1e-a09212e321d4`)
- Region: `australiaeast`
- Workload resource group: `rg-athena-demo-workload`
- Monitoring resource group: `rg-athena-demo-monitoring`

The user approved autonomous continuation in the same subscription and resource
groups used by prior Athena deployments.

### Architecture and rollout

WC-024 adopts the existing Log Analytics workspace, DCE, DCR, eleven canonical
VMs, workload VNet, Network Watcher, and canonical VNet flow log. It adds:

- one isolated, unpeered `10.45.0.0/24` collector VNet with separate runtime and
  private-endpoint subnets;
- separate workload and collector AMPLS scopes;
- separate same-named Azure Monitor private DNS zones in each network boundary;
- collector-only Blob and Key Vault private endpoints and DNS;
- immutable evidence storage, a signing Key Vault/key, and a managed identity;
- exact, narrow monitoring-reader and evidence-writer permissions.

Deployment is phased:

1. Bootstrap both AMPLS scopes independently in `Open` mode.
2. Deploy the isolated collector VNet.
3. Validate and deploy the phase-one monitoring foundation.
4. Defer `set-private-access.ps1` until exact AMPLS membership, approved private
   endpoints, empty exclusions, DNS, connectivity, AMA/DCR health, ingestion,
   collector query/sign/write, and negative-access checks all pass.

The private cutover performs a complete two-scope preflight before any mutation
and is serialized because AMPLS has no supported ETag concurrency contract.

### Provisioning limits

Azure Quota CLI results for `australiaeast`:

| Resource type | New | Total after | Limit | Evidence |
|---------------|----:|------------:|------:|----------|
| Virtual networks | 1 | 8 | 1000 | Usage 7; available 993 |
| Network security groups | 1 | 43 | 5000 | Usage 42; available 4958 |
| Private endpoints | 4 | 8 | 65536 | Usage 4; available 65532 |
| Storage accounts | 1 | 8 | 250 | Usage 7; available 243 |
| Network Watchers | 0 | 1 | 1 | Existing watcher is adopted |
| AMPLS scopes | 2 | 2 | Not exposed by Quota CLI | Azure validate/what-if required |
| Private DNS zones | 11 | 18 | Not exposed by Quota CLI | Current count 7 from Resource Graph |
| User-assigned identities | 1 | 16 | Not exposed by Quota CLI | Current count 15 from Resource Graph |
| Key Vaults | 1 | 6 | Not exposed by Quota CLI | Current count 5 from Resource Graph |

All quota-exposed resources are well within regional limits.

### WC-024 validation checklist

- [x] Bicep roots and parameter files compile.
- [x] Focused WC-024 tests pass: 47.
- [x] Full Python suite passes with two intentional skips.
- [x] Ruff, MyPy, repository validation, PowerShell parsing, and
  `git diff --check` pass.
- [x] Independent code review approves the deployment recovery.
- [x] Independent security review approves the deployment recovery.
- [x] Independent Azure architecture review approves the deployment recovery.
- [x] Static RBAC review confirms exact resource scopes and no generic
  Contributor assignment.
- [x] Complete authoritative azure-validate workflow for the stage-one
  bootstrap and collector-connectivity deployment.
- [x] Re-run Azure validation and ResourceIdOnly what-if for each AMPLS
  bootstrap and the collector VNet.
- [x] Deploy and verify AMPLS bootstrap scopes and collector VNet.
- [x] Complete authoritative validation and what-if for the recovered
  foundation.
- [x] Deploy the phase-one foundation.
- [x] Keep private-only cutover deferred pending runtime acceptance.

### WC-024 validation proof

| Check | Command | Result |
|-------|---------|--------|
| Bicep | `az bicep build` and `az bicep build-params` for WC-024 roots | Passed |
| Focused tests | `python -m pytest tests/test_wc024_monitoring_contract.py tests/test_wc024_monitoring_infra.py -q` | 46 passed |
| Full tests | `python -m pytest -q` | Passed; 2 skipped |
| Static quality | Ruff, MyPy, repository validator, PowerShell parser, `git diff --check` | Passed |
| Reviews | Code, security, and Azure architecture agents | Approved |
| AMPLS bootstrap validation | `az deployment group validate` for both reviewed AMPLS names | Passed |
| AMPLS bootstrap what-if | `az deployment group what-if --result-format ResourceIdOnly` for both reviewed AMPLS names | Passed: one AMPLS create per invocation and no deletes |
| Collector-network validation | `az deployment sub validate` for `infra/wc024-monitoring-connectivity/main.bicep` | Passed |
| Collector-network what-if | `az deployment sub what-if --result-format ResourceIdOnly` | Passed: one VNet and one NSG create; no deletes |
| Static RBAC | Reviewed conditioned Log Analytics Data Reader, exact-resource Reader, existing narrow signal-reader, container-scoped Blob contributor, and key-scoped Crypto User assignments | Passed: no subscription/resource-group Reader and no generic Contributor |
| AMPLS bootstrap deployment | `bootstrap-ampls.ps1` | Passed: both scopes provisioned `Succeeded`, Open/Open, zero exclusions, zero scoped resources, and zero private endpoint connections |
| Collector-network deployment | `az deployment sub create` deployment `wc024-connectivity-20260909-2213` | Passed: correlation `56e32d88-f27e-4a88-9c51-24673732014b`; exact VNet/subnet outputs and zero peerings |
| Complete-foundation validation | `az deployment sub validate` for `infra/wc024-monitoring-foundation/main.bicep` | Passed |
| Complete-foundation what-if | `az deployment sub what-if --result-format ResourceIdOnly` | Passed: 56 creates, 104 ignores, 4 runtime-expression unsupported, and zero deletes or explicit modifies |
| Initial merged foundation deployment | `az deployment sub create` deployment `wc024-foundation-20260909-2255` | Failed safely: tenant custom-role limit and concurrent LAW link update; no private cutover occurred |
| Recovery design | Remove new custom-role creation; use conditioned workspace access, explicitly bound resource-context mode, the exact existing signal role, exact child/resource scopes, and serialized AMPLS links | Implemented and independently approved |
| Recovery focused tests | `python -m pytest tests/test_wc024_monitoring_contract.py tests/test_wc024_monitoring_infra.py -q` | 47 passed |
| Recovery full tests | `python -m pytest -q` | Passed; 2 skipped |
| Recovery static gate | Bicep build, Ruff, MyPy, repository validation, PowerShell parsing, and `git diff --check` | Passed |
| Recovery ARM validation | `az deployment sub validate` | Passed against live partial state, including exact existing signal-role validation |
| Recovery what-if | `az deployment sub what-if --result-format ResourceIdOnly` | Passed: 42 creates, 13 nested deployments, 104 ignores, 40 runtime-expression unsupported, zero custom-role creates, zero Connection Monitor creates, and zero deletes |
| First recovery deployment | `az deployment sub create` deployment `wc024-foundation-recovery-20260910-0119` | Failed after safe partial progress because the adopted LAW returned `dailyQuotaGb` as a Float while a read-only output declared Integer; no private cutover occurred |
| Second recovery deployment | `az deployment sub create` deployment `wc024-foundation-20260910-0152` | Failed after safe partial progress because ARM does not permit converting a Float to a string in a template output; the unused output was removed |
| Third recovery deployment | `az deployment sub create` deployment `wc024-foundation-20260910-0218` | Failed after safe partial progress because extension-resource IDs were emitted through runtime references without API versions and the canonical flow-log PUT omitted its existing location; no private cutover occurred |
| Final foundation deployment | `az deployment sub create` deployment `wc024-foundation-20260910-0233` | Succeeded; correlation `5472b5ce-e2f7-42c3-b36c-d8837abe6d25` |
| AMPLS verification | Live ARM reads for both scopes | Each remains Open/Open with zero exclusions, exact LAW+DCE membership, and one approved local private endpoint |
| VM association verification | `az monitor data-collection rule association list` for all 11 VMs | Each VM has exactly one `athena-linux-dcr` and one `configurationAccessEndpoint` association |
| Private endpoint/DNS verification | Azure CLI reads for all four endpoints, zone groups, zones, and VNet links | All endpoints and links succeeded; workload and collector DNS boundaries remain separate |
| Flow-log verification | `az network watcher flow-log show` | Enabled on the reviewed VNet, writing to `athenademomonchab01`, Traffic Analytics enabled against `athena-hackathon-law` |
| Data-boundary verification | Storage, container immutability, Key Vault, and public-access reads | Storage shared keys disabled with default deny/AzureServices bypass; evidence container has 30-day unlocked immutability; Key Vault is RBAC-only, purge-protected, and public access disabled |
| Live RBAC verification | Role assignments for collector principal `ee4f8f59-adb1-46fa-9613-4ca5547d3553` | 41 exact assignments; conditioned 13-table LAW access, 11 exact VM signal scopes, 27 exact Reader scopes, container writer, and key Crypto User |
| Deployed collector contract | Deployment output `monitoringCollectorContract` | Schema v2; conditioned workspace plus exact resource context; 13 tables, 27 Reader scopes, 11 signal scopes; Connection Monitor remains capability-only |

**WC-024 validation timestamp:** 2026-09-10T00:22:53+10:00

### WC-024 files

| File | Purpose |
|------|---------|
| `infra/wc024-monitoring-connectivity/main.bicep` | Isolated collector network |
| `infra/wc024-monitoring-foundation/bootstrap-ampls.bicep` | Serialized AMPLS bootstrap |
| `infra/wc024-monitoring-foundation/main.bicep` | Monitoring foundation |
| `infra/wc024-monitoring-foundation/set-private-access.ps1` | Deferred private-only cutover |
| `src/athena_context/contracts/monitoring.py` | Signed monitoring contracts |

> Current: WC-024 phase-one monitoring foundation is deployed and verified.
> Private-only cutover remains deferred until collector runtime connectivity,
> allowed/denied query behavior, signing/writing, ingestion, and negative-access
> checks pass.
