# WC-029 deployment and live-validation runbook

This runbook is the release gate for governed intelligent monitoring in the existing Athena demo
environment. It is deliberately fail-closed: every mutating action requires an explicit apply
step, an approved recovery action, and evidence that the environment returned to its baseline.

## Fixed deployment scope

| Setting | Value |
| --- | --- |
| Subscription | `a6add389-9978-47ac-ab1e-a09212e321d4` |
| Region | `australiaeast` |
| Runtime resource group | `rg-athena-wc013-live` |
| Workload resource group | `rg-athena-demo-workload` |
| Monitoring resource group | `rg-athena-demo-monitoring` |
| ACR resource group | `rg-athena-platform-dev` |
| Network Watcher resource group | `NetworkWatcherRG` |
| ACR | `athenademoa6add389.azurecr.io` |

Do not deploy WC-029 resources into `rg-athena-demo-dev-*`. Do not create a new deployment path:
this repository currently uses Azure CLI with subscription-scope Bicep, not `azd`.

## Release prerequisites

Do not begin deployment until all items are true:

1. WC-027 report, guidance, enrichment, feed, presentation, and notification changes are merged.
2. WC-028 reconciliation is merged and the exact published manifest version is approved.
3. WC-025 change ingestion is deployed or NSG-change scenarios are explicitly disabled.
4. Final container images are digest-pinned in `.azure/wc013.parameters.json`.
5. Report, guidance, enrichment, and notification signing keys and identities are declared in IaC.
6. Repository CI, release review, security review, and the zero-delete what-if gate are green.
7. An operator has approved the bounded live scenarios and their recovery windows.

## Authoritative deployment roots

Deploy and review each root independently:

- `infra/wc013-live-acceptance/main.bicep`
- `infra/wc024-monitoring-connectivity/main.bicep`
- `infra/wc024-monitoring-foundation/main.bicep`
- `infra/wc025-change-ingestion/main.bicep`

`bootstrap-ampls.bicep` is not a repeatable deployment root. It sets AMPLS access modes to
`Open/Open` and is resource-group scoped. Verify an existing AMPLS read-only. A missing AMPLS may
be created once only through `infra/wc024-monitoring-foundation/bootstrap-ampls.ps1`, after its
bootstrap-state checks pass. Before invoking the wrapper, run and review a separate
`az deployment group what-if` against `bootstrap-ampls.bicep` for every missing approved AMPLS
name; the wrapper may create both scopes. The wrapper itself performs the creates and refuses an
incompatible existing AMPLS, but does not run what-if.

`infra/wc024-monitoring-foundation/set-private-access.ps1` remains a separate, deferred cutover.
Do not run it until private DNS, AMPLS, collector access, Storage, Key Vault, and negative access
tests all pass.

## Required publication boundary

The final deployment must provide separate, least-privilege signing roles for:

- WC-016 incident state;
- WC-025 change evidence;
- WC-026 correlation report publication;
- WC-027 guidance-authority binding;
- WC-027 guidance publication;
- WC-027 enrichment publication; and
- WC-027 notification publication.

Report, guidance, and enrichment assets remain under the existing `incident-assets` trust domain
unless the final merged contracts explicitly say otherwise. A deployment runbook must never choose
a different container after contract freeze.

The presentation identity may read compact signed presentation and incident assets only. It must
not gain Log Analytics, workload Reader, Key Vault, ARM write, or raw evidence access.

## Phase 1: read-only baseline

Record all output in a timestamped evidence directory outside the repository.

```powershell
$SubscriptionId = 'a6add389-9978-47ac-ab1e-a09212e321d4'
$Location = 'australiaeast'
$RuntimeRg = 'rg-athena-wc013-live'
$WorkloadRg = 'rg-athena-demo-workload'
$MonitoringRg = 'rg-athena-demo-monitoring'

az account set --subscription $SubscriptionId
az account show --output json
az group show --name $RuntimeRg --output json
az group show --name $WorkloadRg --output json
az group show --name $MonitoringRg --output json
```

Baseline acceptance:

- all expected demo VMs are running;
- incident reassessment and notification queues have zero active/dead-letter messages;
- the presentation health endpoint returns HTTP 200 from an approved network location;
- the signed v1 active incident feed is readable and contains only known incidents;
- no temporary WC-029 NSG rules, probe changes, or pressure files exist;
- monitoring and runtime Log Analytics workspaces remain separate; and
- the current published manifest, authority, signing-key versions, and container image digests are
  recorded.

Stop if the baseline is already degraded or if a prior scenario was not completely recovered.

## Phase 2: validation and zero-delete what-if

Use a unique immutable deployment name containing the timestamp and commit SHA.

```powershell
$DeploymentName = "wc029-preflight-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))"

az deployment sub validate `
  --subscription $SubscriptionId `
  --location $Location `
  --template-file infra/wc013-live-acceptance/main.bicep `
  --parameters .azure/wc013.parameters.json

az deployment sub what-if `
  --subscription $SubscriptionId `
  --name $DeploymentName `
  --location $Location `
  --template-file infra/wc013-live-acceptance/main.bicep `
  --parameters .azure/wc013.parameters.json `
  --result-format FullResourcePayloads `
  --no-pretty-print
```

Use scope-correct, reviewed parameters for every root:

| Root | Scope | Parameter requirement |
| --- | --- | --- |
| WC-013/WC-016 | Subscription | `.azure/wc013.parameters.json` with final image digests |
| WC-024 connectivity | Subscription | Reviewed copy of `main.example.bicepparam` |
| WC-024 foundation | Subscription | Reviewed environment parameter artifact; examples are not deployable approval |
| WC-025 change ingestion | Subscription | New reviewed parameter artifact containing the exact image, identities, resource allowlist, containers, and versioned signing key |

The release cannot proceed while any non-WC-013 root lacks its reviewed immutable parameter
artifact. Run `az deployment sub validate` and `az deployment sub what-if` separately for each
subscription-scope root. Save raw JSON before review. AMPLS bootstrap, when genuinely required,
uses `az deployment group` only through its guarded wrapper.

The gate fails on:

- any `Delete`;
- an unapproved `Create` or `Modify`;
- changes to VNet, subnet, NSG, load balancer, Key Vault, Storage network rules, AMPLS, private DNS,
  or role assignments that are absent from the reviewed change set;
- public Container Apps ingress or public data-plane access;
- Storage shared-key access being enabled;
- broad `Owner`, `Contributor`, or `User Access Administrator` assignment at subscription or
  resource-group scope;
- `Reader` at subscription/resource-group scope except the exact approved evidence identity on
  `rg-athena-demo-workload`; or
- overlap between context, evidence, presentation, collector, publication, and notification
  identities.

Do not continue by manually ignoring a failed preflight result. Update IaC or the reviewed
allowlist and rerun the gate.

## Phase 3: effective RBAC

Record inherited and direct assignments for every managed identity:

```powershell
az role assignment list `
  --subscription $SubscriptionId `
  --assignee-object-id '<principal-id>' `
  --include-inherited `
  --all `
  --output json
```

Required separation:

- context identity: no workload Reader and no Log Analytics Reader;
- evidence identity: workload Reader only at the approved workload scope;
- monitoring collector: exact monitoring query/data roles and governed resource scopes;
- presentation identity: Blob Data Reader for presentation/incident assets and ACR pull only;
- incident/enrichment publishers: exact Blob contributor, queue, and Key Vault crypto roles only;
- notification dispatcher: exact v2 queue/table/Logic App rights only; and
- no generic Contributor assignment for a runtime identity.

## Phase 4: deploy

Deployment is an explicit operator action. The approved command, commit SHA, image digests,
deployment name, what-if digest, and operator identity must be captured before execution.

After deployment:

1. record deployment outputs and provisioning state;
2. repeat RBAC checks;
3. verify all Container Apps revisions use the reviewed image digests;
4. verify Storage shared-key and public access remain disabled where required;
5. verify monitoring/runtime workspace isolation;
6. verify exact key versions and trusted fingerprints; and
7. run signed feed/report/guidance/enrichment readback before any fault injection.

## Phase 5: bounded live scenarios

Every scenario follows the same mutation lifecycle:

1. **Plan**: capture target, baseline, expected signal, abort threshold, and recovery command.
2. **Apply**: perform one bounded mutation.
3. **Observe**: capture the evidence supported by that scenario. Incident-producing scenarios
   include guidance/feed/notification evidence; correlation-only scenarios stop at verified
   monitoring, change, correlation, and recovery evidence.
4. **Recover**: restore only the changed setting/resource.
5. **Verify**: prove healthy state and no residual mutation. Incident-producing scenarios also
   require a resolved occurrence and queue drain.

Never run two fault scenarios concurrently.

### Disk-capacity pressure

- Prefer an agreed non-critical demo VM.
- Record current free bytes and abort unless the recovery floor can be maintained.
- Create one capped temporary file beneath `/tmp/athena-wc029/`.
- Keep at least 4 GiB free and never fill the filesystem.
- Delete the exact file during recovery.

Expected evidence: AMA/VM Insights pressure, a bounded WC-026 `guestResourcePressure` report, and
explicit recovery observations. This is correlation-only until a signed incident producer for disk
pressure is deployed; do not claim WC-027 guidance or notifications from WC-016 alone.

### VM failure

- Stop/start one approved low-blast-radius VM.
- Do not delete or deallocate unrelated resources.
- Record the original power state and restore it exactly.

For a non-WC-016 target such as `athena-hackathon-client-01`, acceptance is monitoring and
correlation only. A full active/resolved incident and guidance test must use a resource/scenario
explicitly supported by the deployed WC-016 producer.

### Web-tier failure

- Stop only `athena-hackathon-web-01`.
- Keep the remaining web instances running.
- Restore the VM and verify the original backend health.

Expected evidence: degraded web-role impact, active and resolved signed assets, and active/resolved
notification behavior.

### Backend or load-balancer degradation

Preferred mutation: stop only `athena-hackathon-mid-01`, leaving `mid-02` healthy.

An invalid load-balancer probe path may be used only with separate operator approval. Capture the
complete original probe configuration and restore `/health` on port `8001`.

Expected evidence must distinguish partial backend degradation from complete VIP/path loss.
Partial backend degradation is correlation-only unless the deployed incident producer explicitly
supports that transition. A full signed incident test uses the supported load-balancer VIP failure
scenario.

### NSG connectivity loss

Requires deployed WC-025 change ingestion.

Create one temporary rule on `athena-hackathon-nsg-middle`:

| Field | Value |
| --- | --- |
| Name | `athena-wc029-temp-deny-web-to-middle` |
| Priority | `200` |
| Direction | `Inbound` |
| Source | `10.42.3.0/24` |
| Destination | `10.42.4.0/24` |
| Destination port | `8001` |
| Access | `Deny` |

Abort if priority `200` is already occupied or the captured NSG no longer matches the baseline.
Recovery removes only this exact temporary rule.

Expected evidence: exact change artifact, path-bound flow/Connection Monitor evidence,
`networkSecurityChange` correlation, and recovery after rule removal. Guidance and notifications
are required only after a signed NSG-connectivity incident producer is deployed; the current WC-016
scenario set does not provide that occurrence.

## Signed evidence acceptance

For incident-producing scenarios, verify and retain:

- exact IncidentState occurrence and attestation;
- exact manifest version and clause citations;
- verified WC-026 report and publication attestation;
- deterministic WC-027 guidance and attestation;
- enrichment manifest and attestation;
- v2 feed entry/pointer/index attestations;
- active and resolved notification provenance;
- `noAutoRemediation=true` at every layer;
- queue/dead-letter counts returning to zero; and
- baseline-versus-recovered resource configuration.

For correlation-only scenarios, retain the exact monitoring/change artifacts, verified WC-026
report, report publication attestation, bounded omission metadata, and recovery evidence. Absence
of a supported IncidentState occurrence is expected and must not be replaced with a synthetic or
caller-asserted occurrence.

The scenario fails if any asset requires a mutable/latest read, an untrusted key ID, a draft
manifest, missing recovery evidence, or a renderer-generated instruction.

## Final acceptance and cleanup

WC-029 is complete only when:

1. all reviewed deployments succeeded with no unintended delete or public exposure;
2. effective RBAC matches the separation policy;
3. every enabled scenario met its declared incident-producing or correlation-only acceptance
   criteria;
4. each incident-producing scenario rendered verified guidance from closed templates;
5. each incident-producing scenario used Notification v2 provenance and idempotency for Teams;
6. all temporary files, rules, probe changes, and VM state changes were recovered;
7. active/dead-letter queues are empty;
8. monitoring/runtime isolation remains intact; and
9. the evidence bundle records commit, deployment names, image digests, manifest version, key
   versions, report/guidance/enrichment digests, and operator approval.

If any recovery check fails, stop the release, preserve evidence, and notify the owner because
operator intervention is then required.
