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
- `infra/wc027-enrichment-feed-runtime/main.bicep`
- `infra/wc027-guidance-authority-publisher/main.bicep`
- `infra/wc029-monitoring-prerequisites/main.bicep` (preparation/readiness and explicitly gated guest extensions)

WC-027 is not created by `infra/wc013-live-acceptance/main.bicep`. That root reads existing
Container Apps Jobs only when its two WC-027 readiness flags are true. The governed deployment
sequence is therefore:

1. **Foundation**: deploy `infra/wc013-live-acceptance/main.bicep` with
   `wc027FeedV2ProducerReady=false` and `wc027PublisherReady=false`. Capture the exact managed
   environment, replay Storage, incident container, presentation identity and URL, private
   Service Bus namespace/notification queue, and versioned WC-016/WC-027 signing-key outputs.
2. **Producer**: deploy `infra/wc027-enrichment-feed-runtime/main.bicep` using a reviewed immutable
   parameter artifact bound to those foundation outputs. Capture its exact Job resource ID,
   digest-pinned image, generated configuration JSON and SHA-256 digest, attached identities,
   RBAC evidence, exact queue IDs, and exact storage boundaries. This root also establishes the
   empty private guidance-authority container so its read-only runtime boundary exists before any
   publisher receives create permission.
3. **Publisher**: deploy `infra/wc027-guidance-authority-publisher/main.bicep` with the exact
   producer configuration JSON, digest, correlation-storage boundary, managed environment,
   broker, source identities, and guidance-binding key resource from step 2. Capture its exact Job
   resource ID, image, generated configuration JSON and SHA-256 digest, attached identities, RBAC
   evidence, exact queue/container/table resource IDs, and versioned binding key.
4. **Deployment activation gate (`live-acceptance`)**: redeploy
   `infra/wc013-live-acceptance/main.bicep` with both readiness flags true and only the exact
   producer and publisher handoffs from steps 2 and 3. The root then reads both deployed Jobs and
   fails closed on image, command, scaler, registry, configuration, identity, RBAC,
   embedded-runtime, or key-binding drift. Its
   `wc016ApprovedConfiguration.wc027DeploymentReadiness` output must read back the exact accepted
   Job IDs, images, configuration digests, embedded producer digest, and RBAC evidence.

Use `scripts/wc029_deployment_orchestration.py` for these four stages. It creates immutable
effective-parameter, full-payload what-if, plan, deployment-handoff, and deployment-receipt
artifacts in an operator-selected evidence directory outside the repository. `plan` performs ARM
validation and the repository zero-delete/public-exposure preflight. `apply` accepts only the
unchanged reviewed plan digest, template, effective parameters, freshly repeated identical
what-if, source commit, orchestrator/preflight implementation, and verified predecessor approval
chain. It verifies that expected Jobs, identities, exact current key versions, and
storage/authority resources exist before emitting the next handoff and receipt. Every handoff is
bound to the exact source commit, subscription, deployment scope, reviewed plan digest, verified
predecessor receipt hashes, a deliberately narrowed exact stage-output schema, and an exact
effective-parameter binding. The foundation handoff carries one canonical SHA-256 over every
non-WC-027 effective parameter rather than an open-ended parameter object. Missing, extra,
cross-scope, changed, unapproved, or internally inconsistent plans, receipts, handoffs, parameters,
and deployment outputs fail closed. Never call a later stage without the complete preceding
handoff and independently reviewed receipt set.

This four-stage tool establishes deployment wiring, not a publisher runtime invocation. The
merged production publisher can publish `PublishedGuidanceAuthorityBinding.v2` to the producer
trigger queue, and the orchestrator validates that exact shared queue plus the publisher broker's
Service Bus Data Sender assignment. It does not construct, sign, or submit
`GuidanceAuthorityPublicationRequest.v1`. The final deployment handoff therefore records
`automaticRequestProducerPresent=false` and `runtimeInvocationValidated=false`; do not describe it
as end-to-end WC-029 completion.

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
| WC-027 enrichment/feed runtime | Resource group | Reviewed immutable producer artifact bound to the WC-013 foundation handoff, including exact identities, source containers, trust metadata, image, and expected generated-configuration digest |
| WC-027 guidance-authority publisher | Resource group | Reviewed immutable publisher artifact; the orchestration tool injects the exact producer configuration/digest and derives the shared foundation, correlation storage, broker, activation store, source identities, and binding-key/trust handoffs |
| WC-029 monitoring prerequisites | Subscription | `infra/wc029-monitoring-prerequisites/main.preparation.bicepparam` with both extension gates false; enabling either requires a separately reviewed immutable copy |

The release cannot proceed while any non-WC-013 root lacks its reviewed immutable parameter
artifact. Run `az deployment sub validate` and `az deployment sub what-if` separately for each
subscription-scope root. Save raw JSON before review. AMPLS bootstrap, when genuinely required,
uses `az deployment group` only through its guarded wrapper.

The checked-in WC-029 artifact is preparation-only: it validates the existing baseline and leaves
Dependency Agent and Network Watcher Agent deployment disabled. See
[WC-029 monitoring infrastructure preparation](wc029-monitoring-infrastructure-preparation.md)
for exact prepared scope and blockers. It is not deployment approval.

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

The deployment operator must be able to call Microsoft Graph with `Application.Read.All`.
For every managed-identity service principal, first enumerate
`/servicePrincipals/{id}/transitiveMemberOf/microsoft.graph.group` with `$count=true`, follow every
`@odata.nextLink`, and require the final unique group count to match `@odata.count`. Missing
permissions, unavailable pages, cycles, untrusted continuation URLs, duplicate groups, or a
truncated count fail closed.

For the service principal and every resolved transitive group, the orchestrator queries the ARM
Authorization provider at subscription scope with `$filter=principalId eq '<object-id>'`. It
boundedly follows every trusted `nextLink` and merges, by exact resource ID:

- classic `roleAssignments@2022-04-01`;
- current or upcoming `roleAssignmentScheduleInstances@2020-10-01`; and
- `roleEligibilityScheduleInstances@2020-10-01`, because latent activation is prohibited for
  these governed runtime identities.

One shared page and item budget covers all three resource types and every transitive group in one
effective-assignment scan. Active, pending, and future-start schedules remain relevant until their
end time. Expired or explicitly terminal schedules do not grant current or future authority.
Unknown status, assignment type, membership type, timestamp, principal, role, scope, resource ID,
continuation, duplicate, or over-budget evidence fails closed. Every server-provided continuation
must preserve the exact ARM host, collection path, API version, and filter and include one
non-empty `$skipToken`; a cursorless repeated first page is never accepted as complete evidence.

Required separation:

- context identity: no workload Reader and no Log Analytics Reader;
- evidence identity: workload Reader only at the approved workload scope;
- monitoring collector: exact monitoring query/data roles and governed resource scopes;
- presentation identity: Blob Data Reader for presentation/incident assets and ACR pull only;
- incident/enrichment publishers: exact Blob contributor, queue, and Key Vault crypto roles only;
- notification dispatcher: exact v2 queue/table/Logic App rights only; and
- no generic Contributor assignment for a runtime identity.

Without separate reviewed management-group hierarchy evidence, treat every assignment returned by
the principal-filtered query at a management-group scope as applying to every governed
subscription resource and reject it unless that exact assignment is explicitly reviewed.

The dedicated producer trigger queue also receives a separate `$filter=atScope()` scan across the
same three Authorization resource types. It accepts only the exact current classic assignments and
the bounded reviewed transition set. Active/upcoming PIM assignments, activatable eligibility,
unknown exact-scope assignments, and inherited queue send/receive or RBAC-escalation grants fail
closed. Roles that can create classic assignments, create or activate assignment/eligibility
schedules, alter custom roles, or weaken role-management policy are schedule-administration
authority and are not treated as harmless inherited access. Inherited Service Bus namespace
mutation, authorization-rule creation/update, connection-string/key listing, and key-regeneration
permissions are likewise queue-access escalation because they can re-enable local authentication
or mint SAS access without a Service Bus data-role assignment.

For every exact queue, Blob container, Table, Key Vault key, and ACR registry scope used by a
governed identity, readiness also calls the ARM `denyAssignments` endpoint with
`$filter=atScope()` and follows every trusted `nextLink`. The evaluation includes direct
principals, every resolved transitive group, the `All Principals` system identity, principal and
group exclusions, inherited scopes, `doNotApplyToChildScopes`, enforced versus audit effects, and
assignment-level and permission-level condition version `2.0` expressions. A deny that covers any
required control-plane or data-plane runtime action blocks readiness. Missing pages, malformed
permission arrays, unsupported conditions, or any other incomplete deny evidence also fail
closed.

## Phase 4: deploy

Deployment is an explicit operator action. The approved command, commit SHA, image digests,
deployment name, what-if digest, and operator identity must be captured before execution.

Run the four orchestration stages in order. Use a unique deployment name and a new evidence
directory for each plan. Review the generated `*.what-if.json` and `*.plan.json` before running
`apply`; the apply command rejects any changed byte.

The final plan schema is `athena.wc029DeploymentPlan.v7`. Every reviewed plan, base/effective parameter
document, what-if, predecessor handoff, and receipt is read exactly once through the secure
non-reparse artifact reader. Its immutable raw bytes, parsed document, file identity, and SHA-256
remain attached to that orchestration invocation; later checks never reopen the reviewed path.
Every Azure deployment validate, what-if, and create command includes `--no-prompt true`, and the
subprocess receives no stdin. Final planning compiles Bicep exactly once, writes the canonical ARM
JSON to an immutable `*.template.json` review artifact, and records its path, bytes, identity, and
SHA-256. Validate and what-if consume one private pinned copy of that ARM JSON plus one private
pinned effective-parameter copy. Apply captures those reviewed artifacts without reopening Bicep
and rematerializes the same bytes for its final what-if and create. Post-deployment template export
must corroborate the reviewed ARM JSON; it is not the first detection of template drift.

For producer, publisher, and live-acceptance stages the plan also records
`authorityBlobInventory` plus its exact checkpoint SHA-256. Blob service versioning must be enabled.
Each checkpoint points to the digest of the reviewed predecessor checkpoint. One version-inclusive
listing supplies every version ID, exact case-sensitive Blob name, ETag, and content length. New
versions are downloaded only after every listed content length is present, non-negative, within
the per-artifact bound, consistent with prior checkpoint metadata, and the aggregate listed
content is no more than 64 MiB. This prevents a maximum-count inventory from amplifying into
thousands of bounded-but-cumulative downloads. Accepted new versions are then downloaded by exact
version, SHA-256 hashed, and parsed as canonical
`PublishedGuidanceAuthority.v2` or `PublishedGuidanceAuthorityBinding.v2`; path-bound IDs and each
binding's exact authority name, version, and digest must match. Previously checkpointed versions
and digests must remain byte-identical, no content-addressed name may be overwritten or removed,
and every authority must have a conforming binding. Legitimate publications therefore advance the
checkpoint append-only instead of being compared circularly with the original deployment-time
snapshot. Apply requires the pre-create checkpoint to equal the reviewed plan and emits the
post-deployment successor checkpoint in the handoff and receipt chain. The plan's
`requiredAuthorityCheckpointSha256s` map records every producer/publisher predecessor and prior
same-stage checkpoint that the candidate must preserve, so publisher recovery cannot discard a
newer producer checkpoint.

Initial publisher planning may omit prior publisher evidence only when two independent Azure
readbacks prove that the exact deterministic publisher Job and the requested publisher deployment
do not exist, and the live authority container content exactly equals the producer checkpoint.
Apply repeats both absence reads and the exact content comparison before create. If either
publisher resource exists, an absence result is not an exact Azure `ResourceNotFound` or
`DeploymentNotFound`, or the container has any added, deleted, or changed version, the operator
must supply the prior publisher receipt and checkpoint. Omission is never a recovery shortcut.

Producer upgrades and publisher recovery must additionally supply
`--prior-stage-handoff`, `--prior-stage-receipt`, and
`--prior-stage-reviewed-receipt-sha256`. The reviewed prior same-stage receipt may come from an
earlier source commit, but its receipt, plan, handoff, stage scope, and inventory hashes must remain
internally exact, including deployment name and predecessor-receipt lineage. Every pre-existing
producer authority container, even an empty one, requires prior producer evidence; an out-of-band
deployment cannot establish a new baseline. If a reviewed fresh producer create succeeds but
eventually consistent ARM/RBAC readback or a crash before receipt publication prevents completion,
rerun the same apply with `--resume-succeeded-deployment`. That read-only recovery path is limited
to the original fresh producer plan: it never runs what-if or create, and it requires the exact
succeeded deployment name, incremental mode, reviewed parameters, exported compiled template,
outputs, enabled versioning, and empty container before issuing the recovery receipt. If the first
attempt already published a handoff, the recovered handoff must be byte-identical. Deployment and
readiness readbacks use eight bounded attempts with no delete or unreviewed mutation.

Identity and role migrations use two separately reviewed phases. Phase A runs
`prepare-revocation`, verifies each exact stale assignment while it is still present, and emits
`athena.wc029RevocationPlan.v1` with the full live assignment ID, principal, role, scope, principal
type, condition, and ACR mode where applicable. The operator independently reviews that artifact
and performs the manual revocations. Phase B runs `plan` with `--revocation-plan` and
`--reviewed-revocation-plan-sha256`, verifies every reviewed stale assignment is absent, and only
then compiles the pinned ARM template and generates a new final what-if. Apply rechecks absence and
replays only that post-revocation final what-if. A pre-revocation what-if is never reusable.

Supply `--rotation-transition-assignment <exact-role-assignment-id>
<exact-retired-principal-id>` only to `prepare-revocation`. Producer signer migration uses
`--legacy-crypto-user-migration-assignment <exact-role-assignment-id>` in the same phase.

Upgrading from an earlier ACR module requires a separate reviewed migration because the corrected
principal-object-ID or repository seed intentionally produces a new role-assignment GUID. Record
each old assignment to `prepare-revocation` with `--legacy-acr-pull-migration-assignment
<old-assignment-id> <exact-principal-id>`. Phase A requires every listed legacy assignment to be present with its
exact ACR scope, service-principal type, and one recognized obsolete profile: unconditioned
`AcrPull`, or the exact pre-remediation unconditioned `Container Registry Repository Reader` on an
ABAC-enabled registry. A controlled operator action must revoke all listed assignments before
apply; apply and post-deployment readiness require continued absence. Canonically conditioned
Repository Reader assignments for a retired principal use
`--rotation-transition-assignment <assignment-id> <retired-principal-id>` instead; their exact
repository condition is preserved in revocation evidence. This boundary covers the producer,
publisher, and all WC-013 acceptance, evidence, controller, detector, orchestrator, notification,
and presentation pull assignments. The orchestrator never deletes them.

```powershell
$Orchestrator = '.\scripts\wc029_deployment_orchestration.py'

# When exact assignments require manual revocation, run phase A first and independently
# review its digest. Omit these two commands when there is no revocation set.
python $Orchestrator prepare-revocation --stage <stage> `
  --deployment-name <deployment> `
  --parameters <reviewed base parameters> `
  --evidence-directory <new evidence directory> `
  --rotation-transition-assignment <assignment ID> <retired principal ID> `
  <matching predecessor arguments>
# Manually revoke only the independently reviewed assignments.

python $Orchestrator plan --stage foundation <reviewed foundation arguments>
# For a two-phase deployment append:
#   --revocation-plan <reviewed phase-A plan>
#   --reviewed-revocation-plan-sha256 <independently recorded sha256:...>
python $Orchestrator apply --plan-manifest <reviewed foundation plan> `
  --reviewed-plan-sha256 <independently recorded sha256:...>

python $Orchestrator plan --stage producer `
  --foundation-handoff <foundation handoff> `
  --foundation-receipt <foundation receipt> `
  --foundation-reviewed-receipt-sha256 <independently recorded receipt sha256:...> `
  <reviewed producer arguments>
python $Orchestrator apply --plan-manifest <reviewed producer plan> `
  --reviewed-plan-sha256 <independently recorded sha256:...>

# Only after the exact fresh producer deployment succeeded but evidence completion was
# blocked by eventually consistent readback or a crash after the handoff write:
python $Orchestrator apply --plan-manifest <same reviewed producer plan> `
  --reviewed-plan-sha256 <same independently recorded sha256:...> `
  --resume-succeeded-deployment

python $Orchestrator plan --stage publisher `
  --foundation-handoff <foundation handoff> `
  --foundation-receipt <foundation receipt> `
  --foundation-reviewed-receipt-sha256 <independently recorded receipt sha256:...> `
  --producer-handoff <producer handoff> `
  --producer-receipt <producer receipt> `
  --producer-reviewed-receipt-sha256 <independently recorded receipt sha256:...> `
  <reviewed publisher arguments>
python $Orchestrator apply --plan-manifest <reviewed publisher plan> `
  --reviewed-plan-sha256 <independently recorded sha256:...>

python $Orchestrator plan --stage live-acceptance `
  --foundation-handoff <foundation handoff> `
  --foundation-receipt <foundation receipt> `
  --foundation-reviewed-receipt-sha256 <independently recorded receipt sha256:...> `
  --producer-handoff <producer handoff> `
  --producer-receipt <producer receipt> `
  --producer-reviewed-receipt-sha256 <independently recorded receipt sha256:...> `
  --publisher-handoff <publisher handoff> `
  --publisher-receipt <publisher receipt> `
  --publisher-reviewed-receipt-sha256 <independently recorded receipt sha256:...> `
  <reviewed WC-013 arguments>
python $Orchestrator apply --plan-manifest <reviewed live-acceptance plan> `
  --reviewed-plan-sha256 <independently recorded sha256:...>
```

Every `plan` command requires the fixed subscription, location, deployment name, reviewed
parameter artifact, evidence directory, and explicit `--allow-change` entry for each approved
create or modify. WC-027 resource-group stages additionally require
`--resource-group rg-athena-wc013-live`. Do not treat these abbreviated placeholders as executable
approval; record the complete reviewed commands and plan-file SHA-256 values separately in the
evidence bundle. `apply` writes the immutable `athena.wc029DeploymentHandoff.v7` handoff and a separate
`athena.wc029DeploymentReceipt.v4`, then prints the receipt path. Independently record the receipt
SHA-256 before using it in a later stage. Each later `plan` loads the predecessor receipt, its
referenced plan, effective parameters, what-if, handoff, and earlier receipt chain; a handoff's
self-computed hashes alone are never approval evidence. The evidence directory must be outside the
repository. Planning and apply both refuse a dirty working tree, duplicate allowlist entries, the
wrong stage scope, or any missing or extra predecessor handoff/receipt/approval digest.

Fresh-producer recovery is idempotent across the handoff/receipt publication boundary. If create
succeeded and the byte-exact handoff was durably written but the process stopped before writing
the receipt, rerun the same reviewed plan with `--resume-succeeded-deployment`. The orchestrator
re-attests the succeeded deployment, template, parameters, outputs, RBAC, deny assignments,
image-pull proof, and authority checkpoint, then compares the existing handoff byte-for-byte with
the newly derived handoff and writes only the missing receipt. An existing conflicting handoff or
any existing receipt is never overwritten.

The two WC-027 roots derive their configuration JSON from live ARM resource references, which ARM
what-if cannot fully resolve. Their reviewed digest parameters are therefore recomputed against
the exact resolved deployment output immediately after create. A mismatch emits no handoff and
blocks every later stage; reconcile the reviewed digest and repeat validate/what-if rather than
continuing with the mis-tagged Job. Apply also rejects a non-succeeded deployment, missing required
root output, mismatched queue/container/table/key output, unexpected Job identity, tag, command,
scaler, registry, environment, init container, volume, secret, secret reference, or secret-backed
authentication; any RBAC assignment whose exact assignment ID is not bound to its reviewed
principal, scope, role definition, condition, and — for a custom role — exact `actions`,
`notActions`, `dataActions`, and `notDataActions` sets; any effective broad inherited or transitive
group-derived grant on a governed identity; any unreviewed effective assignment intersecting a
governed WC-027 scope for any attached, submitter, or reader identity; any unreviewed
management-group assignment, which is conservatively treated as inherited by every governed
resource unless separate reviewed hierarchy evidence is introduced; incomplete Microsoft Graph
membership or Azure assignment evidence; any public/non-RBAC parent Key Vault behind an external
trust key; any current Key Vault `kid`, RSA type/size, modulus, exponent, SPKI fingerprint, or
key-operation drift from the same current-version read; any authority Blob service without
versioning or any missing/conflicting/oversized authority content/version inventory; any
assignment whose resolved role permissions include Blob read without the exact
canonical condition-version `2.0` no-`Blob.List` ABAC expression; any queue outside its exact
Active, non-forwarding, non-auto-deleting stage profile; a noncanonical/cross-subscription resource
ID before validation or what-if; and any final WC-013 readiness readback that differs from the two
accepted WC-027 handoffs.

Every ACR pull module is deployed at the exact subscription and resource group parsed from
`registryResourceId`; for the fixed topology this is `rg-athena-platform-dev`, not the WC-027
runtime resource group. The role-assignment GUID is seeded with the canonical registry ID, the
server-returned service-principal object ID, and the full role-definition ID; ABAC assignments add
the exact repository parsed from the reviewed digest-pinned image to the seed so one principal can
hold distinct per-repository grants. Deleting and recreating a same-name UAMI therefore produces a
new legal assignment. Each assignment sets
`principalType: ServicePrincipal`. The module explicitly calls guarded
`reference(registry.id, '2025-04-01', 'Full')` and exports that server-returned ID; a constructed
`existing.id` alone is never treated as runtime evidence. The same read must return
`anonymousPullEnabled: false`; missing or enabled anonymous pull blocks role assignment,
foundation/live-acceptance readiness, producer/publisher readiness, and image-pull evidence.

Foundation and live-acceptance outputs inventory the current WC-013/WC-016/presentation ACR
assignments with exact label, digest-pinned image, parsed repository, assignment ID, principal,
role, mode, scope, type, and condition. Legacy mode has the seven existing registry-wide
`AcrPull` assignments with null conditions. ABAC mode adds a separate presentation-delivery
assignment because the presentation identity pulls two repositories, and every Repository Reader
assignment has condition version `2.0` plus the canonical exact repository-name condition. The
handoff also carries the phase-A `revocationAssignments` records for retired assignments with a
separate digest. Readiness re-reads every current assignment and each registry mode, resolves every
effective role definition across direct, inherited, and transitive-group assignments throughout
the governed subscription, and rejects all extra pull-capable grants even when they target a
sibling registry. This includes `AcrPush`, Repository Writer/Contributor, and custom roles whose
effective permissions grant legacy pull, quarantine pull, quarantined-artifact read, or repository
content read. Classification evaluates each permission in its actual `Actions` or `DataActions`
plane and applies the matching `NotActions` or `NotDataActions` exclusions. Registry control
permissions that can enable pull, retrieve or mint credentials, change quarantine/policy state, or
create tokens/scope maps are also pull-escalating. ACR Tasks creation or execution authority is
pull-escalating because Tasks management can exercise full registry data-plane access. The same is
true for applicable classic-role, PIM schedule, eligibility, custom-role, and
role-management-policy write authority. Registry and ancestor scopes can affect their descendants;
a sibling registry is still an unreviewed ACR authority domain, while a role assigned only to an
unrelated non-ACR resource cannot govern a registry.

The same complete pull-capable scan applies to every WC-027 producer and publisher principal,
including principals with no reviewed ACR assignment. Only the exact reviewed producer and
publisher image-pull assignment IDs are accepted; all sibling-registry, direct, inherited, and
group-derived alternatives fail closed.

Readiness compares the reviewed mode with the live ACR `roleAssignmentMode`.
`LegacyRegistryPermissions` requires `AcrPull`; `AbacRepositoryPermissions` requires
`Container Registry Repository Reader` with the exact repository condition because an ABAC-enabled
registry does not honor legacy `AcrPull`. Missing, altered, prefix, multi-repository, or
registry-wide conditions fail closed. After exact RBAC verification, readiness starts a bounded
no-op Container Apps Job execution with the digest-pinned image, waits for `Succeeded`, validates
the execution image and command override, and records the execution in digest-bound handoff/receipt
evidence. The probe does not pass `--registry-identity`, create RBAC, or invoke the production Job
entry point. Because live anonymous pull is explicitly false and the Job registry configuration
contains only the reviewed managed identity, a successful probe is evidence of identity-authorized
pull rather than public access. Any anonymous-pull or role-mode failure observed after an execution
reaches `Succeeded` raises the dedicated terminal evidence exception. The image-pull retry and
every outer apply/readiness retry propagate it unchanged, so a false-to-true ACR posture drift can
never be retried after the environment later returns to false and accepted as successful evidence.

Producer verification also models the publisher transition explicitly.
Before a publisher exists, no extra sender assignment is required. During partial recovery,
publisher retry, or a later producer upgrade, only the deterministic assignment ID produced by
`guid(triggerQueue.id, brokerIdentity.id, serviceBusDataSenderRoleDefinitionId)` is accepted, and
its live principal, queue scope, sender role, principal type, and absent condition are revalidated.
The complete at-scope Authorization evidence for the dedicated trigger queue must contain only the
current producer assignments, the current deterministic publisher assignment when present, and at
most four exact retired queue transition pairs; inherited queue or schedule-administration
authority is rejected as described above. Record each assignment ID and retired principal ID with
`prepare-revocation --rotation-transition-assignment`; do not overload the what-if
`--allow-change` list. The reviewed revocation plan carries a bounded maximum of 32 transition
assignments across all rotated-identity scopes,
including notification sender, publisher request receiver, exact Key Vault roles, Blob and Table
assignments, and ACR pull. Phase A requires every approved transition ID to be present, bound to
the independently reviewed retired service-principal ID, and constrained to its exact
scope/role/condition profile. After independent phase-A review, an operator performs controlled
revocation. The phase-B plan and apply both require absence before their respective final what-if
and create, and post-deployment verification repeats absence before emitting a handoff. If deletion
and recreation of a same-name UAMI causes ARM's deterministic assignment ID to
be reused, the live assignment is accepted only when its principal is the exact current principal
and its role, scope, principal type, condition, and custom-role permissions exactly match the
current expected assignment. The stale reviewed retired principal always fails. The orchestrator
never deletes RBAC automatically. Any stale or unapproved queue assignment, missing current
assignment, malformed transition pair or role, or leaked assignment page fails closed.

The five deterministic legacy Key Vault Crypto User assignments are not classified as retired
identity transitions. Producer phase-A planning carries them in the separately bounded
`legacyCryptoUserMigrationAssignmentIds` field, validates their current signer principals and
exact key scopes, and requires the reviewed set to match the assignments still present. They must
be manually revoked before phase B; final planning, apply, and every later producer dependency
check require all five IDs to remain absent.

Legacy ACR pull assignments are likewise tracked separately in the bounded
`legacyAcrPullMigrationAssignments` plan field with both assignment and principal IDs. They cannot
be placed in the identity-rotation list or retained alongside the new principal-seeded,
mode-compatible assignment.

Publisher verification re-queries effective RBAC for the union of publisher principals and every
producer principal proven by the independently approved producer binding. Separated producer-only
readers, writers, and signers therefore retain complete direct, group-derived, and inherited
evidence during publisher apply and recovery; the expected producer assignment set is never
reduced to the identities attached to the publisher.

### Publisher invocation boundary

No merged production component automatically constructs and submits
`GuidanceAuthorityPublicationRequest.v1`. After deployment activation, an authorized operator or a
future separately governed request producer must:

1. construct an already-authoritative canonical signed publication request from the exact current
   occurrence, approved context, correlation request, requested actions, evaluation time, and
   expiry;
2. submit it to `wc027-guidance-authority-requests` with
   `athena-context wc027-guidance-authority-submit`;
3. prove one publisher Job execution consumed that request and created the exact immutable
   authority, signed binding, and current signed activation;
4. prove the publisher broker sent that binding to the exact
   `wc027-enrichment-feed-requests` queue and the producer consumed it; and
5. retain signed producer readback through enrichment, registry admission, feed-v2 commit, and
   Notification v2 before claiming end-to-end behavior.

This runtime evidence is outside `scripts/wc029_deployment_orchestration.py`. Root deployment,
successful what-if, and `wc027DeploymentReadiness` prove only the dormant production path and its
least-privilege wiring.

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
