# WC-029 offline acceptance evidence aggregation

`athena_context.wc029_acceptance_evidence` turns one closed directory of captured WC-029 JSON
evidence into a canonical, content-addressed acceptance record. It is an aggregation and
completeness gate, not an Azure acquisition or deployment path.

The harness:

- makes no Azure, HTTP, subprocess, credential, deployment, queue, job, or workload call;
- never applies, recovers, or verifies a live mutation itself;
- never creates an IncidentState, guidance, feed, notification, or other incident artifact;
- consumes exact files already captured by the reviewed deployment, preflight, monitoring,
  correlation, incident, publication, probe, RBAC, queue, and recovery paths;
- validates an exact allowlisted schema for every non-Azure artifact class;
- requires the exact inventory file SHA-256 through the out-of-band
  `--approved-inventory-sha256` argument before trusting any deployment, key, manifest,
  capability, endpoint, or RBAC declaration;
- reuses the existing WC-029 what-if and RBAC evaluators against the captured raw inputs;
- verifies captured RSA public-key fingerprints and every captured signed artifact offline,
  including schema-specific signed preimages and exact versioned Key Vault key IDs;
- rejects incomplete, duplicate, unlisted, linked, escaping, malformed, noncanonical, oversized,
  or internally inconsistent inputs; and
- opens every validated file through a stable no-follow handle before reading any bytes, then
  captures an immutable in-memory snapshot using platform change identity, link-count checks, and
  before/after directory identities; and
- creates one new record exclusively outside the input directory. It never overwrites a prior
  record.

Keep the evidence directory outside the repository. Do not put tokens, response headers containing
credentials, customer data, or mutable `latest` references into it.

## Relationship to the existing WC-029 paths

The harness deliberately does not duplicate:

- the WC-029 deployment orchestration plan/apply and output-handoff checks;
- the WC-029 what-if or effective-RBAC preflight policy;
- WC-028 monitoring acquisition, normalization, persistence, or correlation request creation; or
- WC-027/WC-016 signature verification, incident publication, guidance, feed, or notification
  behavior.

Instead, include their already captured outputs as evidence:

| Existing path | Evidence supplied to this harness |
| --- | --- |
| WC-029 deployment orchestration | Exact inventory-pinned plan, raw what-if, output handoff, and successful deployment read-back for every inventoried deployment |
| WC-029 preflight | Digest-bound successful `what-if` and `rbac` receipts, captured effective RBAC, and reviewed RBAC policy |
| Container Apps Jobs | Execution capture and post-run read-back |
| WC-028/WC-025/WC-026 | Monitoring, change, report, and report-attestation artifacts |
| WC-016/WC-027 | Active/resolved incident, guidance, enrichment, authoritative v1 source indexes, v2 feed indexes, and notification artifacts |
| Context publication | Exact canonical manifest document, resolved profile and dependency digests, cited clauses, publication authority, and independent authority signature |
| Private endpoint probes | Canonical URL probe receipts |
| Service Bus checks | Baseline, scenario-drain, and final zero-count queue receipts |
| Scenario operator | Plan, apply receipt, observation, recovery action, and recovery proof |

An upstream verifier failure remains a failure. Do not replace missing evidence with a hand-authored
success claim.

## Closed input directory

The evidence root contains one `acceptance-index.json` and only the files listed by that index.
Subdirectories are allowed. Every file must be JSON. Symbolic links, hard links, junctions, reparse
points, unreadable subtrees, unlisted files, missing files, path traversal, duplicate paths, and
case-only path aliases fail.

The harness uses incremental bounded `os.scandir` traversal rather than `os.walk`. It charges every
entry before recording its identity or adding a directory to the bounded traversal stack. Before
retaining child handles, it limits the complete tree to 256 directories, 16 path segments, 512
characters per relative path, and 16,384 aggregate relative-path characters. Empty directories
count toward every applicable bound and cannot exhaust the process handle table.

Example:

```text
wc029-capture/
  acceptance-index.json
  deployment/
    foundation.plan.json
    foundation.what-if.json
    foundation.output.json
    foundation.readback.json
  platform/
    job-execution.json
    job-readback.json
    effective-rbac.json
    reviewed-rbac-policy.json
    what-if-preflight.json
    rbac-preflight.json
    queue-baseline.json
    queue-final.json
    presentation-probe.json
    version-inventory.json
    keys/
      incident-public-key.json
  scenarios/
    ...
```

The output directory must already exist and must be outside `wc029-capture/`. The input directory
must remain unchanged while the tool captures its private snapshot. Any file or parent-directory
identity drift fails the run.

On Windows, the harness uses reparse-safe handles that deny write and delete sharing while the
snapshot is captured and compares native file change time. On POSIX, it retains `O_NOFOLLOW`
descriptors for every file and compares `st_ctime_ns` through final verification. Restoring the
original size and modification time after transiently substituting bytes does not make the capture
acceptable.

## Version inventory

The index names exactly one canonical `athena.wc029VersionInventory.v1` artifact. It records:

- the exact 40-character source commit;
- the complete authoritative deployment-root set: WC-013 live acceptance as `live-acceptance`,
  WC-024 connectivity/foundation and WC-029 prerequisites as `foundation`, and WC-025 change
  ingestion as `producer`; every root is subscription scoped and binds its deployment ID, location,
  exact plan artifact ID/SHA-256, template path/SHA-256, base/effective parameter SHA-256, reviewed
  what-if allowlist, orchestrator SHA-256, and exact upstream deployment roots;
- every lowercase digest-pinned container image;
- every approved HTTPS endpoint origin and exact probed path;
- every managed-identity boundary, forbidden role set, and forbidden scope set whose effective
  RBAC must be present;
- every scenario target/action capability and whether a deployed IncidentState producer exists;
- the exact published canonical manifest artifact, approved `PublishedRuntimeContextBinding`,
  authority artifact, independent authority attestation, effective clause set, semantic version,
  resolved profile digest, dependency graph digest, and full dependency-path/coverage-bound
  context-binding payload digest; and
- every signing purpose, exact versioned Key Vault key ID, public-key fingerprint, and captured
  public-key artifact ID.

For each inventoried deployment, the index must contain exactly one plan, raw FullResourcePayloads
what-if, successful what-if receipt, output handoff, and `Succeeded` deployment read-back. The plan
binds the what-if bytes, the output binds the exact plan SHA-256, and the read-back binds the output
handoff plus identical deployment outputs. Source commit, stage, deployment name, scope, and
template digest must agree with the inventory. Every deployment read-back must precede the baseline
queue capture and every scenario execution.

The trusted inventory must pin the complete reviewed plan bytes before the harness calls the
existing what-if evaluator. A plan with an unpinned artifact ID or digest, stage/root/scope,
template, parameters, allowlist, orchestrator digest, or named upstream handoff fails without
evaluating its bundle-selected allowlist.

Every externally supplied digest pin must be non-zero. The all-zero SHA-256 value is reserved only
for the harness's private in-memory aggregate draft before its final digest is computed.

The caller obtains the inventory SHA-256 through the reviewed release channel, not from the bundle
being checked. A digest calculated from an unreviewed bundle is not approval.

Each `athena.wc029SigningPublicKey.v1` artifact contains only a public RSA key, its exact Key Vault
key ID with a 32-hex version, purpose, and fingerprint. The approved inventory binds those values.
The harness recomputes the SPKI SHA-256, requires every independent signing purpose to be exercised,
and verifies the captured signatures with the matching key.

## Required global evidence

Global evidence must contain:

- the version inventory;
- public-key evidence for every inventoried signing purpose;
- exact published-manifest, publication-authority, and authority-attestation evidence;
- deployment plan, what-if, output, and read-back evidence for every inventoried deployment;
- at least one successful Job execution and its exact post-run read-back;
- one canonical successful HTTPS URL probe for every inventoried endpoint/path coordinate;
- captured effective RBAC covering exactly the inventoried principals;
- the reviewed non-vacuous RBAC separation policy, with one exact rule for every approved
  principal/boundary and no recursive case-insensitive key collisions;
- digest-bound successful `what-if` and `rbac` preflight results;
- a baseline zero-count queue capture; and
- a final zero-count queue capture.

The harness does not reimplement preflight policy. It invokes the repository's existing
`evaluate_what_if` and `evaluate_role_assignments` functions on the captured raw evidence and
requires the result receipts to pin the exact inputs, policy, and verifier source digest.

The reviewed RBAC policy must contain an empty `allowedBroadAssignments` array. Separation rules
must exactly equal the trusted inventory boundaries; a bundle cannot add an allowance that hides
a broad Owner, Contributor, Reader, RBAC Administrator, or User Access Administrator assignment.

## Required scenario classes and phases

The index must include each WC-029 scenario class exactly once:

1. `disk-capacity-pressure`
2. `vm-failure`
3. `web-tier-failure`
4. `load-balancer-vip-failure`
5. `backend-degradation`
6. `nsg-connectivity-loss`

The index records a mode for review, but it is not authoritative. The harness derives
`correlation-only` versus `incident-producing` from the approved scenario capability inventory and
the exact capability output in the trusted deployment read-back. At least one approved capability
must use each mode.

Every scenario has all five phases:

| Phase | Minimum evidence |
| --- | --- |
| `plan` | Immutable baseline state, canonical correlation request, and scenario plan |
| `apply` | Exact bounded mutation receipt |
| `observe` | Monitoring evidence, correlation report, and report attestation |
| `recover` | Exact recovery-action receipt |
| `verify` | Immutable recovered state, successful post-recovery Job execution/read-back, signed scenario execution manifest, and recovery proof |

The NSG connectivity scenario also requires signed change evidence.

The plan precommits a unique correlation-request intent nonce and digest over the scenario,
execution ID, accepted context binding, and exact target. The canonical request anchor resource
must equal both the plan and trusted capability targets. Request issuance belongs to `plan`;
`trustedAsOf` and expiry belong to `observe`, with expiry before recovery. The final request digest
is retained by the later signed execution manifest and report lineage, not by the precommit plan,
and is not used as a substitute for the earlier intent commitment.

Every signed phase window has positive duration and is strictly separated from the following
window. Mutation, recovery, recovered-state capture, Job start, Job completion, Job read-back, and
recovery proof timestamps must be strictly increasing; equal timestamps fail.

Signed scenario execution intervals are sorted globally and must be strictly non-overlapping.
Scenario execution IDs, monitoring/correlation request identities, verification inputs, report
IDs, and change-request identities must be globally unique.

The monitoring identity is the digest of the complete canonical handoff, including `collectionId`,
`observedAt`, the exact immutable evidence reference, and the collector attestation. Both that
digest and `collectionId` must be unique across scenarios; changing only time or signature creates
a different identity and replaying either value fails.

### Correlation-only

A correlation-only scenario requires canonical `athena.wc029IncidentOmission.v1` evidence stating
that no supported incident producer exists, no incident was observed, and no synthetic incident
evidence was created. IncidentState, guidance, enrichment, feed, and notification evidence is
forbidden for that scenario. Its report uses the distinct signed
`athena.wc029CorrelationOnlyReportAttestation.v1`, whose closed statement contains no incident ID,
transition, revision, state, subject, bound-request, or incident-asset references.

### Incident-producing

An incident-producing scenario additionally requires:

- a signed incident-bound correlation request containing the exact active IncidentState and
  canonical correlation request;
- active IncidentState and attestation;
- the WC-027 incident report publication statement derived byte-for-byte from the exact bound
  request, report, authority, active state, transition, revision, and state/attestation references;
- exact manifest and clause citation evidence;
- guidance and attestation;
- enrichment manifest and attestation;
- active feed evidence and attestation;
- signed authoritative v1 active source index and attestation;
- active feed index and index attestation;
- active notification provenance;
- resolved IncidentState and attestation;
- resolved feed evidence and attestation;
- signed authoritative v1 resolved source index and attestation;
- resolved feed index and index attestation;
- resolved notification provenance; and
- a scenario-scoped zero-count queue capture in `verify`.

Attestation files bind an exact subject artifact ID. Signing-key purpose is fixed by evidence class,
not chosen by the index. The harness verifies:

- WC-024 monitoring-handoff signatures;
- WC-025 change-evidence signatures;
- canonical WC-026 request digests and embedded `PublishedRuntimeContextBinding`;
- WC-026 report publication statements and signatures bound to the exact captured request;
- signed WC-027 incident-subject and incident-bound-request attestations;
- WC-016 active/resolved IncidentState signatures;
- WC-027 guidance, enrichment, feed-pointer, authoritative v1 source-index, v2 feed-index, and
  notification signatures;
- each v2 feed index against the canonical digest of its corresponding signed v1 active-state
  source index through the shared feed-index validator;
- the incident enrichment manifest through the shared
  `validate_incident_enrichment_manifest_binding` validator against the exact captured bound
  request, report, guidance, subject, transition, revision, publication statement, authority,
  attestations, immutable references, and source-state digests;
- the exact report, guidance, and enrichment references through
  `validate_published_correlation_report_assets`, `validate_incident_guidance_assets`, and
  `validate_incident_enrichment_assets`, including every captured attestation byte digest and
  signature;
- an independent signed scenario-execution manifest that covers every plan/apply/observe/recover/
  verify artifact, its exact bytes, phase, input/request digest, execution ID, target, action, and
  bounded chronological window; and
- the exact active report/state/guidance/enrichment/feed/notification lineage for each
  incident-producing scenario.

Runtime verification remains required before capture; offline verification is a second acceptance
check, not a replacement.

## Recovery proof

Each scenario has one canonical `athena.wc029RecoveryProof.v1` in `verify`. It requires:

- `healthy=true`;
- `residualMutationCount=0`;
- exact plan, signed scenario execution ID, mutation receipt, recovery action, and target resource;
- separate immutable `athena.wc029ResourceState.v1` baseline and recovered artifacts whose
  normalized state digests are recomputed from the exact target and state document;
- equal recomputed baseline and recovered state digests; and
- the exact post-recovery Job read-back, which must start after recovery and reference the recovered
  state and recovery action, plus drained queue evidence for incident-producing scenarios.

A proof referencing global evidence, another scenario, another phase, or itself fails closed.

## Canonical capture receipts

Harness-owned canonical receipts include:

- `athena.wc029QueueState.v1`: baseline, scenario-verify, or final scope; every active,
  dead-letter, and transfer-dead-letter count is zero.
- `athena.wc029UrlProbe.v1`: credential-free HTTPS, HTTP 200, TLS verified, approved network
  location, inventoried endpoint/path, content type, observation time, and exact response-body
  SHA-256. Query strings and fragments are forbidden.
- `athena.wc029JobExecution.v1` and `athena.wc029JobReadback.v1`: exact successful execution,
  source commit, digest-pinned image, result artifact digests, and post-run state.
- `athena.wc029ScenarioPlan.v1`, `athena.wc029MutationReceipt.v1`, and
  `athena.wc029RecoveryAction.v1`: one target-bound plan/apply/recover chain.
- `athena.wc026CorrelationRequest.v2` and
  `athena.wc027IncidentBoundCorrelationRequest.v1`: the exact digest-bound request, accepted
  published runtime context, monitoring handoff, active incident subject, and signed request
  binding consumed by the report.
- `athena.wc029ScenarioExecutionManifest.v1` and its independent RSA attestation: complete
  execution lineage and positive, strictly separated phase windows for every scenario artifact.
- `athena.wc029PublishedManifest.v1`, `athena.wc029PublicationAuthority.v1`, and its independent
  attestation: an exact `CanonicalWorkloadManifest`, native approved-profile resolution, the exact
  shared `PublishedRuntimeContextBinding`, recomputed resolved-profile/dependency/full-authority
  digests, the complete exact effective constraint/control map, publication record/audit heads,
  and authority proof used by report publication. Every report `contextBindingDigest`, signed
  publication request digest, and IncidentState finding clause must resolve to this accepted
  binding and map.
- `athena.wc029ManifestCitation.v1`: the exact published manifest/profile/digest, clause IDs,
  active IncidentState digest, and WC-026 report ID/digest.

These receipts summarize already captured observations. Preserve the raw source capture as a
separate listed evidence artifact when operational review requires it.

Every `bindsArtifactId` is validated as an existing declared artifact before any binding lookup.
Unknown index, attestation, Job, key, manifest, or scenario binding references fail as bounded
domain errors and the CLI returns exit code `2`; they never escape as `KeyError` tracebacks.

## Run

```powershell
python -m athena_context.wc029_acceptance_evidence `
  C:\wc029-evidence\capture-20260914T000000Z `
  --approved-inventory-sha256 'sha256:<reviewed-64-lowercase-hex>' `
  --index acceptance-index.json `
  --output-directory C:\wc029-evidence\records
```

Success prints compact JSON containing:

- `complete: true`;
- the aggregate SHA-256; and
- the newly created output path.

Failure returns exit code `2`, writes no record, and prints a bounded error to stderr.

The output file is named:

```text
wc029-acceptance-<64-lowercase-hex>.json
```

Its `aggregateDigest` covers the canonical record excluding only that digest field. The record
contains exact byte and canonical-JSON SHA-256 values for the index and every evidence artifact,
relative paths only, sorted artifact/scenario references, the full version inventory, and explicit
`validationMode=offline-contract-digest-and-signature`, `azureMutationPerformed=false`, and
`incidentEvidenceSynthesized=false` guardrails. It also records the out-of-band approved inventory
digest.

Output publication uses an exclusive staging file followed by a no-replace hard-link commit. Once
the final digest-named link succeeds, staging cleanup failure cannot turn the committed record into
a reported failure.

Archive the closed input directory and content-addressed output together under the approved release
retention policy. Any later byte change produces a different digest and requires a new record.
