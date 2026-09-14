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
- reuses the existing WC-029 what-if and RBAC evaluators against the captured raw inputs;
- verifies captured RSA public-key fingerprints and every captured signed artifact offline,
  including schema-specific signed preimages and exact versioned Key Vault key IDs;
- rejects incomplete, duplicate, unlisted, linked, escaping, malformed, noncanonical, oversized,
  or internally inconsistent inputs; and
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
| WC-029 deployment orchestration | Exact plan, raw what-if, output handoff, and successful deployment read-back for every inventoried deployment |
| WC-029 preflight | Digest-bound successful `what-if` and `rbac` receipts, captured effective RBAC, and reviewed RBAC policy |
| Container Apps Jobs | Execution capture and post-run read-back |
| WC-028/WC-025/WC-026 | Monitoring, change, report, and report-attestation artifacts |
| WC-016/WC-027 | Active/resolved incident, guidance, enrichment, feed, and notification artifacts |
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

The output directory must already exist and must be outside `wc029-capture/`. This keeps the input
directory read-only and makes directory-membership validation meaningful.

## Version inventory

The index names exactly one canonical `athena.wc029VersionInventory.v1` artifact. It records:

- the exact 40-character source commit;
- every deployment ID, stage, deployment name, and template SHA-256;
- every lowercase digest-pinned container image;
- every approved HTTPS endpoint origin and exact probed path;
- every managed-identity principal whose effective RBAC must be present;
- the published manifest ID, version, profile, and digest; and
- every signing purpose, exact versioned Key Vault key ID, public-key fingerprint, and captured
  public-key artifact ID.

For each inventoried deployment, the index must contain exactly one plan, raw FullResourcePayloads
what-if, successful what-if receipt, output handoff, and `Succeeded` deployment read-back. The plan
binds the what-if bytes, the output binds the exact plan SHA-256, and the read-back binds the output
handoff plus identical deployment outputs. Source commit, stage, deployment name, scope, and
template digest must agree with the inventory.

Each `athena.wc029SigningPublicKey.v1` artifact contains only a public RSA key, its exact versioned
Key Vault key ID, purpose, and fingerprint. The harness recomputes the SPKI SHA-256, requires every
inventoried key to be exercised, and verifies the captured signatures with the matching key.

## Required global evidence

Global evidence must contain:

- the version inventory;
- public-key evidence for every inventoried signing purpose;
- deployment plan, what-if, output, and read-back evidence for every inventoried deployment;
- at least one successful Job execution and its exact post-run read-back;
- one canonical successful HTTPS URL probe for every inventoried endpoint/path coordinate;
- captured effective RBAC covering exactly the inventoried principals;
- the reviewed non-vacuous RBAC separation policy;
- digest-bound successful `what-if` and `rbac` preflight results;
- a baseline zero-count queue capture; and
- a final zero-count queue capture.

The harness does not reimplement preflight policy. It invokes the repository's existing
`evaluate_what_if` and `evaluate_role_assignments` functions on the captured raw evidence and
requires the result receipts to pin the exact inputs, policy, and verifier source digest.

## Required scenario classes and phases

The index must include each WC-029 scenario class exactly once:

1. `disk-capacity-pressure`
2. `vm-failure`
3. `web-tier-failure`
4. `load-balancer-vip-failure`
5. `backend-degradation`
6. `nsg-connectivity-loss`

At least one scenario must be `correlation-only` and at least one must be
`incident-producing`.

Every scenario has all five phases:

| Phase | Minimum evidence |
| --- | --- |
| `plan` | Scenario plan |
| `apply` | Exact bounded mutation receipt |
| `observe` | Monitoring evidence, correlation report, and report attestation |
| `recover` | Exact recovery-action receipt |
| `verify` | Successful Job execution/read-back pair and canonical recovery proof |

The NSG connectivity scenario also requires signed change evidence.

### Correlation-only

A correlation-only scenario requires canonical `athena.wc029IncidentOmission.v1` evidence stating
that no supported incident producer exists, no incident was observed, and no synthetic incident
evidence was created. IncidentState, guidance, enrichment, feed, and notification evidence is
forbidden for that scenario.

### Incident-producing

An incident-producing scenario additionally requires:

- active IncidentState and attestation;
- exact manifest and clause citation evidence;
- guidance and attestation;
- enrichment manifest and attestation;
- active feed evidence and attestation;
- active notification provenance;
- resolved IncidentState and attestation;
- resolved feed evidence and attestation;
- resolved notification provenance; and
- a scenario-scoped zero-count queue capture in `verify`.

Attestation files bind an exact subject artifact ID. Signing-key purpose is fixed by evidence class,
not chosen by the index. The harness verifies:

- WC-024 monitoring-handoff signatures;
- WC-025 change-evidence signatures;
- WC-026 report publication statements and signatures;
- WC-016 active/resolved IncidentState signatures;
- WC-027 guidance, enrichment, feed-pointer, and notification signatures; and
- the exact active report/state/guidance/enrichment/feed/notification lineage for each
  incident-producing scenario.

Runtime verification remains required before capture; offline verification is a second acceptance
check, not a replacement.

## Recovery proof

Each scenario has one canonical `athena.wc029RecoveryProof.v1` in `verify`. It requires:

- `healthy=true`;
- `residualMutationCount=0`;
- exact plan, mutation-receipt, recovery-action, target-resource, and source-state bindings;
- equal baseline and recovered normalized-state digests; and
- the exact scenario Job read-back, plus drained queue evidence for incident-producing scenarios.

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
- `athena.wc029ManifestCitation.v1`: the exact published manifest/profile/digest, clause IDs,
  active IncidentState digest, and WC-026 report ID/digest.

These receipts summarize already captured observations. Preserve the raw source capture as a
separate listed evidence artifact when operational review requires it.

## Run

```powershell
python -m athena_context.wc029_acceptance_evidence `
  C:\wc029-evidence\capture-20260914T000000Z `
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
`incidentEvidenceSynthesized=false` guardrails.

Archive the closed input directory and content-addressed output together under the approved release
retention policy. Any later byte change produces a different digest and requires a new record.
