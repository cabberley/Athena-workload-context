# Governed context and intelligent monitoring development plan

## Objective

Extend Athena from the current event-driven demonstration into a governed live workload-context
and operational-intelligence platform. The phase combines two inseparable workstreams:

1. **Governed Live Epic Workload Context**: authorized users can review, complete, modify, approve,
   publish, compare, and supersede protected workload context.
2. **Intelligent Monitoring, Change Correlation and Operator Guidance**: Athena correlates guest,
   platform, network, and resource-change evidence, determines bounded root-cause hypotheses, and
   presents confidence-sensitive manual investigation and resolution guidance.

Athena remains a context and judgment plane. It does not silently convert observations into
declared intent and does not automatically remediate workload resources.

## Deployment scope

The phase targets the existing deployment boundary:

- subscription: `a6add389-9978-47ac-ab1e-a09212e321d4`;
- monitored workload resource group: `rg-athena-demo-workload`;
- monitoring resource group: `rg-athena-demo-monitoring`;
- Athena runtime resource group: `rg-athena-wc013-live`;
- region: `australiaeast`.

Monitoring-owned destinations, Data Collection Rules, alerting, Connection Monitor definitions,
workbooks, and replacement monitoring storage belong in `rg-athena-demo-monitoring`. Azure-managed
Network Watcher resources may remain in `NetworkWatcherRG`.

## Verified starting point

The September 2026 environment assessment established that:

- all 11 demo VMs have Azure Monitor Agent installed;
- `athena-hackathon-law` receives current Heartbeat, Perf, InsightsMetrics, and Syslog records;
- the active DCR collects processor, memory, logical-disk, disk-transfer, network-throughput,
  VM Insights, selected syslog, and bounded Athena JSON logs;
- VNet and resource flow logs are enabled with Traffic Analytics;
- existing flow logs use `athenahackathonflowwhtco`;
- subscription Activity Logs are not exported to `athena-hackathon-law`;
- the current WC-016 runtime detects VM power-state and load-balancer metric transitions;
- dynamic incident state and Teams notifications require additional trust-boundary hardening before
  becoming the base for this phase.

## Architectural invariants

1. Declared, observed, inferred, and exception relationships remain distinct.
2. Azure evidence never overwrites approved context.
3. Every runtime judgment cites an exact immutable manifest version and evidence references.
4. Unknown, stale, conflicting, ambiguous, or low-confidence information fails closed.
5. AI and MCP tools may propose changes but cannot approve or publish authoritative context.
6. Customer-specific context and detailed provenance remain in protected private stores.
7. Managed identities, private networking, and narrowly scoped RBAC are mandatory.
8. Root-cause confidence is calculated by deterministic rules, not generated solely by an LLM.
9. Guidance proposes manual investigation and resolution; Athena performs no remediation.
10. Static reviewed lifecycle assets and dynamic incident assets use separate signing and storage
    trust boundaries.
11. Azure telemetry is acquired through the private Azure MCP or identity-isolated collectors with
    exact reviewed query/tool allowlists and signed, immutable, version-pinned evidence handoffs.
    The Athena context identity receives no direct workload or monitoring Reader role.
12. Any narrow direct Azure adapter requires an ADR documenting the Azure MCP gap, exact scope,
    bounded response contract, identity, RBAC, freshness, and removal criteria.

## Workstream A: governed live Epic workload context

### A1. Production context schema and research conversion

- Define production contracts for workload identity, environments, roles, dependencies, ownership,
  criticality, objectives, recovery intent, monitoring semantics, evidence requirements, and
  approved exceptions.
- Convert suitable public-safe Epic research concepts into an initial unpublished proposal.
- Preserve every unsupported or customer-specific value as an explicit unknown or human decision.
- Keep `docs/research/drafts/epic-on-azure.draft.yaml` non-runtime.

### A2. Protected durable context store

- Replace the in-memory authoritative store with a transactional, durable implementation.
- Isolate customer/workload context and enforce workload-scoped authorization.
- Store immutable published versions and separate supersession records.
- Add tamper-evident audit history, provenance, actor, timestamp, review decision, and integrity
  digest.
- Ensure the Context API remains the only writer.

### A3. Governed lifecycle

Implement:

```text
Draft -> Validate -> Submit for review -> Review -> Approve -> Publish -> Supersede
```

- Separate author, reviewer, approver, and publisher permissions.
- Record explicit review decisions, comments, rejected fields, and required corrections.
- Require justification for material changes.
- Implement rollback by publishing a new version based on a prior version.
- Prohibit mutation of a published version.

### A4. Context Studio

- Provide structured editing rather than unrestricted YAML.
- Support environments, roles, dependencies, ownership, objectives, recovery expectations,
  monitoring intent, provenance, unknowns, and exceptions.
- Display field-level validation, source, confidence, review status, and unresolved decisions.
- Add exact version comparison and change review.
- Present declared, observed, inferred, and exception relationships distinctly.
- Require reloading of canonical server state before approval or publication.

### A5. Runtime and MCP integration

- Require runtime evaluations and incidents to identify an exact published manifest version.
- Use the manifest for role, criticality, dependency, blast-radius, ownership, escalation intent,
  and operator-guidance selection.
- Remove unique-active fallback from authoritative runtime execution.
- Allow Context MCP and Copilot to read published context, explain differences, identify missing
  declarations, and create bounded proposals only.

## Workstream B: intelligent monitoring and operational evidence

### B1. Azure Monitor Agent and VM Insights

- Validate AMA health and DCR association for every approved VM.
- Detect stale agents and missing ingestion.
- Collect telemetry through identity-isolated evidence jobs or an approved private Azure MCP tool.
  Raw Log Analytics access is not granted to the Context API, Context MCP, presentation, policy,
  or correlation identities.
- Use guest telemetry for:
  - disk-capacity and inode pressure;
  - disk latency and throughput anomalies;
  - memory exhaustion and swapping;
  - sustained CPU saturation;
  - network-interface errors or abnormal throughput;
  - process or service failure;
  - heartbeat loss;
  - relevant operating-system errors.
- Add Dependency Agent and VM Insights dependency mapping where supported and approved.
- Deploy the generic telemetry foundation independently of workload intent.
- Define context-aware thresholds and rates of change only from an exact published manifest
  version and an approved generated monitoring proposal.

### B2. Network Watcher

- Standardize on the approved VNet flow-log model and remove unnecessary duplicate collection.
- Validate Traffic Analytics ingestion, retention, lifecycle management, and private access.
- Create Connection Monitor tests for declared critical paths:
  - client to entry point;
  - web to application or middle tier;
  - application to database;
  - load balancer to backend;
  - approved management paths.
- Incorporate connection results, allow/deny flows, effective NSG rules, effective routes,
  next-hop results, load-balancer probe health, and bounded operator-triggered IP flow verification.
- Treat manifest-derived Connection Monitor configuration as reconciled desired state. Publication,
  supersession, and rollback produce reviewable, idempotent proposals; drafts never change live
  monitoring.

### B3. Monitoring storage migration

- Treat `athenahackathonflowwhtco` as an existing legacy source.
- Create a monitoring-owned replacement storage account in `rg-athena-demo-monitoring`.
- Transition active flow-log destinations without losing retained evidence.
- Keep the existing storage account until the approved retention period expires.
- Validate encryption, private access, lifecycle rules, and least-privilege readers.

### B4. Activity Logs and resource changes

- Do not export unrestricted subscription Activity Logs by default.
- Prefer a resource-group-bounded event route and bounded private Azure MCP queries for approved
  resources in `rg-athena-demo-workload`.
- If Azure platform constraints require subscription diagnostic export, treat it as a separate
  security and data-governance decision. Require explicit approval of workspace isolation,
  categories, retention, RBAC, redaction, cost, unrelated-resource exposure, and evidence-size
  limits before enabling it.
- Retain administrative, policy, security, service-health, resource-health, and alert events.
- Add an event-driven resource write/delete/action route that does not depend solely on Log
  Analytics ingestion latency.
- Query Azure Resource Graph change history for bounded before-and-after evidence where available.
- Normalize changed resource, operation, result, changed properties, actor, timestamp, correlation
  ID, deployment source, and policy context.

## Workstream C: health and change correlation

### C1. Unified incident timeline

Build a deterministic correlation engine that combines:

- health transitions;
- guest telemetry;
- platform and Resource Health events;
- Activity Log and resource-change events;
- Connection Monitor and flow-log evidence;
- load-balancer and backend health;
- declared and observed dependency paths;
- relevant context and exceptions.

### C2. Root-cause hypotheses

For each incident, produce bounded ranked hypotheses with:

- supporting evidence;
- contradicting evidence;
- missing confirmation evidence;
- affected dependency path;
- temporal distance;
- semantic relevance of changed properties;
- recurrence and recovery evidence.

A change is not causal merely because it occurred recently.

### C3. Confidence model

| Level | Meaning | Required behaviour |
|---|---|---|
| Confirmed | Direct evidence demonstrates the causal relationship | State cause, evidence, and approved manual options |
| High | Multiple independent signals strongly support one cause | Present leading cause and targeted confirmation |
| Medium | Timing and topology support a likely explanation | Present hypothesis and investigation checklist |
| Low | Plausible relationship with competing explanations | Present candidates and evidence required; avoid prescriptive resolution |
| Unknown | Insufficient or conflicting evidence | Report symptoms and request specific investigation |

The scoring model must be pure, deterministic, tested at threshold boundaries, and independent of
Azure or storage I/O.

### C4. Example NSG correlation

If an NSG rule changes, denied flows appear, Connection Monitor fails, and a dependent endpoint
becomes unhealthy, Athena may classify the NSG change as probable or confirmed depending on
evidence completeness. It must identify the changed rule, dependency path, evidence timeline,
contradictions, and operator checks without applying a rule change.

## Workstream D: operator investigation and resolution guidance

Each incident must include:

- affected workload role, environment, and business impact;
- observed symptoms and signed timeline;
- recent relevant changes;
- root-cause hypotheses and confidence;
- supporting, contradicting, and missing evidence;
- manual checks required for confirmation;
- safe resolution options from approved guidance;
- rollback considerations;
- recovery-validation steps;
- links to relevant Azure resources and approved runbooks.

Guidance must be evidence- and role-aware:

- disk pressure: inspect filesystem, inode use, growth, consumers, and application logs;
- connectivity loss: inspect Connection Monitor, flow logs, effective NSG rules, routes, DNS, and
  load-balancer health;
- load-balancer symptoms: distinguish VIP/data-path failure from backend degradation;
- guest failure: inspect heartbeat, process state, CPU, memory, disk, and system logs;
- configuration change: identify actor, changed properties, deployment source, and approved
  rollback authority.

Lower confidence must produce more investigation guidance and less prescriptive resolution text.

## Workstream E: presentation and notifications

- Show current health, lifecycle, correlated timeline, root-cause hypotheses, confidence,
  supporting evidence, operator confirmation, and suggested manual next action.
- Preserve browser-side fail-closed signature, digest, freshness, chronology, and trust-anchor
  verification.
- Use per-incident pointers plus a signed aggregate active-incident index so one resolution cannot
  hide another active incident.
- Keep Teams messages concise and link to the full incident.
- Preserve per-incident ordering, retry transient delivery failures, and expose accurate outbox or
  delivery status.

## Delivery waves and pull-request sequence

| Wave | Pull request | Parallelism | Exit gate |
|---|---|---|---|
| 0 | Harden and land WC-016 trust boundaries | Serialized | Deploy v2 identities/key/container/table with runtime disabled; exact legacy cleanup apply report has zero residuals; deployed key is exported and pinned; images are rebuilt; validation passes; cleanup is confirmed; only then activate v2 Jobs |
| 1 | Plan, ADRs, contracts, and schema | Serialized | Architecture challenge and contract tests pass |
| 2 | Durable context store and governance | Parallel with generic monitoring foundation after contracts freeze | API lifecycle and authorization tests pass |
| 2 | Generic monitoring foundation IaC | Parallel with context persistence; no manifest-derived thresholds or paths | Validate, what-if and least-privilege review pass |
| 3 | Context Studio workflows | Parallel with change ingestion | UX tests and accessibility checks pass |
| 3 | Activity/change ingestion | Parallel with Context Studio | Normalization, scope and provenance tests pass |
| 4 | Published-context monitoring reconciliation | Starts only after authoritative publication works | Exact-version proposals, supersession and rollback tests pass |
| 4 | Correlation and confidence engine | Serialized contracts, parallel implementation/tests | Deterministic golden scenarios pass |
| 4 | Operator guidance | Parallel after correlation contracts freeze | Confidence-sensitive guidance tests pass |
| 5 | Runtime, presentation and MCP integration | Serialized integration | Exact manifest pin and signed incident tests pass |
| 6 | Deployment and live scenarios | Serialized | Security, release and live acceptance pass |

Repository policy limits active builders to six to eight despite a higher available agent ceiling.
Builders use isolated issue branches or worktrees. Contract, root IaC, central routing, and shared
public response shapes remain serialized.

## Validation and release gates

Every pull request requires:

1. deterministic unit and negative tests;
2. schema and serialization tests for contract changes;
3. Ruff, MyPy, pytest, repository validation, and deterministic asset checks;
4. Context Studio and presentation npm tests, type checks, lint, build, and audit when affected;
5. Bicep build and static infrastructure assertions when affected;
6. independent code review;
7. independent security review for identity, networking, eventing, MCP, or data-boundary changes;
8. green GitHub Actions checks before merge.

Contract, persistence, policy, binding, and correlation changes must also rerun the original WC-005
golden proof: one immutable Azure evidence snapshot evaluated through one policy code path under
Production, Development, and Training profiles must continue to produce the expected distinct
outcomes.

Azure deployment additionally requires:

1. completed `azure-prepare` plan;
2. `azure-validate` status and evidence;
3. subscription deployment validation;
4. reviewed what-if with no unintended deletes, public exposure, or broad RBAC;
5. live effective-role verification;
6. bounded active and resolved scenario tests;
7. signed presentation and notification verification;
8. explicit cleanup or retention plan for superseded monitoring resources.

## Acceptance criteria

- Authorized users can create, validate, review, approve, publish, compare, and supersede protected
  context through the live system.
- Every production judgment uses an exact immutable published manifest version.
- Azure evidence is visibly distinct from declared and inferred context.
- AMA data detects guest-health and disk-pressure conditions.
- Critical connectivity paths are continuously tested.
- Activity and resource-change evidence is retained and queryable.
- Health changes can be correlated with relevant preceding configuration changes.
- Root-cause claims include confidence and cited supporting and contradicting evidence.
- Lower-confidence incidents provide confirmation steps rather than asserting a cause.
- The live page and Teams notifications present bounded operator guidance.
- Post-change evidence confirms recovery.
- No automatic remediation is introduced.
