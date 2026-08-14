# Initial Copilot build plan

## Objective

Deliver a working Azure-integrated Athena prototype in ten working days, with five contingency
days. Six to eight Copilot agents may build in parallel after contracts stabilize.

The non-negotiable proof is:

> One immutable Azure evidence snapshot is evaluated through one policy code path under Production,
> Development, and Training profiles and produces different, correct contextual outcomes.

The canonical topology contains:

- one database VM in one availability zone;
- worker VMs required to occupy the database zone;
- web-service VMs distributed across three zones; and
- an approved database singleton constraint with explicit residual risk and compensating controls.

## Scope

### Core prototype

- Workload manifest schema and profile inheritance.
- Canonical evidence snapshot and provenance.
- Deterministic contextual policy engine.
- Cohort selectors tested against 1,000 synthetic resource records.
- Context API draft and publication workflow.
- Private read-only Azure MCP and typed evidence client.
- Context Studio manifest, cohort, and comparison experience.
- Read/propose-only Context MCP.
- One Azure event-driven reassessment path.
- One deterministic capacity forecast.
- Embedded grounded Copilot explanation.

### Deferred

- Microsoft 365 Copilot agent.
- Complete Azure event-source coverage.
- Multi-subscription and Azure Lighthouse delivery.
- Automatic Azure tag or Service Group write-back.
- Multi-region Athena deployment and production DR.
- Automatic remediation.
- General-purpose policy language.
- Vector search unless grounded tool context proves insufficient.

## Wave 0: contract and repository lock

Run this wave serially.

| ID | Issue | Owner | Model | Depends on | Acceptance |
|---|---|---|---|---|---|
| WC-001 | Define the canonical context and evidence contracts | Architect + Contract Engineer | GPT-5.5 design, GPT-5.6 Sol architecture challenge, then MAI-Code-1.1-Flash implementation | Bootstrap | GPT-5.6 Sol approves or returns the architecture design before implementation begins. Pydantic contracts and JSON Schema define manifests, profiles, roles, relationships, evidence snapshots, verdicts, controls, and risk acceptance. ADR records declared-versus-inferred precedence. |
| WC-002 | Create the canonical constrained-topology fixture | Contract Engineer | MAI-Code-1.1-Flash | WC-001 | One immutable synthetic evidence snapshot represents the database, worker, web, load-balancer, zones, and dependencies. Canonical hashing is deterministic. |

### Contract vocabulary

Verdicts must distinguish:

- `pass`
- `violation`
- `expectedConstraint`
- `acceptedResidualRisk`
- `observation`
- `unknown`
- `conflicting`

Architecture constraints, risk acceptance, and compensating-control health are separate contracts.

## Wave 1: core differentiation proof

Begin only after WC-001 contracts freeze and WC-002 provides the canonical evidence fixture.
WC-003 and WC-004 can then run in parallel.

| ID | Issue | Owner | Model | Depends on | Acceptance |
|---|---|---|---|---|---|
| WC-003 | Implement environment profile inheritance and manifest validation | Contract Engineer | MAI-Code-1.1-Flash | WC-001 | Production, Development, and Training profiles validate; circular inheritance and unresolved references fail closed. |
| WC-004 | Implement deterministic contextual policy evaluation | Policy Engineer | MAI-Code-1.1-Flash | WC-001, WC-002 | Pure policy functions evaluate singleton DB, worker-zone, and web-zone controls with evidence and clause references. |
| WC-005 | Add the three-environment golden proof | Test Engineer | MAI-Code-1.1-Flash | WC-003, WC-004 | The same snapshot digest yields the expected matrix through one code path. Negative tests remove constraints, move workers, collapse zones, expire risk acceptance, and omit evidence. |
| WC-006 | Add a local reference-demo command | Backend Engineer | MAI-Code-1.1-Flash | WC-005 | One command emits deterministic JSON and human-readable results and exits nonzero on oracle failure. |

### Day 3 gate

Do not proceed to expensive Azure integration if WC-005 and WC-006 are not green.

## Wave 2: parallel platform foundations

These issues begin only after the Day 3 proof gate: WC-005 and WC-006 are green. They then run
concurrently against frozen contracts.

| ID | Issue | Owner | Model | Depends on | Acceptance |
|---|---|---|---|---|---|
| WC-007 | Implement Context API and versioned manifest workflow | Backend Engineer | MAI-Code-1.1-Flash | WC-006 | Draft, validate, approve, publish, supersede, compare, and audit work through typed ports. API is the only writer. |
| WC-008 | Deploy a private read-only Azure MCP foundation | Azure Platform Engineer | MAI-Code-1.1-Flash | WC-006 | Private authenticated ingress, pinned version, hosting identity, read-only mode, exact tool allowlist, and narrow RBAC are proven. |
| WC-009 | Implement the typed Azure MCP evidence client | Azure Platform Engineer | MAI-Code-1.1-Flash | WC-006 | Scope, schema, tool, freshness, count, size, and provenance validation fail closed; fixture and malformed-response tests pass. |
| WC-010 | Implement evidence-backed cohort proposals | Cohort Engineer | MAI-Code-1.1-Flash | WC-006 | Multi-signal cohort proposals include confidence, evidence, dissent, and dynamic selectors. A 1,000-resource synthetic test avoids per-VM approval. |
| WC-011 | Build the Context Studio shell and manifest editor | UX Engineer | MAI-Code-1.1-Flash | WC-006 | Accessible authenticated shell, workload catalogue, environment comparison, structured manifest editor, and visible draft state. |

## Wave 3: vertical product slices

| ID | Issue | Owner | Model | Depends on | Acceptance |
|---|---|---|---|---|---|
| WC-012 | Add cohort review and approval to Context Studio | UX + Cohort Engineers | MAI-Code-1.1-Flash | WC-007, WC-010, WC-011 | Users approve, split, merge, or reject cohorts and preview generated selectors without editing individual resources. |
| WC-013 | Evaluate a live demo workload through Azure MCP | Backend + Azure Platform | MAI-Code-1.1-Flash | WC-007, WC-008, WC-009 | Live evidence becomes one immutable snapshot and is evaluated without direct Azure access by the context identity. |
| WC-014 | Expose the read/propose-only Athena Context MCP | Agent and MCP Engineer | MAI-Code-1.1-Flash | WC-007 | Tools resolve workload, get context, compare environments, explain findings, read history, and propose bounded patches. No publish or remediation tools exist. |
| WC-015 | Add intended-versus-observed topology and findings views | UX Engineer | MAI-Code-1.1-Flash | WC-012, WC-013 | Declared, observed, inferred, and exception relationships are visually distinct and every finding shows evidence and manifest version. |

## Wave 4: operational awareness

| ID | Issue | Owner | Model | Depends on | Acceptance |
|---|---|---|---|---|---|
| WC-016 | Add one event-driven reassessment path | Eventing Engineer | MAI-Code-1.1-Flash | WC-007, WC-009, WC-013 | One Azure Resource Notification or Monitor alert is normalized, deduplicated, placed on Service Bus, and triggers scoped reassessment. |
| WC-017 | Add one workload-aware capacity forecast | Eventing Engineer | MAI-Code-1.1-Flash | WC-007, WC-009 | Aggregated metric history produces time-to-threshold, confidence, horizon stage, and insufficient-data outcomes. |
| WC-018 | Add grounded embedded Copilot | Agent and MCP + UX | MAI-Code-1.1-Flash | WC-014, WC-015 | Copilot explains why environment verdicts differ using cited deterministic findings and refuses unsupported questions. |

## Wave 5: integration and release gate

Run serially.

| ID | Issue | Owner | Model | Depends on | Acceptance |
|---|---|---|---|---|---|
| WC-019 | Complete private Azure deployment and observability | Azure Platform Engineer | MAI-Code-1.1-Flash | WC-013 through WC-018 | Managed identities, private networking, health probes, traces, queues, and least-privilege role matrix are validated. |
| WC-020 | Run adversarial, security, scale, and end-to-end gates | Coordinator + Reviewers | GPT-5.6 Sol review and validation; MAI-Code-1.1-Flash fixes | WC-019 | No unresolved high-severity issues; 1,000-resource cohort test, three-profile oracle, event path, forecast, MCP, web, and Copilot all pass. |

## Day gates

| Day | Required gate |
|---|---|
| 1 | Contracts, verdict vocabulary, and file ownership frozen |
| 2 | Canonical evidence snapshot and three profiles validate |
| 3 | Core three-environment proof passes through one code path |
| 4 | Context API, web shell, Azure MCP, and cohort work progressing in parallel |
| 5 | Local Context API vertical slice and cohort proposals work |
| 6 | Private Azure MCP and typed evidence validation work |
| 7 | Context Studio comparison and cohort approval work |
| 8 | Event reassessment, forecast, and Context MCP work |
| 9 | Embedded Copilot and live Azure vertical slice work |
| 10 | Integrated release candidate passes |
| 11-15 | Contingency for Azure identity, DNS, MCP, eventing, and integration defects |

## Review model

Every builder PR receives:

1. automated tests and static checks;
2. independent GPT-5.6 Sol code review in fresh context;
3. GPT-5.6 Sol security review for identity, MCP, eventing, or data-boundary changes; and
4. independent GPT-5.6 Sol integration validation using recorded test, CI, deployment, and demo
   evidence.

No model approves its own implementation.
