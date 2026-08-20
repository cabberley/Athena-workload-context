# Architecture

This document defines the binding architecture for Athena Workload Context. Changes to these
boundaries require an architecture decision record under `docs/adr/`.

## Product boundary

Athena is the workload intent, context, policy, and governance plane. A separately deployed private
Azure MCP server is the Azure evidence plane.

Athena owns:

- versioned workload manifests;
- environment profiles and inheritance;
- resource-to-role bindings and cohort approval;
- intended dependency semantics;
- contextual policy evaluation;
- compensating controls and risk acceptances;
- operational history and drift;
- workload-aware event correlation and capacity forecasting; and
- the Context API, Context MCP, web Context Studio, and shared agent core.

Azure MCP owns:

- Azure inventory and resource configuration evidence;
- observed dependencies and blast radius;
- Azure Monitor metrics and Log Analytics queries;
- Resource Health, Service Health, Activity Log, and Advisor evidence; and
- bounded investigation of Azure incidents and changes.

Athena must not recreate generic Azure discovery or monitoring clients unless an ADR documents an
unavoidable Azure MCP gap and a narrow adapter is approved.

## Trust boundaries

```text
Users
  |
  +-- Athena Context Studio / embedded Copilot
  |       |
  |       v
  |   Athena Context API and Context MCP
  |       |  managed identity; Athena-owned data only
  |       v
  |   Versioned Context Store
  |
  +-- Private authenticated Azure MCP
          |  separate managed identity
          v
      Read-only Azure evidence
```

The Athena context identity has no Reader role over customer workload resources. Azure evidence is
obtained through the private Azure MCP identity, which is independently scoped, audited, and
revocable. A separately governed workload controller may receive container-scoped receipt-writer
RBAC only so it can create the exact `athena.demoFaultRun.v1` phase-input Blobs before Athena
phase Jobs read them; the create-only exact-name contract is enforced in application code because
Azure RBAC cannot be narrowed to a Blob prefix.

## Logical components

| Component | Responsibility |
|---|---|
| Context API | Single writer, authorization, orchestration, manifest lifecycle |
| Manifest engine | Schema validation, canonicalization, versioning, integrity verification |
| Context store | Published manifests, drafts, bindings, findings, approvals, history |
| Binding engine | Evidence-backed cohort proposals and dynamic selectors |
| Policy engine | Deterministic evaluation of observed state against declared intent |
| Evidence client | Typed, bounded client for the private Azure MCP |
| Operational artifact store | Private, versioned, create-only persistence and exact-version verified retrieval for bounded signed evaluation artifacts |
| Workload controller | Workload-owned `status`/`inject`/`reset` boundary and strict create-only publication of exact run-scoped `athena.demoFaultRun.v1` receipt Blobs |
| Operational phase jobs | Phase-fixed non-mutating Container Apps Jobs that compose reviewed WC-013 plans, exact Blob references, and governed handoff emission |
| Context MCP | Agent-safe access to published context and proposed changes |
| Agent core | Grounded explanations using policy results and cited evidence |
| Context Studio | Workload configuration, cohort approval, topology, findings, Copilot |
| Event processor | Normalizes Azure resource, health, monitoring, and change events |
| Forecast worker | Evaluates trends and time-to-limit against workload objectives |

## Architectural invariants

1. Customer workload data remains inside the customer's Azure boundary.
2. Managed Identity is used for service-to-service authentication.
3. The Context MCP does not receive direct workload Azure RBAC.
4. The private Azure MCP is read-only and exposes an exact reviewed tool allowlist.
5. Unknown context, ambiguous bindings, stale evidence, or low confidence fail closed.
6. Athena never automatically remediates customer infrastructure.
7. Observed relationships never overwrite declared relationships.
8. Agent-generated text never becomes an authoritative manifest without human approval.
9. Every contextual finding cites both Azure evidence and the applicable manifest clause.
10. Pure binding, policy, and forecasting logic remains separate from Azure and storage I/O.
11. Operational artifacts use version-pinned immutable Blob references, create-only conditional writes, and exact-version hash-verifying reads.
12. Operational phase execution uses reviewed bundle paths, phase-fixed Jobs, bounded exact-reference inputs, and governed handoff files.
13. The workload-owned controller, not Athena phase Jobs, creates exact run-scoped receipt Blobs with create-only semantics enforced in application code; Azure RBAC stays container-scoped because Blob roles cannot be narrowed to a prefix.

## Relationship classes

Athena maintains distinct relationship sets:

- **Declared:** approved workload intent.
- **Observed:** current Azure MCP evidence.
- **Inferred:** Athena interpretation with confidence and provenance.
- **Exception:** approved deviation with owner, rationale, and expiry.

Conflicts are surfaced explicitly. They are never silently reconciled.

## Change flow

```text
Draft -> Validate -> Review -> Approve -> Publish -> Supersede
```

MCP and Copilot tools may create proposals. Only the authorized Context API publication workflow
can create an authoritative manifest version.
