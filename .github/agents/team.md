# Athena Copilot agent team

The coordinator assigns one primary owner to each issue. Agents stay within their ownership lane
unless the coordinator explicitly approves a cross-cutting change.

| Agent | Model | Primary ownership |
|---|---|---|
| Coordinator | GPT-5.6 Sol | Routing, sequencing, integration |
| Architect | GPT-5.5 | Architecture, ADRs, cross-cutting contracts |
| Contract and Manifest Engineer | GPT-5.6 Sol | Contracts, schemas, manifest engine |
| Backend Context API Engineer | GPT-5.6 Sol | Context API and persistence adapters |
| Azure Platform and MCP Engineer | GPT-5.6 Sol | Azure MCP evidence client and infrastructure |
| Cohort Binding Engineer | GPT-5.6 Sol | Resource clustering and role selectors |
| Contextual Policy Engineer | GPT-5.3 Codex | Pure contextual policy evaluation |
| Eventing and Forecast Engineer | GPT-5.6 Sol | Event normalization and capacity forecasting |
| UX Engineer | GPT-5.4 | Context Studio and user documentation |
| Agent and MCP Engineer | GPT-5.6 Sol | Context MCP and grounded agent core |
| Test Engineer | GPT-5.3 Codex | Test architecture and regression coverage |
| Security Reviewer | GPT-5.5 | Independent read-only security review |
| Release Reviewer | GPT-5.5 | Independent release readiness review |

## Exclusive ownership

| Path | Primary owner |
|---|---|
| `docs/adr/**`, `ARCHITECTURE.md` | Architect |
| `src/athena_context/contracts/**`, `src/athena_context/manifest/**`, `content/**` | Contract and Manifest |
| `apps/context-api/**` | Backend Context API |
| `src/athena_context/evidence/**`, `infra/**` | Azure Platform and MCP |
| `src/athena_context/binding/**`, `workers/onboarding/**` | Cohort Binding |
| `src/athena_context/policy/**` | Contextual Policy |
| `apps/event-processor/**`, `workers/forecasting/**` | Eventing and Forecast |
| `apps/web/**` | UX |
| `apps/context-mcp/**`, `src/athena_context/agent/**` | Agent and MCP |
| `tests/**` | Test Engineer; feature owners may add focused tests |

Root dependency files, public contracts, root Bicep orchestration, and application routing are
serialized areas. The coordinator names one temporary owner before changes begin.

## Required review pairings

- Architecture or contract change: Architect plus Contract and Manifest reviewer.
- Azure MCP, identity, networking, or RBAC: Azure Platform plus Security Reviewer.
- MCP tool or agent change: Agent and MCP plus Security Reviewer.
- Policy or binding change: owning engineer plus Test Engineer.
- Release: Release Reviewer plus Security Reviewer.

No builder is the sole reviewer of its own change.
