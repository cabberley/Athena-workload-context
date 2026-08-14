# Issue routing

## Route by outcome

| Issue intent | Primary agent | Required skill |
|---|---|---|
| Change product boundary or contract | Architect | `architecture-adr` |
| Add or change manifest fields | Contract and Manifest | `manifest-author` |
| Add Context API behavior | Backend Context API | `context-api` |
| Configure private Azure MCP or Azure RBAC | Azure Platform and MCP | `azure-mcp-integration` |
| Infer resource roles or cohorts | Cohort Binding | `cohort-binding` |
| Evaluate workload-specific correctness | Contextual Policy | `contextual-policy` |
| Process events or forecast limits | Eventing and Forecast | `event-forecast` |
| Change the web experience | UX | `context-studio` |
| Add Context MCP tools or Copilot behavior | Agent and MCP | `context-mcp` |
| Expand or repair tests | Test Engineer | `test-hardening` |
| Review security boundaries | Security Reviewer | `security-review` |
| Prepare a release | Release Reviewer | `release-review` |

## Parallelism

Safe after contracts stabilize:

- Context API persistence and web shell.
- Private Azure MCP infrastructure and manifest engine.
- Cohort binding and policy engine against frozen contracts.
- Event processor and Context MCP against frozen event/tool contracts.

Serialize:

- Public contracts and schemas.
- Root dependency manifests.
- Root Bicep orchestration.
- Cross-application authentication.
- Final integration and release.
