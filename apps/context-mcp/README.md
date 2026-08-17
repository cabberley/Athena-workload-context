# Athena Context MCP

This service exposes exactly seven typed, bounded tools:

`list_workloads`, `resolve_resource`, `get_context`, `compare_environments`,
`explain_finding`, `read_history`, and `propose_manifest_patch`.

The server is transport-neutral because this repository has no existing pinned official MCP
runtime. `ContextMcpServer.serve` accepts an `McpTransportPort`; a deployment transport must verify
authentication and supply `ToolCallContext` out of band. Identity and workload scope are never tool
arguments.

Reads use the WC-007 `ContextApiPort` and an authorization-aware
`AuthoritativeFindingsPort`. The findings result is re-bound to the published manifest, resolved
profile, clause, and exact evidence graph before any projection or deterministic explanation is
returned.

Patch proposals support only RFC 6902-like `replace` operations on:

- `/workload/displayName`
- `/profiles/{profileId}/riskAcceptances/{index}/residualRiskStatement`

The server applies operation count, value, request, and response bounds, creates only a WC-007
`draft` through `ContextApiPort.create_draft`, and exposes no validation, approval, publication,
supersession, remediation, arbitrary query, KQL/code, storage, secret, or raw-log capability.

Run its focused gates from the repository root:

```powershell
python -m pytest apps/context-mcp/tests
python -m ruff check src/athena_context/agent apps/context-mcp
python -m mypy src/athena_context/agent
```
