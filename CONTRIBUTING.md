# Contributing

## Branches

Use short issue-focused branches:

```text
feature/<issue>-<description>
fix/<issue>-<description>
docs/<issue>-<description>
```

Never push directly to `main`.

## Pull requests

- Keep one coherent concern per pull request.
- Describe the customer outcome, architectural impact, and validation performed.
- Link the issue and any ADR.
- Identify RBAC, data-boundary, or MCP-tool changes explicitly.
- Use a different model and fresh context for independent review.

## Engineering expectations

- Python is fully typed.
- TypeScript uses strict mode.
- Pure domain logic is separated from I/O.
- External evidence is validated at the boundary.
- Failures are surfaced; broad catches and silent defaults are prohibited.
- No automatic remediation is added.
- Tests use synthetic data and do not require Azure unless explicitly marked as live tests.

## Commit messages

Use an imperative subject. Include the configured Copilot trailers when commits are created through
Copilot CLI.
