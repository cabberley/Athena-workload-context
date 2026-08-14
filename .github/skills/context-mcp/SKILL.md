---
name: context-mcp
description: Creates safe Athena Context MCP tools and grounded Copilot behavior over published context and deterministic findings.
---

Expose narrow tools for listing workloads, resolving resources, retrieving context, comparing
environments, explaining findings, reading history, and proposing bounded patches. Use typed,
size-bounded schemas.

Do not expose direct storage queries, arbitrary code or KQL, publication, broad mutation, secrets,
raw logs, or remediation. Agent responses must cite deterministic findings and source references.
