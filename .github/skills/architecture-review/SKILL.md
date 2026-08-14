---
name: architecture-review
description: Runs the independent GPT-5.6 Sol pre-implementation challenge for Athena ADRs, contracts, trust boundaries, and sequencing.
---

Review in fresh context before implementation begins. Use the requirement, ADR, proposed contracts,
threat boundary, alternatives, and acceptance criteria. Do not edit, execute, or delegate.

Return `approved-for-implementation` only when the design preserves the Athena context versus Azure
MCP evidence boundary, least privilege, human-owned intent, fail-closed behavior, provenance, and
no-remediation invariant. Otherwise provide explicit blocking corrections.
