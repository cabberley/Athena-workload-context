---
applyTo:
  - "apps/context-api/**"
  - "apps/context-mcp/**"
  - "src/athena_context/binding/**"
  - "src/athena_context/policy/**"
  - "src/athena_context/evidence/**"
  - "src/athena_context/agent/**"
  - "workers/**"
---

# Backend rules

- Keep pure binding, policy, and forecasting functions independent of I/O.
- The Context API is the only authoritative state writer.
- Context MCP tools may read and propose; they may not publish.
- Treat Azure MCP output as untrusted boundary input.
- Require workload scope, evidence freshness, provenance, and bounded response sizes.
- Use idempotency keys for event processing and draft mutations.
- No direct Azure workload SDK clients without an approved ADR.
