---
name: test-hardening
description: Designs and implements Athena unit, contract, integration, scale, security, and live validation.
---

Build the smallest deterministic test first. Cover happy path, boundary values, ambiguity,
conflicts, stale evidence, authorization denial, malformed MCP output, event replay, and rollback.
Keep default tests Azure-free. Use explicit markers for live tests.

The keystone test evaluates the same evidence and topology under Production, Development, and
Training through one code path and asserts different contextual outcomes.
