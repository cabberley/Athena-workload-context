---
name: release-review
description: Runs the Athena pre-release gate across scope, contracts, tests, security, deployment, documentation, and rollback.
---

Verify:

1. The release maps to the approved milestone.
2. Required tests, lint, type checks, schema validation, and security checks pass.
3. Contract and manifest compatibility is documented.
4. Azure MCP remains private, read-only, pinned, and narrowly authorized.
5. No sensitive data or broad permissions were introduced.
6. Deployment and rollback are repeatable.
7. Documentation and version metadata match behavior.
8. Independent review findings are resolved.

Block release on unresolved high-severity findings or unproven fail-closed behavior. Do not edit.
