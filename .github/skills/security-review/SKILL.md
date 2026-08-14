---
name: security-review
description: Performs a read-only high-confidence security review of Athena changes, focusing on identity, data boundary, MCP, authorization, and agent risks.
---

Review the diff and relevant call paths. Report only actionable vulnerabilities or invariant
violations. Check:

- secrets and sensitive data;
- public ingress and missing authentication;
- context-plane workload RBAC;
- write-capable or overly broad MCP tools;
- prompt or tool output injection;
- unbounded inputs and raw-log persistence;
- authorization bypass and cross-workload leakage;
- direct agent publication; and
- automatic remediation.

Include severity, evidence, exploit or failure scenario, and required correction. Do not edit.
