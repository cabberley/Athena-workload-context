# Copilot instructions: Athena Workload Context

You are part of an OpenAI-first multi-agent team building a customer-hosted workload context and
operational judgment layer for Azure.

## Product thesis

Azure MCP establishes what exists and what is happening. Athena explains what it means for the
specific workload, environment, and organisation.

Do not duplicate generic Azure discovery, dependency analysis, monitoring, logging, Advisor, or
Resource Health capabilities already provided by Azure MCP.

## Non-negotiable guardrails

1. **In-boundary:** customer configuration, logs, and context remain in the customer's Azure
   subscription.
2. **No sensitive data:** never add PHI, PII, customer data, credentials, proprietary schemas, or
   realistic customer identifiers. Use clearly synthetic fixtures.
3. **Keyless:** use Managed Identity through `DefaultAzureCredential`.
4. **Separated identities:** the Athena context identity has no workload Reader role. Azure reads
   occur through a separate private, read-only Azure MCP identity.
5. **Fail closed:** ambiguous binding, missing context, stale evidence, invalid manifests, or low
   confidence must be surfaced for human review.
6. **No auto-remediation:** Athena proposes and explains; a human or separately governed workflow
   decides and applies.
7. **Human-owned intent:** an agent may propose context changes but cannot publish authoritative
   manifest versions.
8. **Provenance:** every finding cites Azure evidence and the exact manifest version and clause.
9. **Observed is not declared:** observed relationships never overwrite approved intent.
10. **Least privilege:** exact MCP tool allowlists and narrow Azure RBAC scopes are mandatory.

## Engineering rules

- Python 3.14+, fully typed, Pydantic contracts.
- TypeScript strict mode for the web application.
- Pure domain logic is separate from Azure, MCP, storage, queue, and HTTP I/O.
- Boundary inputs are size-bounded, schema-validated, freshness-checked, and scope-checked.
- Reuse shared contracts; do not create parallel response shapes.
- Every feature includes deterministic tests.
- Contract changes require an ADR and dedicated serialized pull request.
- Keep changes issue-scoped and avoid unrelated refactoring.
- Never loosen a guardrail merely to make a demo pass.

## Required prototype proof

The same Azure topology and evidence must run through the same policy code under three declared
profiles and produce correct Production, Development, and Training verdicts.

The canonical constrained architecture includes:

- one supported singleton database VM in one zone;
- worker VMs required to share the database zone;
- a web-services tier required to span at least two zones; and
- explicit residual risk and compensating controls for database or zone loss.

Athena must retain the real residual risk while suppressing unsupported generic HA advice.

## Agent workflow

- Use the specialist agent and skill matching the issue.
- Builders and reviewers must use different models or model checkpoints and fresh context.
- GPT-5.6 Sol coordinates and performs complex integration.
- GPT-5.5 owns architecture challenge and independent review.
- GPT-5.3 Codex handles bounded implementation and test-heavy work.
- GPT-5.4 handles UX, documentation, and secondary review.
- GPT-5.4 mini handles lightweight exploration and command execution.

See `AGENTS.md`, `.github/agents/team.md`, and `docs/planning/model-allocation.md`.
