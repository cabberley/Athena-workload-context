# Athena Workload Context

Athena is a customer-hosted workload context and operational judgment layer for Azure.

> Azure MCP establishes what exists and what is happening. Athena explains what it means for
> this workload, environment, and organisation.

Athena does not replace Azure MCP discovery, monitoring, dependency analysis, or Azure platform
recommendations. It adds declared workload intent:

- workload and environment identity;
- resource roles and dynamic cohort bindings;
- required, optional, failover, and prohibited relationships;
- production, recovery, development, test, and training profiles;
- SLO, RTO, RPO, criticality, and service hours;
- architecture constraints, compensating controls, and accepted residual risks;
- workload-specific telemetry meaning, ownership, and runbooks; and
- deterministic, evidence-cited contextual findings.

## Prototype objective

The first prototype must prove that the same Azure evidence can produce different, correct
conclusions for Production, Development, and Training. It must also demonstrate a constrained
singleton database architecture where Athena retains the true residual risk without recommending
unsupported high availability.

See:

- [Architecture](ARCHITECTURE.md)
- [Agent operating model](AGENTS.md)
- [Initial build plan](docs/planning/initial-build-plan.md)
- [Copilot model allocation](docs/planning/model-allocation.md)
- [WC-013 live acceptance](docs/operations/wc013-live-acceptance.md)
- [Operational phase runner](docs/operations/operational-phase-runner.md)
- [Operational demo operator](docs/operations/operational-demo-operator.md)

## Local reference proof

Run the packaged three-profile oracle locally, with no Azure connection:

```text
athena-context golden-proof --format text
athena-context golden-proof --format json
```

The command returns zero only when the golden runner reports an exact oracle match.
The approved proof requires two web zones in Production and one in Development and Training.

## Repository status

This repository is locally initialized and intentionally has no remote. Add the GitHub remote only
after the target repository name is confirmed.
