# ADR 0001: Athena is the workload context layer over Azure MCP

- **Status:** Accepted
- **Date:** 2026-08-14

## Context

Azure MCP can discover Azure resources, identify relationships and blast radius, inspect monitoring
data, query logs, and produce Azure platform recommendations. Reimplementing those capabilities
would not create sufficient product differentiation.

Customers still need declared workload meaning: environment purpose, business criticality, roles,
intended relationships, supported constraints, objectives, compensating controls, risk acceptance,
ownership, and history.

## Decision

Athena will be a customer-hosted workload context and operational judgment layer. A separately
deployed private read-only Azure MCP will be the Azure evidence plane.

Athena will:

- manage approved workload manifests;
- bind Azure resources to workload roles through reviewed cohort selectors;
- compare observed evidence with declared intent;
- produce deterministic contextual findings;
- preserve residual risk and compensating controls;
- process Azure events and forecast workload limits; and
- expose context through the Context API, Context MCP, Context Studio, and grounded Copilot.

Athena will not recreate generic Azure inventory, topology, monitoring, logging, Advisor, or
Resource Health capabilities.

## Consequences

- The Athena context identity does not need workload Reader access.
- The Azure MCP identity can be independently scoped and revoked.
- Azure MCP availability becomes a dependency for live evidence collection.
- Athena requires a typed evidence-client abstraction to isolate MCP tool evolution.
- Context quality and governance become the principal source of product value.

## Alternatives considered

### Continue the existing workload intelligence platform

Rejected because it duplicates capabilities now available through Azure MCP and weakens the product
story.

### Build a single wrapper around Azure MCP

Rejected because it would add presentation without authoritative workload intent or durable
governance.

### Allow Athena services to query Azure directly

Rejected as the default because it duplicates clients and erodes the context/evidence trust
boundary. Narrow exceptions require a separate ADR.
