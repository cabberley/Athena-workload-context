# Athena production cohort API

This application is the explicit production boundary for WC-023 cohort proposal and durable
decision routes. Context Studio must receive its URL as `cohortApiBaseUrl`; it never silently falls
back to the lifecycle Context API.

The repository-owned `apps/cohort-api/main.py` constructs:

- one `ContextService` over the intended durable workload store;
- one `CohortProposalService` using that same store plus a trusted snapshot repository and
  verifier;
- one `CohortDecisionService` using the same lifecycle service, proposal service, candidate
  repository, and durable store; and
- the production authentication adapter.

It uses the same Context API store, identity, authentication, and exact-workload role-grant
environment settings. `ATHENA_COHORT_PORTS_FACTORY` names only a narrow installed
`athena_context.<module>:<factory>` callable for the future WC-026/WC-028 trusted snapshot
repository, cryptographic verifier, and durable proposal/preview persistence adapters. It cannot
replace the lifecycle, authorization, Context store, or service graph.

The application validates all object identities before registering a cohort route. Missing,
partial, disconnected, in-memory, empty, or rejecting production ports fail startup rather than
exposing success-shaped routes.
