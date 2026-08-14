---
name: contextual-policy
description: Implements deterministic policy evaluation that interprets Azure evidence using workload roles, environment profiles, constraints, controls, and risk acceptance.
---

Keep evaluation pure. Return explicit outcomes with evidence and manifest clause references. The
canonical oracle uses one topology fixture under Production, Development, and Training.

For the singleton database scenario:

- retain the workload-wide SPOF;
- recognize exact-one and single-zone as an approved constraint;
- require workers to share the database zone;
- require web services to span the declared minimum zones;
- reject unsupported generic HA remediation; and
- independently validate compensating controls and acceptance expiry.
