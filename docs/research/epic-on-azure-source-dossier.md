# Epic on Azure workload-context source dossier (sanitized)

> Public-safe research artifact for GitHub issue #4. This file intentionally contains only
> sanitized source categories and opaque local reference labels. Detailed provenance, including
> source names, locations, timing details, review history, and access-controlled notes, remains in an
> approved private evidence system and is not committed to this public repository.

## Sanitization policy

This dossier must not contain:

- internal URLs, paths, document identifiers, collaboration artifact identifiers, or source-system GUIDs;
- unapproved internal document titles, private source-history metadata, or planning names;
- restricted recovery terminology or procedures;
- copied internal source text, diagrams, tables, or excerpts;
- customer names, customer-specific designs, resource identifiers, sizing values, operational
  thresholds, credentials, PHI/PII, proprietary schemas, ports, commands, or sensitive operational
  values.

The labels below are local, opaque references for this draft only. They are not stable source IDs
and are not intended to let a reader reconstruct the private source set.

## Research method summary

- Private evidence was reviewed through approved search/synthesis and rendered-document tooling.
- Relevant evidence was reduced to abstract workload-context concepts before being committed.
- All detailed source provenance remains outside the repository for authorized reviewers.
- Unsupported or source-specific claims are marked as `TODO(human)` in the draft manifest at `docs/research/drafts/epic-on-azure.draft.yaml`.

## Sanitized source categories

| Local label | Sanitized category | Authority for this draft | Public-safe contribution | Limits and evidence gaps |
|---|---|---|---|---|
| SRC-A | Private architecture reference family | High, pending owner selection of the canonical baseline | Supports abstract environment, tier, placement, and dependency concepts | Exact source titles, versions, diagrams, and implementation details are not committed; owners must choose the canonical baseline before schema conversion |
| SRC-B | Private workload-definition materials | High for manifest-shape hypotheses | Supports generic workload identity, environment profile, role, relationship, and metadata concepts | Not a WC-001 schema; exact role vocabulary and precedence rules require human approval |
| SRC-C | Private network and connectivity architecture materials | High for abstract connectivity boundaries | Supports generic segmentation, application-delivery, private/public boundary, and connectivity-dependency categories | Exact flows, endpoints, certificates, ports, routing, and firewall details are prohibited |
| SRC-D | Private operations and readiness materials | Medium-high for day-2 semantics | Supports generic incident, monitoring, change, backup, drill, support, and readiness concepts | Escalation paths, account status, operational metrics, and customer-specific procedures are prohibited |
| SRC-E | Private recovery-design materials | High for recognizing a distinct recovery-pattern category | Supports only abstract recovery-readiness, isolation, protected-copy, and controlled-activation concepts | Restricted recovery terminology, topology, activation behavior, sizing, and procedures are not committed and remain TODO(human) |
| SRC-F | Private collaboration and decision records | Medium for context and open questions | Supports evidence gaps around non-production parity, data classification, and review ownership | Conversational records are not normative guidance; decisions must be captured in approved durable sources |
| SRC-G | Public Azure architecture and workload-modeling guidance | High for generic Azure taxonomy only | Supports generic workload goals, reliability/recovery language, workload modeling, monitoring semantics, and fail-closed governance concepts | Public Azure guidance does not establish Epic-specific requirements |
| SRC-H | Local Athena repository guardrails | Binding for this repository only | Supports in-boundary, non-runtime, provenance, fail-closed, declared-versus-observed, and human-approval constraints | Does not provide private workload architecture authority |

## Public-safe findings retained

- A reusable workload-context draft may describe workload identity, environment intent, abstract
  roles, relationship classes, objectives, evidence requirements, and operating semantics.
- Environment names must not prove data class. Production-like and recovery environments should be
  treated conservatively; non-production environments require explicit data classification.
- Production-like profiles require declared objective, criticality, placement, dependency inventory, capacity, thresholds, and escalation values; no production criticality, region, or zone default is encoded.
- Recovery profiles may carry alternate-environment and readiness questions, but no single universal scale, activation mode, placement posture, or parity model is safe to assert for every deployment.
- Development, Test, and Training profiles have declaration-required criticality, dependency scope, data class, monitoring expectations, and support intent; no lower-criticality or partial-dependency default is encoded.
- Tags or naming conventions may be discovery hints, but approved context must not depend on them as
  the only source of truth.
- Monitoring should capture signal meaning and evidence requirements, not raw queries, thresholds,
  workspace identifiers, endpoints, or alert-routing values.

## Open evidence gaps for humans

1. Select the private canonical architecture baseline before converting this draft to WC-001.
2. Approve the exact public-safe role and environment vocabulary.
3. Define precedence between declared manifest, tags, and observed discovery evidence.
4. Decide whether specialized recovery context belongs in this template or in a separate template.
5. Provide customer-specific objectives, capacity, recovery, ownership, and escalation values only
   in protected customer manifests.
6. Keep detailed provenance in the approved private evidence system; do not commit it to this repo.
