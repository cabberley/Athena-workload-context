# ADR 0007: Add a private create-only operational artifact plane

- **Status:** Proposed
- **Date:** 2026-08-20

## Context

The one-shot acceptance environment already has a private, keyless StorageV2 account for durable
Azure Table replay reservations. Later operational phases need a durable place for bounded result
and snapshot artifacts, but the prerequisite must not add a phase runner, presentation projection,
or orchestration path.

The storage capability must remain inside the customer boundary, use the existing acceptance
managed identity, reject logical-name overwrites, retain independent hashes with the payload, and
expose no list or delete capability through the application port.

## Decision

Reuse the replay StorageV2 account. Add a Blob private endpoint and the
`privatelink.blob.core.windows.net` private DNS zone linked to the existing VNet. Shared-key access,
public network access, and anonymous Blob access remain disabled.

Create exactly one `operational-artifacts` container. Enable account Blob versioning, enable
version-level immutability support when the container is created, and apply an explicit unlocked
time-based retention policy supplied by the reviewed Bicep parameter file. Protected append writes
remain disabled. The existing AVM soft-delete defaults on the replay account are preserved rather
than changed as part of this prerequisite. The policy is intentionally not locked by automation
because locking is an irreversible human governance decision.

Grant the acceptance identity the requested `Storage Blob Data Contributor` role at the container
resource ID only. The built-in role is broader than the application capability because it includes
read, list, and delete data actions. The compensating controls are the exact container scope, Blob
WORM policy, disabled shared key, and a Python port that exposes only `create`.

The typed adapter accepts immutable JSON bytes only, with a one-MiB hard maximum, a bounded
lowercase relative Blob path, and fixed SHA-256 metadata fields. It recomputes the payload hash
before I/O. It authenticates through the repository's managed-identity-only
`DefaultAzureCredential` configuration and performs one block-blob upload with
`MatchConditions.IfMissing`, which emits `If-None-Match: *`. A duplicate logical name raises a
typed error; no overwrite fallback is attempted.

Successful writes return the Blob version ID, ETag, last-modified time, size, and payload hash.
Callers must persist and later verify the version-pinned reference. An unversioned Blob name is not
an immutable reference because version-level WORM can preserve a new version if a broader client
bypasses the create-only port.

## Consequences

- No second Storage account, public endpoint, key, secret, or connection string is introduced.
- Private Blob DNS and one private endpoint add a small fixed network cost.
- Versioning and retention increase storage consumption.
- The unlocked policy enforces WORM for data operations during retention but can still be changed
  by a sufficiently privileged management-plane administrator.
- A timeout after Azure commits a write is ambiguous: a retry will report that the logical name
  already exists. Recovery must verify the version-pinned artifact and payload hash; this
  prerequisite does not add that orchestration.
- The adapter cannot list, read, overwrite, or delete artifacts. Other clients holding the broader
  built-in Azure role are outside the port's capability boundary.
- Phase execution, artifact naming orchestration, presentation projection, and deployment remain
  explicitly outside this change.

## Alternatives considered

1. **Create a separate Storage account.** Rejected because the existing private StorageV2 account
   supports both Table and Blob private endpoints without broadening identity or network scope.
2. **Use only `overwrite=False`.** Rejected in favor of the explicit `IfMissing` match condition so
   the create-only precondition is visible and tested.
3. **Lock the retention policy in Bicep.** Rejected because policy locking is irreversible and
   requires separate human approval after deployment validation.
4. **Use a custom Azure role.** Not selected because the requirement explicitly calls for
   `Storage Blob Data Contributor`; the role remains constrained to one container.

## Validation

- Unit tests verify payload, path, content-type, and hash bounds; managed-identity-only credential
  configuration; exact conditional upload arguments; duplicate handling; and versioned receipts.
- Infrastructure tests verify private Blob DNS, the Blob private endpoint, versioning, the WORM
  policy, exact container-scoped role assignment, continued public/shared-key denial, and outputs.
- `az bicep build` validates the Azure MCP and WC-013 entrypoints without deployment.
