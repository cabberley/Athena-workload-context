# ADR 0009: Read operational artifacts only by exact verified Blob version

- **Status:** Proposed
- **Date:** 2026-08-20

## Context

ADR 0007 established private create-only artifact persistence and required downstream consumers to
retain a Blob version ID. Receipt ingestion and operator verification now need a narrow read
capability without introducing listing, latest-version lookup, deletion, writes, phase execution,
presentation projection, or orchestration.

An unversioned read can silently select a different current version. Content type and Blob metadata
alone also do not prove that returned bytes are the expected artifact.

## Decision

Add a `VersionPinnedArtifactReaderPort` with one `read` method. Every request contains an exact
bounded Blob name, an opaque non-empty version ID, and an expected lowercase SHA-256 digest. The
adapter constructs the Blob client with that exact version ID and never performs an unversioned
properties lookup or a list operation.

The Azure SDK starts the ranged GET during `download_blob`. The adapter requests at most one MiB
plus one byte, rejects a missing, zero, malformed, or over-limit response size before consuming the
stream, and verifies the post-read byte count. It requires:

1. the response version ID to equal the requested version ID;
2. content type to equal `application/json`;
3. `payload_sha256` Blob metadata to equal the caller's expected digest;
4. the computed digest of the downloaded bytes to equal both values; and
5. the payload to be valid UTF-8 JSON.

Only an exact `BlobNotFound` response is mapped to the typed artifact-not-found error. Container,
authorization, network, and other service failures remain visible to the caller.

Add a required `operatorArtifactReaderObjectIds` Bicep input. These are the Entra object IDs of
one or more separate operator managed identities, not their client IDs. Grant each principal
`Storage Blob Data Reader` at the artifact container resource ID only. The existing acceptance
identity keeps its container-scoped Contributor assignment and may instantiate the same read
adapter for receipt ingestion.

## Consequences

- The application port has no list, latest, delete, or write method.
- The built-in `Storage Blob Data Reader` role still grants Blob read and list data actions. The
  no-list guarantee is therefore a port capability boundary, not an Azure RBAC prohibition.
- Each separate operator identity is Azure-enforced read-only. Using the acceptance Contributor
  identity with the adapter does not reduce that identity's effective Azure permissions.
- Missing version IDs, response version drift, absent hash metadata, wrong content type, oversized
  payloads, malformed JSON, and digest mismatches fail closed.
- Existing `artifactBlobEndpoint`, `artifactContainerName`, and
  `artifactContainerResourceId` outputs remain the composition inputs. No Job environment wiring is
  added by this prerequisite.
- Phase runner, orchestration, presentation, and retry/recovery policy remain outside scope.

## Alternatives considered

1. **Read the latest Blob version.** Rejected because it breaks the immutable receipt binding.
2. **Trust only Blob metadata.** Rejected because metadata does not verify returned bytes.
3. **Grant Reader at the Storage account.** Rejected because it would expose unrelated containers.
4. **Use the acceptance Contributor identity for operators.** Rejected as the default because it
   carries write and delete data actions; it remains permitted only for the already-governed Job.
5. **Create a custom no-list role.** Not selected because Blob read and list use the same data
   action in Azure's built-in data plane; the narrow port prevents listing in application code.

## Validation

- Unit tests cover exact-version calls, one-MiB bounds, response-size inconsistencies, content
  type, metadata, JSON, digest and version failures, selective not-found mapping, and protocol
  surface.
- Infrastructure tests verify the principal is parameterized and receives the Reader role at the
  artifact container only while endpoint and container outputs remain exposed.
- Bicep entrypoint and example parameter validation run without deployment.
