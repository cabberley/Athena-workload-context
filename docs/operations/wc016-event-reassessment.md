# WC-016 event-driven reassessment

## Deployable topology

`infra/wc013-live-acceptance/main.bicep` adds:

- dedicated v2 detector, orchestrator, and notification-dispatcher user-assigned identities;
- dedicated `Wc016DetectorState` and `Wc016NotificationState` tables plus a private
  `incident-assets` Blob container;
- a dedicated non-exportable `wc016-incident-signing` Key Vault RSA key;
- private Premium Service Bus queues `incident-reassessment-requests` and
  `incident-notification-outbox`;
- a one-minute scheduled detector Job;
- a session-scaled incident orchestrator Job; and
- a five-minute scheduled signed-feed heartbeat Job using the orchestrator identity; and
- a session-scaled notification dispatcher Job.

The hardened identity resource names end in `-v2-id`, and the detector, orchestrator, and
notification Job names end in `-v2`. These names are deliberately distinct from the deployed
legacy principals and Jobs.

The heartbeat independently rereads every approved VM and Load Balancer signal before refreshing
the signed aggregate index. It writes no incident state or pointer and sends no notification. If
the live health set does not exactly match the signed active incident set, it refuses to refresh;
the presentation then fails closed once the aggregate is fifteen minutes old. This preserves
long-running incident event timestamps while preventing a stale empty or active feed from being
presented as current.

There is no raw-event queue, Action Group ingress, or normalizer Job. Service Bus, Blob, Table, Key
Vault, and Container Apps remain private; local authentication is disabled and images are
digest-pinned. The Logic App request endpoint is Azure-hosted but SAS is disabled and its Entra
policy accepts only the notification identity. No WC-016 component can mutate the workload.

The detector image is built from `apps/signal-detector/Dockerfile`. The orchestrator and
notification Jobs run separate commands and identities from the same digest-pinned
`apps/incident-orchestrator/Dockerfile` image.

Both privileged Python images install the complete runtime and build dependency set from the
reviewed `requirements-wc016.lock` file. The install is restricted to the fixed Microsoft package
feed proxy for PyPI, requires SHA-256 hashes and binary distributions for every dependency, then
installs the local Athena package with dependency resolution and isolated build dependency
downloads disabled.
Regenerate the lock only in the reviewed Python 3.14 toolchain with:

```text
pip-compile pyproject.toml --all-build-deps --allow-unsafe --generate-hashes --strip-extras --resolver=backtracking --no-emit-index-url --no-emit-trusted-host --output-file requirements-wc016.lock
```

## Signal and identity boundary

The detector and orchestrator independently query only the deployment-owned approved resources:

| Resource | REST evidence | Interpretation |
|---|---|---|
| Approved database/web VM | `{resourceId}/instanceView?api-version=2024-11-01` | exactly one `PowerState/running` is healthy |
| Approved Load Balancer | bounded `VipAvailability,DipAvailability` metrics query | VIP degradation is `loadBalancerFailure`; DIP-only degradation is backend degradation |

The custom WC-016 signal-reader role contains only
`Microsoft.Compute/virtualMachines/instanceView/read` and
`Microsoft.Insights/metrics/read` at the approved workload resource group. Application allowlists
further constrain each request to the exact resource IDs. The detector does not reuse the evidence
identity. Neither identity receives broad Reader.

The detector additionally has only ACR pull, reassessment-queue sender, and data-contributor access
to `Wc016DetectorState`. The notification dispatcher has data-contributor access only to
`Wc016NotificationState`; it has no access to `Wc016DetectorState`. The orchestrator has only ACR pull,
reassessment receiver, notification sender, the narrow signal reader, Crypto User on the incident
key, and Blob Data Contributor on `incident-assets`. It has no lifecycle key or
`presentation-assets` write access. Presentation has Blob Data Reader only on `incident-assets`.

## Durable transition processing

Detector state has committed and pending checkpoints. Before sending, the detector stores the
complete pending transition, including its deterministic transition/request/message ID. It clears
pending state only after send and committed-state persistence succeed. Retrying after either an
uncertain send or a failed state commit therefore repeats the identical message ID and body;
Service Bus duplicate detection makes the operation idempotent.

The reassessment request is never evidence. The orchestrator:

1. validates content type, message ID, session ID, and application properties;
2. parses the strict request contract;
3. rederives source, rule, resource, role, scenario, lifecycle, incident ID, request ID, and
   idempotency key from the exact approved binding;
4. independently queries live ARM state through the bounded adapter; and
5. reconciles live state against the trusted signed active index and acts only on a real
   transition.

The event's observed-to-received interval remains limited to ten minutes. A correctly formed queued
hint remains usable for the queue's one-day lifetime so an outage longer than ten minutes cannot
permanently lose a transition. Duplicate or minted hints that do not represent a live transition,
and resolutions without a prior active incident, complete without signing or notification.

## Incident publication and notification

Immutable signed state and attestation objects are referenced by:

- `incidents/<incident-id>/versions/<digest>/pointer.json` — signed immutable pointer; and
- `incidents/<incident-id>/current.json` — the bounded latest pointer for retry reconciliation; and
- `incidents/active.json` — deterministic signed aggregate of every active incident.

Entries are sorted by incident ID and bind the exact immutable pointer digest. All immutable assets
are written before the aggregate compare-and-swap, so a losing concurrent publication cannot
invalidate the winning feed. A resolution removes only its own entry.

Notification messages use a deterministic SHA-256 ID from transition ID plus lifecycle and use the
incident ID as the Service Bus session. Publication succeeds before notification enqueue. The
signed state includes that exact transition ID. If enqueue fails after publication, retry reads and
verifies the bounded per-incident current pointer, immutable state, and both attestations. It
re-enqueues only when the signed transition ID and live actionable lifecycle still match; a newly
minted hint with a different transition ID remains a no-op. Service Bus duplicate detection absorbs
an already-successful enqueue of the same deterministic notification ID. The Logic App callback
uses the exact API version returned by `listCallbackURL`, and its AAD policy binds the notification
identity token's exact `https://management.azure.com` audience. The request body includes
`notificationId` as the downstream idempotency key. The dispatcher provides
at-most-once posting with explicit uncertainty: it first acquires its Logic Apps managed-identity
token, creates a durable `reserved` record in `Wc016NotificationState`, and uses ETag
compare-and-swap to mark it `dispatching` immediately before HTTP and `delivered` after a 2xx
response. Redelivery of `delivered` completes without reposting. A `reserved` record can be safely
reacquired after a pre-dispatch crash, while a concurrent lease loser abandons without posting.
Redelivery of `dispatching` is dead-lettered as `AthenaNotificationDeliveryUncertain`; it is never
silently completed or resent because the external side effect may have happened. HTTP 408 and 429
reset the record to `reserved` before abandon, permanent 4xx responses are dead-lettered as
`AthenaNotificationRejected`, and ambiguous network outcomes remain explicitly uncertain.
`dispatching` and `delivered` records are retained; cleanup applies only to expired `reserved`
records that cannot represent an attempted HTTP side effect. Signed state uses
`notificationStatus=pendingDispatch`; it records intent rather than claiming a later side effect
already happened.

## Two-stage trust activation

WC-016 must not be activated while any legacy runtime resource remains or while the checked-in
fixture key is configured:

1. Deploy with `wc016RuntimeEnabled=false` and `wc016LegacyCleanupConfirmed=false` (both defaults).
   This provisions only the dedicated incident key, container, table, and hardened v2 identities;
   WC-016 runtime RBAC, queues, and Jobs remain absent.
2. Run the cleanup script in audit mode. It writes a canonical JSON report and changes nothing:

   ```powershell
   pwsh scripts/audit-remove-wc016-legacy-runtime.ps1
   ```

3. Review the report's exact legacy-resource allowlist, protected-resource denylist, resolved
   principal IDs, and proposed actions. Then explicitly apply the same bounded cleanup:

   ```powershell
   pwsh scripts/audit-remove-wc016-legacy-runtime.ps1 -Apply
   ```

   The script deletes only:

   - `athena-wc013-live-w16-det`, `athena-wc013-live-w16-orch`,
     `athena-wc013-live-w16-norm`, and `athena-wc013-live-w16-notify`;
   - `raw-monitor-events`, `incident-reassessment-requests`, and
     `incident-notification-outbox`;
   - the exact legacy metric alerts `athena-wc013-live-database-availability`,
     `athena-wc013-live-web-{0,1,2}-availability`,
     `athena-wc013-live-load-balancer-vip-availability`, and
     `athena-wc013-live-load-balancer-dip-availability`;
   - `athena-wc013-live-wc016-normalizer-id`,
     `athena-wc013-live-wc016-orchestrator-id`, and
     `athena-wc013-live-wc016-notification-id`;
   - only the documented scope-and-role allowlist for those three deleted principals; and
   - the evidence identity's Service Bus Data Sender assignment at the exact legacy reassessment
     queue scope.

   It fails before any mutation if a legacy principal has an assignment outside that allowlist. It
   never deletes the evidence identity, Service Bus namespace, Logic App, protected evidence
   assignments, or unrelated roles. Preserve the report because it records expected, unexpected,
   and residual assignments plus the deleted principal IDs. Audit output also enumerates all six
   legacy metric-alert IDs and explicitly records whether they are absent before and after the run.
   If an audit is repeated after identity deletion, pass those exact IDs through the corresponding
   `-Legacy*PrincipalId` parameters.
4. Require `payload.mode=apply` and `payload.verification.zeroResidualReadback=true` in
   `.azure/wc016-legacy-cleanup-report.json`. Do not continue on unresolved principals, residual
   resources, residual role assignments, or protected-resource changes.
5. Export the public half of the exact deployed `wc016-incident-signing` key version.
6. Replace `wc016-incident-public-key.pem` and
   `apps/presentation-web/public/trust/incident-public-key.jwk.json`.
7. Calculate the SHA-256 fingerprint over the DER SubjectPublicKeyInfo bytes and update
   `signingKeyFingerprint` in the Bicep parameter JSON and replace
   `PINNED_INCIDENT_KEY_FINGERPRINT` in
   `apps/presentation-web/src/verification.ts` with the same reviewed value.
8. Verify the PEM, JWK modulus/exponent, logical key ID, fingerprint, and
   `incidentSigningKeyUriWithVersion` all identify the same key.
9. Rebuild and digest-pin the delivery, presentation, detector, and orchestrator images.
10. Run tests, Bicep build/lint, ARM validation, and what-if.
11. Set `wc016LegacyCleanupConfirmed=true` and `wc016RuntimeEnabled=true` only in the reviewed
    activation deployment.

The Bicep entrypoint rejects activation unless cleanup is confirmed and also rejects the known
checked-in fixture fingerprint. The gateway and browser verify the dedicated key independently.
Any other mismatch withholds incident data; there is no lifecycle-key or unsigned fallback.

## Validation

```powershell
python -m ruff check .
python -m mypy src
python -m pytest
python scripts/validate_repository.py
python scripts/generate_presentation_web_assets.py --check

Push-Location apps/presentation-web
npm test
npm run typecheck
npm run lint
npm run build
Pop-Location

az bicep build --file infra/wc016-event-reassessment/main.bicep --stdout | Out-Null
az bicep build --file infra/wc013-live-acceptance/main.bicep --stdout | Out-Null
az bicep lint --file infra/wc013-live-acceptance/main.bicep
```
