# WC-016 event-driven reassessment

## Signal coverage

| Scenario | Accepted activation signal | Accepted recovery signal |
|---|---|---|
| Singleton database VM | Activity Log stop/deallocate/delete or Resource Health unavailable | VM start/restart plus healthy reassessment |
| Web VM | Activity Log stop/deallocate/delete or Resource Health unavailable | VM start/restart plus healthy reassessment |
| Azure Load Balancer | Monitor common-alert-schema VIP/DIP/probe metric alert or Resource Health unavailable | Resolved alert plus healthy reassessment |

Load Balancer ARM writes are configuration evidence, not failure evidence.

## Runtime flow

1. Deliver the Azure event to `raw-monitor-events`.
2. Normalize only allowlisted fields and send the canonical event using its SHA-256 duplicate key.
3. Require metric alerts to match the exact reviewed rule-name allowlist emitted by the Bicep deployment, then resolve the resource ID against the approved workload role bindings.
4. Send a session-bound request to `incident-reassessment-requests`.
5. Run `wc016-incident-orchestrator` to call the managed-identity-protected scoped reassessment.
6. Sign the incident state with the reviewed WC-013 key and publish immutable state and attestation.
7. Sign `incidents/current.json` and replace it with an ETag compare-and-swap.
8. Enqueue active or resolved notifications in `incident-notification-outbox`.

## Teams connection

Use a separately governed Logic App with a pre-authorized Microsoft Teams managed API connection.
Its Service Bus trigger receives only the bounded notification text. Athena contains no Teams
webhook URL, Graph client secret, or permission to send arbitrary chat messages. Configure the
destination chat during deployment approval.

## Demonstration

Stop each synthetic resource through the existing separately governed workload operator. The page
should progress through detecting/reassessing to active within the evidence collection window.
Restart the resource and verify a resolved alert, healthy reassessment, signed resolved state, and
recovery notification. Athena must never start or repair the resource.
