# Athena WC-016 event processor

This image receives one Service Bus event under peek-lock, normalizes only the reviewed Azure
Activity Log, Resource Health, or Monitor common-alert-schema fields, binds the target through an
approved resource-role file, and emits one session-bound reassessment request.

It cannot read workload resources, publish manifests, send Teams messages, or remediate Azure.
Scale it from `raw-monitor-events`; a separate governed orchestrator consumes
`incident-reassessment-requests`.
