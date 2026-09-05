# Athena WC-016 scheduled signal detector

This image runs once per minute under a dedicated WC-016 detector managed identity. It performs
GET-only ARM/Monitor REST calls for the exact approved database VM, web VMs, and Load Balancer.
VM health uses instanceView power state. Load Balancer failure is based on `VipAvailability`;
`DipAvailability` is retained as backend-degradation evidence and does not independently classify
the Load Balancer as failed.

The detector stores only transition state in a dedicated private table, normalizes a bounded
synthetic Azure Monitor envelope through the WC-016 contracts, and sends a session-bound request
to `incident-reassessment-requests`. It has no remediation command or workload write path.
