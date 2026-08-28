# ADR 0004: Use VNet-scoped external ingress for private Azure MCP

- **Status:** Proposed
- **Date:** 2026-08-20

## Context

WC-013 requires the Azure MCP Container App to be reachable through its normal non-`.internal`
FQDN from approved callers in the connected VNet. The proven live topology uses an internal
Container Apps environment, disabled public network access, app ingress with `external: true`, and
private DNS resolving the environment domain to its static private IP.

The committed WC-008 template still declared `external: false`. Redeploying it would revert the
working route, while the WC-008 assertion contract would incorrectly approve that stale topology.

## Decision

Keep the Container Apps environment `internal: true` with `publicNetworkAccess: Disabled`, and set
the MCP app ingress to `external: true` with insecure transport disabled. In an internal
environment, external ingress is external to the app environment but remains reachable only
through the private environment virtual IP.

Create a private DNS zone named for the managed environment `defaultDomain`, link it to the
dedicated VNet with registration disabled, and create a wildcard A record that targets the
environment `staticIp`. The WC-013 composition adopts the existing reviewed
`wc013-containerapps-link` VNet link.

The WC-008 deployment assertion must pin `external_ingress: true` together with the unchanged
internal-environment, disabled-public-network, and HTTPS-only invariants.

## Consequences

- Approved callers in the linked VNet can use the stable non-`.internal` Container App FQDN.
- The environment still exposes no internet-reachable virtual IP.
- Redeployment adopts the existing live DNS zone, wildcard record, and VNet link instead of
  creating a parallel link.
- Assertions rendered with `external_ingress: false` become invalid and require a new human
  approval after re-rendering.
- Additional VNets require explicit network connectivity and a reviewed private DNS link; they do
  not gain access automatically.

## Alternatives considered

1. **Retain environment-local ingress (`external: false`).** Rejected because it would restore the
   committed drift and remove the proven VNet route used by WC-013.
2. **Use a public Container Apps environment.** Rejected because it broadens exposure beyond the
   customer VNet boundary.
3. **Use a separate public gateway or custom domain.** Rejected because it adds unnecessary
   infrastructure and a larger security surface for the immediate acceptance gate.

## Validation

- Bicep builds must succeed for both the WC-008 foundation and WC-013 composition.
- Deterministic tests must enforce the internal environment, disabled public network access,
  `external: true`, private DNS VNet link, and wildcard A record to `staticIp`.
- WC-008 assertion tests must reject `external_ingress: false`.
- Live validation must resolve the non-`.internal` FQDN to the environment private IP and return an
  authentication failure, rather than a routing failure, for an unauthenticated request.
