# Reviewed WC-013 collector deployment contracts

The protected collector workflow reads only a byte-pinned artifact from the exact repository
commit captured by `workflow_dispatch`. It never reads Azure deployment outputs at run time and
never installs or executes repository Python on the hosted runner.

No active artifact exists while `.azure/deployment-plan.md` is `Executing`. The workflow exposes
only `pending-review-no-deployment`, which exits before Azure login. This is intentional: a
collector cannot start until the final digest-pinned deployment and controller image have completed
independent review.

## Controller image

Build `Dockerfile.wc013-controller` in the existing private ACR before ARM validation. The image has
a digest-pinned Python base, installs the controller and dependencies at build time, runs as
`10001:10001`, and fixes its entrypoint to `athena-context wc013-collector-controller`. Put its
exact ACR RepoDigest in `collectorControllerImage`; Bicep rejects the all-zero placeholder and grants
the GitHub OIDC identity only `AcrPull` in addition to its exact Job permissions.

The reviewed deployment artifact pins the same complete image reference. At execution, the workflow
uses only SHA-pinned checkout and `azure/login` actions on `ubuntu-24.04`. Host `jq`, SHA-256, Azure
CLI, and Docker are plumbing only: no controller code or Python dependencies run on the host.

## Artifact creation and review

1. Deploy the ready template under a new, immutable-style name:
   `wc013-ready-YYYYMMDDTHHMMSSZ-<12-character-source-commit>`.
   Never overwrite or reuse that deployment name.
2. Capture the deployment resource ID, `properties.correlationId`,
   `properties.templateHash`, `properties.outputs.collectorControllerImage.value`, and
   `properties.outputs.evidenceCollectorStartContracts.value` once with the deployment identity.
   The GitHub collector identity does not receive deployment-read permission.
3. Create `wc013-ready-YYYYMMDDTHHMMSSZ-<source-commit>.json` in this directory with exactly:

   ```json
   {
     "schemaVersion": "athena.wc013CollectorDeploymentContract.v2",
     "deploymentResourceId": "/subscriptions/<subscription>/providers/Microsoft.Resources/deployments/<immutable-name>",
     "deploymentCorrelationId": "<deployment-correlation-guid>",
     "deploymentTemplateHash": "<ARM-template-hash>",
     "sourceCommit": "<40-lowercase-hex-source-commit>",
     "controllerImage": "<registry>.azurecr.io/athena/wc013-controller@sha256:<manifest-digest>",
     "collectorContractsDigest": "sha256:<canonical-contracts-object-digest>",
     "collectorContractDigests": {
       "baseline": "sha256:<canonical-contract-digest>",
       "faulted": "sha256:<canonical-contract-digest>",
       "recovered": "sha256:<canonical-contract-digest>"
     },
     "contracts": {
       "baseline": {},
       "faulted": {},
       "recovered": {}
     }
   }
   ```

   Each phase value is the corresponding exact
   `athena.wc013CollectorStartContract.v1` object from the captured output. The contracts object
   contains no `acceptance` entry. Each digest is SHA-256 over UTF-8 JSON serialized with sorted
   keys, no insignificant whitespace, and separators `,` and `:`.
4. Review all metadata, controller RepoDigest, all three contracts and their canonical digests, and
   the SHA-256 of the complete artifact bytes. `.gitattributes` disables text conversion for these
   JSON files, so checkout cannot change reviewed bytes. Verify the deployed Job templates,
   identities, and controller-image deployment output still match.
5. In the same reviewed commit, replace the workflow's pending deployment choice with the exact
   deployment name and add one `index.json` entry containing the exact artifact filename, full
   artifact digest, deployment resource ID, correlation ID, template hash, and source commit. The
   workflow requires the filename to equal `<deployment-choice>.json`; it never accepts an
   arbitrary caller path.
6. Run the offline selector for all three phases. It validates every phase, per-contract hashes,
   shared image/identity/digest bindings, controller-image ACR binding, deployment subscription,
   artifact bytes, and deployment metadata.

## Immutable execution

After environment approval, the workflow remains on `${{ github.sha }}` even if `main` changes. It:

1. validates the index and full artifact hash with fixed hosted-runner plumbing;
2. extracts only the allowlisted phase, writes canonical bytes with mode `0444`, and verifies its
   artifact-pinned digest;
3. logs in with GitHub OIDC, exchanges a piped ARM token directly at the fixed ACR OAuth
   endpoint for a pull token, pulls the artifact-pinned controller image, deletes Docker
   authentication state, and requires the local RepoDigest to equal the
   reviewed reference;
4. pipes one short-lived ARM access token directly from Azure CLI to container stdin; and
5. runs the fixed image entrypoint with fixed contract, identity, and stdin-token arguments.

The container is read-only, unprivileged, capability-free, and receives only the selected contract
as a read-only bind mount. It receives no Docker socket, repository checkout, Azure CLI profile,
credential file, access-token environment variable, command override, or template override. The
stdin credential reads one bounded ARM JWT into process memory, validates audience and expiry, and
all failures redact token content. The token disappears with the process.

## Permission boundary

The controller identity receives only:

- `Microsoft.App/jobs/read`;
- `Microsoft.App/jobs/start/action`;
- `Microsoft.App/jobs/executions/read`; and
- `AcrPull` on the existing controller-image registry.

It receives neither `Microsoft.Resources/deployments/read` nor a built-in Reader role. The
controller's Job GET validates the current deployed identity and complete template against the
selected reviewed contract before posting that exact template as the start body.

The remaining unavoidable boundary is the GitHub-hosted `ubuntu-24.04` runner and its preinstalled
Azure CLI, `curl`, `jq`, SHA-256, Docker client, and Docker daemon. Exact checkout/action/image/contract
hashes, temporary credential storage cleanup, and post-login cleanup reduce but cannot eliminate
trust in that hosted execution substrate.
