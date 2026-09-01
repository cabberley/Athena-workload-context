# Reviewed WC-013 collector deployment contracts

The protected collector workflow reads only a byte-pinned artifact from the exact repository
commit captured by `workflow_dispatch`. It never reads Azure deployment outputs at run time and
never installs or executes controller code through the hosted runner Python. A small repository
strict-selector script executes only in a digest-pinned, networkless verifier container before
Azure login.

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
uses only SHA-pinned checkout and `azure/login` actions on `ubuntu-24.04`. Before Azure login,
Docker runs `scripts/strict_select_wc013_contract.py` as UID 65534 in the same reviewed,
digest-pinned Python base used by the controller build, with a read-only repository mount, no
network, no capabilities, and no credentials. Host `jq` may parse only its canonical bounded
selection; no controller code or dependencies run through host Python.

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
4. Review all metadata, controller RepoDigest, all three contracts and their canonical digests.
   Each phase must use its exact deployment-safe Job suffix (`-base-col`, `-fault-col`, or
   `-recover-col`),
   `wc013-<phase>-evidence-collector` container, fixed
   `/opt/athena/wc013-live/delivery/configs/<phase>.json` path, and the deployment ACR
   `athena/wc013-live@sha256:<64-lowercase-hex>` image. Also review
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

1. pulls and RepoDigest-verifies the fixed minimal verifier image, then runs the strict selector
   without network or credentials; the selector size-bounds and recursively rejects duplicate keys
   in the index, artifact, every contract slot, and all nested objects before emitting one canonical
   selection;
2. allows host `jq` to parse only that canonical bounded selection, writes the contract bytes with
   mode `0444`, verifies its artifact-pinned digest, and independently checks the exact phase Job
   suffix, collector name, fixed configuration path, and acceptance ACR RepoDigest before any
   controller image pull or execution;
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
controller's contract model independently requires a lowercase Azure Container Registry login
server and the exact matching `athena/wc013-live@sha256:<64-lowercase-hex>` image. Its Job GET then
validates the current deployed identity and complete template against the selected reviewed
contract before posting that exact template as the start body.

The remaining unavoidable boundary is the GitHub-hosted `ubuntu-24.04` runner, Docker daemon,
and preinstalled Azure CLI, `curl`, `jq`, and SHA-256, plus the reviewed digest-pinned minimal
Python verifier image. Exact checkout/action/image/contract hashes, temporary credential storage
cleanup, and post-login cleanup reduce but cannot eliminate
trust in that hosted execution substrate.
