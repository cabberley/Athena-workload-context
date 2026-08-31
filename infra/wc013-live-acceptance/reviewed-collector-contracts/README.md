# Reviewed WC-013 collector deployment contracts

The protected collector workflow reads only a byte-pinned artifact from the exact repository
commit captured by `workflow_dispatch`. It never reads Azure deployment outputs at run time.

No active artifact exists while `.azure/deployment-plan.md` is `Executing`. The workflow exposes
only `pending-review-no-deployment`, which exits before Azure login. This is intentional: a
collector cannot start until the final digest-pinned deployment has completed and its output has
been independently reviewed and committed.

## Artifact creation and review

1. Deploy the ready template under a new, immutable-style name:
   `wc013-ready-YYYYMMDDTHHMMSSZ-<12-character-source-commit>`.
   Never overwrite or reuse that deployment name.
2. Capture the deployment resource ID, `properties.correlationId`,
   `properties.templateHash`, and `properties.outputs.evidenceCollectorStartContracts.value`
   once with the deployment identity. The GitHub collector identity does not receive deployment
   read permission.
3. Create `wc013-ready-YYYYMMDDTHHMMSSZ-<source-commit>.json` in this directory with exactly:

   ```json
   {
     "schemaVersion": "athena.wc013CollectorDeploymentContract.v1",
     "deploymentResourceId": "/subscriptions/<subscription>/providers/Microsoft.Resources/deployments/<immutable-name>",
     "deploymentCorrelationId": "<deployment-correlation-guid>",
     "deploymentTemplateHash": "<ARM-template-hash>",
     "sourceCommit": "<40-lowercase-hex-source-commit>",
     "collectorContractsDigest": "sha256:<canonical-contracts-object-digest>",
     "contracts": {
       "baseline": {},
       "faulted": {},
       "recovered": {}
     }
   }
   ```

   Each phase value is the corresponding exact
   `athena.wc013CollectorStartContract.v1` object from the captured output. The contracts object
   contains no `acceptance` entry. `collectorContractsDigest` is SHA-256 over UTF-8 JSON serialized
   with sorted keys, no insignificant whitespace, and separators `,` and `:`.
4. Review all metadata, all three contract objects, the canonical contracts digest, and the SHA-256
   of the complete artifact bytes. `.gitattributes` disables text conversion for these JSON files,
   so checkout cannot change the reviewed bytes. Verify the deployed Job templates and identities still match.
5. In the same reviewed commit, replace the workflow's pending deployment choice with the exact
   deployment name and add one `index.json` entry containing the exact artifact filename, full
   artifact digest, deployment resource ID, correlation ID, template hash, and source commit. The
   selector requires the filename to equal `<deployment-choice>.json`; it never derives or accepts
   an arbitrary caller path.
6. Run the selector locally for all three phases using those exact literals. It validates every
   phase, shared image/identity/digest bindings, deployment subscription, artifact bytes, and
   deployment metadata before writing one exclusive temporary contract.

The workflow then checks out `${{ github.sha }}`, verifies `HEAD`, resolves the selected artifact
before OIDC login, and invokes the controller. A run waiting for environment approval remains bound
to its dispatch commit, exact deployment choice, artifact bytes, and metadata even if `main`, an
Azure deployment record, or environment state changes later.

## Permission boundary

The controller identity receives only:

- `Microsoft.App/jobs/read`;
- `Microsoft.App/jobs/start/action`; and
- `Microsoft.App/jobs/executions/read`.

It receives neither `Microsoft.Resources/deployments/read` nor a built-in Reader role. The
controller's Job GET validates the current deployed identity and complete template against the
selected reviewed contract before posting that exact template as the start body.
