from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_presentation_image_is_reproducible_and_runs_unprivileged() -> None:
    dockerfile = _read("apps/presentation-web/Dockerfile")
    dockerignore = _read("apps/presentation-web/.dockerignore")

    assert dockerfile.startswith(
        "# syntax=docker/dockerfile:1.7@sha256:"
    )
    from_images = re.findall(r"^FROM\s+(\S+)", dockerfile, re.MULTILINE)
    assert len(from_images) == 2
    assert all(
        re.fullmatch(r"[^\s]+@sha256:[a-f0-9]{64}", image) for image in from_images
    )
    assert from_images[0].startswith("node:24.7.0-bookworm-slim@sha256:")
    assert from_images[1].startswith(
        "nginxinc/nginx-unprivileged:1.29.1-alpine3.22-slim@sha256:"
    )
    assert "npm ci --ignore-scripts --no-audit --fund=false" in dockerfile
    assert "RUN npm run build" in dockerfile
    assert "COPY --from=build --chown=101:101 /app/dist" in dockerfile
    assert "USER 101:101" in dockerfile
    assert "EXPOSE 8080" in dockerfile
    assert "http://127.0.0.1:8080/healthz" in dockerfile
    assert "node_modules" in dockerignore
    assert ".env" in dockerignore


def test_presentation_nginx_preserves_json_and_security_boundaries() -> None:
    nginx = _read("apps/presentation-web/nginx.conf")

    expected_headers = (
        "Content-Security-Policy",
        "frame-ancestors 'none'",
        "X-Content-Type-Options \"nosniff\"",
        "Referrer-Policy \"no-referrer\"",
        "Permissions-Policy",
        "X-Frame-Options \"DENY\"",
    )
    for header in expected_headers:
        assert header in nginx
    assert "listen 8080 default_server" in nginx
    assert "gzip off" in nginx
    assert 'default "no-store"' in nginx
    assert '"public, max-age=31536000, immutable"' in nginx
    assert "location = /healthz" in nginx
    assert 'return 200 "healthy\\n"' in nginx
    assert "location ~* \\.json$" in nginx
    assert "application/json json" in nginx
    assert "error_page 404 =404 /json-not-found.json" in nginx
    assert "try_files $uri =404" in nginx
    assert "location = /json-not-found.json" in nginx
    assert "internal;" in nginx
    assert (ROOT / "apps/presentation-web/json-not-found.json").read_bytes() == (
        b'{"error":"not found"}\n'
    )
    assert nginx.index("location ~* \\.json$") < nginx.index("location / {")
    assert "try_files $uri $uri/ /index.html" in nginx


def test_presentation_bicep_is_private_and_acr_pull_only() -> None:
    orchestration = _read("infra/wc013-live-acceptance/main.bicep")
    foundation = _read("infra/azure-mcp/main.bicep")
    presentation = _read(
        "infra/wc013-live-acceptance/modules/presentation-web.bicep"
    )
    acr_pull = _read("infra/wc013-live-acceptance/modules/acr-pull-rbac.bicep")

    assert (
        "br/public:avm/res/managed-identity/user-assigned-identity:0.6.0"
        in presentation
    )
    assert "br/public:avm/res/app/container-app:0.23.0" in presentation
    assert "publicNetworkAccess: 'Disabled'" in foundation
    assert "internal: true" in foundation
    assert "ingressExternal: true" in presentation
    assert "ingressAllowInsecure: false" in presentation
    assert "ingressTargetPort: 8080" in presentation
    assert "managedEnvironmentResourceId: azureMcp.outputs.managedEnvironmentResourceId" in (
        orchestration
    )
    assert "userAssignedResourceIds" in presentation
    assert "presentationIdentity.outputs.resourceId" in presentation
    assert "systemAssigned" not in presentation
    assert "secrets:" not in presentation
    assert "env:" not in presentation
    assert "minReplicas: 1" in presentation
    assert "maxReplicas: 1" in presentation
    assert "path: '/healthz'" in presentation
    assert "presentationImagePull" in presentation
    assert "dependsOn:" in presentation
    assert "presentationImagePull" in acr_pull or "acrPullRoleDefinitionId" in acr_pull
    assert "7f951dda-4ed3-4680-a7ca-43fe172d538d" in acr_pull
    for forbidden in (
        "Key Vault Crypto User",
        "Storage Blob",
        "Storage Table",
        "Reader",
        "Contributor",
        "Microsoft.App/jobs",
    ):
        assert forbidden not in presentation
    for output in (
        "presentationContainerAppName",
        "presentationContainerAppResourceId",
        "presentationFqdn",
        "presentationHttpsUrl",
        "presentationIdentityResourceId",
        "presentationIdentityClientId",
        "presentationIdentityPrincipalId",
    ):
        assert f"output {output}" in orchestration


def test_controller_identity_oidc_and_workflow_are_closed_and_separate() -> None:
    orchestration = _read("infra/wc013-live-acceptance/main.bicep")
    resources = _read(
        "infra/wc013-live-acceptance/modules/acceptance-resources.bicep"
    )
    workflow = _read(".github/workflows/wc013-collector-controller.yml")

    assert "param collectorControllerPrincipalId" not in orchestration
    assert (
        "br/public:avm/res/managed-identity/user-assigned-identity:0.6.0"
        in orchestration
    )
    assert "https://token.actions.githubusercontent.com" in orchestration
    assert "api://AzureADTokenExchange" in orchestration
    assert (
        "repo:cabberley/Athena-workload-context:environment:athena-live"
        in orchestration
    )
    assert (
        "collectorControllerPrincipalId: validatedCollectorControllerPrincipalId"
        in orchestration
    )
    assert "toLower(presentationWeb.outputs.identityPrincipalId)" in orchestration
    assert "toLower(evidenceIdentity.properties.principalId)" in orchestration
    assert "toLower(acceptanceJobIdentity.properties.principalId)" in orchestration
    assert "map(operatorArtifactReaderObjectIds" in orchestration
    assert "map(workloadReceiptWriterObjectIds" in orchestration
    for output in (
        "collectorControllerIdentityClientId",
        "collectorControllerIdentityPrincipalId",
        "collectorControllerIdentityResourceId",
    ):
        assert f"output {output}" in orchestration

    assert "roleAssignments:" in resources
    assert "collectorControllerRoleDefinitionId" in resources
    role_start = orchestration.index("resource collectorControllerRoleDefinition")
    role_end = orchestration.index("\nmodule privateDns", role_start)
    role = orchestration[role_start:role_end]
    assert "'Microsoft.App/jobs/read'" in role
    assert "'Microsoft.App/jobs/start/action'" in role
    assert "'Microsoft.App/jobs/executions/read'" in role
    assert "Microsoft.Resources/deployments/read" not in role
    assert "acdd72a7-3385-48ef-bd42-f606fba81ae7" not in role

    assert "environment: athena-live" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "ref: main" not in workflow
    assert "DISPATCH_SHA: ${{ github.sha }}" in workflow
    assert "git rev-parse HEAD" in workflow
    assert "persist-credentials: false" in workflow
    assert "id-token: write" in workflow
    assert "uses: azure/login@eec3c95657c1536435858eda1f3ff5437fee8474" in workflow
    action_refs = re.findall(r"uses: [^@\s]+@([^\s]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[a-f0-9]{40}", ref) for ref in action_refs)
    assert "client-id: ${{ env.AZURE_CLIENT_ID }}" in workflow
    assert "client-secret" not in workflow.casefold()
    assert "--use-azure-cli-credential" in workflow
    assert "athena-context wc013-collector-controller" in workflow
    assert "athena_context.wc013_reviewed_collector_contract" in workflow
    assert "--index infra/wc013-live-acceptance/reviewed-collector-contracts/index.json" in workflow
    assert '--deployment "$DEPLOYMENT_SELECTION"' in workflow
    assert workflow.index("Select the immutable reviewed deployment contract") < (
        workflow.index("Sign in as the deployment-owned controller identity")
    )
    assert "az deployment" not in workflow
    assert "wc013-ready" not in workflow
    assert "properties.outputs" not in workflow
    assert "pending-review-no-deployment' ]]" in workflow
    assert "No immutable reviewed deployment contract is enabled." in workflow
    reviewed_index = json.loads(
        _read(
            "infra/wc013-live-acceptance/"
            "reviewed-collector-contracts/index.json"
        )
    )
    assert reviewed_index == {
        "schemaVersion": "athena.wc013CollectorDeploymentContractIndex.v1",
        "deployments": {},
    }
    assert (
        "/infra/wc013-live-acceptance/reviewed-collector-contracts/*.json -text"
        in _read(".gitattributes")
    )

    dispatch_inputs = workflow[workflow.index("    inputs:") : workflow.index("\npermissions:")]
    phase_options = re.findall(
        r"^          - (baseline|faulted|recovered)$",
        dispatch_inputs,
        re.MULTILINE,
    )
    assert phase_options == ["baseline", "faulted", "recovered"]
    assert dispatch_inputs.count("type: choice") == 2
    assert "          - pending-review-no-deployment" in dispatch_inputs
    for forbidden_input in ("image:", "command:", "args:", "env:", "template:", "path:"):
        assert forbidden_input not in dispatch_inputs


def test_confirmed_parameters_keep_runner_and_block_presentation_start() -> None:
    parameters = json.loads(_read(".azure/wc013.parameters.json"))["parameters"]

    assert parameters["operatorArtifactReaderObjectIds"]["value"] == [
        "51425b07-8512-4c49-a763-23a09c347f0b"
    ]
    assert parameters["workloadReceiptWriterObjectIds"]["value"] == [
        "48bedd25-5a4d-4d5b-babd-56d259a41b0d"
    ]
    assert parameters["acceptanceImage"]["value"].endswith(
        "@sha256:c2eec01c2c66af0bee9bc495a2f5ab8816724c7d8f51e52dd019dcbf5fc6c9b6"
    )
    presentation_image = parameters["presentationImage"]["value"]
    assert re.fullmatch(
        r"athenademoa6add389\.azurecr\.io/athena/presentation-web"
        r"@sha256:0{64}",
        presentation_image,
    )
    orchestration = _read("infra/wc013-live-acceptance/main.bicep")
    presentation = _read(
        "infra/wc013-live-acceptance/modules/presentation-web.bicep"
    )
    rejected_suffix = "@sha256:" + "0" * 64
    for bicep in (orchestration, presentation):
        assert f"rejectedPresentationImageSuffix = '{rejected_suffix}'" in bicep
        assert (
            "!endsWith(toLower(presentationImage), rejectedPresentationImageSuffix)"
            in bicep
        )
        assert "real non-placeholder sha256 digest" in bicep
    assert "presentationImage: validatedPresentationImage" in orchestration
    example = _read("infra/wc013-live-acceptance/main.example.bicepparam")
    example_presentation_image = next(
        line for line in example.splitlines() if line.startswith("param presentationImage =")
    )
    assert rejected_suffix not in example_presentation_image
    assert parameters["presentationImageRegistryServer"]["value"] == (
        "athenademoa6add389.azurecr.io"
    )
    assert parameters["presentationImageRegistryResourceId"]["value"] == (
        "/subscriptions/a6add389-9978-47ac-ab1e-a09212e321d4/"
        "resourceGroups/rg-athena-platform-dev/providers/"
        "Microsoft.ContainerRegistry/registries/athenademoa6add389"
    )
    assert "collectorControllerPrincipalId" not in parameters