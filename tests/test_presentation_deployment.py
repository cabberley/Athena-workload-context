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
    assert "location = /runtime-manifest.json" in nginx
    assert "location ^~ /live/" in nginx
    assert nginx.count("proxy_pass http://127.0.0.1:8081") == 2
    assert 'proxy_set_header Authorization ""' in nginx
    assert 'proxy_set_header Cookie ""' in nginx
    assert "proxy_pass_request_body off" in nginx
    assert "proxy_redirect off" in nginx
    assert "proxy_buffering off" in nginx
    assert "location ~* \\.json$" in nginx
    assert "application/json json" in nginx
    assert "error_page 404 =404 /json-not-found.json" in nginx
    assert "try_files $uri =404" in nginx
    assert "location = /json-not-found.json" in nginx
    assert "internal;" in nginx
    assert (ROOT / "apps/presentation-web/json-not-found.json").read_bytes() == (
        b'{"error":"not found"}\n'
    )
    assert nginx.index("location = /runtime-manifest.json") < nginx.index(
        "location ~* \\.json$"
    )
    assert nginx.index("location ^~ /live/") < nginx.index("location ~* \\.json$")
    assert nginx.index("location ~* \\.json$") < nginx.index("location / {")
    assert "try_files $uri $uri/ /index.html" in nginx


def test_presentation_bicep_is_private_and_reads_only_presentation_assets() -> None:
    orchestration = _read("infra/wc013-live-acceptance/main.bicep")
    foundation = _read("infra/azure-mcp/main.bicep")
    resources = _read(
        "infra/wc013-live-acceptance/modules/acceptance-resources.bicep"
    )
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
    assert "name: 'athena-presentation-asset-gateway'" in presentation
    assert "image: validatedDeliveryImage" in presentation
    assert "'presentation-asset-gateway'" in presentation
    assert "'--blob-endpoint'" in presentation
    assert "presentationAssetBlobEndpoint" in presentation
    assert "'--container'" in presentation
    assert "presentationAssetContainerName" in presentation
    assert "'--managed-identity-client-id'" in presentation
    assert "presentationIdentity.outputs.clientId" in presentation
    assert "'--port'" in presentation
    assert "'8081'" in presentation
    assert "name: 'AZURE_CLIENT_ID'" in presentation
    assert "minReplicas: 1" in presentation
    assert "maxReplicas: 1" in presentation
    assert "path: '/healthz'" in presentation
    assert "presentationImagePull" in presentation
    assert "dependsOn:" in presentation
    assert "presentationImagePull" in acr_pull or "acrPullRoleDefinitionId" in acr_pull
    assert "7f951dda-4ed3-4680-a7ca-43fe172d538d" in acr_pull
    for forbidden in (
        "Key Vault Crypto User",
        "Storage Table",
        "Microsoft.App/jobs",
        "operational-artifacts",
    ):
        assert forbidden not in presentation
    assert "deliveryImageRepositoryPrefix" in presentation
    assert "/athena/wc013-live@sha256:" in presentation
    assert "deliveryImageDigestInvalidCharacters" in presentation
    assert "!endsWith(deliveryImage, rejectedImageDigestSuffix)" in presentation
    assert "scope: presentationAssetContainer" in resources
    presentation_reader = re.search(
        r"resource presentationAssetBlobDataReader .*?\n\}",
        resources,
        re.DOTALL,
    )
    assert presentation_reader is not None
    assert "presentationIdentityPrincipalId" in presentation_reader.group(0)
    assert "storageBlobDataReaderRoleDefinitionId" in presentation_reader.group(0)
    assert "artifactContainer" not in presentation_reader.group(0)
    for output in (
        "presentationContainerAppName",
        "presentationContainerAppResourceId",
        "presentationFqdn",
        "presentationHttpsUrl",
        "presentationIdentityResourceId",
        "presentationIdentityClientId",
        "presentationIdentityPrincipalId",
        "presentationAssetContainerName",
        "presentationAssetContainerResourceId",
        "presentationAssetBlobEndpoint",
    ):
        assert f"output {output}" in orchestration


def test_controller_image_is_immutable_and_has_a_fixed_entrypoint() -> None:
    dockerfile = _read("Dockerfile.wc013-controller")
    container_test = _read("test-controller-container.ps1")
    ci = _read(".github/workflows/ci.yml")

    assert dockerfile.startswith("# syntax=docker/dockerfile:1.7@sha256:")
    image = re.search(r"^FROM (\S+)$", dockerfile, re.MULTILINE)
    assert image is not None
    assert re.fullmatch(r"python:3\.14\.7-slim-bookworm@sha256:[a-f0-9]{64}", image[1])
    assert "python -m pip install" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert 'ENTRYPOINT ["athena-context", "wc013-collector-controller"]' in dockerfile
    assert "CMD " not in dockerfile
    assert "AZURE_" not in dockerfile
    assert "test-controller-container.ps1" in ci
    assert "docker image inspect" in container_test
    assert "--read-only" in container_test
    assert "--use-arm-access-token-stdin" in container_test


def test_controller_identity_oidc_and_workflow_are_closed_and_separate() -> None:
    orchestration = _read("infra/wc013-live-acceptance/main.bicep")
    resources = _read(
        "infra/wc013-live-acceptance/modules/acceptance-resources.bicep"
    )
    workflow = _read(".github/workflows/wc013-collector-controller.yml")
    acr_pull = _read("infra/wc013-live-acceptance/modules/acr-pull-rbac.bicep")

    assert "param collectorControllerPrincipalId" not in orchestration
    assert "param collectorControllerImage string" in orchestration
    assert (
        "br/public:avm/res/managed-identity/user-assigned-identity:0.6.0"
        in orchestration
    )
    assert "https://token.actions.githubusercontent.com" in orchestration
    assert "api://AzureADTokenExchange" in orchestration
    assert (
        "repo:cabberley@26394346/Athena-workload-context@1334641162:environment:athena-live"
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
        "collectorControllerImage",
    ):
        assert f"output {output}" in orchestration

    assert "roleAssignments:" in resources
    assert "collectorControllerRoleDefinitionId" in resources
    role_start = orchestration.index("resource collectorControllerRoleDefinition")
    role_end = orchestration.index("\nmodule privateDns", role_start)
    role = orchestration[role_start:role_end]
    actions = re.findall(r"^          '([^']+)'$", role, re.MULTILINE)
    assert actions == [
        "Microsoft.App/jobs/read",
        "Microsoft.App/jobs/start/action",
        "Microsoft.App/jobs/executions/read",
    ]
    assert "Microsoft.Resources/deployments/read" not in role
    assert "acdd72a7-3385-48ef-bd42-f606fba81ae7" not in role
    controller_pull_start = orchestration.index("module collectorControllerImagePull")
    controller_pull_end = orchestration.index("\n@description", controller_pull_start)
    controller_pull = orchestration[controller_pull_start:controller_pull_end]
    assert "collectorControllerIdentity.outputs.principalId" in controller_pull
    assert "acceptanceImageRegistryResourceId" in controller_pull
    assert "7f951dda-4ed3-4680-a7ca-43fe172d538d" in acr_pull

    assert "environment: athena-live" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "runs-on: ubuntu-24.04" in workflow
    assert "ubuntu-latest" not in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "ref: main" not in workflow
    assert "DISPATCH_SHA: ${{ github.sha }}" in workflow
    job_env = workflow[workflow.index("    env:") : workflow.index("    steps:")]
    assert "runner.temp" not in job_env
    assert 'CONTRACT_DIRECTORY=$RUNNER_TEMP/wc013-controller' in workflow
    assert "git rev-parse HEAD" in workflow
    assert "persist-credentials: false" in workflow
    assert "id-token: write" in workflow
    assert "uses: azure/login@eec3c95657c1536435858eda1f3ff5437fee8474" in workflow
    action_refs = re.findall(r"uses: [^@\s]+@([^\s]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[a-f0-9]{40}", ref) for ref in action_refs)
    assert "client-id: ${{ env.AZURE_CLIENT_ID }}" in workflow
    assert "client-secret" not in workflow.casefold()
    assert "setup-python" not in workflow
    assert "pip install" not in workflow
    assert "python -m" not in workflow
    assert "--use-azure-cli-credential" not in workflow
    assert "--use-arm-access-token-stdin" in workflow
    assert "az deployment" not in workflow
    assert "properties.outputs" not in workflow
    assert 'docker pull "$CONTROLLER_IMAGE"' in workflow
    assert "az acr login" not in workflow
    assert '"https://$ACR_SERVER/oauth2/exchange"' in workflow
    assert "--data-urlencode 'access_token@-'" in workflow
    assert "| jq -jer '.refresh_token'" in workflow
    assert "--password-stdin" in workflow
    assert "{{json .RepoDigests}}" in workflow
    assert ".[0] == $expected" in workflow
    assert '10001:10001|["athena-context","wc013-collector-controller"]' in workflow
    assert "--entrypoint" not in workflow
    assert "--read-only" in workflow
    assert "--user 10001:10001" in workflow
    assert "--cap-drop ALL" in workflow
    assert "--security-opt no-new-privileges" in workflow
    assert workflow.count("--mount ") == 2
    assert "source=$GITHUB_WORKSPACE,target=/workspace,readonly" in workflow
    assert "target=/run/athena/collector-contract.json,readonly" in workflow
    assert "az account get-access-token" in workflow
    assert "| docker run --rm --interactive" in workflow
    assert "ARM_ACCESS_TOKEN" not in workflow
    assert "accessToken" not in workflow.split("env:", 1)[1].split("steps:", 1)[0]
    selection_step_index = workflow.index(
        "Select one byte-pinned reviewed contract"
    )
    login_step_index = workflow.index(
        "Sign in as the deployment-owned controller identity"
    )
    strict_selector_index = workflow.index(
        "scripts/strict_select_wc013_contract.py"
    )
    canonical_jq_index = workflow.index(
        "jq -e --arg deployment", strict_selector_index
    )
    assert selection_step_index < strict_selector_index < canonical_jq_index
    assert canonical_jq_index < login_step_index
    assert (
        "python:3.14.7-slim-bookworm@sha256:"
        "416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63"
        in workflow
    )
    assert (
        "python@sha256:"
        "416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63"
        in workflow
    )
    assert "--network none" in workflow
    assert "--user 65534:65534" in workflow
    assert "{{.Config.User}}|{{json .Config.Entrypoint}}" in workflow
    assert '"1|$VERIFIER_REPO_DIGEST||null"' in workflow
    assert '"$VERIFIER_IMAGE"' in workflow
    assert '"$STRICT_SELECTION_PATH"' in workflow
    assert "athena.wc013StrictCollectorSelection.v1" in workflow
    pre_verification = workflow[selection_step_index:strict_selector_index]
    assert "jq -" not in pre_verification
    assert "az account" not in workflow[selection_step_index:login_step_index]
    assert 'docker pull "$CONTROLLER_IMAGE"' not in workflow[
        selection_step_index:login_step_index
    ]
    assert 'jq -er ".controllerImage" "$artifact_path"' not in workflow
    assert 'jq -jceS --arg phase "$PHASE"' not in workflow
    phase_binding_index = workflow.index('case "$PHASE" in')
    assert phase_binding_index < workflow.index(
        "Sign in as the deployment-owned controller identity"
    )
    assert phase_binding_index < workflow.index('docker pull "$CONTROLLER_IMAGE"')
    assert phase_binding_index < workflow.index(
        "Validate and start through the immutable controller image"
    )
    phase_job_suffixes = {
        "baseline": "-base-col",
        "faulted": "-fault-col",
        "recovered": "-recover-col",
    }
    for phase, job_suffix in phase_job_suffixes.items():
        assert f"expected_job_suffix='{job_suffix}'" in workflow
        assert (
            f"expected_container_name='wc013-{phase}-evidence-collector'"
            in workflow
        )
        assert (
            "expected_config_path="
            f"'/opt/athena/wc013-live/delivery/configs/{phase}.json'"
            in workflow
        )
    for exact_semantic_check in (
        'endswith($job_suffix)',
        '.template.containers[0].name == $container_name',
        '.template.containers[0].args[0] == "wc013-evidence-collector-job"',
        '.template.containers[0].args[1] == "--config"',
        '.template.containers[0].args[2] == $config_path',
        '"$collector_registry_server" != "$ACR_SERVER"',
        '"$ACR_SERVER/athena/wc013-live@sha256:$collector_image_digest"',
    ):
        assert exact_semantic_check in workflow
    assert (
        "Selected collector contract does not match the requested phase semantics."
        in workflow
    )
    assert (
        "Selected collector contract image is not the exact reviewed acceptance "
        "ACR repository digest."
        in workflow
    )
    assert workflow.index("Pull and verify the exact reviewed controller image") < (
        workflow.index("Validate and start through the immutable controller image")
    )
    assert "pending-review-no-deployment' ]]" in workflow
    assert "No immutable reviewed deployment contract is enabled." in workflow
    reviewed_index = json.loads(
        _read(
            "infra/wc013-live-acceptance/"
            "reviewed-collector-contracts/index.json"
        )
    )
    deployment_name = "wc013-ready-20260902T050729Z-0620492968a1"
    assert f"          - {deployment_name}" in workflow
    assert reviewed_index["schemaVersion"] == (
        "athena.wc013CollectorDeploymentContractIndex.v1"
    )
    assert reviewed_index["deployments"][deployment_name] == {
        "artifactFile": f"{deployment_name}.json",
        "artifactDigest": (
            "sha256:4bed6560e142193a43132872fd038075ce339a6cc7740a0e43ed7f2a3f06aa14"
        ),
        "deploymentResourceId": (
            "/subscriptions/a6add389-9978-47ac-ab1e-a09212e321d4/providers/"
            f"Microsoft.Resources/deployments/{deployment_name}"
        ),
        "deploymentCorrelationId": "9e37ca1e-4d60-436a-aa17-071dd5201a80",
        "deploymentTemplateHash": "5355939670410545896",
        "sourceCommit": "0620492968a123f5b380c62bc3ebfa9bbeab5cd5",
    }
    assert list(reviewed_index["deployments"]) == [deployment_name]
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
    assert f"          - {deployment_name}" in dispatch_inputs
    for forbidden_input in (
        "image:",
        "command:",
        "args:",
        "env:",
        "template:",
        "path:",
        "token:",
    ):
        assert forbidden_input not in dispatch_inputs

def test_confirmed_parameters_use_published_images() -> None:
    parameters = json.loads(_read(".azure/wc013.parameters.json"))["parameters"]

    assert parameters["operatorArtifactReaderObjectIds"]["value"] == [
        "51425b07-8512-4c49-a763-23a09c347f0b"
    ]
    assert parameters["workloadReceiptWriterObjectIds"]["value"] == [
        "48bedd25-5a4d-4d5b-babd-56d259a41b0d"
    ]
    assert parameters["presentationAssetContainerName"]["value"] == (
        "presentation-assets"
    )
    assert parameters["acceptanceImage"]["value"].endswith(
        "@sha256:fbd1e6784ac34309c3ad98f26503f7daf832feaa7dc045aeccae8732dc602b7c"
    )
    assert parameters["presentationImage"]["value"] == (
        "athenademoa6add389.azurecr.io/athena/presentation-web"
        "@sha256:998393cc3153c7f975141a8d8a3036a1596d01f612092ad6c7158cf9d9e27025"
    )
    orchestration = _read("infra/wc013-live-acceptance/main.bicep")
    presentation = _read(
        "infra/wc013-live-acceptance/modules/presentation-web.bicep"
    )
    rejected_suffix = "@sha256:" + "0" * 64
    for bicep in (orchestration, presentation):
        assert f"rejectedImageDigestSuffix = '{rejected_suffix}'" in bicep
        assert (
            "!endsWith(presentationImage, rejectedImageDigestSuffix)"
            in bicep
        )
        assert "presentationImageDigestInvalidCharacters" in bicep
        assert re.search(
            r"length\(\s*presentationImageDigestCandidate\s*\)\s*==\s*64",
            bicep,
        )
        assert "expectedPresentationImageRegistryServer" in bicep
        assert (
            "presentationImageRegistryServer must exactly match the supplied Azure "
            "Container Registry resource ID"
            in bicep
        )
        assert "real 64-character lowercase sha256 digest" in bicep
    assert "presentationImage: validatedPresentationImage" in orchestration
    assert parameters["collectorControllerImage"]["value"] == (
        "athenademoa6add389.azurecr.io/athena/wc013-controller"
        "@sha256:a300b1ff5f679b7589599cde475ae9077f90ceec44b1f4b79bd33bfb7af2c23b"
    )
    assert (
        "!endsWith(collectorControllerImage, rejectedImageDigestSuffix)"
        in orchestration
    )
    assert "controllerImageDigestInvalidCharacters" in orchestration
    assert re.search(
        r"length\(\s*controllerImageDigestCandidate\s*\)\s*==\s*64",
        orchestration,
    )
    assert "collectorControllerImage must use the fixed ACR repository" in orchestration
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