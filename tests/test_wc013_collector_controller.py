from __future__ import annotations

import base64
import json
import time
import traceback
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from urllib.error import URLError

import pytest

import athena_context.wc013_collector_controller as controller_module
from athena_context.wc013_collector_controller import (
    AzureContainerAppsCollectorJobManagementClient,
    Wc013CollectorControllerError,
    Wc013CollectorStartContract,
    validate_deployed_wc013_collector_job,
)

JOB_RESOURCE_ID = (
    "/subscriptions/11111111-1111-1111-1111-111111111111/"
    "resourceGroups/rg-athena-fixture/providers/Microsoft.App/jobs/"
    "athena-acceptance-collector"
)
EVIDENCE_IDENTITY_RESOURCE_ID = (
    "/subscriptions/11111111-1111-1111-1111-111111111111/"
    "resourceGroups/rg-athena-fixture/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/athena-mcp-evidence"
)
EVIDENCE_CLIENT_ID = "22222222-2222-2222-2222-222222222222"


def _base64url_json(value: object) -> str:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _arm_access_token(*, expires_on: int | None = None) -> str:
    return ".".join(
        (
            _base64url_json({"alg": "RS256", "typ": "JWT"}),
            _base64url_json(
                {
                    "aud": "https://management.azure.com/",
                    "exp": expires_on or int(time.time()) + 300,
                    "oid": "44444444-4444-4444-4444-444444444444",
                }
            ),
            "syntheticsignature",
        )
    )


def _contract_payload() -> dict[str, object]:
    return {
        "schemaVersion": "athena.wc013CollectorStartContract.v1",
        "jobResourceId": JOB_RESOURCE_ID,
        "evidenceIdentityResourceId": EVIDENCE_IDENTITY_RESOURCE_ID,
        "evidenceIdentityClientId": EVIDENCE_CLIENT_ID,
        "wc007PinnedAuthorityDigest": "sha256:" + "7" * 64,
        "wc008PinnedAssertionDigest": "sha256:" + "8" * 64,
        "configuration": {
            "triggerType": "Manual",
            "replicaRetryLimit": 0,
            "replicaTimeout": 900,
            "manualTriggerConfig": {
                "parallelism": 1,
                "replicaCompletionCount": 1,
            },
            "registries": [
                {
                    "server": "athenafixture.azurecr.io",
                    "identity": EVIDENCE_IDENTITY_RESOURCE_ID,
                }
            ],
        },
        "template": {
            "containers": [
                {
                    "name": "wc013-acceptance-evidence-collector",
                    "image": (
                        "athenafixture.azurecr.io/athena/wc013-live@sha256:"
                        + "a" * 64
                    ),
                    "command": ["athena-context"],
                    "args": [
                        "wc013-evidence-collector-job",
                        "--config",
                        "/opt/athena/wc013-live/wc013-live-acceptance.json",
                        "--artifact-blob-endpoint",
                        "https://athenafixture.blob.core.windows.net",
                        "--artifact-container",
                        "collected-evidence",
                        "--emit-handoff-base64",
                    ],
                    "env": [
                        {
                            "name": "AZURE_CLIENT_ID",
                            "value": EVIDENCE_CLIENT_ID,
                        },
                        {
                            "name": "ATHENA_WC013_EVIDENCE_IDENTITY_CLIENT_ID",
                            "value": EVIDENCE_CLIENT_ID,
                        },
                        {
                            "name": "ATHENA_WC013_WC007_PINNED_AUTHORITY_DIGEST",
                            "value": "sha256:" + "7" * 64,
                        },
                        {
                            "name": "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST",
                            "value": "sha256:" + "8" * 64,
                        },
                    ],
                    "resources": {
                        "cpu": 0.5,
                        "memory": "1Gi",
                    },
                }
            ]
        },
    }


def _deployed_job(contract: Wc013CollectorStartContract) -> dict[str, object]:
    return {
        "id": contract.job_resource_id,
        "identity": {
            "type": "UserAssigned",
            "userAssignedIdentities": {
                contract.evidence_identity_resource_id: {
                    "clientId": contract.evidence_identity_client_id,
                    "principalId": "33333333-3333-3333-3333-333333333333",
                }
            },
        },
        "properties": {
            "configuration": contract.configuration.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            "template": contract.template.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
        },
    }


def _contract() -> Wc013CollectorStartContract:
    return Wc013CollectorStartContract.model_validate_json(
        json.dumps(_contract_payload())
    )


@pytest.mark.parametrize(
    ("registry_server", "image"),
    [
        (
            "mcr.microsoft.com",
            "mcr.microsoft.com/athena/wc013-live@sha256:" + "a" * 64,
        ),
        (
            "athenafixture.azurecr.io",
            "athenafixture.azurecr.io/other/wc013-live@sha256:" + "a" * 64,
        ),
        (
            "athenafixture.azurecr.io",
            "otherfixture.azurecr.io/athena/wc013-live@sha256:" + "a" * 64,
        ),
        (
            "athenafixture.azurecr.io",
            "athenafixture.azurecr.io/athena/wc013-live@sha256:" + "0" * 64,
        ),
    ],
)
def test_collector_contract_rejects_non_exact_acceptance_acr_image(
    registry_server: str,
    image: str,
) -> None:
    payload = _contract_payload()
    payload["configuration"]["registries"][0]["server"] = registry_server  # type: ignore[index]
    payload["template"]["containers"][0]["image"] = image  # type: ignore[index]

    with pytest.raises(ValueError):
        Wc013CollectorStartContract.model_validate(payload)


def test_governed_collector_start_validates_then_pins_exact_template(
    tmp_path: Path,
) -> None:
    contract = _contract()
    contract_path = tmp_path / "collector-start-contract.json"
    contract_path.write_text(contract.model_dump_json(by_alias=True), encoding="utf-8")

    class _Management:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def get_job(self, job_resource_id: str) -> dict[str, object]:
            self.calls.append(("get", job_resource_id))
            return _deployed_job(contract)

        def start_job_with_exact_template(
            self,
            job_resource_id: str,
            template: object,
        ) -> dict[str, object]:
            assert template == contract.template.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
            self.calls.append(("start-exact-template", job_resource_id))
            return {"name": "athena-acceptance-collector-abc123"}

    management = _Management()
    result = controller_module.run_governed_wc013_collector_start(
        contract_path,
        controller_identity_client_id="44444444-4444-4444-4444-444444444444",
        management=management,
    )

    assert result.execution_template_digest == contract.execution_template_digest
    assert result.execution_name == "athena-acceptance-collector-abc123"
    assert management.calls == [
        ("get", JOB_RESOURCE_ID),
        ("start-exact-template", JOB_RESOURCE_ID),
    ]


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("properties", "template", "containers", 0, "image"), "evil.invalid/x:latest"),
        (("properties", "template", "containers", 0, "command"), ["/bin/sh"]),
        (
            ("properties", "template", "containers", 0, "env", 0, "value"),
            "99999999-9999-9999-9999-999999999999",
        ),
    ],
)
def test_governed_collector_start_rejects_template_mutation(
    path: tuple[object, ...],
    replacement: object,
) -> None:
    contract = _contract()
    deployed = deepcopy(_deployed_job(contract))
    target: object = deployed
    for segment in path[:-1]:
        target = target[segment]  # type: ignore[index]
    target[path[-1]] = replacement  # type: ignore[index]

    with pytest.raises(
        Wc013CollectorControllerError,
        match="exact reviewed template",
    ):
        validate_deployed_wc013_collector_job(contract, deployed)


def test_arm_client_posts_only_the_exact_controller_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class _Credential:
        def get_token(self, scope: str) -> object:
            observed["scope"] = scope
            return SimpleNamespace(token="synthetic-token")

    class _Http:
        def request(self, **kwargs: object) -> tuple[int, str, bytes]:
            observed.update(kwargs)
            return 200, str(kwargs["url"]), b'{"name":"execution-0001"}'

    monkeypatch.setattr(
        controller_module,
        "DefaultAzureCredential",
        lambda **_kwargs: _Credential(),
    )
    monkeypatch.setattr(controller_module, "_ArmHttpStack", lambda: _Http())
    client = AzureContainerAppsCollectorJobManagementClient(
        controller_identity_client_id=(
            "44444444-4444-4444-4444-444444444444"
        )
    )

    contract = _contract()
    exact_template = contract.template.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    response = client.start_job_with_exact_template(
        JOB_RESOURCE_ID,
        exact_template,
    )

    assert response == {"name": "execution-0001"}
    assert observed["method"] == "POST"
    assert observed["body"] == json.dumps(
        exact_template,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def test_real_arm_http_stack_sends_bearer_token_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "synthetic.arm.token"
    url = f"https://management.azure.com{JOB_RESOURCE_ID}/start?api-version=2024-03-01"
    observed: dict[str, object] = {}

    class _Response:
        status = 202

        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return url

        def read(self, limit: int) -> bytes:
            observed["limit"] = limit
            return b'{"name":"execution-0002"}'

    class _Opener:
        def open(self, request: object, timeout: int) -> _Response:
            observed["authorization"] = request.get_header("Authorization")  # type: ignore[attr-defined]
            observed["timeout"] = timeout
            return _Response()

    monkeypatch.setattr(
        controller_module,
        "build_opener",
        lambda *_handlers: _Opener(),
    )

    status, response_url, payload = controller_module._ArmHttpStack().request(
        method="POST",
        url=url,
        token=token,
        body=b"{}",
    )

    assert status == 202
    assert response_url == url
    assert payload == b'{"name":"execution-0002"}'
    assert observed["authorization"] == "Bearer " + token
    assert observed["timeout"] == 30


def test_arm_client_failure_suppresses_token_from_exception_and_logs(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    token = "synthetic-token-that-must-not-leak"

    class _Credential:
        def get_token(self, _scope: str) -> object:
            return SimpleNamespace(token=token)

    class _Opener:
        def open(self, _request: object, timeout: int) -> None:
            assert timeout == 30
            raise URLError(f"upstream failure echoed {token}")

    monkeypatch.setattr(
        controller_module,
        "DefaultAzureCredential",
        lambda **_kwargs: _Credential(),
    )
    monkeypatch.setattr(
        controller_module,
        "build_opener",
        lambda *_handlers: _Opener(),
    )
    client = AzureContainerAppsCollectorJobManagementClient(
        controller_identity_client_id=(
            "44444444-4444-4444-4444-444444444444"
        )
    )

    with pytest.raises(Wc013CollectorControllerError) as captured:
        client.get_job(JOB_RESOURCE_ID)

    formatted = "".join(
        traceback.format_exception(
            type(captured.value),
            captured.value,
            captured.value.__traceback__,
        )
    )
    assert token not in str(captured.value)
    assert token not in formatted
    assert token not in caplog.text
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__


def test_arm_client_consumes_only_one_short_lived_stdin_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    token = _arm_access_token()
    stream = BytesIO((token + "\n").encode("ascii"))

    class _Http:
        def request(self, **kwargs: object) -> tuple[int, str, bytes]:
            observed.update(kwargs)
            return 200, str(kwargs["url"]), b'{"id":"fixture"}'

    monkeypatch.setattr(
        controller_module,
        "DefaultAzureCredential",
        lambda **_kwargs: pytest.fail("managed identity credential was selected"),
    )
    monkeypatch.setattr(controller_module, "_ArmHttpStack", lambda: _Http())

    client = AzureContainerAppsCollectorJobManagementClient(
        controller_identity_client_id="44444444-4444-4444-4444-444444444444",
        use_arm_access_token_stdin=True,
        arm_access_token_stream=stream,
    )
    result = client.get_job(JOB_RESOURCE_ID)

    assert result == {"id": "fixture"}
    assert observed["token"] == token
    assert stream.tell() == len(token) + 1


def test_stdin_arm_token_errors_never_disclose_token() -> None:
    token = _arm_access_token(expires_on=int(time.time()) - 1)
    with pytest.raises(Wc013CollectorControllerError) as captured:
        AzureContainerAppsCollectorJobManagementClient(
            controller_identity_client_id=(
                "44444444-4444-4444-4444-444444444444"
            ),
            use_arm_access_token_stdin=True,
            arm_access_token_stream=BytesIO(token.encode("ascii")),
        )

    formatted = "".join(
        traceback.format_exception(
            type(captured.value),
            captured.value,
            captured.value.__traceback__,
        )
    )
    assert token not in str(captured.value)
    assert token not in formatted
    assert captured.value.__cause__ is None


def test_arm_token_stream_requires_explicit_stdin_mode() -> None:
    with pytest.raises(ValueError, match="explicit stdin"):
        AzureContainerAppsCollectorJobManagementClient(
            controller_identity_client_id=(
                "44444444-4444-4444-4444-444444444444"
            ),
            arm_access_token_stream=BytesIO(_arm_access_token().encode("ascii")),
        )
