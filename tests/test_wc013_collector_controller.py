from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

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
