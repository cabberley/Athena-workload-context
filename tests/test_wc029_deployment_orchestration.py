from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from scripts import wc029_deployment_orchestration as orchestration

from test_wc024_monitoring_contract import _collector_contract
from test_wc027_guidance_authority_publisher import _publisher, _request

REQUIRED_TEMPLATE_PARAMETER_NAMES = orchestration._required_template_parameter_names
COMPILED_TEMPLATE = orchestration._compiled_template
ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "operations" / "wc029-deployment-live-validation.md"
WC013_ROOT = ROOT / "infra" / "wc013-live-acceptance" / "main.bicep"
WC016_ROOT = ROOT / "infra" / "wc016-event-reassessment" / "main.bicep"
PRODUCER_ROOT = ROOT / "infra" / "wc027-enrichment-feed-runtime" / "main.bicep"
PUBLISHER_ROOT = ROOT / "infra" / "wc027-guidance-authority-publisher" / "main.bicep"
SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000001"
RUNTIME_RESOURCE_GROUP = "rg"
PRODUCER_BROKER_PRINCIPAL_ID = "10101010-1111-4111-8111-111111111111"
PUBLISHER_BROKER_PRINCIPAL_ID = "20202020-2222-4222-8222-222222222222"
REGISTRY_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/"
    "rg-athena-platform-dev/providers/Microsoft.ContainerRegistry/registries/athena"
)
REGISTRY_ROLE_ASSIGNMENT_MODE = orchestration.ACR_LEGACY_ROLE_ASSIGNMENT_MODE
SYNTHETIC_COMPILED_TEMPLATE: dict[str, object] = {"parameters": {}}
SYNTHETIC_COMPILED_TEMPLATE_BYTES = orchestration._canonical_json_file_bytes(
    SYNTHETIC_COMPILED_TEMPLATE
)
SYNTHETIC_COMPILED_TEMPLATE_SHA256 = orchestration._sha256_bytes(SYNTHETIC_COMPILED_TEMPLATE_BYTES)


@pytest.fixture(autouse=True)
def _stub_required_template_parameter_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        orchestration,
        "_required_template_parameter_names",
        lambda _stage: set(),
    )
    monkeypatch.setattr(
        orchestration,
        "_compiled_template",
        lambda _stage: (
            dict(SYNTHETIC_COMPILED_TEMPLATE),
            SYNTHETIC_COMPILED_TEMPLATE_BYTES,
            SYNTHETIC_COMPILED_TEMPLATE_SHA256,
        ),
    )


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _write_parameters(path: Path, values: dict[str, object]) -> None:
    path.write_bytes(
        orchestration._canonical_json_file_bytes(
            {
                "$schema": (
                    "https://schema.management.azure.com/schemas/"
                    "2019-04-01/deploymentParameters.json#"
                ),
                "contentVersion": "1.0.0.0",
                "parameters": {name: {"value": value} for name, value in values.items()},
            }
        )
    )


def _empty_authority_inventory(
    *,
    container_exists: bool,
    previous_checkpoint_sha256: str | None = None,
) -> dict[str, object]:
    return {
        "schemaVersion": orchestration.AUTHORITY_BLOB_INVENTORY_SCHEMA_VERSION,
        "containerResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/"
            "providers/Microsoft.Storage/storageAccounts/"
            "athenacorrelation/blobServices/default/containers/"
            "wc027-guidance-authority"
        ),
        "containerExists": container_exists,
        "previousCheckpointSha256": previous_checkpoint_sha256,
        "currentBlobs": [],
        "versions": [],
    }


def _rotation_transition(
    assignment_resource_id: str,
    retired_principal_id: str = "99999999-9999-4999-8999-999999999999",
) -> dict[str, str]:
    return {
        "assignmentResourceId": assignment_resource_id,
        "retiredPrincipalId": retired_principal_id,
    }


def _deny_assignment(
    *,
    scope: str,
    principals: list[dict[str, str]],
    actions: list[str] | None = None,
    data_actions: list[str] | None = None,
    not_actions: list[str] | None = None,
    not_data_actions: list[str] | None = None,
    exclude_principals: list[dict[str, str]] | None = None,
    do_not_apply_to_child_scopes: bool = False,
    condition: str | None = None,
    condition_version: str | None = None,
) -> dict[str, object]:
    return {
        "id": (
            f"{scope.rstrip('/')}/providers/Microsoft.Authorization/denyAssignments/"
            "98989898-8888-4888-8888-888888888888"
        ),
        "properties": {
            "scope": scope,
            "doNotApplyToChildScopes": do_not_apply_to_child_scopes,
            "principals": principals,
            "excludePrincipals": ([] if exclude_principals is None else exclude_principals),
            "permissions": [
                {
                    "actions": [] if actions is None else actions,
                    "notActions": [] if not_actions is None else not_actions,
                    "dataActions": [] if data_actions is None else data_actions,
                    "notDataActions": ([] if not_data_actions is None else not_data_actions),
                }
            ],
            "condition": condition,
            "conditionVersion": condition_version,
        },
    }


def _synthetic_authority_checkpoint_with_pair(
    *,
    previous_checkpoint_sha256: str | None,
) -> dict[str, object]:
    authority_id = "guidance-authority-" + "a" * 32
    binding_id = "guidance-binding-" + "b" * 32
    authority_name = f"guidance-authority/{authority_id}/authority.json"
    authority_digest = f"sha256:{'a' * 64}"
    versions = [
        {
            "name": authority_name,
            "versionId": "version-authority",
            "etag": '"etag-authority"',
            "contentLength": 128,
            "contentSha256": authority_digest,
            "contract": {
                "kind": "authority",
                "artifactId": authority_id,
            },
        },
        {
            "name": f"guidance-bindings/{binding_id}/binding.json",
            "versionId": "version-binding",
            "etag": '"etag-binding"',
            "contentLength": 256,
            "contentSha256": f"sha256:{'b' * 64}",
            "contract": {
                "kind": "binding",
                "artifactId": binding_id,
                "authorityReference": {
                    "name": authority_name,
                    "versionId": "version-authority",
                    "contentSha256": authority_digest,
                },
            },
        },
    ]
    return {
        **_empty_authority_inventory(
            container_exists=True,
            previous_checkpoint_sha256=previous_checkpoint_sha256,
        ),
        "currentBlobs": [
            {
                key: item[key]
                for key in (
                    "name",
                    "versionId",
                    "etag",
                    "contentLength",
                    "contentSha256",
                )
            }
            for item in versions
        ],
        "versions": versions,
    }


def _synthetic_image_pull_evidence(
    *executions: tuple[dict[str, object], str],
) -> dict[str, object]:
    values: list[dict[str, object]] = []
    for outputs, kind in executions:
        prefix = "producer" if kind == "producer" else "publisher"
        values.append(
            {
                "kind": kind,
                "jobResourceId": outputs[f"{prefix}JobResourceId"],
                "executionName": f"synthetic-{prefix}-pull",
                "image": outputs[f"{prefix}Image"],
                "containerName": (
                    "wc027-enrichment-feed-producer"
                    if kind == "producer"
                    else "wc027-guidance-authority-publisher"
                ),
                "registryResourceId": outputs["registryResourceId"],
                "principalId": (
                    PRODUCER_BROKER_PRINCIPAL_ID
                    if kind == "producer"
                    else PUBLISHER_BROKER_PRINCIPAL_ID
                ),
                "registryRoleAssignmentMode": outputs["registryRoleAssignmentMode"],
                "registryRepositoryName": outputs["registryRepositoryName"],
                "registryPullRoleDefinitionId": outputs["registryPullRoleDefinitionId"],
                "registryPullRoleAssignmentResourceId": outputs[
                    "registryPullRoleAssignmentResourceId"
                ],
                "registryPullConditionVersion": outputs["registryPullConditionVersion"],
                "registryPullCondition": outputs["registryPullCondition"],
                "status": "Succeeded",
            }
        )
    values.sort(key=lambda item: str(item["jobResourceId"]).casefold())
    return {
        "schemaVersion": orchestration.IMAGE_PULL_EVIDENCE_SCHEMA_VERSION,
        "executions": values,
    }


def _foundation_parameter_bindings(
    values: dict[str, object],
) -> dict[str, object]:
    parameters = {name: {"value": value} for name, value in values.items()}
    return {"foundationParametersSha256": orchestration._foundation_parameter_digest(parameters)}


def _write_handoff(
    path: Path,
    stage: str,
    outputs: dict[str, object],
    *,
    parameter_bindings: dict[str, object] | None = None,
    predecessor_receipt_sha256s: dict[str, object] | None = None,
    plan_manifest_sha256: str | None = None,
    effective_parameter_sha256: str | None = None,
    authority_inventory: dict[str, object] | None = None,
    image_pull_evidence: dict[str, object] | None = None,
    revocation_assignments: list[dict[str, object]] | None = None,
) -> None:
    bindings = {} if parameter_bindings is None else parameter_bindings
    if stage != "foundation" and authority_inventory is None:
        authority_inventory = _empty_authority_inventory(
            container_exists=True,
            previous_checkpoint_sha256=f"sha256:{'d' * 64}",
        )
    if stage in {"producer", "publisher"} and image_pull_evidence is None:
        image_pull_evidence = _synthetic_image_pull_evidence((outputs, stage))
    reviewed_revocations = [] if revocation_assignments is None else revocation_assignments
    predecessor_hashes = (
        {
            predecessor: f"sha256:{str(index + 1) * 64}"
            for index, predecessor in enumerate(orchestration.EXPECTED_PREDECESSOR_STAGES[stage])
        }
        if predecessor_receipt_sha256s is None
        else predecessor_receipt_sha256s
    )
    resource_group = RUNTIME_RESOURCE_GROUP if stage in {"producer", "publisher"} else None
    path.write_text(
        json.dumps(
            {
                "schemaVersion": orchestration.HANDOFF_SCHEMA_VERSION,
                "stage": stage,
                "sourceCommit": orchestration.SOURCE_COMMIT,
                "subscriptionId": SUBSCRIPTION_ID,
                "resourceGroup": resource_group,
                "deploymentName": f"synthetic-{stage}",
                "outputs": outputs,
                "outputsSha256": orchestration._sha256_bytes(
                    orchestration._canonical_json_bytes(outputs)
                ),
                "parameterBindings": bindings,
                "parameterBindingsSha256": orchestration._sha256_bytes(
                    orchestration._canonical_json_bytes(bindings)
                ),
                "planManifestSha256": (
                    f"sha256:{'a' * 64}" if plan_manifest_sha256 is None else plan_manifest_sha256
                ),
                "predecessorReceiptSha256s": predecessor_hashes,
                "effectiveParameterSha256": (
                    f"sha256:{'b' * 64}"
                    if effective_parameter_sha256 is None
                    else effective_parameter_sha256
                ),
                "applicationMode": "create",
                "deploymentRecordSha256": f"sha256:{'c' * 64}",
                "deployedTemplateSha256": SYNTHETIC_COMPILED_TEMPLATE_SHA256,
                "authorityBlobInventory": authority_inventory,
                "authorityBlobInventorySha256": (
                    orchestration._authority_checkpoint_sha256(authority_inventory)
                ),
                "imagePullEvidence": image_pull_evidence,
                "imagePullEvidenceSha256": (
                    orchestration._image_pull_evidence_sha256(image_pull_evidence)
                ),
                "revocationAssignments": reviewed_revocations,
                "revocationAssignmentsSha256": (
                    orchestration._revocation_assignment_evidence_sha256(reviewed_revocations)
                ),
            }
        ),
        encoding="utf-8",
    )


def _write_plan(
    path: Path,
    *,
    stage: str,
    parameter_path: Path,
    what_if_path: Path,
    predecessor_handoffs: dict[str, Path],
    predecessor_receipts: dict[str, dict[str, object]],
    authority_inventory: dict[str, object] | None = None,
) -> None:
    resource_group = RUNTIME_RESOURCE_GROUP if stage in {"producer", "publisher"} else None
    compiled_template_path = path.with_name(f"{stage}.template.json")
    compiled_template_path.write_bytes(SYNTHETIC_COMPILED_TEMPLATE_BYTES)
    required_checkpoint_sha256s: dict[str, str] = {}
    if stage in {"publisher", "live-acceptance"}:
        predecessor_name = "producer" if stage == "publisher" else "publisher"
        predecessor_handoff = json.loads(
            predecessor_handoffs[predecessor_name].read_text(encoding="utf-8")
        )
        required_checkpoint_sha256s[predecessor_name] = predecessor_handoff[
            "authorityBlobInventorySha256"
        ]
    document: dict[str, object] = {
        "schemaVersion": orchestration.PLAN_SCHEMA_VERSION,
        "stage": stage,
        "sourceCommit": orchestration.SOURCE_COMMIT,
        "subscriptionId": SUBSCRIPTION_ID,
        "location": "australiaeast",
        "resourceGroup": resource_group,
        "deploymentName": f"synthetic-{stage}",
        "templatePath": str(orchestration.TEMPLATES[stage].relative_to(ROOT)).replace("\\", "/"),
        "templateSha256": orchestration._sha256_file(orchestration.TEMPLATES[stage]),
        "compiledTemplatePath": str(compiled_template_path.resolve()),
        "compiledTemplateSha256": SYNTHETIC_COMPILED_TEMPLATE_SHA256,
        "orchestratorSha256": orchestration._sha256_file(Path(orchestration.__file__).resolve()),
        "preflightSha256": orchestration._sha256_file(orchestration.PREFLIGHT_PATH),
        "baseParameterPath": str(parameter_path.resolve()),
        "baseParameterSha256": orchestration._sha256_file(parameter_path),
        "effectiveParameterPath": str(parameter_path.resolve()),
        "effectiveParameterSha256": orchestration._sha256_file(parameter_path),
        "whatIfPath": str(what_if_path.resolve()),
        "whatIfSha256": orchestration._sha256_file(what_if_path),
        "allowedChangeResourceIds": [],
        "rotationTransitionAssignments": [],
        "legacyCryptoUserMigrationAssignmentIds": [],
        "legacyAcrPullMigrationAssignments": [],
        "revocationPlanPath": None,
        "revocationPlanSha256": None,
        "reviewedRevocationPlanSha256": None,
        "revocationAssignments": [],
        "authorityBlobInventory": authority_inventory,
        "authorityBlobInventorySha256": (
            orchestration._authority_checkpoint_sha256(authority_inventory)
        ),
        "requiredAuthorityCheckpointSha256s": required_checkpoint_sha256s,
        "priorStageHandoffPath": None,
        "priorStageHandoffSha256": None,
        "priorStageReceipt": None,
        "predecessorReceipts": predecessor_receipts,
    }
    for predecessor in ("foundation", "producer", "publisher"):
        handoff_path = predecessor_handoffs.get(predecessor)
        document[f"{predecessor}HandoffPath"] = (
            None if handoff_path is None else str(handoff_path.resolve())
        )
        document[f"{predecessor}HandoffSha256"] = (
            None if handoff_path is None else orchestration._sha256_file(handoff_path)
        )
    path.write_text(json.dumps(document), encoding="utf-8")


def _write_receipt(
    path: Path,
    *,
    stage: str,
    plan_path: Path,
    handoff_path: Path,
    predecessor_receipt_sha256s: dict[str, object],
    reviewed_plan_sha256: str | None = None,
) -> None:
    plan_digest = orchestration._sha256_file(plan_path)
    path.write_text(
        json.dumps(
            {
                "schemaVersion": orchestration.RECEIPT_SCHEMA_VERSION,
                "stage": stage,
                "sourceCommit": orchestration.SOURCE_COMMIT,
                "subscriptionId": SUBSCRIPTION_ID,
                "resourceGroup": (
                    RUNTIME_RESOURCE_GROUP if stage in {"producer", "publisher"} else None
                ),
                "deploymentName": f"synthetic-{stage}",
                "planManifestPath": str(plan_path.resolve()),
                "planManifestSha256": plan_digest,
                "reviewedPlanSha256": (
                    plan_digest if reviewed_plan_sha256 is None else reviewed_plan_sha256
                ),
                "handoffPath": str(handoff_path.resolve()),
                "handoffSha256": orchestration._sha256_file(handoff_path),
                "predecessorReceiptSha256s": predecessor_receipt_sha256s,
                "effectiveParameterSha256": json.loads(handoff_path.read_text(encoding="utf-8"))[
                    "effectiveParameterSha256"
                ],
                "applicationMode": json.loads(handoff_path.read_text(encoding="utf-8"))[
                    "applicationMode"
                ],
                "deploymentRecordSha256": json.loads(handoff_path.read_text(encoding="utf-8"))[
                    "deploymentRecordSha256"
                ],
                "deployedTemplateSha256": json.loads(handoff_path.read_text(encoding="utf-8"))[
                    "deployedTemplateSha256"
                ],
                "authorityBlobInventorySha256": json.loads(
                    handoff_path.read_text(encoding="utf-8")
                )["authorityBlobInventorySha256"],
                "imagePullEvidenceSha256": json.loads(handoff_path.read_text(encoding="utf-8"))[
                    "imagePullEvidenceSha256"
                ],
                "revocationAssignmentsSha256": json.loads(handoff_path.read_text(encoding="utf-8"))[
                    "revocationAssignmentsSha256"
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_safe_plan_inputs(tmp_path: Path, stage: str) -> tuple[Path, Path]:
    parameter_path = tmp_path / f"{stage}.parameters.json"
    _write_parameters(parameter_path, {})
    what_if_path = tmp_path / f"{stage}.what-if.json"
    what_if_path.write_bytes(
        orchestration._canonical_json_file_bytes(
            {"status": "Succeeded", "properties": {"changes": []}}
        )
    )
    return parameter_path, what_if_path


def _wc013_acr_pull_assignments(
    *,
    role_assignment_mode: str = REGISTRY_ROLE_ASSIGNMENT_MODE,
) -> list[dict[str, object]]:
    role_definition_id = orchestration._acr_pull_role_definition_id(
        role_assignment_mode=role_assignment_mode,
        subscription_id=SUBSCRIPTION_ID,
    )
    image_repositories = {
        "acceptance": "athena/wc013-live",
        "evidence": "athena/wc013-live",
        "controller": "athena/wc013-controller",
        "presentation": "athena/presentation-web",
        "presentation-delivery": "athena/wc013-live",
        "wc016-detector": "athena/wc016-detector",
        "wc016-orchestrator": "athena/wc016-orchestrator",
        "wc016-notification": "athena/wc016-orchestrator",
    }
    labels = (
        orchestration.WC013_ACR_ABAC_ASSIGNMENT_LABELS
        if role_assignment_mode == orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE
        else orchestration.WC013_ACR_ASSIGNMENT_LABELS
    )
    assignments: list[dict[str, object]] = []
    principal_ids: dict[str, str] = {}
    for index, label in enumerate(labels, start=1):
        principal_key = "presentation" if label == "presentation-delivery" else label
        principal_id = principal_ids.setdefault(
            principal_key,
            f"51515151-{index:04d}-4{index:03d}-8{index:03d}-{index:012d}",
        )
        repository_name = image_repositories[label]
        image = f"athena.azurecr.io/{repository_name}@sha256:{format(index, 'x') * 64}"
        condition_version, condition = orchestration._acr_pull_assignment_condition(
            role_assignment_mode=role_assignment_mode,
            repository_name=repository_name,
        )
        assignments.append(
            {
                "label": label,
                "assignmentResourceId": (
                    orchestration._acr_pull_role_assignment_id(
                        scope=REGISTRY_RESOURCE_ID,
                        principal_id=principal_id,
                        role_definition_id=role_definition_id,
                        role_assignment_mode=role_assignment_mode,
                        repository_name=repository_name,
                    )
                ),
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "roleAssignmentMode": role_assignment_mode,
                "scope": REGISTRY_RESOURCE_ID,
                "image": image,
                "repositoryName": repository_name,
                "conditionVersion": condition_version,
                "condition": condition,
            }
        )
    return assignments


def _foundation_outputs() -> dict[str, object]:
    key_base = "https://athenawc013.vault.azure.net/keys"
    key_version = "1" * 32
    return {
        "managedEnvironmentResourceId": (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/rg-athena-wc013-live/providers/Microsoft.App/"
            "managedEnvironments/athena-wc013-live-mcp-env"
        ),
        "replayStorageAccountResourceId": (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/rg-athena-wc013-live/providers/Microsoft.Storage/"
            "storageAccounts/athenawc013"
        ),
        "keyVaultResourceId": (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/rg-athena-wc013-live/providers/Microsoft.KeyVault/"
            "vaults/athenawc013"
        ),
        "incidentAssetContainerResourceId": (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/rg-athena-wc013-live/providers/Microsoft.Storage/"
            "storageAccounts/athenawc013/blobServices/default/containers/"
            "incident-assets"
        ),
        "presentationIdentityResourceId": (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/rg-athena-wc013-live/providers/"
            "Microsoft.ManagedIdentity/userAssignedIdentities/presentation"
        ),
        "presentationHttpsUrl": "https://athena.internal.example",
        "wc016ServiceBusNamespace": "athena-wc016-events.servicebus.windows.net",
        "incidentSigningKeyUriWithVersion": (f"{key_base}/wc016-incident/{key_version}"),
        "wc016ApprovedConfiguration": {
            "wc013AcrPullAssignments": _wc013_acr_pull_assignments(),
            "wc027OrchestrationFoundation": {
                "notificationQueueName": "incident-notification-outbox",
                "incidentSigningKeyFingerprint": f"sha256:{'1' * 64}",
                "feedSigningKeyUriWithVersion": (f"{key_base}/wc027-feed/{key_version}"),
                "feedSigningKeyFingerprint": f"sha256:{'9' * 64}",
                "reportSigningKeyUriWithVersion": (f"{key_base}/wc027-report/{key_version}"),
                "reportSigningKeyFingerprint": f"sha256:{'6' * 64}",
                "guidanceSigningKeyUriWithVersion": (f"{key_base}/wc027-guidance/{key_version}"),
                "guidanceSigningKeyFingerprint": f"sha256:{'7' * 64}",
                "enrichmentSigningKeyUriWithVersion": (
                    f"{key_base}/wc027-enrichment/{key_version}"
                ),
                "enrichmentSigningKeyFingerprint": f"sha256:{'8' * 64}",
                "notificationSigningKeyUriWithVersion": (
                    f"{key_base}/wc027-notification/{key_version}"
                ),
                "notificationSigningKeyFingerprint": f"sha256:{'a' * 64}",
            },
        },
    }


def _identity(
    identity_base: str,
    name: str,
    suffix: int,
) -> dict[str, str]:
    return {
        "identityResourceId": f"{identity_base}/{name}",
        "identityClientId": f"00000000-0000-0000-0000-{suffix:012d}",
    }


def _producer_outputs() -> dict[str, object]:
    identity_base = (
        "/subscriptions/00000000-0000-0000-0000-000000000001/"
        "resourceGroups/rg/providers/Microsoft.ManagedIdentity/"
        "userAssignedIdentities"
    )
    identities = {
        name: _identity(identity_base, name, index)
        for index, name in enumerate(
            (
                "broker",
                "incident-reader",
                "feed-reader",
                "feed-writer",
                "registry-writer",
                "activation-reader",
                "trust",
                "monitoring",
                "change",
                "context",
                "intent",
                "authority",
                "report-signer",
                "guidance-signer",
                "enrichment-signer",
                "feed-signer",
                "notification-signer",
            ),
            start=10,
        )
    }
    identities["monitoring"] = {
        "identityResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/"
            "rg-athena-demo-monitoring/providers/Microsoft.ManagedIdentity/"
            "userAssignedIdentities/"
            "athena-demo-monitoring-monitoring-collector-id"
        ),
        "identityClientId": "00000000-0000-0000-0000-000000000001",
    }
    replay_storage_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athenawc013"
    )
    correlation_storage_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athenacorrelation"
    )
    service_bus_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events"
    )
    foundation = _foundation_outputs()
    external_key_version = "2" * 32

    def key_binding(
        *,
        identity_name: str,
        key_vault_key_id: str,
        fingerprint_character: str,
        logical_key_id: str | None = None,
    ) -> dict[str, str]:
        return {
            "keyId": logical_key_id or key_vault_key_id,
            "keyVaultKeyId": key_vault_key_id,
            "keyFingerprint": (f"sha256:{fingerprint_character * 64}"),
            **identities[identity_name],
        }

    monitoring_collector_contract = json.loads(
        json.dumps(
            _collector_contract().model_dump(
                mode="json",
                by_alias=True,
            )
        ).replace(
            "00000000-0000-0000-0000-000000000000",
            SUBSCRIPTION_ID,
        )
    )
    configuration = {
        "schemaVersion": ("athena.wc027EnrichmentFeedRuntimeConfiguration.v1"),
        "serviceBus": {
            "namespace": "athena-wc016-events.servicebus.windows.net",
            "triggerQueueName": "wc027-enrichment-feed-requests",
            "notificationQueueName": "incident-notification-outbox",
            "brokerIdentityClientId": identities["broker"]["identityClientId"],
            "brokerIdentityResourceId": identities["broker"]["identityResourceId"],
        },
        "incidentLifecycleAssets": {
            "blobEndpoint": "https://athenawc013.blob.core.windows.net",
            "containerName": "incident-assets",
            **identities["incident-reader"],
        },
        "enrichmentFeedAssets": {
            "blobEndpoint": "https://athenawc013.blob.core.windows.net",
            "containerName": "wc027-enrichment-feed-v2",
            "readerIdentityClientId": identities["feed-reader"]["identityClientId"],
            "readerIdentityResourceId": identities["feed-reader"]["identityResourceId"],
            "writerIdentityClientId": identities["feed-writer"]["identityClientId"],
            "writerIdentityResourceId": identities["feed-writer"]["identityResourceId"],
        },
        "feedRegistry": {
            "tableEndpoint": "https://athenawc013.table.core.windows.net",
            "tableName": "Wc027FeedRegistry",
            "partitionKey": "wc027-feed-v2",
            **identities["registry-writer"],
        },
        "guidanceActivation": {
            "tableEndpoint": "https://athenawc013.table.core.windows.net",
            "tableName": "Wc027GuidanceActivation",
            "partitionKey": "wc027-guidance-authority",
            **identities["activation-reader"],
        },
        "correlationSources": {
            "monitoring": {
                "blobEndpoint": ("https://athenacorrelation.blob.core.windows.net"),
                "containerName": "monitoring-context",
                **identities["monitoring"],
            },
            "change": {
                "blobEndpoint": ("https://athenacorrelation.blob.core.windows.net"),
                "containerName": "change-evidence",
                **identities["change"],
            },
            "contextAuthority": {
                "blobEndpoint": ("https://athenacorrelation.blob.core.windows.net"),
                "containerName": "context-authority",
                **identities["context"],
            },
            "monitoringIntent": {
                "blobEndpoint": ("https://athenacorrelation.blob.core.windows.net"),
                "containerName": "monitoring-intent",
                **identities["intent"],
            },
        },
        "guidanceAuthoritySource": {
            "blobEndpoint": ("https://athenacorrelation.blob.core.windows.net"),
            "containerName": "wc027-guidance-authority",
            **identities["authority"],
        },
        "monitoringCollectorContract": monitoring_collector_contract,
        "monitoringCollectorKey": {
            **key_binding(
                identity_name="trust",
                key_vault_key_id=(
                    "https://athena.vault.azure.net/keys/"
                    f"monitoring-collector/{external_key_version}"
                ),
                fingerprint_character="b",
            ),
            "activatedAt": "2026-09-01T00:00:00Z",
            "expiresAt": None,
        },
        "keys": {
            "incident": key_binding(
                identity_name="trust",
                key_vault_key_id=str(foundation["incidentSigningKeyUriWithVersion"]),
                fingerprint_character="1",
                logical_key_id=("synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1"),
            ),
            "correlationBinding": key_binding(
                identity_name="trust",
                key_vault_key_id=(
                    "https://athena.vault.azure.net/keys/"
                    f"correlation-binding/{external_key_version}"
                ),
                fingerprint_character="2",
            ),
            "guidanceBinding": key_binding(
                identity_name="trust",
                key_vault_key_id=(
                    f"https://athena.vault.azure.net/keys/guidance-binding/{external_key_version}"
                ),
                fingerprint_character="3",
                logical_key_id=("synthetic-key://athena/wc027-guidance-binding"),
            ),
            "change": key_binding(
                identity_name="trust",
                key_vault_key_id=(
                    f"https://athena.vault.azure.net/keys/change/{external_key_version}"
                ),
                fingerprint_character="4",
            ),
            "monitoringIntent": key_binding(
                identity_name="trust",
                key_vault_key_id=(
                    f"https://athena.vault.azure.net/keys/monitoring-intent/{external_key_version}"
                ),
                fingerprint_character="5",
            ),
            "report": key_binding(
                identity_name="report-signer",
                key_vault_key_id=str(
                    foundation["wc016ApprovedConfiguration"]["wc027OrchestrationFoundation"][
                        "reportSigningKeyUriWithVersion"
                    ]
                ),
                fingerprint_character="6",
            ),
            "guidance": key_binding(
                identity_name="guidance-signer",
                key_vault_key_id=str(
                    foundation["wc016ApprovedConfiguration"]["wc027OrchestrationFoundation"][
                        "guidanceSigningKeyUriWithVersion"
                    ]
                ),
                fingerprint_character="7",
            ),
            "enrichment": key_binding(
                identity_name="enrichment-signer",
                key_vault_key_id=str(
                    foundation["wc016ApprovedConfiguration"]["wc027OrchestrationFoundation"][
                        "enrichmentSigningKeyUriWithVersion"
                    ]
                ),
                fingerprint_character="8",
            ),
            "feed": key_binding(
                identity_name="feed-signer",
                key_vault_key_id=str(
                    foundation["wc016ApprovedConfiguration"]["wc027OrchestrationFoundation"][
                        "feedSigningKeyUriWithVersion"
                    ]
                ),
                fingerprint_character="9",
            ),
            "notification": key_binding(
                identity_name="notification-signer",
                key_vault_key_id=str(
                    foundation["wc016ApprovedConfiguration"]["wc027OrchestrationFoundation"][
                        "notificationSigningKeyUriWithVersion"
                    ]
                ),
                fingerprint_character="a",
            ),
        },
        "presentationUrl": "https://athena.internal.example",
        "deploymentBinding": {
            "attachedIdentityResourceIds": [
                value["identityResourceId"] for value in identities.values()
            ],
            "bindingEvidenceId": "11111111-1111-1111-1111-111111111111",
            "rbacResourceIds": [
                f"{service_bus_id}/queues/wc027-enrichment-feed-requests/"
                "providers/Microsoft.Authorization/roleAssignments/"
                "11111111-1111-1111-1111-111111111111"
            ],
        },
    }
    configuration_json = json.dumps(configuration, separators=(",", ":"))
    registry_role_definition_id = orchestration._acr_pull_role_definition_id(
        role_assignment_mode=REGISTRY_ROLE_ASSIGNMENT_MODE,
        subscription_id=SUBSCRIPTION_ID,
    )
    producer_image = "athena.azurecr.io/athena/wc027-enrichment-feed-producer@sha256:" + "2" * 64
    repository_name = orchestration._acr_repository_name(
        producer_image,
        REGISTRY_RESOURCE_ID,
        field="producer image",
    )
    condition_version, condition = orchestration._acr_pull_assignment_condition(
        role_assignment_mode=REGISTRY_ROLE_ASSIGNMENT_MODE,
        repository_name=repository_name,
    )
    registry_role_assignment_id = orchestration._acr_pull_role_assignment_id(
        scope=REGISTRY_RESOURCE_ID,
        principal_id=PRODUCER_BROKER_PRINCIPAL_ID,
        role_definition_id=registry_role_definition_id,
        role_assignment_mode=REGISTRY_ROLE_ASSIGNMENT_MODE,
        repository_name=repository_name,
    )
    return {
        "producerJobResourceId": (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/rg/providers/Microsoft.App/jobs/wc027-producer"
        ),
        "producerImage": producer_image,
        "deployedRuntimeConfigurationJson": configuration_json,
        "deployedRuntimeConfigurationDigest": _digest(configuration_json),
        "attachedIdentityResourceIds": configuration["deploymentBinding"][
            "attachedIdentityResourceIds"
        ],
        "bindingEvidenceDigest": configuration["deploymentBinding"]["bindingEvidenceId"],
        "feedV2WriterRoleDefinitionId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            "33333333-3333-3333-3333-333333333333"
        ),
        "feedV2ContainerName": "wc027-enrichment-feed-v2",
        "feedV2ContainerResourceId": (
            f"{replay_storage_id}/blobServices/default/containers/wc027-enrichment-feed-v2"
        ),
        "feedRegistryTableResourceId": (
            f"{replay_storage_id}/tableServices/default/tables/Wc027FeedRegistry"
        ),
        "guidanceActivationTableResourceId": (
            f"{replay_storage_id}/tableServices/default/tables/Wc027GuidanceActivation"
        ),
        "guidanceAuthoritySourceContainerResourceId": (
            f"{correlation_storage_id}/blobServices/default/containers/wc027-guidance-authority"
        ),
        "triggerQueueName": "wc027-enrichment-feed-requests",
        "triggerQueueResourceId": (f"{service_bus_id}/queues/wc027-enrichment-feed-requests"),
        "notificationQueueName": "incident-notification-outbox",
        "notificationQueueResourceId": (f"{service_bus_id}/queues/incident-notification-outbox"),
        "registryResourceId": REGISTRY_RESOURCE_ID,
        "registryRoleAssignmentMode": REGISTRY_ROLE_ASSIGNMENT_MODE,
        "registryRepositoryName": repository_name,
        "registryPullRoleDefinitionId": registry_role_definition_id,
        "registryPullRoleAssignmentResourceId": registry_role_assignment_id,
        "registryPullConditionVersion": condition_version,
        "registryPullCondition": condition,
        "namespaceHostName": "athena-wc016-events.servicebus.windows.net",
    }


def _producer_parameter_bindings() -> dict[str, object]:
    return {
        "brokerIdentityPrincipalId": PRODUCER_BROKER_PRINCIPAL_ID,
        "correlationSourceStorageAccountResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.Storage/storageAccounts/athenacorrelation"
        ),
        "correlationBindingKeyResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.KeyVault/vaults/athena/keys/correlation-binding"
        ),
        "changeKeyResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.KeyVault/vaults/athena/keys/change"
        ),
        "feedV2ReaderIdentityResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.ManagedIdentity/userAssignedIdentities/presentation"
        ),
        "guidanceBindingKeyResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.KeyVault/vaults/athena/keys/guidance-binding"
        ),
        "managedEnvironmentResourceId": _foundation_outputs()["managedEnvironmentResourceId"],
        "monitoringCollectorKeyResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.KeyVault/vaults/athena/keys/monitoring-collector"
        ),
        "monitoringIntentKeyResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.KeyVault/vaults/athena/keys/monitoring-intent"
        ),
        "registryResourceId": REGISTRY_RESOURCE_ID,
        "registryRoleAssignmentMode": REGISTRY_ROLE_ASSIGNMENT_MODE,
        "serviceBusNamespaceName": "athena-wc016-events",
        "triggerSubmitterIdentityResourceIds": [
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.ManagedIdentity/userAssignedIdentities/submitter"
        ],
    }


def _publisher_outputs(producer: dict[str, object]) -> dict[str, object]:
    identity_base = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ManagedIdentity/userAssignedIdentities"
    )
    publisher_identities = {
        name: _identity(identity_base, name, index)
        for index, name in enumerate(
            (
                "publisher-broker",
                "authority-reader",
                "authority-writer",
                "activation-writer",
                "binding-signer",
                "request-trust",
            ),
            start=40,
        )
    }
    producer_configuration = json.loads(str(producer["deployedRuntimeConfigurationJson"]))
    source_identity_ids = [
        producer_configuration["incidentLifecycleAssets"]["identityResourceId"],
        *(
            producer_configuration["correlationSources"][name]["identityResourceId"]
            for name in ("monitoring", "change", "contextAuthority", "monitoringIntent")
        ),
        producer_configuration["keys"]["guidanceBinding"]["identityResourceId"],
    ]
    attached_identity_ids = [value["identityResourceId"] for value in publisher_identities.values()]
    attached_identity_ids.extend(source_identity_ids)
    service_bus_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events"
    )
    authority_storage_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athenacorrelation"
    )
    activation_storage_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athenawc013"
    )
    binding_key_resource_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.KeyVault/vaults/athena/keys/guidance-binding"
    )
    runtime_authority = producer_configuration["guidanceAuthoritySource"]
    runtime_activation = producer_configuration["guidanceActivation"]
    runtime_binding_key = producer_configuration["keys"]["guidanceBinding"]
    configuration = {
        "schemaVersion": ("athena.wc027GuidanceAuthorityPublisherConfiguration.v1"),
        "serviceBus": {
            "namespace": "athena-wc016-events.servicebus.windows.net",
            "requestQueueName": "wc027-guidance-authority-requests",
            "triggerQueueName": "wc027-enrichment-feed-requests",
            "brokerIdentityClientId": publisher_identities["publisher-broker"]["identityClientId"],
            "brokerIdentityResourceId": publisher_identities["publisher-broker"][
                "identityResourceId"
            ],
        },
        "authorityAssets": {
            "blobEndpoint": runtime_authority["blobEndpoint"],
            "containerName": "wc027-guidance-authority",
            "readerIdentityClientId": publisher_identities["authority-reader"]["identityClientId"],
            "readerIdentityResourceId": publisher_identities["authority-reader"][
                "identityResourceId"
            ],
            "writerIdentityClientId": publisher_identities["authority-writer"]["identityClientId"],
            "writerIdentityResourceId": publisher_identities["authority-writer"][
                "identityResourceId"
            ],
        },
        "guidanceActivation": {
            "tableEndpoint": runtime_activation["tableEndpoint"],
            "tableName": "Wc027GuidanceActivation",
            "partitionKey": runtime_activation["partitionKey"],
            "identityClientId": publisher_identities["activation-writer"]["identityClientId"],
            "identityResourceId": publisher_identities["activation-writer"]["identityResourceId"],
        },
        "requestKey": {
            "keyId": ("synthetic-key://athena/wc027-guidance-publication-request"),
            "keyVaultKeyId": (f"https://athena.vault.azure.net/keys/guidance-request/{'3' * 32}"),
            "keyFingerprint": f"sha256:{'c' * 64}",
            **publisher_identities["request-trust"],
        },
        "bindingSigningKey": {
            "keyId": runtime_binding_key["keyId"],
            "keyVaultKeyId": runtime_binding_key["keyVaultKeyId"],
            "keyFingerprint": runtime_binding_key["keyFingerprint"],
            **publisher_identities["binding-signer"],
        },
        "enrichmentRuntimeConfiguration": producer_configuration,
        "deploymentBinding": {
            "attachedIdentityResourceIds": attached_identity_ids,
            "bindingEvidenceId": "22222222-2222-2222-2222-222222222222",
            "rbacResourceIds": [
                f"{service_bus_id}/queues/wc027-guidance-authority-requests/"
                "providers/Microsoft.Authorization/roleAssignments/"
                "22222222-2222-2222-2222-222222222222"
            ],
        },
    }
    configuration_json = json.dumps(configuration, separators=(",", ":"))
    registry_role_definition_id = orchestration._acr_pull_role_definition_id(
        role_assignment_mode=REGISTRY_ROLE_ASSIGNMENT_MODE,
        subscription_id=SUBSCRIPTION_ID,
    )
    publisher_image = (
        "athena.azurecr.io/athena/wc027-guidance-authority-publisher@sha256:" + "1" * 64
    )
    repository_name = orchestration._acr_repository_name(
        publisher_image,
        REGISTRY_RESOURCE_ID,
        field="publisher image",
    )
    condition_version, condition = orchestration._acr_pull_assignment_condition(
        role_assignment_mode=REGISTRY_ROLE_ASSIGNMENT_MODE,
        repository_name=repository_name,
    )
    registry_role_assignment_id = orchestration._acr_pull_role_assignment_id(
        scope=REGISTRY_RESOURCE_ID,
        principal_id=PUBLISHER_BROKER_PRINCIPAL_ID,
        role_definition_id=registry_role_definition_id,
        role_assignment_mode=REGISTRY_ROLE_ASSIGNMENT_MODE,
        repository_name=repository_name,
    )
    return {
        "publisherJobResourceId": (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/rg/providers/Microsoft.App/jobs/wc027-publisher"
        ),
        "publisherImage": publisher_image,
        "deployedPublisherConfigurationJson": configuration_json,
        "deployedPublisherConfigurationDigest": _digest(configuration_json),
        "attachedIdentityResourceIds": configuration["deploymentBinding"][
            "attachedIdentityResourceIds"
        ],
        "bindingEvidenceDigest": configuration["deploymentBinding"]["bindingEvidenceId"],
        "requestQueueName": "wc027-guidance-authority-requests",
        "requestQueueResourceId": (f"{service_bus_id}/queues/wc027-guidance-authority-requests"),
        "triggerQueueResourceId": (f"{service_bus_id}/queues/wc027-enrichment-feed-requests"),
        "authorityContainerName": "wc027-guidance-authority",
        "authorityContainerResourceId": (
            f"{authority_storage_id}/blobServices/default/containers/wc027-guidance-authority"
        ),
        "activationTableName": "Wc027GuidanceActivation",
        "activationTableResourceId": (
            f"{activation_storage_id}/tableServices/default/tables/Wc027GuidanceActivation"
        ),
        "bindingLogicalKeyId": "synthetic-key://athena/wc027-guidance-binding",
        "bindingKeyResourceId": binding_key_resource_id,
        "bindingKeyVaultKeyId": runtime_binding_key["keyVaultKeyId"],
        "registryResourceId": REGISTRY_RESOURCE_ID,
        "registryRoleAssignmentMode": REGISTRY_ROLE_ASSIGNMENT_MODE,
        "registryRepositoryName": repository_name,
        "registryPullRoleDefinitionId": registry_role_definition_id,
        "registryPullRoleAssignmentResourceId": registry_role_assignment_id,
        "registryPullConditionVersion": condition_version,
        "registryPullCondition": condition,
    }


def _publisher_parameter_bindings() -> dict[str, object]:
    return {
        "brokerIdentityPrincipalId": PUBLISHER_BROKER_PRINCIPAL_ID,
        "authorityStorageAccountResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.Storage/storageAccounts/athenacorrelation"
        ),
        "activationStorageAccountResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.Storage/storageAccounts/athenawc013"
        ),
        "bindingKeyResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.KeyVault/vaults/athena/keys/guidance-binding"
        ),
        "bindingTrustReaderIdentityResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.ManagedIdentity/userAssignedIdentities/trust"
        ),
        "managedEnvironmentResourceId": _foundation_outputs()["managedEnvironmentResourceId"],
        "registryResourceId": REGISTRY_RESOURCE_ID,
        "registryRoleAssignmentMode": REGISTRY_ROLE_ASSIGNMENT_MODE,
        "requestSubmitterIdentityResourceIds": [
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.ManagedIdentity/userAssignedIdentities/request-submitter"
        ],
        "requestKeyResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.KeyVault/vaults/athena/keys/guidance-request"
        ),
        "serviceBusNamespaceName": "athena-wc016-events",
    }


def _write_stage_bundle(
    tmp_path: Path,
    *,
    stage: str,
    outputs: dict[str, object],
    parameter_bindings: dict[str, object],
    predecessors: dict[str, dict[str, object]],
) -> dict[str, object]:
    stage_directory = tmp_path / stage
    stage_directory.mkdir()
    parameter_path, what_if_path = _write_safe_plan_inputs(
        stage_directory,
        stage,
    )
    predecessor_handoffs = {
        predecessor: Path(str(bundle["handoffPath"]))
        for predecessor, bundle in predecessors.items()
    }
    predecessor_receipts = {
        predecessor: {
            "path": str(Path(str(bundle["receiptPath"])).resolve()),
            "sha256": bundle["receiptSha256"],
            "reviewedSha256": bundle["receiptSha256"],
        }
        for predecessor, bundle in predecessors.items()
    }
    trusted_inventory = (
        None
        if stage == "foundation"
        else (
            None
            if stage == "producer"
            else predecessors["producer" if stage == "publisher" else "publisher"][
                "authorityInventory"
            ]
        )
    )
    plan_authority_inventory = (
        None
        if stage == "foundation"
        else _empty_authority_inventory(
            container_exists=stage != "producer",
            previous_checkpoint_sha256=(
                orchestration._authority_checkpoint_sha256(trusted_inventory)
            ),
        )
    )
    plan_path = stage_directory / f"{stage}.plan.json"
    _write_plan(
        plan_path,
        stage=stage,
        parameter_path=parameter_path,
        what_if_path=what_if_path,
        predecessor_handoffs=predecessor_handoffs,
        predecessor_receipts=predecessor_receipts,
        authority_inventory=plan_authority_inventory,
    )
    predecessor_hashes = {
        predecessor: bundle["receiptSha256"] for predecessor, bundle in predecessors.items()
    }
    handoff_path = stage_directory / f"{stage}.handoff.json"
    handoff_authority_inventory = (
        None
        if plan_authority_inventory is None
        else _empty_authority_inventory(
            container_exists=True,
            previous_checkpoint_sha256=(
                orchestration._authority_checkpoint_sha256(plan_authority_inventory)
            ),
        )
    )
    image_pull_evidence = (
        _synthetic_image_pull_evidence(
            (predecessors["producer"]["outputs"], "producer"),
            (predecessors["publisher"]["outputs"], "publisher"),
        )
        if stage == "live-acceptance"
        else None
    )
    _write_handoff(
        handoff_path,
        stage,
        outputs,
        parameter_bindings=parameter_bindings,
        predecessor_receipt_sha256s=predecessor_hashes,
        plan_manifest_sha256=orchestration._sha256_file(plan_path),
        effective_parameter_sha256=orchestration._sha256_file(parameter_path),
        authority_inventory=handoff_authority_inventory,
        image_pull_evidence=image_pull_evidence,
    )
    receipt_path = stage_directory / f"{stage}.receipt.json"
    _write_receipt(
        receipt_path,
        stage=stage,
        plan_path=plan_path,
        handoff_path=handoff_path,
        predecessor_receipt_sha256s=predecessor_hashes,
    )
    return {
        "planPath": plan_path,
        "handoffPath": handoff_path,
        "receiptPath": receipt_path,
        "receiptSha256": orchestration._sha256_file(receipt_path),
        "authorityInventory": handoff_authority_inventory,
        "outputs": outputs,
    }


def _accepted_readiness_outputs(
    producer: dict[str, object],
    publisher: dict[str, object],
) -> dict[str, object]:
    return {
        "wc016ApprovedConfiguration": {
            "wc013AcrPullAssignments": _wc013_acr_pull_assignments(),
            "wc027DeploymentReadiness": {
                "producer": {
                    "ready": True,
                    "jobResourceId": producer["producerJobResourceId"],
                    "image": producer["producerImage"],
                    "configurationDigest": producer["deployedRuntimeConfigurationDigest"],
                    "bindingEvidenceDigest": producer["bindingEvidenceDigest"],
                },
                "publisher": {
                    "ready": True,
                    "jobResourceId": publisher["publisherJobResourceId"],
                    "image": publisher["publisherImage"],
                    "configurationDigest": publisher["deployedPublisherConfigurationDigest"],
                    "embeddedProducerConfigurationDigest": producer[
                        "deployedRuntimeConfigurationDigest"
                    ],
                    "bindingEvidenceDigest": publisher["bindingEvidenceDigest"],
                },
            },
        }
    }


def test_governed_sequence_names_both_wc027_roots_before_final_gate() -> None:
    assert orchestration.STAGES == (
        "foundation",
        "producer",
        "publisher",
        "live-acceptance",
    )
    assert orchestration.TEMPLATES["producer"].relative_to(ROOT).as_posix() == (
        "infra/wc027-enrichment-feed-runtime/main.bicep"
    )
    assert orchestration.TEMPLATES["publisher"].relative_to(ROOT).as_posix() == (
        "infra/wc027-guidance-authority-publisher/main.bicep"
    )
    assert orchestration.TEMPLATES["live-acceptance"].relative_to(ROOT).as_posix() == (
        "infra/wc013-live-acceptance/main.bicep"
    )


def test_foundation_forces_wc027_readiness_closed(tmp_path: Path) -> None:
    parameters = tmp_path / "wc013.parameters.json"
    _write_parameters(
        parameters,
        {
            "wc016RuntimeEnabled": True,
            "wc016LegacyCleanupConfirmed": True,
            "wc027FeedV2ProducerReady": True,
            "wc027PublisherReady": True,
        },
    )

    effective = orchestration.build_effective_parameters(
        stage="foundation",
        parameter_path=parameters,
    )

    assert effective["wc027FeedV2ProducerReady"]["value"] is False
    assert effective["wc027PublisherReady"]["value"] is False
    assert effective["wc027EnrichmentFeedProducerJobResourceId"]["value"] == ""
    assert effective["wc027PublisherConfigurationJson"]["value"] == ""


def test_producer_parameters_are_bound_to_foundation_outputs(tmp_path: Path) -> None:
    foundation_path = tmp_path / "foundation.handoff.json"
    outputs = _foundation_outputs()
    _write_handoff(
        foundation_path,
        "foundation",
        outputs,
        parameter_bindings=_foundation_parameter_bindings({"wc016RuntimeEnabled": True}),
    )
    parameters = tmp_path / "producer.parameters.json"
    _write_parameters(
        parameters,
        {
            "managedEnvironmentResourceId": outputs["managedEnvironmentResourceId"],
            "replayStorageAccountName": "athenawc013",
            "serviceBusNamespaceName": "athena-wc016-events",
            "notificationQueueName": "incident-notification-outbox",
            "incidentAssetContainerName": "incident-assets",
            "feedV2ReaderIdentityResourceId": outputs["presentationIdentityResourceId"],
            "presentationUrl": outputs["presentationHttpsUrl"],
            "keyVaultName": "athenawc013",
            "incidentSigningKeyName": "wc016-incident",
            "feedSigningKeyName": "wc027-feed",
            "reportSigningKeyName": "wc027-report",
            "guidanceSigningKeyName": "wc027-guidance",
            "enrichmentSigningKeyName": "wc027-enrichment",
            "notificationSigningKeyName": "wc027-notification",
        },
    )

    effective = orchestration.build_effective_parameters(
        stage="producer",
        parameter_path=parameters,
        foundation_handoff_path=foundation_path,
    )
    assert (
        effective["managedEnvironmentResourceId"]["value"]
        == outputs["managedEnvironmentResourceId"]
    )

    document = json.loads(parameters.read_text(encoding="utf-8"))
    document["parameters"]["notificationQueueName"]["value"] = "wrong-queue"
    parameters.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(orchestration.OrchestrationError, match="notificationQueueName"):
        orchestration.build_effective_parameters(
            stage="producer",
            parameter_path=parameters,
            foundation_handoff_path=foundation_path,
        )


def test_publisher_and_acceptance_use_exact_output_handoffs(tmp_path: Path) -> None:
    foundation_path = tmp_path / "foundation.handoff.json"
    _write_handoff(
        foundation_path,
        "foundation",
        _foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings(
            {
                "wc016RuntimeEnabled": True,
                "wc016LegacyCleanupConfirmed": True,
            }
        ),
    )
    producer = _producer_outputs()
    producer_path = tmp_path / "producer.handoff.json"
    _write_handoff(
        producer_path,
        "producer",
        producer,
        parameter_bindings=_producer_parameter_bindings(),
    )
    publisher_parameters = tmp_path / "publisher.parameters.json"
    _write_parameters(publisher_parameters, {"location": "australiaeast"})

    effective_publisher = orchestration.build_effective_parameters(
        stage="publisher",
        parameter_path=publisher_parameters,
        foundation_handoff_path=foundation_path,
        producer_handoff_path=producer_path,
    )
    assert (
        effective_publisher["enrichmentRuntimeConfigurationJson"]["value"]
        == (producer["deployedRuntimeConfigurationJson"])
    )
    assert (
        effective_publisher["enrichmentRuntimeConfigurationDigest"]["value"]
        == (producer["deployedRuntimeConfigurationDigest"])
    )
    assert effective_publisher["serviceBusNamespaceName"]["value"] == ("athena-wc016-events")
    assert (
        effective_publisher["managedEnvironmentResourceId"]["value"]
        == (_foundation_outputs()["managedEnvironmentResourceId"])
    )
    assert (
        effective_publisher["authorityStorageAccountResourceId"]["value"]
        == (_producer_parameter_bindings()["correlationSourceStorageAccountResourceId"])
    )
    assert (
        effective_publisher["bindingKeyResourceId"]["value"]
        == (_producer_parameter_bindings()["guidanceBindingKeyResourceId"])
    )
    producer_configuration = json.loads(str(producer["deployedRuntimeConfigurationJson"]))
    assert (
        effective_publisher["brokerIdentityResourceId"]["value"]
        == (producer_configuration["serviceBus"]["brokerIdentityResourceId"])
    )
    assert (
        effective_publisher["bindingLogicalKeyId"]["value"]
        == (producer_configuration["keys"]["guidanceBinding"]["keyId"])
    )
    assert (
        effective_publisher["bindingKeyFingerprint"]["value"]
        == (producer_configuration["keys"]["guidanceBinding"]["keyFingerprint"])
    )
    assert effective_publisher["bindingTrustReaderIdentityResourceId"]["value"].endswith("/trust")
    assert len(effective_publisher["sourceIdentityResourceIds"]["value"]) == 5

    publisher = _publisher_outputs(producer)
    publisher_path = tmp_path / "publisher.handoff.json"
    _write_handoff(
        publisher_path,
        "publisher",
        publisher,
        parameter_bindings=_publisher_parameter_bindings(),
    )
    acceptance_parameters = tmp_path / "acceptance.parameters.json"
    _write_parameters(
        acceptance_parameters,
        {
            "wc016RuntimeEnabled": True,
            "wc016LegacyCleanupConfirmed": True,
        },
    )
    effective_acceptance = orchestration.build_effective_parameters(
        stage="live-acceptance",
        parameter_path=acceptance_parameters,
        foundation_handoff_path=foundation_path,
        producer_handoff_path=producer_path,
        publisher_handoff_path=publisher_path,
    )
    assert effective_acceptance["wc027FeedV2ProducerReady"]["value"] is True
    assert effective_acceptance["wc027PublisherReady"]["value"] is True
    assert effective_acceptance["wc027PublisherImage"]["value"] == publisher["publisherImage"]
    assert (
        effective_acceptance["wc027EnrichmentFeedProducerImage"]["value"]
        == producer["producerImage"]
    )
    assert effective_acceptance["wc016RuntimeEnabled"]["value"] is True


def test_invalid_digest_or_embedded_runtime_fails_closed(tmp_path: Path) -> None:
    foundation_path = tmp_path / "foundation.handoff.json"
    _write_handoff(
        foundation_path,
        "foundation",
        _foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings(
            {
                "wc016RuntimeEnabled": True,
                "wc016LegacyCleanupConfirmed": True,
            }
        ),
    )
    producer = _producer_outputs()
    producer["deployedRuntimeConfigurationDigest"] = f"sha256:{'0' * 64}"
    producer_path = tmp_path / "producer.handoff.json"
    _write_handoff(
        producer_path,
        "producer",
        producer,
        parameter_bindings=_producer_parameter_bindings(),
    )
    parameters = tmp_path / "publisher.parameters.json"
    _write_parameters(parameters, {"location": "australiaeast"})

    with pytest.raises(orchestration.OrchestrationError, match="does not hash"):
        orchestration.build_effective_parameters(
            stage="publisher",
            parameter_path=parameters,
            foundation_handoff_path=foundation_path,
            producer_handoff_path=producer_path,
        )


def test_stage_inputs_require_exact_governed_predecessors_and_scope() -> None:
    foundation = Path("foundation.handoff.json")
    producer = Path("producer.handoff.json")
    publisher = Path("publisher.handoff.json")

    orchestration._validate_stage_inputs(
        stage="producer",
        resource_group=RUNTIME_RESOURCE_GROUP,
        foundation_handoff_path=foundation,
        producer_handoff_path=None,
        publisher_handoff_path=None,
    )
    with pytest.raises(orchestration.OrchestrationError, match="exactly"):
        orchestration._validate_stage_inputs(
            stage="producer",
            resource_group=RUNTIME_RESOURCE_GROUP,
            foundation_handoff_path=None,
            producer_handoff_path=None,
            publisher_handoff_path=None,
        )
    with pytest.raises(orchestration.OrchestrationError, match="subscription-scoped"):
        orchestration._validate_stage_inputs(
            stage="live-acceptance",
            resource_group=RUNTIME_RESOURCE_GROUP,
            foundation_handoff_path=foundation,
            producer_handoff_path=producer,
            publisher_handoff_path=publisher,
        )


@pytest.mark.parametrize("operation", ("validate", "what-if", "create"))
def test_azure_deployment_commands_are_noninteractive(operation: str) -> None:
    command = orchestration._az_command(
        operation=operation,
        stage="producer",
        deployment_name="synthetic-producer",
        subscription_id=SUBSCRIPTION_ID,
        location="australiaeast",
        resource_group=RUNTIME_RESOURCE_GROUP,
        template_path=Path("synthetic.template.json"),
        parameter_path=Path("synthetic.parameters.json"),
    )
    no_prompt_index = command.index("--no-prompt")
    assert command[no_prompt_index + 1] == "true"


def test_azure_command_stdin_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def run(command: object, **kwargs: object) -> object:
        captured.update(kwargs)
        return orchestration.subprocess.CompletedProcess(
            command,
            0,
            stdout="{}",
            stderr="",
        )

    monkeypatch.setattr(orchestration.shutil, "which", lambda _name: "az")
    monkeypatch.setattr(orchestration.subprocess, "run", run)
    assert orchestration._run(["az", "deployment", "group", "validate"]) == "{}"
    assert captured["stdin"] is orchestration.subprocess.DEVNULL


def test_reviewed_create_uses_one_private_pinned_parameter_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parameter_path = tmp_path / "reviewed.parameters.json"
    parameter_document = {
        "$schema": (
            "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
        ),
        "contentVersion": "1.0.0.0",
        "parameters": {"reviewed": {"value": "exact"}},
    }
    parameter_path.write_bytes(orchestration._canonical_json_file_bytes(parameter_document))
    artifact = orchestration._ArtifactReader().capture_json(
        parameter_path,
        field="reviewed parameters",
    )
    parameter_path.write_bytes(
        orchestration._canonical_json_file_bytes(
            {
                **parameter_document,
                "parameters": {"reviewed": {"value": "path-swapped"}},
            }
        )
    )
    reviewed_what_if = {"status": "Succeeded", "properties": {"changes": []}}
    parameter_paths: list[Path] = []
    template_paths: list[Path] = []
    compiled_template = {"parameters": {"reviewed": {"type": "string"}}}
    compiled_template_bytes = orchestration._canonical_json_file_bytes(compiled_template)
    compiled_template_artifact = orchestration._CapturedJsonArtifact(
        path=Path("captured.template.json"),
        raw_bytes=compiled_template_bytes,
        document=compiled_template,
        sha256=orchestration._sha256_bytes(compiled_template_bytes),
        identity=orchestration._FileIdentity(2, 2, len(compiled_template_bytes), 2),
    )

    def run_json(command: object, *, field: str) -> object:
        arguments = list(command)
        pinned_path = Path(arguments[arguments.index("--parameters") + 1])
        pinned_template_path = Path(arguments[arguments.index("--template-file") + 1])
        parameter_paths.append(pinned_path)
        template_paths.append(pinned_template_path)
        assert pinned_path != parameter_path
        assert pinned_path.read_bytes() == artifact.raw_bytes
        assert pinned_template_path.read_bytes() == compiled_template_bytes
        if "what-if" in arguments:
            return reviewed_what_if
        return {
            "name": "synthetic",
            "properties": {
                "provisioningState": "Succeeded",
                "outputs": {},
            },
        }

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    monkeypatch.setattr(
        orchestration,
        "_attest_succeeded_deployment",
        lambda **_kwargs: (
            {},
            f"sha256:{'1' * 64}",
            f"sha256:{'2' * 64}",
        ),
    )
    outputs, _, _ = orchestration._execute_reviewed_deployment(
        resume_succeeded_deployment=False,
        stage="producer",
        deployment_name="synthetic",
        subscription_id=SUBSCRIPTION_ID,
        location="australiaeast",
        resource_group=RUNTIME_RESOURCE_GROUP,
        effective_parameter_artifact=artifact,
        effective_parameters={"reviewed": {"value": "exact"}},
        reviewed_what_if=reviewed_what_if,
        compiled_template_artifact=compiled_template_artifact,
        compiled_template=compiled_template,
        compiled_template_sha256=compiled_template_artifact.sha256,
    )
    assert outputs == {}
    assert len(parameter_paths) == 2
    assert parameter_paths[0] == parameter_paths[1]
    assert template_paths[0] == template_paths[1]
    assert not parameter_paths[0].exists()
    assert not template_paths[0].exists()


def test_resume_retries_attestation_without_recreating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    sleeps: list[float] = []

    def attest(**_kwargs: object) -> tuple[dict[str, object], str, str]:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise orchestration.OrchestrationError("synthetic propagation delay")
        return {}, f"sha256:{'3' * 64}", f"sha256:{'4' * 64}"

    monkeypatch.setattr(orchestration, "_attest_succeeded_deployment", attest)
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda *_args, **_kwargs: pytest.fail(
            "resume must not invoke what-if or deployment create"
        ),
    )
    monkeypatch.setattr(
        orchestration.time,
        "sleep",
        lambda seconds: sleeps.append(seconds),
    )
    artifact = orchestration._CapturedJsonArtifact(
        path=Path("captured.parameters.json"),
        raw_bytes=b"{}\n",
        document={},
        sha256=orchestration._sha256_bytes(b"{}\n"),
        identity=orchestration._FileIdentity(1, 1, 3, 1),
    )
    compiled_template_bytes = orchestration._canonical_json_file_bytes({"parameters": {}})
    compiled_template_artifact = orchestration._CapturedJsonArtifact(
        path=Path("captured.template.json"),
        raw_bytes=compiled_template_bytes,
        document={"parameters": {}},
        sha256=orchestration._sha256_bytes(compiled_template_bytes),
        identity=orchestration._FileIdentity(2, 2, len(compiled_template_bytes), 2),
    )

    outputs, _, _ = orchestration._execute_reviewed_deployment(
        resume_succeeded_deployment=True,
        stage="producer",
        deployment_name="synthetic",
        subscription_id=SUBSCRIPTION_ID,
        location="australiaeast",
        resource_group=RUNTIME_RESOURCE_GROUP,
        effective_parameter_artifact=artifact,
        effective_parameters={},
        reviewed_what_if={},
        compiled_template_artifact=compiled_template_artifact,
        compiled_template={"parameters": {}},
        compiled_template_sha256=compiled_template_artifact.sha256,
    )
    assert outputs == {}
    assert attempts == 3
    assert sleeps == [
        orchestration.READBACK_RETRY_SECONDS,
        orchestration.READBACK_RETRY_SECONDS,
    ]


def test_evidence_bundle_recovers_after_crash_between_handoff_and_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handoff_path = tmp_path / "producer-synthetic.handoff.json"
    receipt_path = tmp_path / "producer-synthetic.receipt.json"
    handoff_bytes = orchestration._canonical_json_file_bytes(
        {"applicationMode": "create", "evidence": "exact"}
    )
    receipt_bytes = orchestration._canonical_json_file_bytes(
        {"handoffSha256": orchestration._sha256_bytes(handoff_bytes)}
    )
    real_write = orchestration._write_new_bytes

    def crash_before_receipt(path: Path, raw_bytes: bytes) -> None:
        if path == receipt_path:
            raise orchestration.OrchestrationError("synthetic crash before receipt")
        real_write(path, raw_bytes)

    monkeypatch.setattr(orchestration, "_write_new_bytes", crash_before_receipt)
    with pytest.raises(orchestration.OrchestrationError, match="synthetic crash"):
        orchestration._publish_evidence_bundle(
            handoff_path=handoff_path,
            handoff_raw_bytes=handoff_bytes,
            receipt_path=receipt_path,
            receipt_raw_bytes=receipt_bytes,
            allow_existing_handoff=False,
        )
    assert handoff_path.read_bytes() == handoff_bytes
    assert not receipt_path.exists()

    monkeypatch.setattr(orchestration, "_write_new_bytes", real_write)
    orchestration._publish_evidence_bundle(
        handoff_path=handoff_path,
        handoff_raw_bytes=handoff_bytes,
        receipt_path=receipt_path,
        receipt_raw_bytes=receipt_bytes,
        allow_existing_handoff=True,
    )
    assert handoff_path.read_bytes() == handoff_bytes
    assert receipt_path.read_bytes() == receipt_bytes


def test_resume_accepts_valid_partial_handoff_and_completes_only_receipt(
    tmp_path: Path,
) -> None:
    handoff_path = tmp_path / "producer-synthetic.handoff.json"
    receipt_path = tmp_path / "producer-synthetic.receipt.json"
    _write_handoff(
        handoff_path,
        "producer",
        _producer_outputs(),
        parameter_bindings=_producer_parameter_bindings(),
    )
    handoff_bytes = handoff_path.read_bytes()
    loaded = orchestration._load_partial_handoff_for_resume(
        handoff_path=handoff_path,
        receipt_path=receipt_path,
        resume_succeeded_deployment=True,
        stage="producer",
        artifact_reader=orchestration._ArtifactReader(),
    )
    assert loaded is not None
    assert loaded["applicationMode"] == "create"

    receipt_bytes = orchestration._canonical_json_file_bytes(
        {"handoffSha256": orchestration._sha256_bytes(handoff_bytes)}
    )
    orchestration._publish_evidence_bundle(
        handoff_path=handoff_path,
        handoff_raw_bytes=handoff_bytes,
        receipt_path=receipt_path,
        receipt_raw_bytes=receipt_bytes,
        allow_existing_handoff=True,
    )
    assert handoff_path.read_bytes() == handoff_bytes
    assert receipt_path.read_bytes() == receipt_bytes


def test_nonresume_apply_rejects_partial_handoff(tmp_path: Path) -> None:
    handoff_path = tmp_path / "producer-synthetic.handoff.json"
    receipt_path = tmp_path / "producer-synthetic.receipt.json"
    _write_handoff(
        handoff_path,
        "producer",
        _producer_outputs(),
        parameter_bindings=_producer_parameter_bindings(),
    )
    with pytest.raises(orchestration.OrchestrationError, match="refusing to overwrite"):
        orchestration._load_partial_handoff_for_resume(
            handoff_path=handoff_path,
            receipt_path=receipt_path,
            resume_succeeded_deployment=False,
            stage="producer",
            artifact_reader=orchestration._ArtifactReader(),
        )


def test_immutable_evidence_write_is_atomic_on_publication_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "evidence.json"

    def fail_link(_source: object, _target: object) -> None:
        raise OSError("synthetic atomic publication failure")

    monkeypatch.setattr(orchestration.os, "link", fail_link)
    with pytest.raises(orchestration.OrchestrationError, match="atomically publish"):
        orchestration._write_new_bytes(target, b'{"synthetic":true}\n')
    assert not target.exists()
    assert list(tmp_path.glob(".evidence.json.*.tmp")) == []


def test_partial_evidence_retry_rejects_conflicting_handoff(tmp_path: Path) -> None:
    handoff_path = tmp_path / "producer-synthetic.handoff.json"
    receipt_path = tmp_path / "producer-synthetic.receipt.json"
    handoff_path.write_bytes(
        orchestration._canonical_json_file_bytes(
            {"applicationMode": "create", "evidence": "conflicting"}
        )
    )
    with pytest.raises(orchestration.OrchestrationError, match="conflicts"):
        orchestration._publish_evidence_bundle(
            handoff_path=handoff_path,
            handoff_raw_bytes=orchestration._canonical_json_file_bytes(
                {"applicationMode": "create", "evidence": "exact"}
            ),
            receipt_path=receipt_path,
            receipt_raw_bytes=orchestration._canonical_json_file_bytes(
                {"handoffSha256": f"sha256:{'1' * 64}"}
            ),
            allow_existing_handoff=True,
        )
    assert not receipt_path.exists()


def test_succeeded_deployment_attestation_binds_template_and_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiled_template = {
        "parameters": {
            "reviewed": {"type": "string"},
            "defaulted": {"type": "string", "defaultValue": "default"},
        },
        "resources": [],
    }
    compiled_digest = orchestration._sha256_bytes(
        orchestration._canonical_json_file_bytes(compiled_template)
    )
    recorded_value = "exact"

    def run_json(command: object, *, field: str) -> object:
        arguments = list(command)
        if "export" in arguments:
            return compiled_template
        return {
            "name": "synthetic",
            "properties": {
                "provisioningState": "Succeeded",
                "mode": "Incremental",
                "parameters": {
                    "reviewed": {"value": recorded_value},
                    "defaulted": {"value": "default"},
                },
                "outputs": {},
            },
        }

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    _, _, deployed_digest = orchestration._attest_succeeded_deployment(
        stage="producer",
        deployment_name="synthetic",
        subscription_id=SUBSCRIPTION_ID,
        location="australiaeast",
        resource_group=RUNTIME_RESOURCE_GROUP,
        effective_parameters={"reviewed": {"value": "exact"}},
        compiled_template=compiled_template,
        compiled_template_sha256=compiled_digest,
    )
    assert deployed_digest == compiled_digest

    recorded_value = "unreviewed"
    with pytest.raises(orchestration.OrchestrationError, match="differs from reviewed"):
        orchestration._attest_succeeded_deployment(
            stage="producer",
            deployment_name="synthetic",
            subscription_id=SUBSCRIPTION_ID,
            location="australiaeast",
            resource_group=RUNTIME_RESOURCE_GROUP,
            effective_parameters={"reviewed": {"value": "exact"}},
            compiled_template=compiled_template,
            compiled_template_sha256=compiled_digest,
        )


def test_resume_is_limited_to_fresh_producer_bootstrap() -> None:
    fresh = _empty_authority_inventory(container_exists=False)
    orchestration._validate_resume_succeeded_deployment(
        requested=True,
        stage="producer",
        reviewed_authority_inventory=fresh,
        trusted_prior_inventory=None,
    )
    with pytest.raises(orchestration.OrchestrationError, match="fresh producer"):
        orchestration._validate_resume_succeeded_deployment(
            requested=True,
            stage="publisher",
            reviewed_authority_inventory=fresh,
            trusted_prior_inventory=None,
        )
    with pytest.raises(orchestration.OrchestrationError, match="fresh producer"):
        orchestration._validate_resume_succeeded_deployment(
            requested=True,
            stage="producer",
            reviewed_authority_inventory={
                **fresh,
                "containerExists": True,
            },
            trusted_prior_inventory=None,
        )


def test_transition_arguments_are_phase_a_only() -> None:
    parser = orchestration._parser()
    common = [
        "--stage",
        "foundation",
        "--subscription",
        SUBSCRIPTION_ID,
        "--deployment-name",
        "synthetic",
        "--parameters",
        "parameters.json",
        "--evidence-directory",
        "evidence",
    ]
    assignment_id = (
        f"{REGISTRY_RESOURCE_ID}/providers/Microsoft.Authorization/roleAssignments/"
        "61616161-1111-4111-8111-111111111111"
    )
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "plan",
                *common,
                "--location",
                "australiaeast",
                "--rotation-transition-assignment",
                assignment_id,
                PRODUCER_BROKER_PRINCIPAL_ID,
            ]
        )
    revocation = parser.parse_args(
        [
            "prepare-revocation",
            *common,
            "--rotation-transition-assignment",
            assignment_id,
            PRODUCER_BROKER_PRINCIPAL_ID,
        ]
    )
    assert revocation.command == "prepare-revocation"
    final = parser.parse_args(
        [
            "plan",
            *common,
            "--location",
            "australiaeast",
            "--revocation-plan",
            "revocation.plan.json",
            "--reviewed-revocation-plan-sha256",
            f"sha256:{'1' * 64}",
        ]
    )
    assert final.revocation_plan == Path("revocation.plan.json")


def test_reviewed_revocation_plan_binds_phase_a_to_final_inputs(
    tmp_path: Path,
) -> None:
    base_path = tmp_path / "base.parameters.json"
    effective_path = tmp_path / "revocation.parameters.json"
    _write_parameters(base_path, {})
    _write_parameters(effective_path, {})
    principal_id = PRODUCER_BROKER_PRINCIPAL_ID
    role_definition_id = orchestration._acr_pull_role_definition_id(
        role_assignment_mode=REGISTRY_ROLE_ASSIGNMENT_MODE,
        subscription_id=SUBSCRIPTION_ID,
    )
    assignment_id = (
        f"{REGISTRY_RESOURCE_ID}/providers/Microsoft.Authorization/roleAssignments/"
        "62626262-2222-4222-8222-222222222222"
    )
    revocation_plan = {
        "schemaVersion": orchestration.REVOCATION_PLAN_SCHEMA_VERSION,
        "stage": "foundation",
        "sourceCommit": orchestration.SOURCE_COMMIT,
        "subscriptionId": SUBSCRIPTION_ID,
        "resourceGroup": None,
        "deploymentName": "synthetic",
        "baseParameterPath": str(base_path.resolve()),
        "baseParameterSha256": orchestration._sha256_file(base_path),
        "effectiveParameterPath": str(effective_path.resolve()),
        "effectiveParameterSha256": orchestration._sha256_file(effective_path),
        "foundationHandoffPath": None,
        "foundationHandoffSha256": None,
        "producerHandoffPath": None,
        "producerHandoffSha256": None,
        "publisherHandoffPath": None,
        "publisherHandoffSha256": None,
        "predecessorReceipts": {},
        "rotationTransitionAssignments": [_rotation_transition(assignment_id, principal_id)],
        "legacyCryptoUserMigrationAssignmentIds": [],
        "legacyAcrPullMigrationAssignments": [],
        "revocationAssignments": [
            {
                "assignmentResourceId": assignment_id,
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": REGISTRY_RESOURCE_ID,
                "conditionVersion": None,
                "condition": None,
                "registryRoleAssignmentMode": REGISTRY_ROLE_ASSIGNMENT_MODE,
            }
        ],
    }
    plan_path = tmp_path / "foundation.revocation.plan.json"
    plan_path.write_bytes(orchestration._canonical_json_file_bytes(revocation_plan))
    reader = orchestration._ArtifactReader()
    record = orchestration._load_revocation_plan(
        plan_path,
        reviewed_sha256=orchestration._sha256_file(plan_path),
        artifact_reader=reader,
    )
    base_artifact = reader.capture_json(
        base_path,
        field="base parameters",
    )
    orchestration._verify_revocation_plan_binding(
        record,
        stage="foundation",
        subscription_id=SUBSCRIPTION_ID,
        resource_group=None,
        deployment_name="synthetic",
        base_parameter_artifact=base_artifact,
        effective_parameters={},
        verified_predecessors={},
    )
    with pytest.raises(orchestration.OrchestrationError, match="final deployment scope"):
        orchestration._verify_revocation_plan_binding(
            record,
            stage="foundation",
            subscription_id=SUBSCRIPTION_ID,
            resource_group=None,
            deployment_name="different",
            base_parameter_artifact=base_artifact,
            effective_parameters={},
            verified_predecessors={},
        )

    raced_plan = json.loads(json.dumps(revocation_plan))
    raced_plan["revocationAssignments"][0]["principalId"] = "62626262-9999-4999-8999-999999999999"
    raced_path = tmp_path / "raced.revocation.plan.json"
    raced_path.write_bytes(orchestration._canonical_json_file_bytes(raced_plan))
    with pytest.raises(
        orchestration.OrchestrationError,
        match="reviewed retired principal",
    ):
        orchestration._load_revocation_plan(
            raced_path,
            reviewed_sha256=orchestration._sha256_file(raced_path),
            artifact_reader=orchestration._ArtifactReader(),
        )


def test_apply_uses_reviewed_compiled_template_without_reopening_bicep() -> None:
    source = (ROOT / "scripts" / "wc029_deployment_orchestration.py").read_text(encoding="utf-8")
    apply_source = source[source.index("def apply(") : source.index("def _parser(")]
    assert "_compiled_template(" not in apply_source
    assert "_sha256_file(TEMPLATES[stage])" not in apply_source
    assert "compiled_template_artifact.raw_bytes" in source
    assert "template_path=pinned_template.path" in source


def test_effective_parameters_require_every_required_template_parameter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        orchestration,
        "_required_template_parameter_names",
        lambda _stage: {"present", "missing"},
    )
    with pytest.raises(
        orchestration.OrchestrationError,
        match="omits required template parameters: missing",
    ):
        orchestration._verify_effective_parameter_completeness(
            "producer",
            {"present": {"value": "reviewed"}},
        )


def test_required_template_parameters_come_from_compiled_bicep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[list[str]] = []

    def run_json(command: object, *, field: str) -> object:
        captured.append(list(command))
        return {
            "parameters": {
                "required": {"type": "string"},
                "optional": {
                    "type": "string",
                    "defaultValue": "reviewed-default",
                },
            }
        }

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    monkeypatch.setattr(orchestration, "_compiled_template", COMPILED_TEMPLATE)
    assert REQUIRED_TEMPLATE_PARAMETER_NAMES("producer") == {"required"}
    assert captured[0][:3] == ["az", "bicep", "build"]


def test_parameter_completeness_precedes_azure_validation() -> None:
    source = (ROOT / "scripts" / "wc029_deployment_orchestration.py").read_text(encoding="utf-8")
    plan_start = source.index("def plan(")
    completeness = source.index(
        "_verify_effective_parameter_completeness(",
        plan_start,
    )
    pinned_parameters = source.index(
        "_materialized_private_artifact(effective_raw_bytes)",
        completeness,
    )
    azure_validate = source.index('operation="validate"', pinned_parameters)
    parameter_write = source.index("_write_new_bytes(effective_path", azure_validate)
    assert completeness < pinned_parameters < azure_validate < parameter_write


def test_subscription_boundary_rejects_cross_subscription_and_noncanonical_ids() -> None:
    governed_resource = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athena"
    )
    orchestration._canonical_subscription_resource_id(
        governed_resource,
        subscription_id=SUBSCRIPTION_ID,
        field="resource",
    )
    for invalid in (
        governed_resource.replace(
            SUBSCRIPTION_ID,
            "99999999-9999-9999-9999-999999999999",
        ),
        governed_resource.replace("/resourceGroups/", "//resourceGroups/"),
        f"{governed_resource}/",
        governed_resource.replace("/providers/", "/Providers/"),
    ):
        with pytest.raises(orchestration.OrchestrationError):
            orchestration._canonical_subscription_resource_id(
                invalid,
                subscription_id=SUBSCRIPTION_ID,
                field="resource",
            )
    with pytest.raises(
        orchestration.OrchestrationError,
        match="canonical|governed",
    ):
        orchestration._validate_subscription_boundary(
            json.dumps(
                {
                    "nestedResourceId": governed_resource.replace(
                        SUBSCRIPTION_ID,
                        "99999999-9999-9999-9999-999999999999",
                    )
                }
            ),
            subscription_id=SUBSCRIPTION_ID,
            field="embedded configuration",
        )
    for invalid_resource_value in (
        (
            " /subscriptions/99999999-9999-9999-9999-999999999999/"
            "resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/x"
        ),
        (
            "prefix/subscriptions/99999999-9999-9999-9999-999999999999/"
            "resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/x"
        ),
    ):
        with pytest.raises(orchestration.OrchestrationError):
            orchestration._validate_subscription_boundary(
                {"brokerIdentityResourceId": invalid_resource_value},
                subscription_id=SUBSCRIPTION_ID,
                field="embedded configuration",
            )
    with pytest.raises(
        orchestration.OrchestrationError,
        match="canonical|governed",
    ):
        orchestration._validate_subscription_boundary(
            {
                (
                    "prefix"
                    + governed_resource.replace(
                        SUBSCRIPTION_ID,
                        "99999999-9999-9999-9999-999999999999",
                    )
                ): {}
            },
            subscription_id=SUBSCRIPTION_ID,
            field="identity map",
        )


def test_plan_rejects_cross_subscription_parameters_before_azure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parameters = tmp_path / "foundation.parameters.json"
    _write_parameters(
        parameters,
        {
            "wc016RuntimeEnabled": True,
            "wc016LegacyCleanupConfirmed": True,
            "targetDemoWorkloadSubscriptionId": SUBSCRIPTION_ID,
            "brokerIdentityResourceId": (
                " /subscriptions/99999999-9999-9999-9999-999999999999/"
                "resourceGroups/rg/providers/Microsoft.ManagedIdentity/"
                "userAssignedIdentities/cross-subscription"
            ),
        },
    )
    monkeypatch.setattr(orchestration, "_ensure_clean_worktree", lambda: None)
    monkeypatch.setattr(
        orchestration,
        "_run",
        lambda _command: pytest.fail("Azure command ran before subscription validation"),
    )
    args = orchestration.argparse.Namespace(
        stage="foundation",
        subscription=SUBSCRIPTION_ID,
        location="australiaeast",
        resource_group=None,
        deployment_name="synthetic-foundation",
        parameters=parameters,
        evidence_directory=tmp_path / "evidence",
        foundation_handoff=None,
        foundation_receipt=None,
        foundation_reviewed_receipt_sha256=None,
        producer_handoff=None,
        producer_receipt=None,
        producer_reviewed_receipt_sha256=None,
        publisher_handoff=None,
        publisher_receipt=None,
        publisher_reviewed_receipt_sha256=None,
        allow_change=[],
    )
    with pytest.raises(orchestration.OrchestrationError, match="canonical"):
        orchestration.plan(args)


def test_required_root_outputs_cannot_be_missing_or_mismatched() -> None:
    producer = _producer_outputs()
    orchestration._producer_outputs({"outputs": producer})

    missing_producer_output = dict(producer)
    missing_producer_output.pop("triggerQueueResourceId")
    with pytest.raises(orchestration.OrchestrationError, match="triggerQueueResourceId"):
        orchestration._producer_outputs({"outputs": missing_producer_output})

    mismatched_producer_output = dict(producer)
    mismatched_producer_output["notificationQueueResourceId"] = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/wrong"
    )
    with pytest.raises(
        orchestration.OrchestrationError,
        match="notificationQueueResourceId",
    ):
        orchestration._producer_outputs({"outputs": mismatched_producer_output})

    unexpected_producer_output = dict(producer)
    unexpected_producer_output["unexpectedOutput"] = "not-reviewed"
    with pytest.raises(orchestration.OrchestrationError, match="unexpectedOutput"):
        orchestration._producer_outputs({"outputs": unexpected_producer_output})

    publisher = _publisher_outputs(producer)
    orchestration._publisher_outputs({"outputs": publisher})
    mismatched_publisher_output = dict(publisher)
    mismatched_publisher_output["bindingKeyVaultKeyId"] = (
        "https://athena.vault.azure.net/keys/guidance-binding/v2"
    )
    with pytest.raises(
        orchestration.OrchestrationError,
        match="binding key version output",
    ):
        orchestration._publisher_outputs({"outputs": mismatched_publisher_output})


@pytest.mark.parametrize("stage", ("producer", "publisher"))
def test_output_validators_use_authoritative_production_configuration_models(
    stage: str,
) -> None:
    producer = _producer_outputs()
    if stage == "producer":
        outputs = dict(producer)
        configuration_field = "deployedRuntimeConfigurationJson"
        digest_field = "deployedRuntimeConfigurationDigest"
        validator = orchestration._producer_outputs
    else:
        outputs = _publisher_outputs(producer)
        configuration_field = "deployedPublisherConfigurationJson"
        digest_field = "deployedPublisherConfigurationDigest"
        validator = orchestration._publisher_outputs
    configuration = json.loads(str(outputs[configuration_field]))
    configuration["schemaVersion"] = "athena.synthetic.invalid.v1"
    configuration_json = json.dumps(configuration, separators=(",", ":"))
    outputs[configuration_field] = configuration_json
    outputs[digest_field] = _digest(configuration_json)

    with pytest.raises(
        orchestration.OrchestrationError,
        match="authoritative production model",
    ):
        validator({"outputs": outputs})


def test_handoff_schema_rejects_unexpected_fields(tmp_path: Path) -> None:
    path = tmp_path / "foundation.handoff.json"
    _write_handoff(
        path,
        "foundation",
        _foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings({"wc016RuntimeEnabled": True}),
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    document["unexpected"] = "not-reviewed"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(orchestration.OrchestrationError, match="unexpected"):
        orchestration._load_handoff(path, expected_stage="foundation")


def test_foundation_handoff_carries_current_and_retired_acr_assignments(
    tmp_path: Path,
) -> None:
    current = _wc013_acr_pull_assignments()
    retired = [
        {
            "assignmentResourceId": (
                f"{REGISTRY_RESOURCE_ID}/providers/"
                "Microsoft.Authorization/roleAssignments/"
                "81818181-1111-4111-8111-111111111111"
            ),
            "principalId": current[0]["principalId"],
            "principalType": "ServicePrincipal",
            "roleDefinitionId": current[0]["roleDefinitionId"],
            "scope": REGISTRY_RESOURCE_ID,
            "conditionVersion": None,
            "condition": None,
            "registryRoleAssignmentMode": REGISTRY_ROLE_ASSIGNMENT_MODE,
        }
    ]
    path = tmp_path / "foundation.handoff.json"
    _write_handoff(
        path,
        "foundation",
        _foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings({}),
        revocation_assignments=retired,
    )

    handoff = orchestration._load_handoff(
        path,
        expected_stage="foundation",
    )
    outputs = orchestration._foundation_outputs(handoff)
    assert outputs["wc013AcrPullAssignments"] == current
    assert handoff["revocationAssignments"] == retired


def test_predecessor_requires_exact_plan_and_trusted_receipt(
    tmp_path: Path,
) -> None:
    foundation = _write_stage_bundle(
        tmp_path,
        stage="foundation",
        outputs=_foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings({}),
        predecessors={},
    )
    record = orchestration._load_verified_predecessor(
        expected_stage="foundation",
        handoff_path=Path(str(foundation["handoffPath"])),
        receipt_path=Path(str(foundation["receiptPath"])),
        reviewed_receipt_sha256=str(foundation["receiptSha256"]),
    )
    assert record["receiptSha256"] == foundation["receiptSha256"]

    with pytest.raises(orchestration.OrchestrationError, match="trusted approval"):
        orchestration._load_verified_predecessor(
            expected_stage="foundation",
            handoff_path=Path(str(foundation["handoffPath"])),
            receipt_path=Path(str(foundation["receiptPath"])),
            reviewed_receipt_sha256=f"sha256:{'f' * 64}",
        )

    forged_receipt = tmp_path / "forged-foundation.receipt.json"
    _write_receipt(
        forged_receipt,
        stage="foundation",
        plan_path=Path(str(foundation["planPath"])),
        handoff_path=Path(str(foundation["handoffPath"])),
        predecessor_receipt_sha256s={},
        reviewed_plan_sha256=f"sha256:{'e' * 64}",
    )
    with pytest.raises(orchestration.OrchestrationError, match="reviewed plan"):
        orchestration._load_verified_predecessor(
            expected_stage="foundation",
            handoff_path=Path(str(foundation["handoffPath"])),
            receipt_path=forged_receipt,
            reviewed_receipt_sha256=orchestration._sha256_file(forged_receipt),
        )


def test_predecessor_receipts_preserve_exact_approval_order(
    tmp_path: Path,
) -> None:
    foundation = _write_stage_bundle(
        tmp_path,
        stage="foundation",
        outputs=_foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings({}),
        predecessors={},
    )
    producer = _write_stage_bundle(
        tmp_path,
        stage="producer",
        outputs=_producer_outputs(),
        parameter_bindings=_producer_parameter_bindings(),
        predecessors={"foundation": foundation},
    )
    verified = orchestration._load_verified_predecessors(
        stage="publisher",
        handoff_paths={
            "foundation": Path(str(foundation["handoffPath"])),
            "producer": Path(str(producer["handoffPath"])),
            "publisher": None,
        },
        receipt_paths={
            "foundation": Path(str(foundation["receiptPath"])),
            "producer": Path(str(producer["receiptPath"])),
            "publisher": None,
        },
        reviewed_receipt_sha256s={
            "foundation": str(foundation["receiptSha256"]),
            "producer": str(producer["receiptSha256"]),
            "publisher": None,
        },
    )
    assert tuple(verified) == ("foundation", "producer")

    producer_receipt_path = Path(str(producer["receiptPath"]))
    producer_receipt = json.loads(producer_receipt_path.read_text(encoding="utf-8"))
    producer_receipt["predecessorReceiptSha256s"]["foundation"] = f"sha256:{'d' * 64}"
    producer_receipt_path.write_text(
        json.dumps(producer_receipt),
        encoding="utf-8",
    )
    with pytest.raises(orchestration.OrchestrationError, match="receipt chain"):
        orchestration._load_verified_predecessors(
            stage="publisher",
            handoff_paths={
                "foundation": Path(str(foundation["handoffPath"])),
                "producer": Path(str(producer["handoffPath"])),
                "publisher": None,
            },
            receipt_paths={
                "foundation": Path(str(foundation["receiptPath"])),
                "producer": producer_receipt_path,
                "publisher": None,
            },
            reviewed_receipt_sha256s={
                "foundation": str(foundation["receiptSha256"]),
                "producer": orchestration._sha256_file(producer_receipt_path),
                "publisher": None,
            },
        )


def test_prior_same_stage_receipt_carries_trusted_authority_inventory(
    tmp_path: Path,
) -> None:
    foundation = _write_stage_bundle(
        tmp_path,
        stage="foundation",
        outputs=_foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings({}),
        predecessors={},
    )
    producer = _write_stage_bundle(
        tmp_path,
        stage="producer",
        outputs=_producer_outputs(),
        parameter_bindings=_producer_parameter_bindings(),
        predecessors={"foundation": foundation},
    )
    record = orchestration._load_verified_prior_stage_inventory(
        expected_stage="producer",
        handoff_path=Path(str(producer["handoffPath"])),
        receipt_path=Path(str(producer["receiptPath"])),
        reviewed_receipt_sha256=str(producer["receiptSha256"]),
        subscription_id=SUBSCRIPTION_ID,
        resource_group=RUNTIME_RESOURCE_GROUP,
    )
    inventory = record["inventory"]
    assert inventory["containerExists"] is True
    assert inventory["currentBlobs"] == []
    assert inventory["versions"] == []


def test_authority_checkpoints_chain_through_plan_handoff_and_receipt(
    tmp_path: Path,
) -> None:
    foundation = _write_stage_bundle(
        tmp_path,
        stage="foundation",
        outputs=_foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings({}),
        predecessors={},
    )
    producer = _write_stage_bundle(
        tmp_path,
        stage="producer",
        outputs=_producer_outputs(),
        parameter_bindings=_producer_parameter_bindings(),
        predecessors={"foundation": foundation},
    )
    publisher = _write_stage_bundle(
        tmp_path,
        stage="publisher",
        outputs=_publisher_outputs(_producer_outputs()),
        parameter_bindings=_publisher_parameter_bindings(),
        predecessors={"foundation": foundation, "producer": producer},
    )

    producer_plan = json.loads(Path(str(producer["planPath"])).read_text(encoding="utf-8"))
    producer_handoff = json.loads(Path(str(producer["handoffPath"])).read_text(encoding="utf-8"))
    producer_receipt = json.loads(Path(str(producer["receiptPath"])).read_text(encoding="utf-8"))
    publisher_plan = json.loads(Path(str(publisher["planPath"])).read_text(encoding="utf-8"))
    assert producer_handoff["authorityBlobInventory"][
        "previousCheckpointSha256"
    ] == orchestration._authority_checkpoint_sha256(producer_plan["authorityBlobInventory"])
    assert (
        producer_receipt["authorityBlobInventorySha256"]
        == (producer_handoff["authorityBlobInventorySha256"])
    )
    assert (
        publisher_plan["authorityBlobInventory"]["previousCheckpointSha256"]
        == producer_handoff["authorityBlobInventorySha256"]
    )
    assert publisher_plan["requiredAuthorityCheckpointSha256s"] == {
        "producer": producer_handoff["authorityBlobInventorySha256"]
    }


def test_prior_same_stage_receipt_accepts_an_exact_older_source_lineage(
    tmp_path: Path,
) -> None:
    foundation = _write_stage_bundle(
        tmp_path,
        stage="foundation",
        outputs=_foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings({}),
        predecessors={},
    )
    producer = _write_stage_bundle(
        tmp_path,
        stage="producer",
        outputs=_producer_outputs(),
        parameter_bindings=_producer_parameter_bindings(),
        predecessors={"foundation": foundation},
    )
    historical_source_commit = "4" * 40
    plan_path = Path(str(producer["planPath"]))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["sourceCommit"] = historical_source_commit
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    plan_digest = orchestration._sha256_file(plan_path)

    handoff_path = Path(str(producer["handoffPath"]))
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    handoff["sourceCommit"] = historical_source_commit
    handoff["planManifestSha256"] = plan_digest
    handoff_path.write_text(json.dumps(handoff), encoding="utf-8")

    receipt_path = Path(str(producer["receiptPath"]))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["sourceCommit"] = historical_source_commit
    receipt["planManifestSha256"] = plan_digest
    receipt["reviewedPlanSha256"] = plan_digest
    receipt["handoffSha256"] = orchestration._sha256_file(handoff_path)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    record = orchestration._load_verified_prior_stage_inventory(
        expected_stage="producer",
        handoff_path=handoff_path,
        receipt_path=receipt_path,
        reviewed_receipt_sha256=orchestration._sha256_file(receipt_path),
        subscription_id=SUBSCRIPTION_ID,
        resource_group=RUNTIME_RESOURCE_GROUP,
    )
    assert record["inventory"]["containerExists"] is True


def test_prior_same_stage_receipt_rejects_mismatched_deployment_lineage(
    tmp_path: Path,
) -> None:
    foundation = _write_stage_bundle(
        tmp_path,
        stage="foundation",
        outputs=_foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings({}),
        predecessors={},
    )
    producer = _write_stage_bundle(
        tmp_path,
        stage="producer",
        outputs=_producer_outputs(),
        parameter_bindings=_producer_parameter_bindings(),
        predecessors={"foundation": foundation},
    )
    receipt_path = Path(str(producer["receiptPath"]))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["deploymentName"] = "synthetic-forged-producer"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    with pytest.raises(orchestration.OrchestrationError, match="plan does not match"):
        orchestration._load_verified_prior_stage_inventory(
            expected_stage="producer",
            handoff_path=Path(str(producer["handoffPath"])),
            receipt_path=receipt_path,
            reviewed_receipt_sha256=orchestration._sha256_file(receipt_path),
            subscription_id=SUBSCRIPTION_ID,
            resource_group=RUNTIME_RESOURCE_GROUP,
        )


def test_prior_same_stage_receipt_rejects_mismatched_predecessor_chain(
    tmp_path: Path,
) -> None:
    foundation = _write_stage_bundle(
        tmp_path,
        stage="foundation",
        outputs=_foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings({}),
        predecessors={},
    )
    producer = _write_stage_bundle(
        tmp_path,
        stage="producer",
        outputs=_producer_outputs(),
        parameter_bindings=_producer_parameter_bindings(),
        predecessors={"foundation": foundation},
    )
    receipt_path = Path(str(producer["receiptPath"]))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["predecessorReceiptSha256s"]["foundation"] = f"sha256:{'f' * 64}"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    with pytest.raises(orchestration.OrchestrationError, match="predecessor receipt chain"):
        orchestration._load_verified_prior_stage_inventory(
            expected_stage="producer",
            handoff_path=Path(str(producer["handoffPath"])),
            receipt_path=receipt_path,
            reviewed_receipt_sha256=orchestration._sha256_file(receipt_path),
            subscription_id=SUBSCRIPTION_ID,
            resource_group=RUNTIME_RESOURCE_GROUP,
        )


def test_prior_same_stage_receipt_rejects_inventory_for_another_container(
    tmp_path: Path,
) -> None:
    foundation = _write_stage_bundle(
        tmp_path,
        stage="foundation",
        outputs=_foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings({}),
        predecessors={},
    )
    producer = _write_stage_bundle(
        tmp_path,
        stage="producer",
        outputs=_producer_outputs(),
        parameter_bindings=_producer_parameter_bindings(),
        predecessors={"foundation": foundation},
    )
    plan_path = Path(str(producer["planPath"]))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["authorityBlobInventory"]["containerResourceId"] = str(
        plan["authorityBlobInventory"]["containerResourceId"]
    ).replace("athenacorrelation", "athenadecoy")
    plan["authorityBlobInventorySha256"] = orchestration._authority_checkpoint_sha256(
        plan["authorityBlobInventory"]
    )
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    plan_digest = orchestration._sha256_file(plan_path)

    handoff_path = Path(str(producer["handoffPath"]))
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    handoff["planManifestSha256"] = plan_digest
    handoff["authorityBlobInventory"]["containerResourceId"] = plan["authorityBlobInventory"][
        "containerResourceId"
    ]
    handoff["authorityBlobInventory"]["previousCheckpointSha256"] = (
        orchestration._authority_checkpoint_sha256(plan["authorityBlobInventory"])
    )
    handoff["authorityBlobInventorySha256"] = orchestration._authority_checkpoint_sha256(
        handoff["authorityBlobInventory"]
    )
    handoff_path.write_text(json.dumps(handoff), encoding="utf-8")

    receipt_path = Path(str(producer["receiptPath"]))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["planManifestSha256"] = plan_digest
    receipt["reviewedPlanSha256"] = plan_digest
    receipt["handoffSha256"] = orchestration._sha256_file(handoff_path)
    receipt["authorityBlobInventorySha256"] = handoff["authorityBlobInventorySha256"]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    with pytest.raises(orchestration.OrchestrationError, match="exact handoff output"):
        orchestration._load_verified_prior_stage_inventory(
            expected_stage="producer",
            handoff_path=handoff_path,
            receipt_path=receipt_path,
            reviewed_receipt_sha256=orchestration._sha256_file(receipt_path),
            subscription_id=SUBSCRIPTION_ID,
            resource_group=RUNTIME_RESOURCE_GROUP,
        )


def test_reviewed_json_artifacts_reject_reparse_links(tmp_path: Path) -> None:
    target = tmp_path / "approved.json"
    target.write_text('{"approved":true}', encoding="utf-8")
    link = tmp_path / "reviewed.json"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable in this environment: {exc}")

    with pytest.raises(orchestration.OrchestrationError, match="non-reparse regular file"):
        orchestration._read_json_artifact(
            link,
            field="reviewed test artifact",
        )


def test_artifact_reader_preserves_first_bytes_across_path_swap(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reviewed.json"
    original = {"reviewed": "original"}
    replacement = {"reviewed": "replacement"}
    path.write_bytes(orchestration._canonical_json_file_bytes(original))
    reader = orchestration._ArtifactReader()

    captured = reader.capture_json(path, field="reviewed artifact")
    path.write_bytes(orchestration._canonical_json_file_bytes(replacement))
    reused = reader.capture_json(path, field="reviewed artifact")

    assert reused is captured
    assert reused.document == original
    assert reused.raw_bytes == orchestration._canonical_json_file_bytes(original)
    assert (
        orchestration._ArtifactReader().capture_json(path, field="replacement artifact").document
        == replacement
    )


def test_private_parameter_materialization_detects_identity_replacement() -> None:
    raw_bytes = orchestration._canonical_json_file_bytes(
        {"parameters": {"reviewed": {"value": "exact"}}}
    )

    with (
        pytest.raises(
            orchestration.OrchestrationError,
            match="changed during Azure execution",
        ),
        orchestration._materialized_private_artifact(raw_bytes) as pinned,
    ):
        assert pinned.raw_bytes == raw_bytes
        pinned.path.unlink()
        pinned.path.write_bytes(raw_bytes)


def test_compiled_template_write_capture_rejects_replacement_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_document = {"resources": []}
    expected_bytes = orchestration._canonical_json_file_bytes(expected_document)
    replacement_bytes = orchestration._canonical_json_file_bytes(
        {"resources": [{"type": "Synthetic/Replacement"}]}
    )

    monkeypatch.setattr(
        orchestration,
        "_write_new_bytes",
        lambda path, _raw_bytes: path.write_bytes(replacement_bytes),
    )
    with pytest.raises(
        orchestration.OrchestrationError,
        match="exact generated bytes",
    ):
        orchestration._write_and_capture_exact_json(
            tmp_path / "compiled.template.json",
            raw_bytes=expected_bytes,
            document=expected_document,
            artifact_reader=orchestration._ArtifactReader(),
            field="compiled template",
        )


def test_live_acceptance_requires_exact_job_readback() -> None:
    producer = _producer_outputs()
    publisher = _publisher_outputs(producer)
    outputs = _accepted_readiness_outputs(producer, publisher)

    orchestration._acceptance_outputs(
        outputs,
        producer={"outputs": producer},
        publisher={"outputs": publisher},
    )

    missing_readback = json.loads(json.dumps(outputs))
    del missing_readback["wc016ApprovedConfiguration"]["wc027DeploymentReadiness"]
    with pytest.raises(orchestration.OrchestrationError, match="readiness output"):
        orchestration._acceptance_outputs(
            missing_readback,
            producer={"outputs": producer},
            publisher={"outputs": publisher},
        )

    mismatched_readback = json.loads(json.dumps(outputs))
    mismatched_readback["wc016ApprovedConfiguration"]["wc027DeploymentReadiness"]["producer"][
        "image"
    ] = str(producer["producerImage"]).replace("2" * 64, "3" * 64)
    with pytest.raises(orchestration.OrchestrationError, match="producer image"):
        orchestration._acceptance_outputs(
            mismatched_readback,
            producer={"outputs": producer},
            publisher={"outputs": publisher},
        )


def test_handoff_outputs_are_narrowed_to_exact_stage_contracts() -> None:
    foundation_outputs = _foundation_outputs()
    foundation_outputs["unrelatedRootOutput"] = "must-not-cross-handoff"
    projected_foundation = orchestration._handoff_outputs(
        "foundation",
        foundation_outputs,
    )
    assert set(projected_foundation) == orchestration.FOUNDATION_OUTPUT_FIELDS
    assert "unrelatedRootOutput" not in projected_foundation

    producer = _producer_outputs()
    publisher = _publisher_outputs(producer)
    live_outputs = _accepted_readiness_outputs(producer, publisher)
    live_outputs["unrelatedRootOutput"] = "must-not-cross-handoff"
    projected_live = orchestration._handoff_outputs(
        "live-acceptance",
        live_outputs,
    )
    assert set(projected_live) == orchestration.LIVE_ACCEPTANCE_OUTPUT_FIELDS
    assert "unrelatedRootOutput" not in projected_live
    assert projected_live["publisherInvocationBoundary"] == (
        orchestration.PUBLISHER_INVOCATION_BOUNDARY
    )


def test_job_binding_rejects_missing_identity_or_mismatched_tags() -> None:
    producer = _producer_outputs()
    configuration = json.loads(str(producer["deployedRuntimeConfigurationJson"]))
    identity_ids = configuration["deploymentBinding"]["attachedIdentityResourceIds"]
    job = {
        "id": producer["producerJobResourceId"],
        "properties": {
            "provisioningState": "Succeeded",
            "environmentId": _foundation_outputs()["managedEnvironmentResourceId"],
        },
        "identity": {
            "type": "UserAssigned",
            "userAssignedIdentities": {identity_id: {} for identity_id in identity_ids},
        },
        "tags": {
            "runtimeConfigurationDigest": producer["deployedRuntimeConfigurationDigest"],
            "bindingEvidenceDigest": producer["bindingEvidenceDigest"],
        },
    }
    orchestration._verify_job_deployment_binding(
        job=job,
        expected_resource_id=str(producer["producerJobResourceId"]),
        expected_environment_resource_id=str(_foundation_outputs()["managedEnvironmentResourceId"]),
        expected_identity_resource_ids=identity_ids,
        expected_configuration_digest=str(producer["deployedRuntimeConfigurationDigest"]),
        expected_binding_evidence=str(producer["bindingEvidenceDigest"]),
    )

    missing_identity = json.loads(json.dumps(job))
    missing_identity["identity"]["userAssignedIdentities"].pop(identity_ids[0])
    with pytest.raises(orchestration.OrchestrationError, match="identities"):
        orchestration._verify_job_deployment_binding(
            job=missing_identity,
            expected_resource_id=str(producer["producerJobResourceId"]),
            expected_environment_resource_id=str(
                _foundation_outputs()["managedEnvironmentResourceId"]
            ),
            expected_identity_resource_ids=identity_ids,
            expected_configuration_digest=str(producer["deployedRuntimeConfigurationDigest"]),
            expected_binding_evidence=str(producer["bindingEvidenceDigest"]),
        )

    mismatched_tag = json.loads(json.dumps(job))
    mismatched_tag["tags"]["bindingEvidenceDigest"] = "wrong"
    with pytest.raises(orchestration.OrchestrationError, match="binding evidence tag"):
        orchestration._verify_job_deployment_binding(
            job=mismatched_tag,
            expected_resource_id=str(producer["producerJobResourceId"]),
            expected_environment_resource_id=str(
                _foundation_outputs()["managedEnvironmentResourceId"]
            ),
            expected_identity_resource_ids=identity_ids,
            expected_configuration_digest=str(producer["deployedRuntimeConfigurationDigest"]),
            expected_binding_evidence=str(producer["bindingEvidenceDigest"]),
        )


def test_job_behavior_rejects_ungoverned_executable_or_secret_fields() -> None:
    producer = _producer_outputs()
    configuration_json = str(producer["deployedRuntimeConfigurationJson"])
    configuration = json.loads(configuration_json)
    service_bus = configuration["serviceBus"]
    job = {
        "properties": {
            "template": {
                "containers": [
                    {
                        "name": "wc027-enrichment-feed-producer",
                        "image": producer["producerImage"],
                        "command": ["athena-context"],
                        "args": ["wc027-enrichment-feed-producer"],
                        "env": [
                            {
                                "name": "AZURE_CLIENT_ID",
                                "value": service_bus["brokerIdentityClientId"],
                            },
                            {
                                "name": "ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON",
                                "value": configuration_json,
                            },
                        ],
                        "resources": {"cpu": 1, "memory": "2Gi"},
                    }
                ]
            },
            "configuration": {
                "replicaTimeout": 900,
                "replicaRetryLimit": 0,
                "triggerType": "Event",
                "eventTriggerConfig": {
                    "parallelism": 1,
                    "replicaCompletionCount": 1,
                    "scale": {
                        "minExecutions": 0,
                        "maxExecutions": 1,
                        "pollingInterval": 30,
                        "rules": [
                            {
                                "name": "wc027-signed-binding",
                                "type": "azure-servicebus",
                                "identity": service_bus["brokerIdentityResourceId"],
                                "metadata": {
                                    "namespace": "athena-wc016-events",
                                    "queueName": "wc027-enrichment-feed-requests",
                                    "messageCount": "1",
                                    "cloud": "AzurePublicCloud",
                                    "isSessionsEnabled": "true",
                                },
                            }
                        ],
                    },
                },
                "registries": [
                    {
                        "server": "athena.azurecr.io",
                        "identity": service_bus["brokerIdentityResourceId"],
                    }
                ],
            },
        }
    }
    kwargs = {
        "expected_image": str(producer["producerImage"]),
        "expected_container_name": "wc027-enrichment-feed-producer",
        "expected_command": "athena-context",
        "expected_argument": "wc027-enrichment-feed-producer",
        "expected_rule_name": "wc027-signed-binding",
        "expected_environment_name": "ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON",
        "expected_configuration_json": configuration_json,
        "broker_identity_resource_id": service_bus["brokerIdentityResourceId"],
        "namespace_host": service_bus["namespace"],
        "queue_name": service_bus["triggerQueueName"],
    }
    orchestration._verify_job_behavior(job=job, **kwargs)

    init_container_job = json.loads(json.dumps(job))
    init_container_job["properties"]["template"]["initContainers"] = [
        {"name": "unreviewed", "image": "example.invalid/extra@sha256:" + "4" * 64}
    ]
    with pytest.raises(orchestration.OrchestrationError, match="init containers"):
        orchestration._verify_job_behavior(job=init_container_job, **kwargs)

    secret_registry_job = json.loads(json.dumps(job))
    secret_registry_job["properties"]["configuration"]["secrets"] = [
        {"name": "registry-password", "value": "synthetic-not-a-secret"}
    ]
    with pytest.raises(orchestration.OrchestrationError, match="secrets"):
        orchestration._verify_job_behavior(job=secret_registry_job, **kwargs)

    extra_scaler_metadata_job = json.loads(json.dumps(job))
    extra_scaler_metadata_job["properties"]["configuration"]["eventTriggerConfig"]["scale"][
        "rules"
    ][0]["metadata"]["activationMessageCount"] = "1"
    with pytest.raises(
        orchestration.OrchestrationError,
        match="scaler metadata.*activationMessageCount",
    ):
        orchestration._verify_job_behavior(
            job=extra_scaler_metadata_job,
            **kwargs,
        )


def test_rbac_role_must_match_its_exact_resource_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    assignment_id = (
        f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "44444444-4444-4444-4444-444444444444"
    )
    principal_id = "55555555-5555-5555-5555-555555555555"

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        assert subscription_id == SUBSCRIPTION_ID
        assert resource_id == assignment_id
        return {
            "id": assignment_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": (
                    f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                    "Microsoft.Authorization/roleDefinitions/"
                    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
                ),
                "conditionVersion": "2.0",
                "condition": orchestration.BLOB_LIST_DENY_CONDITION,
                "scope": queue_scope,
            },
        }

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    with pytest.raises(orchestration.OrchestrationError, match="exact resource scope"):
        orchestration._verify_rbac_resources(
            {"rbacResourceIds": [assignment_id]},
            expected_assignments={
                assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
                    label="synthetic queue blob reader",
                    principal_id=principal_id,
                    scope=queue_scope,
                    role_definition_id=(
                        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                        "Microsoft.Authorization/roleDefinitions/"
                        f"{orchestration.BLOB_DATA_READER_ROLE_ID}"
                    ),
                    condition_version="2.0",
                    condition=orchestration.BLOB_LIST_DENY_CONDITION,
                )
            },
            subscription_id=SUBSCRIPTION_ID,
        )


@pytest.mark.parametrize(
    ("condition_version", "condition"),
    (
        (None, None),
        ("2.0", "(!(ActionMatches{'wrong'}))"),
        (
            "2.0",
            (
                f"{orchestration.BLOB_LIST_DENY_CONDITION} AND "
                f"{orchestration.BLOB_LIST_DENY_CONDITION}"
            ),
        ),
    ),
)
def test_blob_reader_requires_exact_no_list_condition(
    monkeypatch: pytest.MonkeyPatch,
    condition_version: str | None,
    condition: str | None,
) -> None:
    container_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athena/blobServices/default/"
        "containers/wc027-enrichment-feed-v2"
    )
    assignment_id = (
        f"{container_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "10101010-1010-1010-1010-101010101010"
    )
    principal_id = "20202020-2020-2020-2020-202020202020"
    properties: dict[str, object] = {
        "principalId": principal_id,
        "principalType": "ServicePrincipal",
        "roleDefinitionId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            f"{orchestration.BLOB_DATA_READER_ROLE_ID}"
        ),
        "scope": container_scope,
    }
    if condition_version is not None:
        properties["conditionVersion"] = condition_version
    if condition is not None:
        properties["condition"] = condition
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda resource_id, *, subscription_id: {
            "id": resource_id,
            "properties": properties,
        },
    )

    with pytest.raises(orchestration.OrchestrationError, match="no-Blob.List"):
        orchestration._verify_rbac_resources(
            {"rbacResourceIds": [assignment_id]},
            expected_assignments={
                assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
                    label="synthetic blob reader",
                    principal_id=principal_id,
                    scope=container_scope,
                    role_definition_id=(
                        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                        "Microsoft.Authorization/roleDefinitions/"
                        f"{orchestration.BLOB_DATA_READER_ROLE_ID}"
                    ),
                    condition_version="2.0",
                    condition=orchestration.BLOB_LIST_DENY_CONDITION,
                )
            },
            subscription_id=SUBSCRIPTION_ID,
        )


def test_blob_reader_accepts_only_canonical_no_list_condition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athena/blobServices/default/"
        "containers/wc027-enrichment-feed-v2"
    )
    assignment_id = (
        f"{container_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "30303030-3030-3030-3030-303030303030"
    )
    principal_id = "40404040-4040-4040-4040-404040404040"
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda resource_id, *, subscription_id: {
            "id": resource_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": (
                    f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                    "Microsoft.Authorization/roleDefinitions/"
                    f"{orchestration.BLOB_DATA_READER_ROLE_ID}"
                ),
                "conditionVersion": "2.0",
                "condition": orchestration.BLOB_LIST_DENY_CONDITION,
                "scope": container_scope,
            },
        },
    )

    verified = orchestration._verify_rbac_resources(
        {"rbacResourceIds": [assignment_id]},
        expected_assignments={
            assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
                label="synthetic blob reader",
                principal_id=principal_id,
                scope=container_scope,
                role_definition_id=(
                    f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                    "Microsoft.Authorization/roleDefinitions/"
                    f"{orchestration.BLOB_DATA_READER_ROLE_ID}"
                ),
                condition_version="2.0",
                condition=orchestration.BLOB_LIST_DENY_CONDITION,
            )
        },
        subscription_id=SUBSCRIPTION_ID,
    )
    assert verified == {principal_id: {assignment_id.casefold()}}


def test_custom_feed_writer_requires_canonical_no_list_condition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athena/blobServices/default/"
        "containers/wc027-enrichment-feed-v2"
    )
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "50505050-5050-5050-5050-505050505050"
    )
    assignment_id = (
        f"{container_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "60606060-6060-6060-6060-606060606060"
    )
    principal_id = "70707070-7070-7070-7070-707070707070"
    resources = {
        role_definition_id.casefold(): {
            "id": role_definition_id,
            "properties": {
                "permissions": [
                    {
                        "actions": [],
                        "notActions": [],
                        "dataActions": [
                            orchestration.BLOB_READ_DATA_ACTION,
                            (
                                "Microsoft.Storage/storageAccounts/blobServices/"
                                "containers/blobs/write"
                            ),
                        ],
                        "notDataActions": [],
                    }
                ]
            },
        },
        assignment_id.casefold(): {
            "id": assignment_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": container_scope,
            },
        },
    }
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda resource_id, *, subscription_id: resources[resource_id.casefold()],
    )

    with pytest.raises(orchestration.OrchestrationError, match="no-Blob.List"):
        orchestration._verify_rbac_resources(
            {"rbacResourceIds": [role_definition_id, assignment_id]},
            expected_assignments={
                assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
                    label="producer feed-v2 writer",
                    principal_id=principal_id,
                    scope=container_scope,
                    role_definition_id=role_definition_id,
                    condition_version="2.0",
                    condition=orchestration.BLOB_LIST_DENY_CONDITION,
                    custom_role_permissions=(orchestration.FEED_BLOB_WRITER_PERMISSION_PROFILE),
                )
            },
            subscription_id=SUBSCRIPTION_ID,
        )


@pytest.mark.parametrize(
    ("actual_profile", "expected_profile", "label"),
    (
        (
            orchestration.KEY_SIGN_PERMISSION_PROFILE,
            orchestration.KEY_VERIFY_PERMISSION_PROFILE,
            "publisher request key verifier",
        ),
        (
            orchestration.KEY_VERIFY_PERMISSION_PROFILE,
            orchestration.KEY_SIGN_PERMISSION_PROFILE,
            "publisher binding signer",
        ),
    ),
)
def test_custom_key_roles_reject_sign_verify_permission_swaps(
    monkeypatch: pytest.MonkeyPatch,
    actual_profile: orchestration._RolePermissionProfile,
    expected_profile: orchestration._RolePermissionProfile,
    label: str,
) -> None:
    key_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.KeyVault/vaults/athena/keys/guidance-binding"
    )
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "61616161-6161-6161-6161-616161616161"
    )
    assignment_id = (
        f"{key_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "62626262-6262-6262-6262-626262626262"
    )
    principal_id = "63636363-6363-6363-6363-636363636363"
    permission = {
        "actions": sorted(actual_profile.actions),
        "notActions": sorted(actual_profile.not_actions),
        "dataActions": sorted(actual_profile.data_actions),
        "notDataActions": sorted(actual_profile.not_data_actions),
    }
    resources = {
        role_definition_id.casefold(): {
            "id": role_definition_id,
            "properties": {"permissions": [permission]},
        },
        assignment_id.casefold(): {
            "id": assignment_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": key_scope,
            },
        },
    }
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda resource_id, *, subscription_id: resources[resource_id.casefold()],
    )

    with pytest.raises(
        orchestration.OrchestrationError,
        match="exact per-assignment permission profile",
    ):
        orchestration._verify_rbac_resources(
            {"rbacResourceIds": [role_definition_id, assignment_id]},
            expected_assignments={
                assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
                    label=label,
                    principal_id=principal_id,
                    scope=key_scope,
                    role_definition_id=role_definition_id,
                    custom_role_permissions=expected_profile,
                )
            },
            subscription_id=SUBSCRIPTION_ID,
        )


def test_exact_assignment_mapping_rejects_principal_swaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        f"{orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID}"
    )
    assignment_ids = [
        (
            f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
            "71717171-7171-7171-7171-717171717171"
        ),
        (
            f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
            "72727272-7272-7272-7272-727272727272"
        ),
    ]
    principal_ids = [
        "73737373-7373-7373-7373-737373737373",
        "74747474-7474-7474-7474-747474747474",
    ]
    resources = {
        assignment_ids[0].casefold(): {
            "id": assignment_ids[0],
            "properties": {
                "principalId": principal_ids[1],
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": queue_scope,
            },
        },
        assignment_ids[1].casefold(): {
            "id": assignment_ids[1],
            "properties": {
                "principalId": principal_ids[0],
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": queue_scope,
            },
        },
    }
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda resource_id, *, subscription_id: resources[resource_id.casefold()],
    )
    expected_assignments = {
        assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
            label=f"synthetic submitter {index}",
            principal_id=principal_ids[index],
            scope=queue_scope,
            role_definition_id=role_definition_id,
        )
        for index, assignment_id in enumerate(assignment_ids)
    }

    with pytest.raises(
        orchestration.OrchestrationError,
        match="exact intended principal",
    ):
        orchestration._verify_rbac_resources(
            {"rbacResourceIds": assignment_ids},
            expected_assignments=expected_assignments,
            subscription_id=SUBSCRIPTION_ID,
        )


def test_exact_assignment_mapping_rejects_unreviewed_non_blob_condition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    assignment_id = (
        f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "75757575-7575-7575-7575-757575757575"
    )
    principal_id = "76767676-7676-7676-7676-767676767676"
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        f"{orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID}"
    )
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda resource_id, *, subscription_id: {
            "id": resource_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "conditionVersion": "2.0",
                "condition": orchestration.BLOB_LIST_DENY_CONDITION,
                "scope": queue_scope,
            },
        },
    )

    with pytest.raises(
        orchestration.OrchestrationError,
        match="exact intended condition",
    ):
        orchestration._verify_rbac_resources(
            {"rbacResourceIds": [assignment_id]},
            expected_assignments={
                assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
                    label="producer trigger submitter",
                    principal_id=principal_id,
                    scope=queue_scope,
                    role_definition_id=role_definition_id,
                )
            },
            subscription_id=SUBSCRIPTION_ID,
        )


def test_both_wc027_roots_derive_complete_exact_assignment_maps() -> None:
    generic_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/synthetic-rbac"
    )

    def synthetic_uuid(index: int) -> str:
        return f"00000000-0000-0000-0000-{index:012x}"

    def role_definition_id(index: int) -> str:
        return (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            f"{synthetic_uuid(index)}"
        )

    def assignment_id(index: int) -> str:
        return (
            f"{generic_scope}/providers/Microsoft.Authorization/roleAssignments/"
            f"{synthetic_uuid(index)}"
        )

    producer = _producer_outputs()
    producer_configuration = json.loads(str(producer["deployedRuntimeConfigurationJson"]))
    producer_binding = {
        "rbacResourceIds": [
            str(producer["feedV2WriterRoleDefinitionId"]),
            *(role_definition_id(index) for index in range(1, 12)),
            *(assignment_id(index) for index in range(100, 126)),
        ]
    }
    producer_identity_ids = {
        identity_id.casefold()
        for identity_id in producer_configuration["deploymentBinding"][
            "attachedIdentityResourceIds"
        ]
    }
    producer_identity_ids.add(
        str(_producer_parameter_bindings()["feedV2ReaderIdentityResourceId"]).casefold()
    )
    producer_identity_ids.update(
        identity_id.casefold()
        for identity_id in _producer_parameter_bindings()["triggerSubmitterIdentityResourceIds"]
    )
    producer_principals = {
        identity_id: synthetic_uuid(index)
        for index, identity_id in enumerate(
            sorted(producer_identity_ids),
            start=500,
        )
    }
    producer_expected = orchestration._producer_expected_rbac_assignments(
        producer_binding,
        configuration=producer_configuration,
        outputs=producer,
        foundation_values=_foundation_outputs(),
        effective_parameters={
            name: {"value": value} for name, value in _producer_parameter_bindings().items()
        },
        principal_ids_by_identity=producer_principals,
        subscription_id=SUBSCRIPTION_ID,
    )
    producer_assignment_ids = [assignment_id(index).casefold() for index in range(100, 126)]
    assert len(producer_expected) == 26
    assert producer_expected[producer_assignment_ids[3]].label == ("producer feed-v2 writer")
    assert producer_expected[producer_assignment_ids[3]].condition == (
        orchestration.BLOB_LIST_DENY_CONDITION
    )
    assert producer_expected[producer_assignment_ids[3]].custom_role_permissions == (
        orchestration.FEED_BLOB_WRITER_PERMISSION_PROFILE
    )
    assert producer_expected[producer_assignment_ids[14]].custom_role_permissions == (
        orchestration.KEY_VERIFY_PERMISSION_PROFILE
    )
    assert producer_expected[producer_assignment_ids[20]].custom_role_permissions == (
        orchestration.KEY_SIGN_VERIFY_PERMISSION_PROFILE
    )
    assert producer_expected[producer_assignment_ids[-1]].label == ("producer trigger submitter 0")

    publisher = _publisher_outputs(producer)
    publisher_configuration = json.loads(str(publisher["deployedPublisherConfigurationJson"]))
    publisher_binding = {
        "rbacResourceIds": [
            *(role_definition_id(index) for index in range(10, 15)),
            *(assignment_id(index) for index in range(200, 210)),
        ]
    }
    publisher_identity_ids = {
        identity_id.casefold()
        for identity_id in publisher_configuration["deploymentBinding"][
            "attachedIdentityResourceIds"
        ]
    }
    publisher_identity_ids.update(
        identity_id.casefold()
        for identity_id in _publisher_parameter_bindings()["requestSubmitterIdentityResourceIds"]
    )
    publisher_principals = {
        identity_id: synthetic_uuid(index)
        for index, identity_id in enumerate(
            sorted(publisher_identity_ids),
            start=600,
        )
    }
    publisher_expected = orchestration._publisher_expected_rbac_assignments(
        publisher_binding,
        configuration=publisher_configuration,
        outputs=publisher,
        effective_parameters={
            name: {"value": value} for name, value in _publisher_parameter_bindings().items()
        },
        principal_ids_by_identity=publisher_principals,
        subscription_id=SUBSCRIPTION_ID,
    )
    publisher_assignment_ids = [assignment_id(index).casefold() for index in range(200, 210)]
    assert len(publisher_expected) == 10
    assert publisher_expected[publisher_assignment_ids[3]].label == ("publisher authority reader")
    assert publisher_expected[publisher_assignment_ids[5]].custom_role_permissions == (
        orchestration.KEY_VERIFY_PERMISSION_PROFILE
    )
    assert publisher_expected[publisher_assignment_ids[7]].custom_role_permissions == (
        orchestration.KEY_SIGN_PERMISSION_PROFILE
    )
    assert (
        publisher_expected[publisher_assignment_ids[6]].principal_id
        == (
            publisher_principals[
                str(
                    _publisher_parameter_bindings()["bindingTrustReaderIdentityResourceId"]
                ).casefold()
            ]
        )
    )
    assert publisher_expected[publisher_assignment_ids[-1]].label == (
        "publisher request submitter 0"
    )


@pytest.mark.parametrize(
    ("transition_path", "publisher_assignment_present"),
    (
        ("fresh-deploy", False),
        ("partial-recovery", True),
        ("producer-upgrade", True),
        ("publisher-retry", True),
    ),
)
def test_prospective_publisher_sender_transition_is_exact(
    monkeypatch: pytest.MonkeyPatch,
    transition_path: str,
    publisher_assignment_present: bool,
) -> None:
    broker_identity_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ManagedIdentity/userAssignedIdentities/broker"
    )
    principal_id = "91919191-1111-4111-8111-111111111111"
    trigger_queue_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    own_assignment_id = (
        f"{trigger_queue_id}/providers/Microsoft.Authorization/roleAssignments/"
        "91919191-2222-4222-8222-222222222222"
    )
    prospective = orchestration._prospective_publisher_sender_assignment(
        configuration={"serviceBus": {"brokerIdentityResourceId": broker_identity_id}},
        outputs={"triggerQueueResourceId": trigger_queue_id},
        principal_ids_by_identity={broker_identity_id.casefold(): principal_id},
        subscription_id=SUBSCRIPTION_ID,
    )
    prospective_id, expected = next(iter(prospective.items()))
    prospective_resource_id = orchestration._deterministic_role_assignment_id(
        trigger_queue_id,
        broker_identity_id,
        orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID,
    )
    assert prospective_id == prospective_resource_id.casefold()
    assert prospective_resource_id.endswith(
        "/providers/Microsoft.Authorization/roleAssignments/f21ca640-0463-57c6-97a0-23eea6715f9c"
    )
    effective_assignments = [{"id": own_assignment_id, "scope": trigger_queue_id}]
    if publisher_assignment_present:
        effective_assignments.append({"id": prospective_resource_id, "scope": trigger_queue_id})
    evidence = {principal_id: effective_assignments}
    producer_expected = {
        own_assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
            label="producer trigger receiver",
            principal_id=principal_id,
            scope=trigger_queue_id,
            role_definition_id=(
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{orchestration.SERVICE_BUS_DATA_RECEIVER_ROLE_ID}"
            ),
        )
    }

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        if resource_id.casefold() == own_assignment_id.casefold():
            return {
                "id": own_assignment_id,
                "properties": {
                    "principalId": principal_id,
                    "principalType": "ServicePrincipal",
                    "roleDefinitionId": producer_expected[
                        own_assignment_id.casefold()
                    ].role_definition_id,
                    "scope": trigger_queue_id,
                },
            }
        assert transition_path != "fresh-deploy"
        assert resource_id == prospective_resource_id
        return {
            "id": prospective_resource_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": expected.role_definition_id,
                "scope": trigger_queue_id,
            },
        }

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda command, *, field: effective_assignments,
    )
    additional = orchestration._verify_trigger_queue_assignment_set(
        producer_expected_assignments=producer_expected,
        prospective_publisher_assignments=prospective,
        approved_transitions=[],
        require_transition_revoked=True,
        subscription_id=SUBSCRIPTION_ID,
    )
    assert bool(additional) is publisher_assignment_present
    orchestration._verify_exact_effective_assignments(
        {principal_id: {own_assignment_id.casefold()}},
        additional_allowed_assignments_by_principal=additional,
        subscription_id=SUBSCRIPTION_ID,
        effective_assignments_by_principal=evidence,
    )


def test_prospective_publisher_sender_rejects_nondeterministic_assignment_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker_identity_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ManagedIdentity/userAssignedIdentities/broker"
    )
    principal_id = "92929292-1111-4111-8111-111111111111"
    trigger_queue_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    own_assignment_id = (
        f"{trigger_queue_id}/providers/Microsoft.Authorization/roleAssignments/"
        "92929292-2222-4222-8222-222222222222"
    )
    decoy_assignment_id = (
        f"{trigger_queue_id}/providers/Microsoft.Authorization/roleAssignments/"
        "92929292-3333-4333-8333-333333333333"
    )
    prospective = orchestration._prospective_publisher_sender_assignment(
        configuration={"serviceBus": {"brokerIdentityResourceId": broker_identity_id}},
        outputs={"triggerQueueResourceId": trigger_queue_id},
        principal_ids_by_identity={broker_identity_id.casefold(): principal_id},
        subscription_id=SUBSCRIPTION_ID,
    )
    producer_expected = {
        own_assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
            label="producer trigger receiver",
            principal_id=principal_id,
            scope=trigger_queue_id,
            role_definition_id=(
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{orchestration.SERVICE_BUS_DATA_RECEIVER_ROLE_ID}"
            ),
        )
    }
    scope_assignments = [
        {"id": own_assignment_id, "scope": trigger_queue_id},
        {"id": decoy_assignment_id, "scope": trigger_queue_id},
    ]
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda *_args, **_kwargs: pytest.fail(
            "a nondeterministic publisher assignment must not be read as approved"
        ),
    )
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda command, *, field: scope_assignments,
    )

    with pytest.raises(
        orchestration.OrchestrationError,
        match="unreviewed or obsolete role assignment",
    ):
        orchestration._verify_trigger_queue_assignment_set(
            producer_expected_assignments=producer_expected,
            prospective_publisher_assignments=prospective,
            approved_transitions=[],
            require_transition_revoked=True,
            subscription_id=SUBSCRIPTION_ID,
        )


def test_prospective_publisher_sender_rejects_wrong_existing_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker_identity_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ManagedIdentity/userAssignedIdentities/broker"
    )
    expected_principal_id = "93939393-1111-4111-8111-111111111111"
    wrong_principal_id = "93939393-2222-4222-8222-222222222222"
    trigger_queue_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    own_assignment_id = (
        f"{trigger_queue_id}/providers/Microsoft.Authorization/roleAssignments/"
        "93939393-3333-4333-8333-333333333333"
    )
    producer_expected = {
        own_assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
            label="producer trigger receiver",
            principal_id=expected_principal_id,
            scope=trigger_queue_id,
            role_definition_id=(
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{orchestration.SERVICE_BUS_DATA_RECEIVER_ROLE_ID}"
            ),
        )
    }
    prospective = orchestration._prospective_publisher_sender_assignment(
        configuration={"serviceBus": {"brokerIdentityResourceId": broker_identity_id}},
        outputs={"triggerQueueResourceId": trigger_queue_id},
        principal_ids_by_identity={broker_identity_id.casefold(): expected_principal_id},
        subscription_id=SUBSCRIPTION_ID,
    )
    prospective_id, expected = next(iter(prospective.items()))
    prospective_resource_id = orchestration._deterministic_role_assignment_id(
        trigger_queue_id,
        broker_identity_id,
        orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID,
    )
    assert prospective_id == prospective_resource_id.casefold()
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda command, *, field: [
            {"id": own_assignment_id, "scope": trigger_queue_id},
            {"id": prospective_resource_id, "scope": trigger_queue_id},
        ],
    )

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        if resource_id.casefold() == own_assignment_id.casefold():
            return {
                "id": own_assignment_id,
                "properties": {
                    "principalId": expected_principal_id,
                    "principalType": "ServicePrincipal",
                    "roleDefinitionId": producer_expected[
                        own_assignment_id.casefold()
                    ].role_definition_id,
                    "scope": trigger_queue_id,
                },
            }
        return {
            "id": resource_id,
            "properties": {
                "principalId": wrong_principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": expected.role_definition_id,
                "scope": trigger_queue_id,
            },
        }

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)

    with pytest.raises(
        orchestration.OrchestrationError,
        match="exact intended principal",
    ):
        orchestration._verify_trigger_queue_assignment_set(
            producer_expected_assignments=producer_expected,
            prospective_publisher_assignments=prospective,
            approved_transitions=[],
            require_transition_revoked=True,
            subscription_id=SUBSCRIPTION_ID,
        )


def test_broker_identity_rotation_requires_controlled_stale_sender_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_broker_identity_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ManagedIdentity/userAssignedIdentities/current-broker"
    )
    retired_broker_identity_id = current_broker_identity_id.replace(
        "current-broker",
        "retired-broker",
    )
    current_principal_id = "95959595-1111-4111-8111-111111111111"
    retired_principal_id = "95959595-2222-4222-8222-222222222222"
    trigger_queue_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    current_receiver_id = (
        f"{trigger_queue_id}/providers/Microsoft.Authorization/roleAssignments/"
        "95959595-3333-4333-8333-333333333333"
    )
    retired_sender_id = (
        f"{trigger_queue_id}/providers/Microsoft.Authorization/roleAssignments/"
        f"{
            orchestration._arm_guid(
                trigger_queue_id,
                retired_broker_identity_id,
                orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID,
            )
        }"
    )
    producer_expected = {
        current_receiver_id.casefold(): orchestration._ExpectedRoleAssignment(
            label="producer trigger receiver",
            principal_id=current_principal_id,
            scope=trigger_queue_id,
            role_definition_id=(
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{orchestration.SERVICE_BUS_DATA_RECEIVER_ROLE_ID}"
            ),
        )
    }
    prospective = orchestration._prospective_publisher_sender_assignment(
        configuration={"serviceBus": {"brokerIdentityResourceId": current_broker_identity_id}},
        outputs={"triggerQueueResourceId": trigger_queue_id},
        principal_ids_by_identity={current_broker_identity_id.casefold(): current_principal_id},
        subscription_id=SUBSCRIPTION_ID,
    )
    scope_assignments = [
        {"id": current_receiver_id, "scope": trigger_queue_id},
        {"id": retired_sender_id, "scope": trigger_queue_id},
    ]
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda command, *, field: list(scope_assignments),
    )

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        if resource_id.casefold() == current_receiver_id.casefold():
            return {
                "id": current_receiver_id,
                "properties": {
                    "principalId": current_principal_id,
                    "principalType": "ServicePrincipal",
                    "roleDefinitionId": producer_expected[
                        current_receiver_id.casefold()
                    ].role_definition_id,
                    "scope": trigger_queue_id,
                },
            }
        assert resource_id == retired_sender_id
        return {
            "id": retired_sender_id,
            "properties": {
                "principalId": retired_principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": (
                    f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                    "Microsoft.Authorization/roleDefinitions/"
                    f"{orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID}"
                ),
                "scope": trigger_queue_id,
            },
        }

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    approved_transitions = [_rotation_transition(retired_sender_id, retired_principal_id)]

    assert (
        orchestration._verify_trigger_queue_assignment_set(
            producer_expected_assignments=producer_expected,
            prospective_publisher_assignments=prospective,
            approved_transitions=approved_transitions,
            require_transition_revoked=False,
            subscription_id=SUBSCRIPTION_ID,
        )
        == {}
    )
    with pytest.raises(
        orchestration.OrchestrationError,
        match="retired trigger-queue assignment",
    ):
        orchestration._verify_trigger_queue_assignment_set(
            producer_expected_assignments=producer_expected,
            prospective_publisher_assignments=prospective,
            approved_transitions=approved_transitions,
            require_transition_revoked=True,
            subscription_id=SUBSCRIPTION_ID,
        )
    assert any(assignment["id"] == retired_sender_id for assignment in scope_assignments)

    scope_assignments[:] = [{"id": current_receiver_id, "scope": trigger_queue_id}]
    assert (
        orchestration._verify_trigger_queue_assignment_set(
            producer_expected_assignments=producer_expected,
            prospective_publisher_assignments=prospective,
            approved_transitions=approved_transitions,
            require_transition_revoked=True,
            subscription_id=SUBSCRIPTION_ID,
        )
        == {}
    )


def test_same_name_uami_trigger_assignment_reuse_requires_current_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena/queues/requests"
    )
    assignment_id = (
        f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "96969696-1111-4111-8111-111111111111"
    )
    retired_principal_id = "96969696-2222-4222-8222-222222222222"
    current_principal_id = "96969696-3333-4333-8333-333333333333"
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        f"{orchestration.SERVICE_BUS_DATA_RECEIVER_ROLE_ID}"
    )
    expected = orchestration._ExpectedRoleAssignment(
        label="recreated trigger receiver",
        principal_id=current_principal_id,
        scope=queue_scope,
        role_definition_id=role_definition_id,
    )
    live_principal_id = current_principal_id
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda _command, *, field: [{"id": assignment_id, "scope": queue_scope}],
    )

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        return {
            "id": resource_id,
            "properties": {
                "principalId": live_principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": queue_scope,
            },
        }

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    verified = orchestration._verify_complete_trigger_queue_assignment_set(
        current_expected_assignments={assignment_id.casefold(): expected},
        required_current_assignment_ids={assignment_id},
        approved_transitions=[_rotation_transition(assignment_id, retired_principal_id)],
        transition_state="absent",
        subscription_id=SUBSCRIPTION_ID,
    )
    assert verified == {current_principal_id: {assignment_id.casefold()}}

    live_principal_id = retired_principal_id
    with pytest.raises(orchestration.OrchestrationError, match="retired principal"):
        orchestration._verify_complete_trigger_queue_assignment_set(
            current_expected_assignments={assignment_id.casefold(): expected},
            required_current_assignment_ids={assignment_id},
            approved_transitions=[_rotation_transition(assignment_id, retired_principal_id)],
            transition_state="absent",
            subscription_id=SUBSCRIPTION_ID,
        )


def test_same_name_uami_nonqueue_assignment_reuse_is_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athena/blobServices/default/"
        "containers/wc027-enrichment-feed-v2"
    )
    assignment_id = (
        f"{scope}/providers/Microsoft.Authorization/roleAssignments/"
        "97979797-1111-4111-8111-111111111111"
    )
    retired_principal_id = "97979797-2222-4222-8222-222222222222"
    current_principal_id = "97979797-3333-4333-8333-333333333333"
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        f"{orchestration.BLOB_DATA_READER_ROLE_ID}"
    )
    expected = orchestration._ExpectedRoleAssignment(
        label="recreated Blob reader",
        principal_id=current_principal_id,
        scope=scope,
        role_definition_id=role_definition_id,
        condition_version="2.0",
        condition=orchestration.BLOB_LIST_DENY_CONDITION,
    )
    live_principal_id = current_principal_id
    live_condition = orchestration.BLOB_LIST_DENY_CONDITION
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda _command, *, field: [{"id": assignment_id, "scope": scope}],
    )

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        return {
            "id": resource_id,
            "properties": {
                "principalId": live_principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": scope,
                "conditionVersion": "2.0",
                "condition": live_condition,
            },
        }

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    transition = _rotation_transition(assignment_id, retired_principal_id)
    orchestration._verify_reviewed_rotation_transitions(
        [transition],
        current_principal_ids={current_principal_id},
        transition_state="absent",
        subscription_id=SUBSCRIPTION_ID,
        current_expected_assignments={assignment_id.casefold(): expected},
    )

    live_principal_id = retired_principal_id
    with pytest.raises(orchestration.OrchestrationError, match="retired principal"):
        orchestration._verify_reviewed_rotation_transitions(
            [transition],
            current_principal_ids={current_principal_id},
            transition_state="absent",
            subscription_id=SUBSCRIPTION_ID,
            current_expected_assignments={assignment_id.casefold(): expected},
        )

    live_principal_id = current_principal_id
    live_condition = None
    with pytest.raises(orchestration.OrchestrationError, match="condition"):
        orchestration._verify_reviewed_rotation_transitions(
            [transition],
            current_principal_ids={current_principal_id},
            transition_state="absent",
            subscription_id=SUBSCRIPTION_ID,
            current_expected_assignments={assignment_id.casefold(): expected},
        )


def test_removed_scope_rotation_transition_must_be_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retired_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/retired/tableServices/default/"
        "tables/Retired"
    )
    assignment_id = (
        f"{retired_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "98989898-1111-4111-8111-111111111111"
    )
    retired_principal_id = "98989898-2222-4222-8222-222222222222"
    transition = _rotation_transition(assignment_id, retired_principal_id)
    assignment_present = True

    def run_json(command: object, *, field: str) -> object:
        return [{"id": assignment_id, "scope": retired_scope}] if assignment_present else []

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda resource_id, *, subscription_id: {
            "id": resource_id,
            "properties": {
                "principalId": retired_principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": (
                    f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                    "Microsoft.Authorization/roleDefinitions/"
                    f"{orchestration.TABLE_DATA_READER_ROLE_ID}"
                ),
                "scope": retired_scope,
            },
        },
    )
    with pytest.raises(orchestration.OrchestrationError, match="retired principal"):
        orchestration._verify_unmatched_rotation_transitions_absent(
            [transition],
            handled_transition_ids=set(),
            subscription_id=SUBSCRIPTION_ID,
        )

    assignment_present = False
    orchestration._verify_unmatched_rotation_transitions_absent(
        [transition],
        handled_transition_ids=set(),
        subscription_id=SUBSCRIPTION_ID,
    )


def test_rotation_transitions_cover_all_deterministic_assignment_domains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subscription_role_base = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions"
    )
    custom_role_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "97979797-1111-4111-8111-111111111111"
    )
    domains = (
        (
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
                "incident-notification-outbox"
            ),
            f"{subscription_role_base}/{orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID}",
            None,
            None,
        ),
        (
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
                "wc027-guidance-authority-requests"
            ),
            f"{subscription_role_base}/{orchestration.SERVICE_BUS_DATA_RECEIVER_ROLE_ID}",
            None,
            None,
        ),
        (
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.KeyVault/vaults/athena/keys/wc027-report"
            ),
            custom_role_id,
            None,
            None,
        ),
        (
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.Storage/storageAccounts/athena/blobServices/default/"
                "containers/wc027-enrichment-feed-v2"
            ),
            f"{subscription_role_base}/{orchestration.BLOB_DATA_READER_ROLE_ID}",
            "2.0",
            orchestration.BLOB_LIST_DENY_CONDITION,
        ),
        (
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.Storage/storageAccounts/athena/tableServices/default/"
                "tables/Wc027FeedRegistry"
            ),
            f"{subscription_role_base}/{orchestration.TABLE_DATA_CONTRIBUTOR_ROLE_ID}",
            None,
            None,
        ),
        (
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/"
                "rg-athena-platform-dev/providers/Microsoft.ContainerRegistry/"
                "registries/athena"
            ),
            f"{subscription_role_base}/{orchestration.ACR_PULL_ROLE_ID}",
            None,
            None,
        ),
        (
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/"
                "rg-athena-platform-dev/providers/Microsoft.ContainerRegistry/"
                "registries/athena"
            ),
            f"{subscription_role_base}/{orchestration.ACR_REPOSITORY_READER_ROLE_ID}",
            "2.0",
            orchestration._acr_repository_condition("athena/wc027-enrichment-feed-producer"),
        ),
    )
    transition_ids: set[str] = set()
    transition_documents: list[dict[str, str]] = []
    resources: dict[str, dict[str, object]] = {
        custom_role_id.casefold(): {
            "id": custom_role_id,
            "properties": {
                "permissions": [
                    {
                        "actions": [],
                        "notActions": [],
                        "dataActions": sorted(
                            orchestration.KEY_SIGN_VERIFY_PERMISSION_PROFILE.data_actions
                        ),
                        "notDataActions": [],
                    }
                ]
            },
        }
    }
    assignments_by_scope: dict[str, list[dict[str, object]]] = {}
    requested_resource_ids: list[str] = []
    for index, (
        scope,
        role_definition_id,
        condition_version,
        condition,
    ) in enumerate(domains, start=1):
        assignment_id = (
            f"{scope}/providers/Microsoft.Authorization/roleAssignments/"
            f"97979797-{index:04d}-4{index:03d}-8{index:03d}-{index:012d}"
        )
        principal_id = f"98989898-{index:04d}-4{index:03d}-8{index:03d}-{index:012d}"
        transition_ids.add(assignment_id)
        transition_documents.append(_rotation_transition(assignment_id, principal_id))
        assignments_by_scope.setdefault(scope.casefold(), []).append(
            {"id": assignment_id, "scope": scope}
        )
        resources[assignment_id.casefold()] = {
            "id": assignment_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": scope,
                "conditionVersion": condition_version,
                "condition": condition,
            },
        }
    transitions_present = True

    def run_json(command: object, *, field: str) -> object:
        arguments = list(command)
        if arguments[:3] == ["az", "resource", "show"]:
            resource_id = arguments[arguments.index("--ids") + 1]
            requested_resource_ids.append(resource_id)
            return resources[resource_id.casefold()]
        scope = arguments[arguments.index("--scope") + 1]
        return assignments_by_scope.get(scope.casefold(), []) if transitions_present else []

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    orchestration._verify_reviewed_rotation_transitions(
        transition_documents,
        current_principal_ids={"99999999-9999-4999-8999-999999999999"},
        transition_state="present",
        subscription_id=SUBSCRIPTION_ID,
    )
    assert set(requested_resource_ids) == {
        *transition_ids,
        custom_role_id,
    }

    mismatched_assignment_id = sorted(transition_ids)[0]
    original_principal_id = resources[mismatched_assignment_id.casefold()]["properties"][
        "principalId"
    ]
    resources[mismatched_assignment_id.casefold()]["properties"]["principalId"] = (
        "98989898-9999-4999-8999-999999999999"
    )
    with pytest.raises(
        orchestration.OrchestrationError,
        match="reviewed retired principal",
    ):
        orchestration._verify_reviewed_rotation_transitions(
            transition_documents,
            current_principal_ids={"99999999-9999-4999-8999-999999999999"},
            transition_state="present",
            subscription_id=SUBSCRIPTION_ID,
        )
    resources[mismatched_assignment_id.casefold()]["properties"]["principalId"] = (
        original_principal_id
    )

    transitions_present = False
    orchestration._verify_reviewed_rotation_transitions(
        transition_documents,
        current_principal_ids={"99999999-9999-4999-8999-999999999999"},
        transition_state="absent",
        subscription_id=SUBSCRIPTION_ID,
    )


def test_revocation_evidence_accepts_canonical_retired_abac_repository_reader() -> None:
    principal_id = "97979797-7777-4777-8777-777777777777"
    repository_name = "athena/wc027-enrichment-feed-producer"
    role_definition_id = orchestration._acr_pull_role_definition_id(
        role_assignment_mode=orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE,
        subscription_id=SUBSCRIPTION_ID,
    )
    assignment_id = orchestration._acr_pull_role_assignment_id(
        scope=REGISTRY_RESOURCE_ID,
        principal_id=principal_id,
        role_definition_id=role_definition_id,
        role_assignment_mode=orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE,
        repository_name=repository_name,
    )
    rotation = _rotation_transition(assignment_id, principal_id)
    orchestration._verify_revocation_assignment_evidence_bindings(
        [
            {
                "assignmentResourceId": assignment_id,
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": REGISTRY_RESOURCE_ID,
                "conditionVersion": "2.0",
                "condition": orchestration._acr_repository_condition(repository_name),
                "registryRoleAssignmentMode": orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE,
            }
        ],
        rotations=[rotation],
        legacy_acr_migrations=[],
        legacy_crypto_expected=None,
        subscription_id=SUBSCRIPTION_ID,
    )


def test_rotation_transition_manifest_is_bounded_and_role_assignment_only() -> None:
    non_assignment = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athena"
    )
    with pytest.raises(
        orchestration.OrchestrationError,
        match="identify one role assignment",
    ):
        orchestration._canonical_rotation_transition_assignments(
            [_rotation_transition(non_assignment)],
            subscription_id=SUBSCRIPTION_ID,
            field="rotation transitions",
        )


def test_legacy_crypto_user_migration_allows_current_principal_only_until_revoked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "98989898-1111-4111-8111-111111111111"
    key_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.KeyVault/vaults/athena/keys/wc027-report"
    )
    assignment_id = (
        f"{key_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "98989898-2222-4222-8222-222222222222"
    )
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        f"{orchestration.KEY_VAULT_CRYPTO_USER_ROLE_ID}"
    )
    expected = {
        assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
            label="legacy producer report Crypto User migration",
            principal_id=principal_id,
            scope=key_scope,
            role_definition_id=role_definition_id,
        )
    }
    migration_present = True
    requested_resource_ids: list[str] = []

    def run_json(command: object, *, field: str) -> object:
        arguments = list(command)
        if arguments[:3] == ["az", "resource", "show"]:
            resource_id = arguments[arguments.index("--ids") + 1]
            requested_resource_ids.append(resource_id)
            return {
                "id": resource_id,
                "properties": {
                    "principalId": principal_id,
                    "principalType": "ServicePrincipal",
                    "roleDefinitionId": role_definition_id,
                    "scope": key_scope,
                },
            }
        return [{"id": assignment_id, "scope": key_scope}] if migration_present else []

    monkeypatch.setattr(orchestration, "_run_json", run_json)

    orchestration._verify_legacy_crypto_user_migration(
        expected,
        {assignment_id},
        migration_state="present",
        subscription_id=SUBSCRIPTION_ID,
    )
    assert requested_resource_ids == [assignment_id]
    with pytest.raises(
        orchestration.OrchestrationError,
        match="does not exactly match",
    ):
        orchestration._verify_legacy_crypto_user_migration(
            expected,
            set(),
            migration_state="present",
            subscription_id=SUBSCRIPTION_ID,
        )

    migration_present = False
    orchestration._verify_legacy_crypto_user_migration(
        expected,
        {assignment_id},
        migration_state="absent",
        subscription_id=SUBSCRIPTION_ID,
    )


def test_fresh_producer_plan_allows_empty_trigger_queue_assignment_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "96969696-1111-4111-8111-111111111111"
    trigger_queue_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    future_assignment_id = (
        f"{trigger_queue_id}/providers/Microsoft.Authorization/roleAssignments/"
        "96969696-2222-4222-8222-222222222222"
    )
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda command, *, field: [],
    )
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda *_args, **_kwargs: pytest.fail(
            "fresh planning must not read absent queue assignments"
        ),
    )

    assert (
        orchestration._verify_complete_trigger_queue_assignment_set(
            current_expected_assignments={
                future_assignment_id.casefold(): (
                    orchestration._ExpectedRoleAssignment(
                        label="planned producer trigger receiver",
                        principal_id=principal_id,
                        scope=trigger_queue_id,
                        role_definition_id=(
                            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                            "Microsoft.Authorization/roleDefinitions/"
                            f"{orchestration.SERVICE_BUS_DATA_RECEIVER_ROLE_ID}"
                        ),
                    )
                )
            },
            required_current_assignment_ids=set(),
            approved_transitions=[],
            transition_state="present",
            subscription_id=SUBSCRIPTION_ID,
        )
        == {}
    )


def test_publisher_trigger_handoff_requires_exact_sender_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trigger_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    assignment_id = (
        f"{trigger_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "88888888-8888-8888-8888-888888888888"
    )
    principal_id = "99999999-9999-9999-9999-999999999999"

    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda resource_id, *, subscription_id: {
            "id": resource_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": (
                    f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                    "Microsoft.Authorization/roleDefinitions/"
                    "4f6c0938-94ea-4d52-8e5a-2e02b7ef8e7d"
                ),
                "scope": trigger_scope,
            },
        },
    )
    with pytest.raises(orchestration.OrchestrationError, match="role definition"):
        orchestration._verify_rbac_resources(
            {"rbacResourceIds": [assignment_id]},
            expected_assignments={
                assignment_id.casefold(): orchestration._ExpectedRoleAssignment(
                    label="publisher producer-trigger sender",
                    principal_id=principal_id,
                    scope=trigger_scope,
                    role_definition_id=(
                        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                        "Microsoft.Authorization/roleDefinitions/"
                        f"{orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID}"
                    ),
                )
            },
            subscription_id=SUBSCRIPTION_ID,
        )


def test_cross_subscription_resource_is_rejected_before_azure_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("Azure CLI must not run for a cross-subscription resource")

    monkeypatch.setattr(orchestration, "_run_json", unexpected_run)
    with pytest.raises(orchestration.OrchestrationError, match="governed"):
        orchestration._get_resource(
            (
                "/subscriptions/99999999-9999-9999-9999-999999999999/"
                "resourceGroups/rg/providers/Microsoft.Storage/"
                "storageAccounts/outside"
            ),
            subscription_id=SUBSCRIPTION_ID,
        )


@pytest.mark.parametrize(
    ("mode", "role_id"),
    (
        (
            orchestration.ACR_LEGACY_ROLE_ASSIGNMENT_MODE,
            orchestration.ACR_PULL_ROLE_ID,
        ),
        (
            orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE,
            orchestration.ACR_REPOSITORY_READER_ROLE_ID,
        ),
    ),
)
def test_acr_pull_role_matches_registry_permission_mode(
    mode: str,
    role_id: str,
) -> None:
    assert orchestration._acr_pull_role_definition_id(
        role_assignment_mode=mode,
        subscription_id=SUBSCRIPTION_ID,
    ) == (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{role_id}"
    )


def test_acr_abac_condition_is_exact_and_denies_cross_repository_reads() -> None:
    repository_name = "athena/wc027-enrichment-feed-producer"
    condition = orchestration._acr_repository_condition(repository_name)

    assert orchestration._deny_condition_applies(
        condition,
        action=orchestration.ACR_REPOSITORY_CONTENT_READ_DATA_ACTION,
        scope=REGISTRY_RESOURCE_ID,
        repository_name=repository_name,
        suboperation=None,
    )
    assert not orchestration._deny_condition_applies(
        condition,
        action=orchestration.ACR_REPOSITORY_CONTENT_READ_DATA_ACTION,
        scope=REGISTRY_RESOURCE_ID,
        repository_name="athena/other-repository",
        suboperation=None,
    )
    assert not orchestration._deny_condition_applies(
        condition,
        action=orchestration.ACR_REPOSITORY_METADATA_READ_DATA_ACTION,
        scope=REGISTRY_RESOURCE_ID,
        repository_name="athena/other-repository",
        suboperation=None,
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("conditionVersion", None),
        ("conditionVersion", "1.0"),
        ("condition", None),
        (
            "condition",
            orchestration._acr_repository_condition("athena/other-repository"),
        ),
        (
            "condition",
            (
                "((!(ActionMatches{'Microsoft.ContainerRegistry/registries/repositories/"
                "content/read'}) AND !(ActionMatches{'Microsoft.ContainerRegistry/registries/"
                "repositories/metadata/read'})) OR (@Request[Microsoft.ContainerRegistry/"
                "registries/repositories:name] StringStartsWithIgnoreCase 'athena/'))"
            ),
        ),
    ),
)
def test_wc013_abac_inventory_rejects_missing_or_altered_repository_conditions(
    field: str,
    replacement: object,
) -> None:
    assignments = _wc013_acr_pull_assignments(
        role_assignment_mode=orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE,
    )
    orchestration._validated_wc013_acr_pull_assignments(
        assignments,
        subscription_id=SUBSCRIPTION_ID,
    )
    assignments[0][field] = replacement
    with pytest.raises(orchestration.OrchestrationError, match="exact repository"):
        orchestration._validated_wc013_acr_pull_assignments(
            assignments,
            subscription_id=SUBSCRIPTION_ID,
        )


def test_wc013_legacy_inventory_rejects_any_repository_condition() -> None:
    assignments = _wc013_acr_pull_assignments()
    assignments[0]["conditionVersion"] = "2.0"
    assignments[0]["condition"] = orchestration._acr_repository_condition(
        str(assignments[0]["repositoryName"])
    )
    with pytest.raises(orchestration.OrchestrationError, match="exact repository"):
        orchestration._validated_wc013_acr_pull_assignments(
            assignments,
            subscription_id=SUBSCRIPTION_ID,
        )


@pytest.mark.parametrize(
    ("condition_version", "condition"),
    (
        (None, None),
        ("2.0", None),
        ("2.0", "registry-wide"),
        (
            "2.0",
            orchestration._acr_repository_condition("athena/other-repository"),
        ),
    ),
)
def test_wc027_abac_assignment_readback_rejects_noncanonical_conditions(
    monkeypatch: pytest.MonkeyPatch,
    condition_version: object,
    condition: object,
) -> None:
    principal_id = PRODUCER_BROKER_PRINCIPAL_ID
    repository_name = "athena/wc027-enrichment-feed-producer"
    role_definition_id = orchestration._acr_pull_role_definition_id(
        role_assignment_mode=orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE,
        subscription_id=SUBSCRIPTION_ID,
    )
    assignment_id = orchestration._acr_pull_role_assignment_id(
        scope=REGISTRY_RESOURCE_ID,
        principal_id=principal_id,
        role_definition_id=role_definition_id,
        role_assignment_mode=orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE,
        repository_name=repository_name,
    )
    expected_condition = orchestration._acr_repository_condition(repository_name)
    expected = orchestration._ExpectedRoleAssignment(
        label="producer registry pull",
        principal_id=principal_id,
        scope=REGISTRY_RESOURCE_ID,
        role_definition_id=role_definition_id,
        condition_version="2.0",
        condition=expected_condition,
        repository_name=repository_name,
    )
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda resource_id, *, subscription_id: {
            "id": resource_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": REGISTRY_RESOURCE_ID,
                "conditionVersion": condition_version,
                "condition": condition,
            },
        },
    )
    with pytest.raises(orchestration.OrchestrationError, match="exact intended condition"):
        orchestration._verify_rbac_resources(
            {"rbacResourceIds": [assignment_id]},
            expected_assignments={assignment_id.casefold(): expected},
            subscription_id=SUBSCRIPTION_ID,
        )


def test_acr_readiness_binds_live_mode_principal_seed_and_server_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = _producer_outputs()
    parameters = {name: {"value": value} for name, value in _producer_parameter_bindings().items()}
    live_mode = REGISTRY_ROLE_ASSIGNMENT_MODE
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda resource_id, *, subscription_id: {
            "id": resource_id,
            "properties": {"roleAssignmentMode": live_mode},
        },
    )
    role_definition_id = orchestration._verify_acr_pull_binding(
        outputs,
        effective_parameters=parameters,
        principal_id=PRODUCER_BROKER_PRINCIPAL_ID,
        subscription_id=SUBSCRIPTION_ID,
        field="producer",
    )
    assert role_definition_id == outputs["registryPullRoleDefinitionId"]
    recreated_assignment_id = orchestration._deterministic_principal_role_assignment_id(
        REGISTRY_RESOURCE_ID,
        "10101010-9999-4999-8999-999999999999",
        role_definition_id,
    )
    assert recreated_assignment_id != outputs["registryPullRoleAssignmentResourceId"]

    live_mode = orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE
    with pytest.raises(orchestration.OrchestrationError, match="role-assignment mode"):
        orchestration._verify_acr_pull_binding(
            outputs,
            effective_parameters=parameters,
            principal_id=PRODUCER_BROKER_PRINCIPAL_ID,
            subscription_id=SUBSCRIPTION_ID,
            field="producer",
        )

    abac_outputs = dict(outputs)
    abac_outputs["registryRoleAssignmentMode"] = live_mode
    abac_role_definition_id = orchestration._acr_pull_role_definition_id(
        role_assignment_mode=live_mode,
        subscription_id=SUBSCRIPTION_ID,
    )
    repository_name = orchestration._acr_repository_name(
        abac_outputs["producerImage"],
        REGISTRY_RESOURCE_ID,
        field="producer image",
    )
    condition_version, condition = orchestration._acr_pull_assignment_condition(
        role_assignment_mode=live_mode,
        repository_name=repository_name,
    )
    abac_outputs["registryPullRoleDefinitionId"] = abac_role_definition_id
    abac_outputs["registryRepositoryName"] = repository_name
    abac_outputs["registryPullConditionVersion"] = condition_version
    abac_outputs["registryPullCondition"] = condition
    abac_outputs["registryPullRoleAssignmentResourceId"] = (
        orchestration._acr_pull_role_assignment_id(
            scope=REGISTRY_RESOURCE_ID,
            principal_id=PRODUCER_BROKER_PRINCIPAL_ID,
            role_definition_id=abac_role_definition_id,
            role_assignment_mode=live_mode,
            repository_name=repository_name,
        )
    )
    parameters["registryRoleAssignmentMode"] = {"value": live_mode}
    orchestration._verify_acr_pull_binding(
        abac_outputs,
        effective_parameters=parameters,
        principal_id=PRODUCER_BROKER_PRINCIPAL_ID,
        subscription_id=SUBSCRIPTION_ID,
        field="producer",
    )

    abac_outputs["registryPullRoleAssignmentResourceId"] = (
        orchestration._deterministic_role_assignment_id(
            REGISTRY_RESOURCE_ID,
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.ManagedIdentity/userAssignedIdentities/broker"
            ),
            orchestration.ACR_REPOSITORY_READER_ROLE_ID,
        )
    )
    with pytest.raises(orchestration.OrchestrationError, match="pull assignment"):
        orchestration._verify_acr_pull_binding(
            abac_outputs,
            effective_parameters=parameters,
            principal_id=PRODUCER_BROKER_PRINCIPAL_ID,
            subscription_id=SUBSCRIPTION_ID,
            field="producer",
        )


def test_legacy_acr_assignment_requires_reviewed_manual_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = PRODUCER_BROKER_PRINCIPAL_ID
    assignment_id = (
        f"{REGISTRY_RESOURCE_ID}/providers/Microsoft.Authorization/roleAssignments/"
        "30303030-3333-4333-8333-333333333333"
    )
    role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        f"{orchestration.ACR_PULL_ROLE_ID}"
    )
    assignment_present = True

    def run_json(command: object, *, field: str) -> object:
        return [{"id": assignment_id, "scope": REGISTRY_RESOURCE_ID}] if assignment_present else []

    monkeypatch.setattr(orchestration, "_run_json", run_json)

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        if resource_id.casefold() == REGISTRY_RESOURCE_ID.casefold():
            return {
                "id": resource_id,
                "properties": {"roleAssignmentMode": orchestration.ACR_LEGACY_ROLE_ASSIGNMENT_MODE},
            }
        return {
            "id": resource_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": REGISTRY_RESOURCE_ID,
            },
        }

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    parameters = {
        "registryResourceId": {"value": REGISTRY_RESOURCE_ID},
    }
    migration = {
        "assignmentResourceId": assignment_id,
        "principalId": principal_id,
    }
    orchestration._verify_legacy_acr_pull_migration(
        [migration],
        migration_state="present",
        stage="producer",
        effective_parameters=parameters,
        subscription_id=SUBSCRIPTION_ID,
    )
    evidence = orchestration._capture_revocation_assignment_evidence(
        [assignment_id],
        subscription_id=SUBSCRIPTION_ID,
    )
    orchestration._verify_revocation_assignment_evidence_bindings(
        evidence,
        rotations=[],
        legacy_acr_migrations=[migration],
        legacy_crypto_expected=None,
        subscription_id=SUBSCRIPTION_ID,
    )
    with pytest.raises(orchestration.OrchestrationError, match="controlled revocation"):
        orchestration._verify_legacy_acr_pull_migration(
            [migration],
            migration_state="absent",
            stage="producer",
            effective_parameters=parameters,
            subscription_id=SUBSCRIPTION_ID,
        )

    assignment_present = False
    orchestration._verify_legacy_acr_pull_migration(
        [migration],
        migration_state="absent",
        stage="producer",
        effective_parameters=parameters,
        subscription_id=SUBSCRIPTION_ID,
    )


def test_exact_head_unconditioned_repository_reader_requires_reviewed_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = PRODUCER_BROKER_PRINCIPAL_ID
    role_definition_id = orchestration._acr_pull_role_definition_id(
        role_assignment_mode=orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE,
        subscription_id=SUBSCRIPTION_ID,
    )
    assignment_id = orchestration._deterministic_principal_role_assignment_id(
        REGISTRY_RESOURCE_ID,
        principal_id,
        role_definition_id,
    )
    assignment_present = True

    def run_json(command: object, *, field: str) -> object:
        return [{"id": assignment_id, "scope": REGISTRY_RESOURCE_ID}] if assignment_present else []

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        if resource_id.casefold() == REGISTRY_RESOURCE_ID.casefold():
            return {
                "id": resource_id,
                "properties": {"roleAssignmentMode": orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE},
            }
        return {
            "id": resource_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": REGISTRY_RESOURCE_ID,
                "conditionVersion": None,
                "condition": None,
            },
        }

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    migration = {
        "assignmentResourceId": assignment_id,
        "principalId": principal_id,
    }
    parameters = {"registryResourceId": {"value": REGISTRY_RESOURCE_ID}}
    orchestration._verify_legacy_acr_pull_migration(
        [migration],
        migration_state="present",
        stage="producer",
        effective_parameters=parameters,
        subscription_id=SUBSCRIPTION_ID,
    )
    with pytest.raises(orchestration.OrchestrationError, match="controlled revocation"):
        orchestration._verify_legacy_acr_pull_migration(
            [migration],
            migration_state="absent",
            stage="producer",
            effective_parameters=parameters,
            subscription_id=SUBSCRIPTION_ID,
        )

    assignment_present = False
    orchestration._verify_legacy_acr_pull_migration(
        [migration],
        migration_state="absent",
        stage="producer",
        effective_parameters=parameters,
        subscription_id=SUBSCRIPTION_ID,
    )


def test_current_legacy_acr_pull_assignment_cannot_be_misclassified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = PRODUCER_BROKER_PRINCIPAL_ID
    role_definition_id = orchestration._acr_pull_role_definition_id(
        role_assignment_mode=orchestration.ACR_LEGACY_ROLE_ASSIGNMENT_MODE,
        subscription_id=SUBSCRIPTION_ID,
    )
    assignment_id = orchestration._acr_pull_role_assignment_id(
        scope=REGISTRY_RESOURCE_ID,
        principal_id=principal_id,
        role_definition_id=role_definition_id,
        role_assignment_mode=orchestration.ACR_LEGACY_ROLE_ASSIGNMENT_MODE,
        repository_name="",
    )
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda _command, *, field: [{"id": assignment_id, "scope": REGISTRY_RESOURCE_ID}],
    )

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        if resource_id.casefold() == REGISTRY_RESOURCE_ID.casefold():
            return {
                "id": resource_id,
                "properties": {"roleAssignmentMode": orchestration.ACR_LEGACY_ROLE_ASSIGNMENT_MODE},
            }
        return {
            "id": resource_id,
            "properties": {
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": role_definition_id,
                "scope": REGISTRY_RESOURCE_ID,
            },
        }

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    with pytest.raises(orchestration.OrchestrationError, match="cannot be classified"):
        orchestration._verify_legacy_acr_pull_migration(
            [
                {
                    "assignmentResourceId": assignment_id,
                    "principalId": principal_id,
                }
            ],
            migration_state="present",
            stage="producer",
            effective_parameters={"registryResourceId": {"value": REGISTRY_RESOURCE_ID}},
            subscription_id=SUBSCRIPTION_ID,
        )


def test_foundation_legacy_acr_migration_is_limited_to_reviewed_registries() -> None:
    reviewed_registry = REGISTRY_RESOURCE_ID
    outside_registry = reviewed_registry.replace("/registries/athena", "/registries/outside")
    assignment_id = (
        f"{outside_registry}/providers/Microsoft.Authorization/roleAssignments/"
        "40404040-4444-4444-8444-444444444444"
    )
    with pytest.raises(orchestration.OrchestrationError, match="reviewed registry scopes"):
        orchestration._verify_legacy_acr_pull_migration(
            [
                {
                    "assignmentResourceId": assignment_id,
                    "principalId": PRODUCER_BROKER_PRINCIPAL_ID,
                }
            ],
            migration_state="present",
            stage="foundation",
            effective_parameters={
                "acceptanceImageRegistryResourceId": {"value": reviewed_registry},
                "presentationImageRegistryResourceId": {"value": reviewed_registry},
            },
            subscription_id=SUBSCRIPTION_ID,
        )


def test_wc013_acr_inventory_rejects_stale_pull_grants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assignments = _wc013_acr_pull_assignments()
    assignments_by_id = {str(item["assignmentResourceId"]).casefold(): item for item in assignments}
    stale_present = False
    stale_assignment_id = (
        f"{REGISTRY_RESOURCE_ID}/providers/Microsoft.Authorization/roleAssignments/"
        "71717171-1111-4111-8111-111111111111"
    )

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        if resource_id.casefold() == REGISTRY_RESOURCE_ID.casefold():
            return {
                "id": resource_id,
                "properties": {"roleAssignmentMode": REGISTRY_ROLE_ASSIGNMENT_MODE},
            }
        if "/roledefinitions/" in resource_id.casefold():
            return {
                "id": resource_id,
                "properties": {
                    "permissions": [
                        {
                            "actions": [orchestration.ACR_LEGACY_PULL_ACTION],
                            "notActions": [],
                            "dataActions": [],
                            "notDataActions": [],
                        }
                    ]
                },
            }
        assignment = assignments_by_id[resource_id.casefold()]
        return {
            "id": resource_id,
            "properties": {
                "principalId": assignment["principalId"],
                "principalType": "ServicePrincipal",
                "roleDefinitionId": assignment["roleDefinitionId"],
                "scope": assignment["scope"],
            },
        }

    def resolved_assignments(
        principal_id: str,
        *,
        subscription_id: str,
        field: str,
    ) -> list[dict[str, object]]:
        expected = next(
            item
            for item in assignments
            if str(item["principalId"]).casefold() == principal_id.casefold()
        )
        observed = [
            {
                "id": expected["assignmentResourceId"],
                "principalId": expected["principalId"],
                "roleDefinitionId": expected["roleDefinitionId"],
                "scope": expected["scope"],
            }
        ]
        if (
            stale_present
            and principal_id.casefold() == str(assignments[0]["principalId"]).casefold()
        ):
            observed.append(
                {
                    "id": stale_assignment_id,
                    "principalId": assignments[0]["principalId"],
                    "roleDefinitionId": (
                        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                        "Microsoft.Authorization/roleDefinitions/"
                        f"{orchestration.ACR_PULL_ROLE_ID}"
                    ),
                    "scope": REGISTRY_RESOURCE_ID,
                }
            )
        return observed

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    monkeypatch.setattr(
        orchestration,
        "_resolved_effective_role_assignments",
        resolved_assignments,
    )
    monkeypatch.setattr(
        orchestration,
        "_get_role_definition",
        lambda role_definition_id, *, subscription_id: {
            "id": role_definition_id,
            "properties": {
                "permissions": [
                    {
                        "actions": [orchestration.ACR_LEGACY_PULL_ACTION],
                        "notActions": [],
                        "dataActions": [],
                        "notDataActions": [],
                    }
                ]
            },
        },
    )
    monkeypatch.setattr(
        orchestration,
        "_verify_no_applicable_deny_assignments",
        lambda *_args, **_kwargs: None,
    )
    orchestration._verify_wc013_acr_pull_assignments(
        assignments,
        subscription_id=SUBSCRIPTION_ID,
    )

    stale_present = True
    with pytest.raises(
        orchestration.OrchestrationError,
        match="stale, inherited, group-derived",
    ):
        orchestration._verify_wc013_acr_pull_assignments(
            assignments,
            subscription_id=SUBSCRIPTION_ID,
        )


def test_wc013_abac_effective_set_requires_both_presentation_repositories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assignments = _wc013_acr_pull_assignments(
        role_assignment_mode=orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE,
    )
    assignments_by_id = {str(item["assignmentResourceId"]).casefold(): item for item in assignments}
    omitted_assignment_id: str | None = None

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        if resource_id.casefold() == REGISTRY_RESOURCE_ID.casefold():
            return {
                "id": resource_id,
                "properties": {"roleAssignmentMode": orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE},
            }
        assignment = assignments_by_id[resource_id.casefold()]
        return {
            "id": resource_id,
            "properties": {
                "principalId": assignment["principalId"],
                "principalType": "ServicePrincipal",
                "roleDefinitionId": assignment["roleDefinitionId"],
                "scope": assignment["scope"],
                "conditionVersion": assignment["conditionVersion"],
                "condition": assignment["condition"],
            },
        }

    def resolved_assignments(
        principal_id: str,
        *,
        subscription_id: str,
        field: str,
    ) -> list[dict[str, object]]:
        return [
            {
                "id": item["assignmentResourceId"],
                "principalId": item["principalId"],
                "roleDefinitionId": item["roleDefinitionId"],
                "scope": item["scope"],
            }
            for item in assignments
            if str(item["principalId"]).casefold() == principal_id.casefold()
            and str(item["assignmentResourceId"]).casefold() != omitted_assignment_id
        ]

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    monkeypatch.setattr(
        orchestration,
        "_resolved_effective_role_assignments",
        resolved_assignments,
    )
    monkeypatch.setattr(
        orchestration,
        "_get_role_definition",
        lambda role_definition_id, *, subscription_id: {
            "id": role_definition_id,
            "properties": {
                "permissions": [
                    {
                        "actions": [],
                        "notActions": [],
                        "dataActions": [
                            orchestration.ACR_REPOSITORY_CONTENT_READ_DATA_ACTION,
                            orchestration.ACR_REPOSITORY_METADATA_READ_DATA_ACTION,
                        ],
                        "notDataActions": [],
                    }
                ]
            },
        },
    )
    monkeypatch.setattr(
        orchestration,
        "_verify_no_applicable_deny_assignments",
        lambda *_args, **_kwargs: None,
    )
    orchestration._verify_wc013_acr_pull_assignments(
        assignments,
        subscription_id=SUBSCRIPTION_ID,
    )

    omitted_assignment_id = str(
        next(
            item["assignmentResourceId"]
            for item in assignments
            if item["label"] == "presentation-delivery"
        )
    ).casefold()
    with pytest.raises(orchestration.OrchestrationError, match="missing its exact current"):
        orchestration._verify_wc013_acr_pull_assignments(
            assignments,
            subscription_id=SUBSCRIPTION_ID,
        )


@pytest.mark.parametrize(
    ("role_id", "actions", "data_actions", "stale_scope"),
    (
        (
            orchestration.ACR_PULL_ROLE_ID,
            [orchestration.ACR_LEGACY_PULL_ACTION],
            [],
            REGISTRY_RESOURCE_ID.replace("/registries/athena", "/registries/sibling"),
        ),
        (
            orchestration.ACR_PUSH_ROLE_ID,
            [
                orchestration.ACR_LEGACY_PULL_ACTION,
                "Microsoft.ContainerRegistry/registries/push/write",
            ],
            [],
            REGISTRY_RESOURCE_ID,
        ),
        (
            orchestration.ACR_REPOSITORY_WRITER_ROLE_ID,
            [],
            [
                orchestration.ACR_REPOSITORY_CONTENT_READ_DATA_ACTION,
                "Microsoft.ContainerRegistry/registries/repositories/content/write",
            ],
            REGISTRY_RESOURCE_ID,
        ),
        (
            orchestration.ACR_REPOSITORY_CONTRIBUTOR_ROLE_ID,
            [],
            [
                orchestration.ACR_REPOSITORY_CONTENT_READ_DATA_ACTION,
                "Microsoft.ContainerRegistry/registries/repositories/content/delete",
            ],
            REGISTRY_RESOURCE_ID,
        ),
        (
            "91919191-1111-4111-8111-111111111111",
            ["Microsoft.ContainerRegistry/registries/*"],
            [],
            REGISTRY_RESOURCE_ID,
        ),
        (
            "92929292-2222-4222-8222-222222222222",
            [],
            ["Microsoft.ContainerRegistry/registries/repositories/content/read"],
            f"/subscriptions/{SUBSCRIPTION_ID}",
        ),
    ),
)
def test_wc013_rejects_every_extra_pull_capable_role_definition(
    monkeypatch: pytest.MonkeyPatch,
    role_id: str,
    actions: list[str],
    data_actions: list[str],
    stale_scope: str,
) -> None:
    assignments = _wc013_acr_pull_assignments()
    assignments_by_id = {str(item["assignmentResourceId"]).casefold(): item for item in assignments}
    stale_role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{role_id}"
    )
    stale_assignment_id = (
        f"{stale_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "93939393-3333-4333-8333-333333333333"
    )

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        if resource_id.casefold() == REGISTRY_RESOURCE_ID.casefold():
            return {
                "id": resource_id,
                "properties": {"roleAssignmentMode": REGISTRY_ROLE_ASSIGNMENT_MODE},
            }
        if "/roledefinitions/" in resource_id.casefold():
            role_actions = (
                [orchestration.ACR_LEGACY_PULL_ACTION]
                if resource_id.casefold().endswith(orchestration.ACR_PULL_ROLE_ID)
                else actions
            )
            role_data_actions = (
                []
                if resource_id.casefold().endswith(orchestration.ACR_PULL_ROLE_ID)
                else data_actions
            )
            return {
                "id": resource_id,
                "properties": {
                    "permissions": [
                        {
                            "actions": role_actions,
                            "notActions": [],
                            "dataActions": role_data_actions,
                            "notDataActions": [],
                        }
                    ]
                },
            }
        assignment = assignments_by_id[resource_id.casefold()]
        return {
            "id": resource_id,
            "properties": {
                "principalId": assignment["principalId"],
                "principalType": "ServicePrincipal",
                "roleDefinitionId": assignment["roleDefinitionId"],
                "scope": assignment["scope"],
                "conditionVersion": assignment["conditionVersion"],
                "condition": assignment["condition"],
            },
        }

    def resolved_assignments(
        principal_id: str,
        *,
        subscription_id: str,
        field: str,
    ) -> list[dict[str, object]]:
        expected = next(
            item
            for item in assignments
            if str(item["principalId"]).casefold() == principal_id.casefold()
        )
        observed = [
            {
                "id": expected["assignmentResourceId"],
                "principalId": expected["principalId"],
                "roleDefinitionId": expected["roleDefinitionId"],
                "scope": expected["scope"],
            }
        ]
        if principal_id.casefold() == str(assignments[0]["principalId"]).casefold():
            observed.append(
                {
                    "id": stale_assignment_id,
                    "principalId": assignments[0]["principalId"],
                    "roleDefinitionId": stale_role_definition_id,
                    "scope": stale_scope,
                }
            )
        return observed

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    monkeypatch.setattr(
        orchestration,
        "_resolved_effective_role_assignments",
        resolved_assignments,
    )
    monkeypatch.setattr(
        orchestration,
        "_get_role_definition",
        lambda role_definition_id, *, subscription_id: {
            "id": role_definition_id,
            "properties": {
                "permissions": [
                    {
                        "actions": (
                            [orchestration.ACR_LEGACY_PULL_ACTION]
                            if role_definition_id.casefold().endswith(
                                orchestration.ACR_PULL_ROLE_ID
                            )
                            else actions
                        ),
                        "notActions": [],
                        "dataActions": (
                            []
                            if role_definition_id.casefold().endswith(
                                orchestration.ACR_PULL_ROLE_ID
                            )
                            else data_actions
                        ),
                        "notDataActions": [],
                    }
                ]
            },
        },
    )
    monkeypatch.setattr(
        orchestration,
        "_verify_no_applicable_deny_assignments",
        lambda *_args, **_kwargs: None,
    )
    with pytest.raises(orchestration.OrchestrationError, match="pull-capable"):
        orchestration._verify_wc013_acr_pull_assignments(
            assignments,
            subscription_id=SUBSCRIPTION_ID,
        )


def test_wc013_rejects_group_derived_and_inherited_custom_pull_grants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assignments = _wc013_acr_pull_assignments()
    assignments_by_id = {str(item["assignmentResourceId"]).casefold(): item for item in assignments}
    governed_principal = str(assignments[0]["principalId"])
    group_id = "94949494-4444-4444-8444-444444444444"
    custom_role_definition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleDefinitions/"
        "95959595-5555-4555-8555-555555555555"
    )
    inherited_assignment_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleAssignments/"
        "96969696-6666-4666-8666-666666666666"
    )

    def get_resource(resource_id: str, *, subscription_id: str) -> dict[str, object]:
        if resource_id.casefold() == REGISTRY_RESOURCE_ID.casefold():
            return {
                "id": resource_id,
                "properties": {"roleAssignmentMode": REGISTRY_ROLE_ASSIGNMENT_MODE},
            }
        assignment = assignments_by_id[resource_id.casefold()]
        return {
            "id": resource_id,
            "properties": {
                "principalId": assignment["principalId"],
                "principalType": "ServicePrincipal",
                "roleDefinitionId": assignment["roleDefinitionId"],
                "scope": assignment["scope"],
                "conditionVersion": assignment["conditionVersion"],
                "condition": assignment["condition"],
            },
        }

    def effective_assignments(
        principal_id: str,
        *,
        subscription_id: str,
        field: str,
    ) -> list[dict[str, object]]:
        if principal_id == group_id:
            return [
                {
                    "id": inherited_assignment_id,
                    "principalId": group_id,
                    "roleDefinitionId": custom_role_definition_id,
                    "scope": f"/subscriptions/{SUBSCRIPTION_ID}",
                }
            ]
        expected = next(
            item
            for item in assignments
            if str(item["principalId"]).casefold() == principal_id.casefold()
        )
        return [
            {
                "id": expected["assignmentResourceId"],
                "principalId": expected["principalId"],
                "roleDefinitionId": expected["roleDefinitionId"],
                "scope": expected["scope"],
            }
        ]

    def get_role_definition(
        role_definition_id: str,
        *,
        subscription_id: str,
    ) -> dict[str, object]:
        return {
            "id": role_definition_id,
            "properties": {
                "permissions": [
                    {
                        "actions": [],
                        "notActions": [],
                        "dataActions": [orchestration.ACR_REPOSITORY_CONTENT_READ_DATA_ACTION],
                        "notDataActions": [],
                    }
                ]
            },
        }

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    monkeypatch.setattr(
        orchestration,
        "_transitive_group_ids",
        lambda principal_id: {group_id} if principal_id == governed_principal else set(),
    )
    monkeypatch.setattr(orchestration, "_effective_role_assignments", effective_assignments)
    monkeypatch.setattr(orchestration, "_get_role_definition", get_role_definition)
    monkeypatch.setattr(
        orchestration,
        "_verify_no_applicable_deny_assignments",
        lambda *_args, **_kwargs: None,
    )
    with pytest.raises(orchestration.OrchestrationError, match="group-derived"):
        orchestration._verify_wc013_acr_pull_assignments(
            assignments,
            subscription_id=SUBSCRIPTION_ID,
        )


def test_digest_pinned_job_pull_probe_retries_without_implicit_role_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = _producer_outputs()
    start_attempts = 0
    execution_polls = 0
    sleeps: list[float] = []

    def run_json(command: object, *, field: str) -> object:
        nonlocal start_attempts, execution_polls
        arguments = list(command)
        if arguments[:4] == ["az", "containerapp", "job", "start"]:
            start_attempts += 1
            assert "--registry-identity" not in arguments
            assert arguments[arguments.index("--image") + 1] == outputs["producerImage"]
            if start_attempts == 1:
                raise orchestration.OrchestrationError("synthetic RBAC propagation delay")
            return {"name": "wc027-producer-pull-proof"}
        execution_polls += 1
        status = "Running" if execution_polls == 1 else "Succeeded"
        return {
            "properties": {
                "status": status,
                "template": {
                    "containers": [
                        {
                            "name": "wc027-enrichment-feed-producer",
                            "image": outputs["producerImage"],
                            "command": ["/bin/sh"],
                            "args": ["-c", "exit 0"],
                        }
                    ]
                },
            }
        }

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    monkeypatch.setattr(
        orchestration.time,
        "sleep",
        lambda seconds: sleeps.append(seconds),
    )
    evidence = orchestration._verify_digest_pinned_job_image_pull(
        job_resource_id=str(outputs["producerJobResourceId"]),
        image=str(outputs["producerImage"]),
        container_name="wc027-enrichment-feed-producer",
        registry_resource_id=str(outputs["registryResourceId"]),
        principal_id=PRODUCER_BROKER_PRINCIPAL_ID,
        registry_role_assignment_mode=str(outputs["registryRoleAssignmentMode"]),
        registry_pull_role_definition_id=str(outputs["registryPullRoleDefinitionId"]),
        registry_pull_role_assignment_resource_id=str(
            outputs["registryPullRoleAssignmentResourceId"]
        ),
        subscription_id=SUBSCRIPTION_ID,
    )
    assert evidence["status"] == "Succeeded"
    assert evidence["executionName"] == "wc027-producer-pull-proof"
    assert start_attempts == 2
    assert execution_polls == 2
    assert sleeps == [
        orchestration.READBACK_RETRY_SECONDS,
        orchestration.READBACK_RETRY_SECONDS,
    ]


def test_image_pull_evidence_rejects_legacy_role_in_abac_mode() -> None:
    outputs = _producer_outputs()
    evidence = _synthetic_image_pull_evidence((outputs, "producer"))
    execution = evidence["executions"][0]
    execution["registryRoleAssignmentMode"] = orchestration.ACR_ABAC_ROLE_ASSIGNMENT_MODE
    with pytest.raises(orchestration.OrchestrationError, match="role definition"):
        orchestration._validated_image_pull_evidence(
            evidence,
            stage="producer",
            subscription_id=SUBSCRIPTION_ID,
        )


def test_image_pull_evidence_is_bound_to_exact_jobs_and_distinct_kinds() -> None:
    producer = _producer_outputs()
    publisher = _publisher_outputs(producer)
    evidence = _synthetic_image_pull_evidence(
        (producer, "producer"),
        (publisher, "publisher"),
    )
    orchestration._validated_image_pull_evidence(
        evidence,
        stage="live-acceptance",
        subscription_id=SUBSCRIPTION_ID,
    )
    orchestration._verify_image_pull_evidence_matches_outputs(
        evidence,
        kind="producer",
        outputs=producer,
        principal_id=PRODUCER_BROKER_PRINCIPAL_ID,
    )
    orchestration._verify_image_pull_evidence_matches_outputs(
        evidence,
        kind="publisher",
        outputs=publisher,
        principal_id=PUBLISHER_BROKER_PRINCIPAL_ID,
    )

    duplicate_producer = json.loads(json.dumps(evidence))
    duplicate_producer["executions"][1] = dict(duplicate_producer["executions"][0])
    with pytest.raises(orchestration.OrchestrationError, match="exact job kinds"):
        orchestration._validated_image_pull_evidence(
            duplicate_producer,
            stage="live-acceptance",
            subscription_id=SUBSCRIPTION_ID,
        )

    wrong_image = json.loads(json.dumps(evidence))
    wrong_image["executions"][0]["image"] = "athena.azurecr.io/athena/unreviewed@sha256:" + "f" * 64
    with pytest.raises(orchestration.OrchestrationError, match="reviewed outputs"):
        orchestration._verify_image_pull_evidence_matches_outputs(
            wrong_image,
            kind="producer",
            outputs=producer,
            principal_id=PRODUCER_BROKER_PRINCIPAL_ID,
        )


def test_identity_reads_preserve_original_canonical_arm_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ManagedIdentity/userAssignedIdentities/CanonicalIdentity"
    )
    client_id = "70717171-1111-4111-8111-111111111111"
    principal_id = "70717171-2222-4222-8222-222222222222"
    requested_ids: list[str] = []

    def run_json(command: object, *, field: str) -> object:
        arguments = list(command)
        requested_id = arguments[arguments.index("--ids") + 1]
        requested_ids.append(requested_id)
        return {
            "id": requested_id,
            "properties": {
                "clientId": client_id,
                "principalId": principal_id,
            },
        }

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    verified = orchestration._verify_identities(
        {
            "identityResourceId": identity_id,
            "identityClientId": client_id,
        },
        additional_identity_resource_ids=[identity_id],
        rbac_identity_resource_ids=[identity_id],
        subscription_id=SUBSCRIPTION_ID,
    )
    assert requested_ids == [identity_id]
    assert verified == {identity_id.casefold(): principal_id}


def test_predecessor_transitions_preserve_canonical_arm_casing() -> None:
    assignment_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena/queues/requests/providers/"
        "Microsoft.Authorization/roleAssignments/"
        "71717171-1111-4111-8111-111111111111"
    )
    transition = _rotation_transition(assignment_id)
    assert orchestration._predecessor_rotation_transition_assignments(
        {"producer": {"plan": {"rotationTransitionAssignments": [transition]}}},
        subscription_id=SUBSCRIPTION_ID,
    ) == [transition]


def test_dependency_security_properties_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athena/blobServices/default/"
        "containers/wc027-guidance-authority"
    )
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda _resource_id, *, subscription_id: {
            "id": container_id,
            "properties": {"publicAccess": "Container"},
        },
    )
    with pytest.raises(orchestration.OrchestrationError, match="public access"):
        orchestration._verify_private_blob_container(
            container_id,
            subscription_id=SUBSCRIPTION_ID,
        )

    queue_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda _resource_id, *, subscription_id: {
            "id": queue_id,
            "properties": {
                **orchestration.PRODUCER_TRIGGER_QUEUE_PROFILE,
                "requiresSession": False,
            },
        },
    )
    with pytest.raises(orchestration.OrchestrationError, match="requiresSession"):
        orchestration._verify_service_bus_queue(
            job_resource_id=(
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.App/jobs/wc027-producer"
            ),
            namespace_name="athena-wc016-events",
            queue_name="wc027-enrichment-feed-requests",
            profile_name="producer trigger",
            expected_profile=orchestration.PRODUCER_TRIGGER_QUEUE_PROFILE,
            subscription_id=SUBSCRIPTION_ID,
        )


def test_authority_blob_inventory_requires_versioning_and_preserves_canonical_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athenacorrelation/"
        "blobServices/default/containers/wc027-guidance-authority"
    )
    blob_service_id = container_id.rsplit("/containers/", 1)[0]
    requested_resource_ids: list[str] = []
    versioning_enabled = True
    container_exists = False

    def run_json(command: object, *, field: str) -> object:
        arguments = list(command)
        if arguments[:3] == ["az", "resource", "show"]:
            resource_id = arguments[arguments.index("--ids") + 1]
            requested_resource_ids.append(resource_id)
            return {
                "id": resource_id,
                "properties": {"isVersioningEnabled": versioning_enabled},
            }
        if arguments[:3] == ["az", "storage", "container"]:
            return {"exists": container_exists}
        return []

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    inventory = orchestration._authority_blob_inventory(
        container_id,
        subscription_id=SUBSCRIPTION_ID,
    )
    assert requested_resource_ids == [blob_service_id]
    assert inventory == {
        "schemaVersion": (orchestration.AUTHORITY_BLOB_INVENTORY_SCHEMA_VERSION),
        "containerResourceId": container_id,
        "containerExists": False,
        "previousCheckpointSha256": None,
        "currentBlobs": [],
        "versions": [],
    }

    versioning_enabled = False
    with pytest.raises(orchestration.OrchestrationError, match="versioning"):
        orchestration._authority_blob_inventory(
            container_id,
            subscription_id=SUBSCRIPTION_ID,
        )


def test_authority_blob_inventory_fresh_and_recovery_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athenacorrelation/"
        "blobServices/default/containers/wc027-guidance-authority"
    )
    versioned_blobs: list[dict[str, object]] = []
    payloads: dict[tuple[str, str], bytes] = {}

    def run_json(command: object, *, field: str) -> object:
        arguments = list(command)
        if arguments[:3] == ["az", "resource", "show"]:
            resource_id = arguments[arguments.index("--ids") + 1]
            return {
                "id": resource_id,
                "properties": {"isVersioningEnabled": True},
            }
        if arguments[:3] == ["az", "storage", "container"]:
            return {"exists": True}
        if "--include" in arguments:
            return versioned_blobs
        return []

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    monkeypatch.setattr(
        orchestration,
        "_run_bytes",
        lambda command: payloads[
            (
                list(command)[list(command).index("--name") + 1],
                list(command)[list(command).index("--version-id") + 1],
            )
        ],
    )
    reviewed_absent = _empty_authority_inventory(container_exists=False)
    empty_inventory = orchestration._authority_blob_inventory(
        container_id,
        subscription_id=SUBSCRIPTION_ID,
        previous_inventory=reviewed_absent,
    )
    orchestration._verify_post_deployment_authority_inventory(
        stage="producer",
        reviewed_inventory=reviewed_absent,
        current_inventory=empty_inventory,
    )

    fixture, publisher, writer, _activation, _trigger, _correlation, _incident = _publisher()
    publication = publisher.publish(
        _request(fixture),
        now=_request(fixture).evaluated_at,
    )
    for reference in (
        publication.authority_reference,
        publication.binding_reference,
    ):
        payload = writer.payloads[reference.name]
        payloads[(reference.name, reference.version)] = payload
        versioned_blobs.append(
            {
                "name": reference.name,
                "versionId": reference.version,
                "isCurrentVersion": True,
                "properties": {
                    "etag": f'"etag-{reference.version}"',
                    "contentLength": len(payload),
                },
            }
        )
    advanced_inventory = orchestration._authority_blob_inventory(
        container_id,
        subscription_id=SUBSCRIPTION_ID,
        previous_inventory=empty_inventory,
    )
    orchestration._verify_post_deployment_authority_inventory(
        stage="publisher",
        reviewed_inventory=empty_inventory,
        current_inventory=advanced_inventory,
    )
    assert [item["contract"]["kind"] for item in advanced_inventory["versions"]] == [
        "authority",
        "binding",
    ]

    monkeypatch.setattr(
        orchestration,
        "_run_bytes",
        lambda _command: pytest.fail("reviewed immutable versions must not be downloaded again"),
    )
    stable_successor = orchestration._authority_blob_inventory(
        container_id,
        subscription_id=SUBSCRIPTION_ID,
        previous_inventory=advanced_inventory,
    )
    assert stable_successor["versions"] == advanced_inventory["versions"]

    conflicting_inventory = json.loads(json.dumps(stable_successor))
    conflicting_inventory["versions"][0]["etag"] = '"etag-conflict"'
    with pytest.raises(
        orchestration.OrchestrationError,
        match="changed reviewed version",
    ):
        orchestration._verify_authority_checkpoint_successor(
            previous_inventory=advanced_inventory,
            current_inventory=conflicting_inventory,
            allow_container_creation=False,
        )


def test_authority_blob_inventory_rejects_missing_or_conflicting_versions() -> None:
    authority_id = "guidance-authority-" + "a" * 32
    binding_id = "guidance-binding-" + "b" * 32
    authority_name = f"guidance-authority/{authority_id}/authority.json"
    binding_name = f"guidance-bindings/{binding_id}/binding.json"
    authority_digest = f"sha256:{'a' * 64}"
    versions = [
        {
            "name": authority_name,
            "versionId": "version-authority",
            "etag": '"etag-authority"',
            "contentLength": 128,
            "contentSha256": authority_digest,
            "contract": {
                "kind": "authority",
                "artifactId": authority_id,
            },
        },
        {
            "name": binding_name,
            "versionId": "version-binding",
            "etag": '"etag-binding"',
            "contentLength": 256,
            "contentSha256": f"sha256:{'b' * 64}",
            "contract": {
                "kind": "binding",
                "artifactId": binding_id,
                "authorityReference": {
                    "name": authority_name,
                    "versionId": "version-authority",
                    "contentSha256": authority_digest,
                },
            },
        },
    ]
    current_blobs = [
        {
            key: item[key]
            for key in (
                "name",
                "versionId",
                "etag",
                "contentLength",
                "contentSha256",
            )
        }
        for item in versions
    ]
    inventory = {
        **_empty_authority_inventory(container_exists=True),
        "currentBlobs": current_blobs,
        "versions": versions,
    }
    orchestration._validated_authority_blob_inventory(
        inventory,
        subscription_id=SUBSCRIPTION_ID,
    )

    conflicting_current = json.loads(json.dumps(inventory))
    conflicting_current["currentBlobs"][0]["contentSha256"] = f"sha256:{'f' * 64}"
    with pytest.raises(orchestration.OrchestrationError, match="conflict"):
        orchestration._validated_authority_blob_inventory(
            conflicting_current,
            subscription_id=SUBSCRIPTION_ID,
        )

    duplicate_version = json.loads(json.dumps(inventory))
    duplicate_version["versions"].append(dict(duplicate_version["versions"][0]))
    duplicate_version["versions"].sort(key=lambda item: (item["name"], item["versionId"]))
    with pytest.raises(orchestration.OrchestrationError, match="duplicates|multiple versions"):
        orchestration._validated_authority_blob_inventory(
            duplicate_version,
            subscription_id=SUBSCRIPTION_ID,
        )

    unpaired = json.loads(json.dumps(inventory))
    unpaired["currentBlobs"] = unpaired["currentBlobs"][:1]
    unpaired["versions"] = unpaired["versions"][:1]
    with pytest.raises(orchestration.OrchestrationError, match="unpaired"):
        orchestration._validated_authority_blob_inventory(
            unpaired,
            subscription_id=SUBSCRIPTION_ID,
        )


def test_authority_blob_inventory_uses_trusted_predecessor_plan_evidence() -> None:
    producer_inventory = _empty_authority_inventory(
        container_exists=True,
        previous_checkpoint_sha256=f"sha256:{'1' * 64}",
    )
    assert (
        orchestration._predecessor_authority_blob_inventory(
            stage="publisher",
            verified_predecessors={
                "producer": {
                    "handoff": {
                        "authorityBlobInventory": producer_inventory,
                        "authorityBlobInventorySha256": (
                            orchestration._authority_checkpoint_sha256(producer_inventory)
                        ),
                    }
                }
            },
            subscription_id=SUBSCRIPTION_ID,
        )
        == producer_inventory
    )
    assert (
        orchestration._predecessor_authority_blob_inventory(
            stage="live-acceptance",
            verified_predecessors={
                "publisher": {
                    "handoff": {
                        "authorityBlobInventory": producer_inventory,
                        "authorityBlobInventorySha256": (
                            orchestration._authority_checkpoint_sha256(producer_inventory)
                        ),
                    }
                }
            },
            subscription_id=SUBSCRIPTION_ID,
        )
        == producer_inventory
    )


def test_authority_blob_planning_requires_absent_fresh_or_trusted_predecessor() -> None:
    absent_inventory = _empty_authority_inventory(container_exists=False)
    existing_empty_inventory = {
        **absent_inventory,
        "containerExists": True,
    }
    orchestration._verify_planned_authority_blob_inventory(
        stage="producer",
        current_inventory=absent_inventory,
        trusted_inventory=None,
    )
    with pytest.raises(orchestration.OrchestrationError, match="pre-existing container"):
        orchestration._verify_planned_authority_blob_inventory(
            stage="producer",
            current_inventory=existing_empty_inventory,
            trusted_inventory=None,
        )
    trusted_inventory = _empty_authority_inventory(
        container_exists=True,
        previous_checkpoint_sha256=f"sha256:{'3' * 64}",
    )
    successor_inventory = _empty_authority_inventory(
        container_exists=True,
        previous_checkpoint_sha256=(orchestration._authority_checkpoint_sha256(trusted_inventory)),
    )
    orchestration._verify_planned_authority_blob_inventory(
        stage="producer",
        current_inventory=successor_inventory,
        trusted_inventory=trusted_inventory,
    )
    with pytest.raises(orchestration.OrchestrationError, match="predecessor evidence"):
        orchestration._verify_planned_authority_blob_inventory(
            stage="publisher",
            current_inventory=existing_empty_inventory,
            trusted_inventory=None,
        )


def test_publisher_recovery_preserves_newer_producer_checkpoint() -> None:
    prior_publisher = _empty_authority_inventory(
        container_exists=True,
        previous_checkpoint_sha256=f"sha256:{'4' * 64}",
    )
    newer_producer = _synthetic_authority_checkpoint_with_pair(
        previous_checkpoint_sha256=f"sha256:{'5' * 64}",
    )
    candidate = _empty_authority_inventory(
        container_exists=True,
        previous_checkpoint_sha256=(orchestration._authority_checkpoint_sha256(prior_publisher)),
    )
    orchestration._verify_planned_authority_blob_inventory(
        stage="publisher",
        current_inventory=candidate,
        trusted_inventory=prior_publisher,
    )
    with pytest.raises(
        orchestration.OrchestrationError,
        match="removed a reviewed immutable version",
    ):
        orchestration._verify_authority_checkpoint_contains(
            required_inventory=newer_producer,
            current_inventory=candidate,
        )


def test_service_bus_queue_requires_exact_stage_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    properties = dict(orchestration.PRODUCER_TRIGGER_QUEUE_PROFILE)

    monkeypatch.setattr(
        orchestration,
        "_get_resource",
        lambda _resource_id, *, subscription_id: {
            "id": queue_id,
            "properties": properties,
        },
    )
    arguments = {
        "job_resource_id": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.App/jobs/wc027-producer"
        ),
        "namespace_name": "athena-wc016-events",
        "queue_name": "wc027-enrichment-feed-requests",
        "profile_name": "producer trigger",
        "expected_profile": orchestration.PRODUCER_TRIGGER_QUEUE_PROFILE,
        "subscription_id": SUBSCRIPTION_ID,
    }
    orchestration._verify_service_bus_queue(**arguments)

    properties["status"] = "SendDisabled"
    with pytest.raises(orchestration.OrchestrationError, match="status"):
        orchestration._verify_service_bus_queue(**arguments)
    properties["status"] = "Active"

    properties["duplicateDetectionHistoryTimeWindow"] = "PT10M"
    with pytest.raises(orchestration.OrchestrationError, match="duplicateDetection"):
        orchestration._verify_service_bus_queue(**arguments)
    properties["duplicateDetectionHistoryTimeWindow"] = "P7D"

    properties["forwardTo"] = "unexpected-forward"
    with pytest.raises(orchestration.OrchestrationError, match="forwardTo"):
        orchestration._verify_service_bus_queue(**arguments)
    properties["forwardTo"] = None

    properties["autoDeleteOnIdle"] = "PT5M"
    with pytest.raises(orchestration.OrchestrationError, match="autoDeleteOnIdle"):
        orchestration._verify_service_bus_queue(**arguments)


def test_wc027_queue_templates_pin_non_auto_deleting_profiles() -> None:
    non_auto_delete = f"autoDeleteOnIdle: '{orchestration.SERVICE_BUS_NON_AUTO_DELETE_DURATION}'"
    for template in (PRODUCER_ROOT, PUBLISHER_ROOT, WC016_ROOT):
        source = template.read_text(encoding="utf-8")
        assert non_auto_delete in source
        assert "autoDeleteOnIdle: 'PT5M'" not in source


def test_external_key_must_match_a_private_governed_vault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_resource_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.KeyVault/vaults/athena/keys/guidance-binding"
    )
    checked_vaults: list[str] = []
    monkeypatch.setattr(
        orchestration,
        "_verify_private_key_vault",
        lambda resource_id, *, subscription_id: checked_vaults.append(resource_id),
    )
    orchestration._verify_key_resource_binding(
        key_resource_id,
        "https://athena.vault.azure.net/keys/guidance-binding/v1",
        subscription_id=SUBSCRIPTION_ID,
    )
    assert checked_vaults == [
        (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.KeyVault/vaults/athena"
        )
    ]

    with pytest.raises(orchestration.OrchestrationError, match="does not match"):
        orchestration._verify_key_resource_binding(
            key_resource_id,
            "https://other.vault.azure.net/keys/guidance-binding/v1",
            subscription_id=SUBSCRIPTION_ID,
        )


def test_key_verification_binds_exact_rsa_material_and_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_uri = "https://athena.vault.azure.net/keys/wc027-report/" + "1" * 32

    def key_document(key_size: int = 3072) -> tuple[dict[str, object], str]:
        private_key = orchestration.rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()
        numbers = public_key.public_numbers()

        def encoded(value: int) -> str:
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
            return orchestration.base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        spki = public_key.public_bytes(
            encoding=orchestration.serialization.Encoding.DER,
            format=(orchestration.serialization.PublicFormat.SubjectPublicKeyInfo),
        )
        return (
            {
                "attributes": {"enabled": True},
                "key": {
                    "kid": key_uri,
                    "kty": "RSA",
                    "keyOps": ["sign", "verify"],
                    "n": encoded(numbers.n),
                    "e": encoded(numbers.e),
                },
            },
            f"sha256:{hashlib.sha256(spki).hexdigest()}",
        )

    valid_document, fingerprint = key_document()
    current_document = valid_document
    commands: list[list[str]] = []

    def run_json(command: object, *, field: str) -> object:
        commands.append(list(command))
        return current_document

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    orchestration._verify_key(
        key_uri,
        subscription_id=SUBSCRIPTION_ID,
        required_operations=frozenset({"sign", "verify"}),
        expected_fingerprint=fingerprint,
    )
    assert commands[-1][0:4] == ["az", "keyvault", "key", "show"]
    assert "--id" not in commands[-1]
    assert commands[-1][commands[-1].index("--vault-name") + 1] == "athena"
    assert commands[-1][commands[-1].index("--name") + 1] == "wc027-report"

    for mutation, message in (
        ({"kty": "EC"}, "key type"),
        ({"n": None}, "modulus"),
        ({"kid": key_uri.replace("1" * 32, "2" * 32)}, "key version"),
        ({"kid": key_uri.replace("athena", "Athena", 1)}, "key version"),
        ({"keyOps": ["verify"]}, "reviewed operations"),
    ):
        current_document = json.loads(json.dumps(valid_document))
        current_document["key"].update(mutation)
        with pytest.raises(orchestration.OrchestrationError, match=message):
            orchestration._verify_key(
                key_uri,
                subscription_id=SUBSCRIPTION_ID,
                required_operations=frozenset({"verify"}),
                expected_fingerprint=fingerprint,
            )

    current_document = valid_document
    with pytest.raises(orchestration.OrchestrationError, match="fingerprint"):
        orchestration._verify_key(
            key_uri,
            subscription_id=SUBSCRIPTION_ID,
            required_operations=frozenset({"verify"}),
            expected_fingerprint=f"sha256:{'f' * 64}",
        )

    current_document, smaller_fingerprint = key_document(2048)
    with pytest.raises(orchestration.OrchestrationError, match="reviewed size"):
        orchestration._verify_key(
            key_uri,
            subscription_id=SUBSCRIPTION_ID,
            required_operations=frozenset({"verify"}),
            expected_fingerprint=smaller_fingerprint,
        )


def test_effective_broad_rbac_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "55555555-5555-5555-5555-555555555555"
    assignment_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleAssignments/"
        "54545454-5454-5454-5454-545454545454"
    )

    def run_json(_command: object, *, field: str) -> object:
        assert "effective role assignments" in field
        return [
            {
                "id": assignment_id,
                "principalId": principal_id,
                "roleDefinitionName": "Contributor",
                "scope": f"/subscriptions/{SUBSCRIPTION_ID}",
            }
        ]

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    monkeypatch.setattr(orchestration, "_transitive_group_ids", lambda _principal_id: set())
    with pytest.raises(orchestration.OrchestrationError, match="prohibited broad RBAC"):
        orchestration._verify_no_broad_effective_assignments(
            {principal_id},
            subscription_id=SUBSCRIPTION_ID,
        )


def test_unreviewed_effective_assignment_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "55555555-5555-5555-5555-555555555555"
    expected_assignment = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests/providers/"
        "Microsoft.Authorization/roleAssignments/"
        "66666666-6666-6666-6666-666666666666"
    )
    unexpected_assignment = expected_assignment.replace(
        "66666666-6666-6666-6666-666666666666",
        "77777777-7777-7777-7777-777777777777",
    )
    governed_scope = orchestration._role_assignment_scope(expected_assignment)
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda _command, *, field: [{"id": unexpected_assignment, "scope": governed_scope}],
    )
    monkeypatch.setattr(orchestration, "_transitive_group_ids", lambda _principal_id: set())
    with pytest.raises(
        orchestration.OrchestrationError,
        match="unreviewed effective role assignment",
    ):
        orchestration._verify_exact_effective_assignments(
            {
                principal_id: {
                    expected_assignment.casefold(),
                }
            },
            additional_allowed_assignments_by_principal={},
            subscription_id=SUBSCRIPTION_ID,
        )


def test_effective_assignment_allowlist_is_bound_to_exact_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_principal = "81818181-8181-8181-8181-818181818181"
    second_principal = "82828282-8282-8282-8282-828282828282"
    queue_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    first_assignment = (
        f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "83838383-8383-8383-8383-838383838383"
    )
    second_assignment = (
        f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "84848484-8484-8484-8484-848484848484"
    )

    def run_json(command: object, *, field: str) -> object:
        arguments = list(command)
        principal = arguments[arguments.index("--assignee-object-id") + 1]
        if principal == first_principal:
            return [{"id": first_assignment, "scope": queue_scope}]
        assert principal == second_principal
        return [{"id": first_assignment, "scope": queue_scope}]

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    monkeypatch.setattr(orchestration, "_transitive_group_ids", lambda _principal_id: set())

    with pytest.raises(
        orchestration.OrchestrationError,
        match="unreviewed effective role assignment",
    ):
        orchestration._verify_exact_effective_assignments(
            {
                first_principal: {first_assignment.casefold()},
                second_principal: {second_assignment.casefold()},
            },
            additional_allowed_assignments_by_principal={},
            subscription_id=SUBSCRIPTION_ID,
        )


def test_exact_effective_assignments_check_additional_only_principals() -> None:
    principal_id = "85858585-1111-4111-8111-111111111111"
    queue_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    reviewed_assignment = (
        f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "85858585-2222-4222-8222-222222222222"
    )
    unexpected_assignment = (
        f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "85858585-3333-4333-8333-333333333333"
    )

    with pytest.raises(
        orchestration.OrchestrationError,
        match="unreviewed effective role assignment",
    ):
        orchestration._verify_exact_effective_assignments(
            {},
            additional_allowed_assignments_by_principal={
                principal_id: {reviewed_assignment.casefold()}
            },
            subscription_id=SUBSCRIPTION_ID,
            effective_assignments_by_principal={
                principal_id: [
                    {"id": reviewed_assignment, "scope": queue_scope},
                    {"id": unexpected_assignment, "scope": queue_scope},
                ]
            },
        )


def test_exact_effective_assignments_require_all_reviewed_ids_in_evidence() -> None:
    principal_id = "86868686-1111-4111-8111-111111111111"
    queue_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    expected_assignment = (
        f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "86868686-2222-4222-8222-222222222222"
    )

    with pytest.raises(
        orchestration.OrchestrationError,
        match="evidence is incomplete",
    ):
        orchestration._verify_exact_effective_assignments(
            {principal_id: {expected_assignment.casefold()}},
            additional_allowed_assignments_by_principal={},
            subscription_id=SUBSCRIPTION_ID,
            effective_assignments_by_principal={principal_id: []},
        )


def test_exact_effective_assignments_use_global_governed_scope_set() -> None:
    first_principal = "87878787-1111-4111-8111-111111111111"
    second_principal = "87878787-2222-4222-8222-222222222222"
    first_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    second_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-guidance-authority-requests"
    )
    first_assignment = (
        f"{first_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "87878787-3333-4333-8333-333333333333"
    )
    second_assignment = (
        f"{second_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "87878787-4444-4444-8444-444444444444"
    )
    cross_domain_assignment = (
        f"{second_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "87878787-5555-4555-8555-555555555555"
    )

    with pytest.raises(
        orchestration.OrchestrationError,
        match="unreviewed effective role assignment",
    ):
        orchestration._verify_exact_effective_assignments(
            {
                first_principal: {first_assignment.casefold()},
                second_principal: {second_assignment.casefold()},
            },
            additional_allowed_assignments_by_principal={},
            subscription_id=SUBSCRIPTION_ID,
            effective_assignments_by_principal={
                first_principal: [
                    {"id": first_assignment, "scope": first_scope},
                    {"id": cross_domain_assignment, "scope": second_scope},
                ],
                second_principal: [{"id": second_assignment, "scope": second_scope}],
            },
        )


@pytest.mark.parametrize(
    ("scope", "role_definition_id", "custom_profile", "denied_action", "is_data_action"),
    (
        (
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
                "wc027-enrichment-feed-requests"
            ),
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID}"
            ),
            None,
            orchestration.SERVICE_BUS_SEND_DATA_ACTION,
            True,
        ),
        (
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.Storage/storageAccounts/athena/blobServices/default/"
                "containers/evidence"
            ),
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{orchestration.BLOB_DATA_READER_ROLE_ID}"
            ),
            None,
            orchestration.BLOB_READ_DATA_ACTION,
            True,
        ),
        (
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.Storage/storageAccounts/athena/tableServices/default/"
                "tables/Wc027FeedRegistry"
            ),
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{orchestration.TABLE_DATA_READER_ROLE_ID}"
            ),
            None,
            orchestration.TABLE_ENTITY_READ_DATA_ACTION,
            True,
        ),
        (
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.KeyVault/vaults/athena/keys/signing"
            ),
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                "99999999-1111-4111-8111-111111111111"
            ),
            orchestration.KEY_SIGN_PERMISSION_PROFILE,
            orchestration.KEY_SIGN_DATA_ACTION,
            True,
        ),
        (
            REGISTRY_RESOURCE_ID,
            (
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/roleDefinitions/"
                f"{orchestration.ACR_REPOSITORY_READER_ROLE_ID}"
            ),
            None,
            orchestration.ACR_REPOSITORY_CONTENT_READ_DATA_ACTION,
            True,
        ),
    ),
)
def test_required_runtime_actions_fail_when_applicable_deny_blocks_them(
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    role_definition_id: str,
    custom_profile: orchestration._RolePermissionProfile | None,
    denied_action: str,
    is_data_action: bool,
) -> None:
    principal_id = "97979797-7777-4777-8777-777777777777"
    repository_name = (
        "athena/wc027-enrichment-feed-producer" if scope == REGISTRY_RESOURCE_ID else None
    )
    expected = orchestration._ExpectedRoleAssignment(
        label="synthetic required runtime permission",
        principal_id=principal_id,
        scope=scope,
        role_definition_id=role_definition_id,
        custom_role_permissions=custom_profile,
        repository_name=repository_name,
    )
    deny = _deny_assignment(
        scope=f"/subscriptions/{SUBSCRIPTION_ID}",
        principals=[
            {
                "id": orchestration.ALL_PRINCIPALS_ID,
                "type": "SystemDefined",
            }
        ],
        actions=[denied_action] if not is_data_action else [],
        data_actions=[denied_action] if is_data_action else [],
    )
    monkeypatch.setattr(orchestration, "_transitive_group_ids", lambda _principal_id: set())
    monkeypatch.setattr(
        orchestration,
        "_deny_assignments_at_or_above_scope",
        lambda _scope, *, subscription_id: [deny],
    )
    with pytest.raises(orchestration.OrchestrationError, match="required action"):
        orchestration._verify_no_applicable_deny_assignments(
            [expected],
            subscription_id=SUBSCRIPTION_ID,
        )


def test_deny_assignment_honors_transitive_groups_exclusions_and_child_scope_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "98989898-1111-4111-8111-111111111111"
    group_id = "98989898-2222-4222-8222-222222222222"
    scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    expected = orchestration._ExpectedRoleAssignment(
        label="producer trigger sender",
        principal_id=principal_id,
        scope=scope,
        role_definition_id=(
            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            f"{orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID}"
        ),
    )
    deny = _deny_assignment(
        scope=f"/subscriptions/{SUBSCRIPTION_ID}",
        principals=[{"id": group_id, "type": "Group"}],
        data_actions=[orchestration.SERVICE_BUS_SEND_DATA_ACTION],
    )
    monkeypatch.setattr(
        orchestration,
        "_transitive_group_ids",
        lambda resolved_principal_id: (
            {group_id} if resolved_principal_id == principal_id else set()
        ),
    )
    monkeypatch.setattr(
        orchestration,
        "_deny_assignments_at_or_above_scope",
        lambda _scope, *, subscription_id: [deny],
    )
    with pytest.raises(orchestration.OrchestrationError, match="required action"):
        orchestration._verify_no_applicable_deny_assignments(
            [expected],
            subscription_id=SUBSCRIPTION_ID,
        )

    deny["properties"]["excludePrincipals"] = [{"id": group_id, "type": "Group"}]
    orchestration._verify_no_applicable_deny_assignments(
        [expected],
        subscription_id=SUBSCRIPTION_ID,
    )

    deny["properties"]["excludePrincipals"] = []
    deny["properties"]["doNotApplyToChildScopes"] = True
    orchestration._verify_no_applicable_deny_assignments(
        [expected],
        subscription_id=SUBSCRIPTION_ID,
    )


def test_deny_assignment_conditions_are_evaluated_and_unsupported_evidence_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "99999999-2222-4222-8222-222222222222"
    scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    expected = orchestration._ExpectedRoleAssignment(
        label="producer trigger sender",
        principal_id=principal_id,
        scope=scope,
        role_definition_id=(
            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            f"{orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID}"
        ),
    )
    deny = _deny_assignment(
        scope=f"/subscriptions/{SUBSCRIPTION_ID}",
        principals=[{"id": principal_id, "type": "ServicePrincipal"}],
        data_actions=[orchestration.SERVICE_BUS_SEND_DATA_ACTION],
        condition=(
            "@Resource[Microsoft.ServiceBus/namespaces/queues:QueueName] "
            "StringEqualsIgnoreCase 'another-queue'"
        ),
        condition_version="2.0",
    )
    monkeypatch.setattr(orchestration, "_transitive_group_ids", lambda _principal_id: set())
    monkeypatch.setattr(
        orchestration,
        "_deny_assignments_at_or_above_scope",
        lambda _scope, *, subscription_id: [deny],
    )
    orchestration._verify_no_applicable_deny_assignments(
        [expected],
        subscription_id=SUBSCRIPTION_ID,
    )

    deny["properties"]["condition"] = (
        "@Resource[Microsoft.ServiceBus/namespaces/queues:QueueName] "
        "StringEqualsIgnoreCase 'wc027-enrichment-feed-requests'"
    )
    with pytest.raises(orchestration.OrchestrationError, match="required action"):
        orchestration._verify_no_applicable_deny_assignments(
            [expected],
            subscription_id=SUBSCRIPTION_ID,
        )

    deny["properties"]["condition"] = "@Resource[unsupported] GuidEquals 'value'"
    with pytest.raises(orchestration.OrchestrationError, match="incomplete or uses unsupported"):
        orchestration._verify_no_applicable_deny_assignments(
            [expected],
            subscription_id=SUBSCRIPTION_ID,
        )


def test_permission_level_deny_conditions_are_evaluated_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "99999999-3333-4333-8333-333333333333"
    scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    expected = orchestration._ExpectedRoleAssignment(
        label="producer trigger sender",
        principal_id=principal_id,
        scope=scope,
        role_definition_id=(
            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            f"{orchestration.SERVICE_BUS_DATA_SENDER_ROLE_ID}"
        ),
    )
    deny = _deny_assignment(
        scope=f"/subscriptions/{SUBSCRIPTION_ID}",
        principals=[{"id": principal_id, "type": "ServicePrincipal"}],
        data_actions=[orchestration.SERVICE_BUS_SEND_DATA_ACTION],
    )
    permission = deny["properties"]["permissions"][0]
    permission["condition"] = (
        "@Resource[Microsoft.ServiceBus/namespaces/queues:QueueName] "
        "StringEqualsIgnoreCase 'another-queue'"
    )
    permission["conditionVersion"] = "2.0"
    monkeypatch.setattr(orchestration, "_transitive_group_ids", lambda _principal_id: set())
    monkeypatch.setattr(
        orchestration,
        "_deny_assignments_at_or_above_scope",
        lambda _scope, *, subscription_id: [deny],
    )
    orchestration._verify_no_applicable_deny_assignments(
        [expected],
        subscription_id=SUBSCRIPTION_ID,
    )

    permission["condition"] = (
        "@Resource[Microsoft.ServiceBus/namespaces/queues:QueueName] "
        "StringEqualsIgnoreCase 'wc027-enrichment-feed-requests'"
    )
    with pytest.raises(orchestration.OrchestrationError, match="required action"):
        orchestration._verify_no_applicable_deny_assignments(
            [expected],
            subscription_id=SUBSCRIPTION_ID,
        )

    permission["conditionVersion"] = None
    with pytest.raises(orchestration.OrchestrationError, match="condition evidence"):
        orchestration._verify_no_applicable_deny_assignments(
            [expected],
            subscription_id=SUBSCRIPTION_ID,
        )


def test_deny_assignment_enumeration_follows_every_trusted_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athena"
    )
    next_link = (
        f"https://{orchestration.ARM_HOST}{scope}/providers/"
        "Microsoft.Authorization/denyAssignments"
        f"?api-version={orchestration.DENY_ASSIGNMENTS_API_VERSION}"
        "&%24filter=atScope%28%29&%24skiptoken=synthetic"
    )
    first = _deny_assignment(
        scope=scope,
        principals=[{"id": orchestration.ALL_PRINCIPALS_ID, "type": "SystemDefined"}],
        actions=["Microsoft.Storage/storageAccounts/read"],
    )
    second = json.loads(json.dumps(first))
    second["id"] = str(second["id"]).replace(
        "98989898-8888-4888-8888-888888888888",
        "99999999-9999-4999-8999-999999999999",
    )
    requested_urls: list[str] = []

    def run_json(command: object, *, field: str) -> object:
        arguments = list(command)
        url = arguments[arguments.index("--url") + 1]
        requested_urls.append(url)
        return (
            {"value": [first], "nextLink": next_link}
            if len(requested_urls) == 1
            else {"value": [second]}
        )

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    assert orchestration._deny_assignments_at_or_above_scope(
        scope,
        subscription_id=SUBSCRIPTION_ID,
    ) == [first, second]
    assert requested_urls[1] == next_link


def test_deny_assignment_enumeration_rejects_untrusted_or_incomplete_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athena"
    )
    responses: list[object] = [
        {
            "value": [],
            "nextLink": (
                "https://example.invalid/providers/Microsoft.Authorization/"
                "denyAssignments?api-version=2022-04-01"
            ),
        }
    ]
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda _command, *, field: responses.pop(0),
    )
    with pytest.raises(orchestration.OrchestrationError, match="untrusted continuation"):
        orchestration._deny_assignments_at_or_above_scope(
            scope,
            subscription_id=SUBSCRIPTION_ID,
        )

    responses.append({"nextLink": None})
    with pytest.raises(orchestration.OrchestrationError, match="value array"):
        orchestration._deny_assignments_at_or_above_scope(
            scope,
            subscription_id=SUBSCRIPTION_ID,
        )


@pytest.mark.parametrize("path", ("publisher-apply", "publisher-recovery"))
def test_publisher_verification_collects_separated_producer_principal_evidence(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    producer_principal = "88818181-1111-4111-8111-111111111111"
    publisher_principal = "88818181-2222-4222-8222-222222222222"
    producer_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/athena/blobServices/default/"
        "containers/wc027-enrichment-feed-v2"
    )
    publisher_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-guidance-authority-requests"
    )
    producer_assignment = (
        f"{producer_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "88818181-3333-4333-8333-333333333333"
    )
    publisher_assignment = (
        f"{publisher_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "88818181-4444-4444-8444-444444444444"
    )
    queried_principals: list[set[str]] = []

    def verified_evidence(
        principal_ids: set[str],
        *,
        subscription_id: str,
    ) -> dict[str, list[dict[str, object]]]:
        assert path in {"publisher-apply", "publisher-recovery"}
        queried_principals.append(set(principal_ids))
        return {
            producer_principal: [{"id": producer_assignment, "scope": producer_scope}],
            publisher_principal: [{"id": publisher_assignment, "scope": publisher_scope}],
        }

    monkeypatch.setattr(
        orchestration,
        "_verify_no_broad_effective_assignments",
        verified_evidence,
    )
    orchestration._verify_publisher_effective_assignments(
        publisher_principal_ids={publisher_principal},
        publisher_assignment_ids_by_principal={
            publisher_principal: {publisher_assignment.casefold()}
        },
        producer_assignment_ids_by_principal={producer_principal: {producer_assignment.casefold()}},
        subscription_id=SUBSCRIPTION_ID,
    )
    assert queried_principals == [{producer_principal, publisher_principal}]


def test_live_acceptance_revalidates_predecessor_rotation_transitions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transition_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.KeyVault/vaults/athena/keys/wc027-report/providers/"
        "Microsoft.Authorization/roleAssignments/"
        "99919191-1111-4111-8111-111111111111"
    )
    transition = _rotation_transition(transition_id)
    captured: list[tuple[str, list[dict[str, str]], bool]] = []
    monkeypatch.setattr(
        orchestration,
        "_verify_foundation_resources",
        lambda *_args, **_kwargs: None,
    )

    def verify_producer(
        _outputs: object,
        **kwargs: object,
    ) -> dict[str, set[str]]:
        kwargs["handled_transition_ids"].add(transition_id.casefold())
        captured.append(
            (
                "producer",
                list(kwargs["approved_transitions"]),
                bool(kwargs["require_transition_revoked"]),
            )
        )
        return {}

    def verify_publisher(
        _outputs: object,
        **kwargs: object,
    ) -> dict[str, set[str]]:
        captured.append(
            (
                "publisher",
                list(kwargs["approved_transitions"]),
                bool(kwargs["require_transition_revoked"]),
            )
        )
        return {}

    monkeypatch.setattr(
        orchestration,
        "_verify_producer_resources",
        verify_producer,
    )
    monkeypatch.setattr(
        orchestration,
        "_verify_publisher_resources",
        verify_publisher,
    )
    orchestration._verify_live_dependencies(
        foundation={},
        producer={"outputs": {}},
        publisher={"outputs": {}},
        subscription_id=SUBSCRIPTION_ID,
        rotation_transitions=[transition],
    )
    assert captured == [
        ("producer", [transition], True),
        ("publisher", [transition], True),
    ]


def test_management_group_service_bus_data_owner_is_treated_as_inherited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "85858585-8585-8585-8585-858585858585"
    expected_assignment = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests/providers/"
        "Microsoft.Authorization/roleAssignments/"
        "86868686-8686-8686-8686-868686868686"
    )
    management_group_assignment = (
        "/providers/Microsoft.Management/managementGroups/review-required/"
        "providers/Microsoft.Authorization/roleAssignments/"
        "87878787-8787-8787-8787-878787878787"
    )

    def run_json(command: object, *, field: str) -> object:
        arguments = list(command)
        if "--all" in arguments:
            assert "--scope" not in arguments
            assert "--include-inherited" not in arguments
            return []
        assert "--all" not in arguments
        assert "--include-inherited" in arguments
        scope_index = arguments.index("--scope")
        assert arguments[scope_index + 1] == f"/subscriptions/{SUBSCRIPTION_ID}"
        return [
            {
                "id": management_group_assignment,
                "principalId": principal_id,
                "roleDefinitionName": "Azure Service Bus Data Owner",
                "scope": ("/providers/Microsoft.Management/managementGroups/review-required"),
            }
        ]

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    monkeypatch.setattr(orchestration, "_transitive_group_ids", lambda _principal_id: set())

    with pytest.raises(
        orchestration.OrchestrationError,
        match="unreviewed effective role assignment",
    ):
        orchestration._verify_exact_effective_assignments(
            {principal_id: {expected_assignment.casefold()}},
            additional_allowed_assignments_by_principal={},
            subscription_id=SUBSCRIPTION_ID,
        )


def test_transitive_group_assignments_are_fully_paged_and_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "88888888-1111-4111-8111-111111111111"
    group_ids = (
        "88888888-2222-4222-8222-222222222222",
        "88888888-3333-4333-8333-333333333333",
    )
    queue_scope = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
        "Microsoft.ServiceBus/namespaces/athena-wc016-events/queues/"
        "wc027-enrichment-feed-requests"
    )
    expected_assignment = (
        f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "88888888-4444-4444-8444-444444444444"
    )
    group_assignment = (
        f"{queue_scope}/providers/Microsoft.Authorization/roleAssignments/"
        "88888888-5555-4555-8555-555555555555"
    )
    next_link = (
        f"https://graph.microsoft.com/v1.0/servicePrincipals/{principal_id}/"
        "transitiveMemberOf/microsoft.graph.group"
        "?$select=id&$count=true&$top=999&$skiptoken=synthetic"
    )
    graph_urls: list[str] = []
    queried_assignees: list[str] = []

    def run_json(command: object, *, field: str) -> object:
        arguments = list(command)
        if arguments[:2] == ["az", "rest"]:
            url = arguments[arguments.index("--url") + 1]
            graph_urls.append(url)
            if len(graph_urls) == 1:
                return {
                    "@odata.count": 2,
                    "value": [
                        {
                            "@odata.type": "#microsoft.graph.group",
                            "id": group_ids[0],
                        }
                    ],
                    "@odata.nextLink": next_link,
                }
            assert url == next_link
            return {
                "value": [
                    {
                        "@odata.type": "#microsoft.graph.group",
                        "id": group_ids[1],
                    }
                ]
            }
        assignee = arguments[arguments.index("--assignee-object-id") + 1]
        queried_assignees.append(assignee)
        if "--all" not in arguments:
            return []
        if assignee == principal_id:
            return [
                {
                    "id": expected_assignment,
                    "principalId": principal_id,
                    "roleDefinitionName": "Azure Service Bus Data Receiver",
                    "scope": queue_scope,
                }
            ]
        if assignee == group_ids[1]:
            return [
                {
                    "id": group_assignment,
                    "principalId": group_ids[1],
                    "roleDefinitionName": "Azure Service Bus Data Owner",
                    "scope": queue_scope,
                }
            ]
        return []

    monkeypatch.setattr(orchestration, "_run_json", run_json)
    evidence = orchestration._verify_no_broad_effective_assignments(
        {principal_id},
        subscription_id=SUBSCRIPTION_ID,
    )

    assert graph_urls == [
        (
            f"https://graph.microsoft.com/v1.0/servicePrincipals/{principal_id}/"
            "transitiveMemberOf/microsoft.graph.group"
            "?$select=id&$count=true&$top=999"
        ),
        next_link,
    ]
    assert set(queried_assignees) == {principal_id, *group_ids}
    with pytest.raises(
        orchestration.OrchestrationError,
        match="unreviewed effective role assignment",
    ):
        orchestration._verify_exact_effective_assignments(
            {principal_id: {expected_assignment.casefold()}},
            additional_allowed_assignments_by_principal={},
            subscription_id=SUBSCRIPTION_ID,
            effective_assignments_by_principal=evidence,
        )


def test_transitive_group_membership_incomplete_page_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "89898989-1111-4111-8111-111111111111"
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda _command, *, field: {
            "@odata.count": 2,
            "value": [{"id": "89898989-2222-4222-8222-222222222222"}],
        },
    )

    with pytest.raises(orchestration.OrchestrationError, match="pagination is incomplete"):
        orchestration._transitive_group_ids(principal_id)


def test_transitive_group_membership_unavailable_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "90909090-1111-4111-8111-111111111111"

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise orchestration.OrchestrationError("Microsoft Graph unavailable")

    monkeypatch.setattr(orchestration, "_run_json", unavailable)
    with pytest.raises(orchestration.OrchestrationError, match="unavailable"):
        orchestration._transitive_group_ids(principal_id)


def test_effective_assignment_incomplete_page_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        orchestration,
        "_run_json",
        lambda _command, *, field: {
            "value": [],
            "nextLink": "https://management.azure.com/synthetic-next-page",
        },
    )

    with pytest.raises(orchestration.OrchestrationError, match="must be an array"):
        orchestration._effective_role_assignments(
            "93939393-1111-4111-8111-111111111111",
            subscription_id=SUBSCRIPTION_ID,
            field="synthetic paged role assignments",
        )


def test_effective_assignment_query_unavailable_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise orchestration.OrchestrationError("role assignment query unavailable")

    monkeypatch.setattr(orchestration, "_run_json", unavailable)
    with pytest.raises(orchestration.OrchestrationError, match="unavailable"):
        orchestration._effective_role_assignments(
            "94949494-1111-4111-8111-111111111111",
            subscription_id=SUBSCRIPTION_ID,
            field="synthetic role assignments",
        )


def test_deployment_outputs_require_succeeded_provisioning_state() -> None:
    with pytest.raises(orchestration.OrchestrationError, match="provisioning state"):
        orchestration._deployment_outputs(
            {
                "properties": {
                    "provisioningState": "Failed",
                    "outputs": {},
                }
            }
        )


def test_wc013_exports_foundation_values_required_by_orchestrator() -> None:
    source = WC013_ROOT.read_text(encoding="utf-8")
    assert "wc027OrchestrationFoundation: {" in source
    assert "wc027DeploymentReadiness: {" in source
    assert "param wc027EnrichmentFeedProducerImage string = ''" in source
    assert "wc027PublisherJobResourceIdRawSegments,\n  [" in source
    for required_job_check in (
        "WC-027 producer Job container array does not match",
        "WC-027 producer Job image does not match",
        "WC-027 producer Job scaler identity does not match",
        "WC-027 producer Job registry server does not match",
        "WC-027 producer Job contains ungoverned identity",
        "WC-027 producer Job must use only the exact user-assigned identities",
        "WC-027 producer Job scaler must not use secret authentication",
        "WC-027 producer Job registry must use managed identity only",
        "WC-027 publisher Job container array does not match",
        "WC-027 publisher Job RBAC binding evidence tag does not match",
        "WC-027 publisher logical binding key does not match",
        "WC-027 publisher Job contains ungoverned identity",
        "WC-027 publisher Job must use only the exact user-assigned identities",
        "WC-027 producer Job scaler metadata fields do not match",
        "WC-027 publisher Job scaler metadata fields do not match",
    ):
        assert required_job_check in source
    assert "var wc027ExpectedScalerMetadataKeys = [" in source
    assert "wc027ProducerScalerMetadataFieldsMatch" in source
    assert "wc027PublisherScalerMetadataFieldsMatch" in source
    for expected in (
        "notificationQueueName: validatedWc016RuntimeEnabled",
        (
            "feedSigningKeyUriWithVersion: "
            "acceptanceResources.outputs.incidentFeedV2SigningKeyUriWithVersion"
        ),
        "feedSigningKeyFingerprint: incidentFeedV2SigningKeyFingerprint",
        (
            "reportSigningKeyUriWithVersion: "
            "acceptanceResources.outputs.incidentReportSigningKeyUriWithVersion"
        ),
        "reportSigningKeyFingerprint: incidentReportSigningKeyFingerprint",
        (
            "guidanceSigningKeyUriWithVersion: "
            "acceptanceResources.outputs.incidentGuidanceSigningKeyUriWithVersion"
        ),
        "guidanceSigningKeyFingerprint: incidentGuidanceSigningKeyFingerprint",
        (
            "enrichmentSigningKeyUriWithVersion: "
            "acceptanceResources.outputs.incidentEnrichmentSigningKeyUriWithVersion"
        ),
        "enrichmentSigningKeyFingerprint: incidentEnrichmentSigningKeyFingerprint",
        (
            "notificationSigningKeyUriWithVersion: "
            "acceptanceResources.outputs.incidentNotificationSigningKeyUriWithVersion"
        ),
        "notificationSigningKeyFingerprint: incidentNotificationSigningKeyFingerprint",
        "incidentSigningKeyFingerprint: signingKeyFingerprint",
    ):
        assert expected in source


def test_wc027_roots_emit_exact_handoff_outputs() -> None:
    producer = PRODUCER_ROOT.read_text(encoding="utf-8")
    publisher = PUBLISHER_ROOT.read_text(encoding="utf-8")

    assert "module guidanceAuthoritySourceContainer 'modules/private-container.bicep'" in (producer)
    for output_name in (
        "producerImage",
        "feedV2ContainerResourceId",
        "feedRegistryTableResourceId",
        "guidanceActivationTableResourceId",
        "guidanceAuthoritySourceContainerResourceId",
        "triggerQueueResourceId",
        "notificationQueueResourceId",
        "registryRepositoryName",
        "registryPullConditionVersion",
        "registryPullCondition",
    ):
        assert f"output {output_name} " in producer
    for output_name in (
        "requestQueueResourceId",
        "triggerQueueResourceId",
        "authorityContainerResourceId",
        "activationTableResourceId",
        "bindingKeyResourceId",
        "bindingKeyVaultKeyId",
        "registryRepositoryName",
        "registryPullConditionVersion",
        "registryPullCondition",
    ):
        assert f"output {output_name} " in publisher


def test_publisher_acr_pull_uses_cross_resource_group_platform_topology() -> None:
    registry_resource_id = str(_publisher_parameter_bindings()["registryResourceId"])
    registry_segments = [segment for segment in registry_resource_id.split("/") if segment]
    assert registry_segments[3] == "rg-athena-platform-dev"

    publisher = PUBLISHER_ROOT.read_text(encoding="utf-8")
    module_start = publisher.index(
        "module publisherImagePull '../wc027-enrichment-feed-runtime/modules/acr-pull-rbac.bicep'"
    )
    module_end = publisher.index("\n}", module_start)
    module = publisher[module_start:module_end]
    assert "registrySubscriptionId = split(registryResourceId, '/')[2]" in publisher
    assert "registryResourceGroupName = split(registryResourceId, '/')[4]" in publisher
    assert "scope: resourceGroup(registrySubscriptionId, registryResourceGroupName)" in module


def test_service_bus_stage_profiles_are_explicit_in_iac() -> None:
    producer = PRODUCER_ROOT.read_text(encoding="utf-8")
    publisher = PUBLISHER_ROOT.read_text(encoding="utf-8")
    wc016 = WC016_ROOT.read_text(encoding="utf-8")

    for source, duration, ttl, lock, deliveries, message_size in (
        (producer, "'P7D'", "'P1D'", "'PT5M'", "10", "12288"),
        (publisher, "'PT15M'", "'PT5M'", "'PT5M'", "5", "12288"),
        (wc016, "'P7D'", "'P7D'", "'PT1M'", "10", "1024"),
    ):
        for expected in (
            "status: 'Active'",
            f"duplicateDetectionHistoryTimeWindow: {duration}",
            f"defaultMessageTimeToLive: {ttl}",
            f"lockDuration: {lock}",
            f"maxDeliveryCount: {deliveries}",
            f"maxMessageSizeInKilobytes: {message_size}",
            "maxSizeInMegabytes: 1024",
            "enableBatchedOperations: true",
            "enableExpress: false",
            "enablePartitioning: false",
        ):
            assert expected in source


def test_apply_is_bound_to_external_digest_and_fresh_what_if() -> None:
    source = (ROOT / "scripts" / "wc029_deployment_orchestration.py").read_text(encoding="utf-8")
    assert '--reviewed-plan-sha256", required=True' in source
    assert '--foundation-receipt", type=Path' in source
    assert '--foundation-reviewed-receipt-sha256"' in source
    assert '--producer-reviewed-receipt-sha256"' in source
    assert '--publisher-reviewed-receipt-sha256"' in source
    assert "athena.wc029DeploymentPlan.v7" in source
    assert "athena.wc029DeploymentReceipt.v4" in source
    assert "athena.wc029DeploymentHandoff.v6" in source
    assert "athena.wc029ImagePullEvidence.v2" in source
    assert "athena.wc029RevocationPlan.v1" in source
    assert "predecessorReceiptSha256s" in source
    assert "--rotation-transition-assignment" in source
    assert "rotationTransitionAssignments" in source
    assert "--legacy-crypto-user-migration-assignment" in source
    assert "legacyCryptoUserMigrationAssignmentIds" in source
    assert "--legacy-acr-pull-migration-assignment" in source
    assert "legacyAcrPullMigrationAssignments" in source
    assert "authorityBlobInventory" in source
    assert "authorityBlobInventorySha256" in source
    assert "requiredAuthorityCheckpointSha256s" in source
    assert "--resume-succeeded-deployment" in source
    assert "_materialized_private_artifact" in source
    assert "--prior-stage-handoff" in source
    assert "--prior-stage-receipt" in source
    assert "--prior-stage-reviewed-receipt-sha256" in source
    assert "priorStageReceipt" in source
    assert "receipt does not prove an independently reviewed plan" in source
    assert "return receipt_path" in source
    assert "plan manifest does not match the independently reviewed SHA-256" in source
    assert 'operation="what-if"' in source
    assert "current what-if differs from the plan" in source
    assert "_publish_evidence_bundle(" in source
    assert "deployment planning and apply require a clean committed working tree" in source
    assert "_verify_rbac_resources(" in source
    assert "_verify_job_behavior(" in source
    assert "_verify_identities(" in source


def test_trigger_queue_transition_cleanup_precedes_apply_mutation() -> None:
    source = (ROOT / "scripts" / "wc029_deployment_orchestration.py").read_text(encoding="utf-8")
    revocation_start = source.index("def prepare_revocation(")
    revocation_end = source.index("def plan(", revocation_start)
    revocation_source = source[revocation_start:revocation_end]
    assert 'transition_state="present"' in revocation_source
    assert 'operation="what-if"' not in revocation_source

    plan_start = source.index("def plan(")
    plan_transition_check = source.index(
        'transition_state="absent"',
        plan_start,
    )
    assert (
        "phase_a_rotation_assignments"
        in source[plan_transition_check - 300 : plan_transition_check]
    )
    plan_what_if = source.index('operation="what-if"', plan_transition_check)
    assert plan_transition_check < plan_what_if

    apply_start = source.index("def apply(")
    apply_source = source[apply_start:]
    apply_transition_check = apply_source.index('transition_state="absent"')
    assert (
        "phase_a_rotations" in apply_source[apply_transition_check - 300 : apply_transition_check]
    )
    execute = apply_source.index("_execute_reviewed_deployment(")
    helper_start = source.index("def _execute_reviewed_deployment(")
    current_what_if = source.index("current_what_if = _run_json(", helper_start)
    deployment_create = source.index('operation="create"', current_what_if)
    assert apply_transition_check < execute
    assert current_what_if < deployment_create
    assert "require_transition_revoked=False" not in apply_source
    assert "does not accept new rotation transition assignments" not in apply_source


def test_authority_blob_inventory_gates_plan_apply_and_handoff() -> None:
    source = (ROOT / "scripts" / "wc029_deployment_orchestration.py").read_text(encoding="utf-8")
    plan_start = source.index("def plan(")
    plan_inventory = source.index(
        "authority_blob_inventory =",
        plan_start,
    )
    plan_validate = source.index('operation="validate"', plan_inventory)
    assert plan_inventory < plan_validate

    apply_start = source.index("def apply(")
    apply_source = source[apply_start:]
    pre_inventory = apply_source.index("current_authority_blob_inventory =")
    deployment_execute = apply_source.index("_execute_reviewed_deployment(")
    post_inventory = apply_source.index(
        "post_deployment_authority_inventory,",
        deployment_execute,
    )
    handoff = apply_source.index("handoff = {", post_inventory)
    assert pre_inventory < deployment_execute < post_inventory < handoff


def test_runbook_keeps_wc027_roots_and_order_governed() -> None:
    source = RUNBOOK.read_text(encoding="utf-8")
    producer = "infra/wc027-enrichment-feed-runtime/main.bicep"
    publisher = "infra/wc027-guidance-authority-publisher/main.bicep"
    acceptance = "infra/wc013-live-acceptance/main.bicep"
    assert producer in source
    assert publisher in source
    sequence = source.index("sequence is therefore")
    producer_step = source.index("2. **Producer**", sequence)
    publisher_step = source.index("3. **Publisher**", producer_step)
    acceptance_step = source.index(
        "4. **Deployment activation gate (`live-acceptance`)**",
        publisher_step,
    )
    assert producer in source[producer_step:publisher_step]
    assert publisher in source[publisher_step:acceptance_step]
    assert acceptance in source[acceptance_step:]


def test_publisher_runtime_exists_but_automatic_request_invocation_is_separate() -> None:
    production = (ROOT / "src" / "athena_context" / "guidance" / "production.py").read_text(
        encoding="utf-8"
    )
    azure = (ROOT / "src" / "athena_context" / "guidance" / "azure.py").read_text(encoding="utf-8")
    orchestrator = (ROOT / "scripts" / "wc029_deployment_orchestration.py").read_text(
        encoding="utf-8"
    )
    runbook = RUNBOOK.read_text(encoding="utf-8")

    assert "client.get_queue_sender(" in production
    assert "queue_name=configuration.trigger_queue_name" in production
    assert "AzureServiceBusGuidanceAuthorityTrigger(trigger_sender)" in production
    assert "cast(Any, self._sender).send_messages(message)" in azure
    assert "publisher-to-producer trigger queue handoff" in orchestrator
    assert "submit_wc027_guidance_authority_request" not in orchestrator
    assert '"automaticRequestProducerPresent": False' in orchestrator
    assert '"runtimeInvocationValidated": False' in orchestrator
    assert "This four-stage tool establishes deployment wiring" in runbook
    assert "No merged production component automatically constructs and submits" in (runbook)
