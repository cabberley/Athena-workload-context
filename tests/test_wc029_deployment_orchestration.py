from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from scripts import wc029_deployment_orchestration as orchestration

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "operations" / "wc029-deployment-live-validation.md"
WC013_ROOT = ROOT / "infra" / "wc013-live-acceptance" / "main.bicep"
PRODUCER_ROOT = ROOT / "infra" / "wc027-enrichment-feed-runtime" / "main.bicep"
PUBLISHER_ROOT = (
    ROOT / "infra" / "wc027-guidance-authority-publisher" / "main.bicep"
)
SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000001"
RUNTIME_RESOURCE_GROUP = "rg"


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _write_parameters(path: Path, values: dict[str, object]) -> None:
    path.write_text(
        json.dumps(
            {
                "$schema": (
                    "https://schema.management.azure.com/schemas/"
                    "2019-04-01/deploymentParameters.json#"
                ),
                "contentVersion": "1.0.0.0",
                "parameters": {
                    name: {"value": value} for name, value in values.items()
                },
            }
        ),
        encoding="utf-8",
    )


def _foundation_parameter_bindings(
    values: dict[str, object],
) -> dict[str, object]:
    parameters = {name: {"value": value} for name, value in values.items()}
    return {
        "foundationParametersSha256": orchestration._foundation_parameter_digest(
            parameters
        )
    }


def _write_handoff(
    path: Path,
    stage: str,
    outputs: dict[str, object],
    *,
    parameter_bindings: dict[str, object] | None = None,
) -> None:
    bindings = {} if parameter_bindings is None else parameter_bindings
    resource_group = (
        RUNTIME_RESOURCE_GROUP if stage in {"producer", "publisher"} else None
    )
    path.write_text(
        json.dumps(
            {
                "schemaVersion": "athena.wc029DeploymentHandoff.v1",
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
                "planManifestSha256": f"sha256:{'a' * 64}",
            }
        ),
        encoding="utf-8",
    )


def _foundation_outputs() -> dict[str, object]:
    key_base = "https://athenawc013.vault.azure.net/keys"
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
        "incidentSigningKeyUriWithVersion": f"{key_base}/wc016-incident/v1",
        "wc016ApprovedConfiguration": {
            "wc027OrchestrationFoundation": {
                "notificationQueueName": "incident-notification-outbox",
                "feedSigningKeyUriWithVersion": f"{key_base}/wc027-feed/v1",
                "reportSigningKeyUriWithVersion": f"{key_base}/wc027-report/v1",
                "guidanceSigningKeyUriWithVersion": (
                    f"{key_base}/wc027-guidance/v1"
                ),
                "enrichmentSigningKeyUriWithVersion": (
                    f"{key_base}/wc027-enrichment/v1"
                ),
                "notificationSigningKeyUriWithVersion": (
                    f"{key_base}/wc027-notification/v1"
                ),
            }
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
    configuration = {
        "serviceBus": {
            "namespace": "athena-wc016-events.servicebus.windows.net",
            "triggerQueueName": "wc027-enrichment-feed-requests",
            "notificationQueueName": "incident-notification-outbox",
            "brokerIdentityClientId": identities["broker"]["identityClientId"],
            "brokerIdentityResourceId": identities["broker"]["identityResourceId"],
        },
        "incidentLifecycleAssets": identities["incident-reader"],
        "enrichmentFeedAssets": {
            "containerName": "wc027-enrichment-feed-v2",
            "readerIdentityClientId": identities["feed-reader"]["identityClientId"],
            "readerIdentityResourceId": identities["feed-reader"][
                "identityResourceId"
            ],
            "writerIdentityClientId": identities["feed-writer"]["identityClientId"],
            "writerIdentityResourceId": identities["feed-writer"][
                "identityResourceId"
            ],
        },
        "feedRegistry": {
            "tableName": "Wc027FeedRegistry",
            **identities["registry-writer"],
        },
        "guidanceActivation": {
            "tableName": "Wc027GuidanceActivation",
            "partitionKey": "wc027-guidance-authority",
            **identities["activation-reader"],
        },
        "correlationSources": {
            "monitoring": identities["monitoring"],
            "change": identities["change"],
            "contextAuthority": identities["context"],
            "monitoringIntent": identities["intent"],
        },
        "guidanceAuthoritySource": {
            "containerName": "wc027-guidance-authority",
            **identities["authority"],
        },
        "monitoringCollectorKey": identities["trust"],
        "keys": {
            "incident": identities["trust"],
            "correlationBinding": identities["trust"],
            "guidanceBinding": {
                **identities["trust"],
                "keyId": "synthetic-key://athena/wc027-guidance-binding",
                "keyVaultKeyId": (
                    "https://athena.vault.azure.net/keys/guidance-binding/v1"
                ),
                "keyFingerprint": f"sha256:{'b' * 64}",
            },
            "change": identities["trust"],
            "monitoringIntent": identities["trust"],
            "report": identities["report-signer"],
            "guidance": identities["guidance-signer"],
            "enrichment": identities["enrichment-signer"],
            "feed": identities["feed-signer"],
            "notification": identities["notification-signer"],
        },
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
    return {
        "producerJobResourceId": (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/rg/providers/Microsoft.App/jobs/wc027-producer"
        ),
        "producerImage": (
            "athena.azurecr.io/athena/wc027-enrichment-feed-producer@sha256:"
            + "2" * 64
        ),
        "deployedRuntimeConfigurationJson": configuration_json,
        "deployedRuntimeConfigurationDigest": _digest(configuration_json),
        "attachedIdentityResourceIds": configuration["deploymentBinding"][
            "attachedIdentityResourceIds"
        ],
        "bindingEvidenceDigest": configuration["deploymentBinding"][
            "bindingEvidenceId"
        ],
        "feedV2WriterRoleDefinitionId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            "33333333-3333-3333-3333-333333333333"
        ),
        "feedV2ContainerName": "wc027-enrichment-feed-v2",
        "feedV2ContainerResourceId": (
            f"{replay_storage_id}/blobServices/default/containers/"
            "wc027-enrichment-feed-v2"
        ),
        "feedRegistryTableResourceId": (
            f"{replay_storage_id}/tableServices/default/tables/Wc027FeedRegistry"
        ),
        "guidanceActivationTableResourceId": (
            f"{replay_storage_id}/tableServices/default/tables/"
            "Wc027GuidanceActivation"
        ),
        "guidanceAuthoritySourceContainerResourceId": (
            f"{correlation_storage_id}/blobServices/default/containers/"
            "wc027-guidance-authority"
        ),
        "triggerQueueName": "wc027-enrichment-feed-requests",
        "triggerQueueResourceId": (
            f"{service_bus_id}/queues/wc027-enrichment-feed-requests"
        ),
        "notificationQueueName": "incident-notification-outbox",
        "notificationQueueResourceId": (
            f"{service_bus_id}/queues/incident-notification-outbox"
        ),
        "namespaceHostName": "athena-wc016-events.servicebus.windows.net",
    }


def _producer_parameter_bindings() -> dict[str, object]:
    return {
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
        "managedEnvironmentResourceId": _foundation_outputs()[
            "managedEnvironmentResourceId"
        ],
        "monitoringCollectorKeyResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.KeyVault/vaults/athena/keys/monitoring-collector"
        ),
        "monitoringIntentKeyResourceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
            "Microsoft.KeyVault/vaults/athena/keys/monitoring-intent"
        ),
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
    producer_configuration = json.loads(
        str(producer["deployedRuntimeConfigurationJson"])
    )
    source_identity_ids = [
        producer_configuration["incidentLifecycleAssets"]["identityResourceId"],
        *(
            producer_configuration["correlationSources"][name]["identityResourceId"]
            for name in ("monitoring", "change", "contextAuthority", "monitoringIntent")
        ),
        producer_configuration["keys"]["guidanceBinding"]["identityResourceId"],
    ]
    attached_identity_ids = [
        value["identityResourceId"] for value in publisher_identities.values()
    ]
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
    configuration = {
        "serviceBus": {
            "namespace": "athena-wc016-events.servicebus.windows.net",
            "requestQueueName": "wc027-guidance-authority-requests",
            "triggerQueueName": "wc027-enrichment-feed-requests",
            "brokerIdentityClientId": publisher_identities["publisher-broker"][
                "identityClientId"
            ],
            "brokerIdentityResourceId": publisher_identities["publisher-broker"][
                "identityResourceId"
            ],
        },
        "authorityAssets": {
            "containerName": "wc027-guidance-authority",
            "readerIdentityClientId": publisher_identities["authority-reader"][
                "identityClientId"
            ],
            "readerIdentityResourceId": publisher_identities["authority-reader"][
                "identityResourceId"
            ],
            "writerIdentityClientId": publisher_identities["authority-writer"][
                "identityClientId"
            ],
            "writerIdentityResourceId": publisher_identities["authority-writer"][
                "identityResourceId"
            ],
        },
        "guidanceActivation": {
            "tableName": "Wc027GuidanceActivation",
            "identityClientId": publisher_identities["activation-writer"][
                "identityClientId"
            ],
            "identityResourceId": publisher_identities["activation-writer"][
                "identityResourceId"
            ],
        },
        "requestKey": publisher_identities["request-trust"],
        "bindingSigningKey": {
            "keyId": "synthetic-key://athena/wc027-guidance-binding",
            "keyVaultKeyId": (
                "https://athena.vault.azure.net/keys/guidance-binding/v1"
            ),
            "keyFingerprint": f"sha256:{'b' * 64}",
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
    return {
        "publisherJobResourceId": (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/rg/providers/Microsoft.App/jobs/wc027-publisher"
        ),
        "publisherImage": (
            "athena.azurecr.io/athena/wc027-guidance-authority-publisher@sha256:"
            + "1" * 64
        ),
        "deployedPublisherConfigurationJson": configuration_json,
        "deployedPublisherConfigurationDigest": _digest(configuration_json),
        "attachedIdentityResourceIds": configuration["deploymentBinding"][
            "attachedIdentityResourceIds"
        ],
        "bindingEvidenceDigest": configuration["deploymentBinding"][
            "bindingEvidenceId"
        ],
        "requestQueueName": "wc027-guidance-authority-requests",
        "requestQueueResourceId": (
            f"{service_bus_id}/queues/wc027-guidance-authority-requests"
        ),
        "triggerQueueResourceId": (
            f"{service_bus_id}/queues/wc027-enrichment-feed-requests"
        ),
        "authorityContainerName": "wc027-guidance-authority",
        "authorityContainerResourceId": (
            f"{authority_storage_id}/blobServices/default/containers/"
            "wc027-guidance-authority"
        ),
        "activationTableName": "Wc027GuidanceActivation",
        "activationTableResourceId": (
            f"{activation_storage_id}/tableServices/default/tables/"
            "Wc027GuidanceActivation"
        ),
        "bindingLogicalKeyId": "synthetic-key://athena/wc027-guidance-binding",
        "bindingKeyResourceId": binding_key_resource_id,
        "bindingKeyVaultKeyId": (
            "https://athena.vault.azure.net/keys/guidance-binding/v1"
        ),
    }


def _publisher_parameter_bindings() -> dict[str, object]:
    return {
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
        "managedEnvironmentResourceId": _foundation_outputs()[
            "managedEnvironmentResourceId"
        ],
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


def _accepted_readiness_outputs(
    producer: dict[str, object],
    publisher: dict[str, object],
) -> dict[str, object]:
    return {
        "wc016ApprovedConfiguration": {
            "wc027DeploymentReadiness": {
                "producer": {
                    "ready": True,
                    "jobResourceId": producer["producerJobResourceId"],
                    "image": producer["producerImage"],
                    "configurationDigest": producer[
                        "deployedRuntimeConfigurationDigest"
                    ],
                    "bindingEvidenceDigest": producer["bindingEvidenceDigest"],
                },
                "publisher": {
                    "ready": True,
                    "jobResourceId": publisher["publisherJobResourceId"],
                    "image": publisher["publisherImage"],
                    "configurationDigest": publisher[
                        "deployedPublisherConfigurationDigest"
                    ],
                    "embeddedProducerConfigurationDigest": producer[
                        "deployedRuntimeConfigurationDigest"
                    ],
                    "bindingEvidenceDigest": publisher["bindingEvidenceDigest"],
                },
            }
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
        parameter_bindings=_foundation_parameter_bindings(
            {"wc016RuntimeEnabled": True}
        ),
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
            "feedV2ReaderIdentityResourceId": outputs[
                "presentationIdentityResourceId"
            ],
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
    assert effective["managedEnvironmentResourceId"]["value"] == outputs[
        "managedEnvironmentResourceId"
    ]

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
    assert effective_publisher["enrichmentRuntimeConfigurationJson"]["value"] == (
        producer["deployedRuntimeConfigurationJson"]
    )
    assert effective_publisher["enrichmentRuntimeConfigurationDigest"]["value"] == (
        producer["deployedRuntimeConfigurationDigest"]
    )
    assert effective_publisher["serviceBusNamespaceName"]["value"] == (
        "athena-wc016-events"
    )
    assert effective_publisher["managedEnvironmentResourceId"]["value"] == (
        _foundation_outputs()["managedEnvironmentResourceId"]
    )
    assert effective_publisher["authorityStorageAccountResourceId"]["value"] == (
        _producer_parameter_bindings()["correlationSourceStorageAccountResourceId"]
    )
    assert effective_publisher["bindingKeyResourceId"]["value"] == (
        _producer_parameter_bindings()["guidanceBindingKeyResourceId"]
    )
    producer_configuration = json.loads(
        str(producer["deployedRuntimeConfigurationJson"])
    )
    assert effective_publisher["brokerIdentityResourceId"]["value"] == (
        producer_configuration["serviceBus"]["brokerIdentityResourceId"]
    )
    assert effective_publisher["bindingLogicalKeyId"]["value"] == (
        producer_configuration["keys"]["guidanceBinding"]["keyId"]
    )
    assert effective_publisher["bindingKeyFingerprint"]["value"] == (
        producer_configuration["keys"]["guidanceBinding"]["keyFingerprint"]
    )
    assert effective_publisher["bindingTrustReaderIdentityResourceId"]["value"].endswith(
        "/trust"
    )
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
    assert effective_acceptance["wc027PublisherImage"]["value"] == publisher[
        "publisherImage"
    ]
    assert effective_acceptance["wc027EnrichmentFeedProducerImage"]["value"] == producer[
        "producerImage"
    ]
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


def test_handoff_schema_rejects_unexpected_fields(tmp_path: Path) -> None:
    path = tmp_path / "foundation.handoff.json"
    _write_handoff(
        path,
        "foundation",
        _foundation_outputs(),
        parameter_bindings=_foundation_parameter_bindings(
            {"wc016RuntimeEnabled": True}
        ),
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    document["unexpected"] = "not-reviewed"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(orchestration.OrchestrationError, match="unexpected"):
        orchestration._load_handoff(path, expected_stage="foundation")


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
    mismatched_readback["wc016ApprovedConfiguration"]["wc027DeploymentReadiness"][
        "producer"
    ]["image"] = str(producer["producerImage"]).replace("2" * 64, "3" * 64)
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
            "userAssignedIdentities": {
                identity_id: {} for identity_id in identity_ids
            },
        },
        "tags": {
            "runtimeConfigurationDigest": producer[
                "deployedRuntimeConfigurationDigest"
            ],
            "bindingEvidenceDigest": producer["bindingEvidenceDigest"],
        },
    }
    orchestration._verify_job_deployment_binding(
        job=job,
        expected_resource_id=str(producer["producerJobResourceId"]),
        expected_environment_resource_id=str(
            _foundation_outputs()["managedEnvironmentResourceId"]
        ),
        expected_identity_resource_ids=identity_ids,
        expected_configuration_digest=str(
            producer["deployedRuntimeConfigurationDigest"]
        ),
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
            expected_configuration_digest=str(
                producer["deployedRuntimeConfigurationDigest"]
            ),
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
            expected_configuration_digest=str(
                producer["deployedRuntimeConfigurationDigest"]
            ),
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
                                "identity": service_bus[
                                    "brokerIdentityResourceId"
                                ],
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
                "scope": queue_scope,
            },
        }

    monkeypatch.setattr(orchestration, "_get_resource", get_resource)
    with pytest.raises(orchestration.OrchestrationError, match="exact resource scope"):
        orchestration._verify_rbac_resources(
            {"rbacResourceIds": [assignment_id]},
            allowed_principal_ids={principal_id},
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
                "requiresSession": False,
                "requiresDuplicateDetection": True,
                "deadLetteringOnMessageExpiration": True,
            },
        },
    )
    with pytest.raises(orchestration.OrchestrationError, match="require sessions"):
        orchestration._verify_service_bus_queue(
            job_resource_id=(
                f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
                "Microsoft.App/jobs/wc027-producer"
            ),
            namespace_name="athena-wc016-events",
            queue_name="wc027-enrichment-feed-requests",
            subscription_id=SUBSCRIPTION_ID,
        )


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


def test_effective_broad_rbac_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal_id = "55555555-5555-5555-5555-555555555555"

    def run_json(_command: object, *, field: str) -> object:
        assert "effective role assignments" in field
        return [
            {
                "principalId": principal_id,
                "roleDefinitionName": "Contributor",
                "scope": f"/subscriptions/{SUBSCRIPTION_ID}",
            }
        ]

    monkeypatch.setattr(orchestration, "_run_json", run_json)
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
        lambda _command, *, field: [
            {"id": unexpected_assignment, "scope": governed_scope}
        ],
    )
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
            additional_allowed_assignment_ids=set(),
            subscription_id=SUBSCRIPTION_ID,
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
    assert (
        "wc027PublisherJobResourceIdRawSegments,\n  ["
        in source
    )
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
    ):
        assert required_job_check in source
    for expected in (
        "notificationQueueName: validatedWc016RuntimeEnabled",
        (
            "feedSigningKeyUriWithVersion: "
            "acceptanceResources.outputs.incidentFeedV2SigningKeyUriWithVersion"
        ),
        (
            "reportSigningKeyUriWithVersion: "
            "acceptanceResources.outputs.incidentReportSigningKeyUriWithVersion"
        ),
        (
            "guidanceSigningKeyUriWithVersion: "
            "acceptanceResources.outputs.incidentGuidanceSigningKeyUriWithVersion"
        ),
        (
            "enrichmentSigningKeyUriWithVersion: "
            "acceptanceResources.outputs.incidentEnrichmentSigningKeyUriWithVersion"
        ),
        (
            "notificationSigningKeyUriWithVersion: "
            "acceptanceResources.outputs.incidentNotificationSigningKeyUriWithVersion"
        ),
    ):
        assert expected in source


def test_wc027_roots_emit_exact_handoff_outputs() -> None:
    producer = PRODUCER_ROOT.read_text(encoding="utf-8")
    publisher = PUBLISHER_ROOT.read_text(encoding="utf-8")

    assert "module guidanceAuthoritySourceContainer 'modules/private-container.bicep'" in (
        producer
    )
    for output_name in (
        "producerImage",
        "feedV2ContainerResourceId",
        "feedRegistryTableResourceId",
        "guidanceActivationTableResourceId",
        "guidanceAuthoritySourceContainerResourceId",
        "triggerQueueResourceId",
        "notificationQueueResourceId",
    ):
        assert f"output {output_name} " in producer
    for output_name in (
        "requestQueueResourceId",
        "triggerQueueResourceId",
        "authorityContainerResourceId",
        "activationTableResourceId",
        "bindingKeyResourceId",
        "bindingKeyVaultKeyId",
    ):
        assert f"output {output_name} " in publisher


def test_apply_is_bound_to_external_digest_and_fresh_what_if() -> None:
    source = (
        ROOT / "scripts" / "wc029_deployment_orchestration.py"
    ).read_text(encoding="utf-8")
    assert '--reviewed-plan-sha256", required=True' in source
    assert "plan manifest does not match the independently reviewed SHA-256" in source
    assert 'operation="what-if"' in source
    assert "current what-if differs from the plan" in source
    assert "deployment planning and apply require a clean committed working tree" in source
    assert "_verify_rbac_resources(" in source
    assert "_verify_job_behavior(" in source
    assert "_verify_identities(" in source


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
    acceptance_step = source.index("4. **Live-acceptance gate**", publisher_step)
    assert producer in source[producer_step:publisher_step]
    assert publisher in source[publisher_step:acceptance_step]
    assert acceptance in source[acceptance_step:]
