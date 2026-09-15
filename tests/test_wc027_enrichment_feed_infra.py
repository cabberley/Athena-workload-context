from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
RUNTIME = ROOT / "infra" / "wc027-enrichment-feed-runtime" / "main.bicep"
ROOT_BICEP = ROOT / "infra" / "wc013-live-acceptance" / "main.bicep"
DOCKERFILE = ROOT / "apps" / "enrichment-feed-producer" / "Dockerfile"
CLI = ROOT / "src" / "athena_context" / "cli.py"
BLOB_READER_RBAC = (
    ROOT / "infra" / "wc027-enrichment-feed-runtime" / "modules" / "blob-reader-rbac.bicep"
)
KEY_VERIFIER_RBAC = (
    ROOT / "infra" / "wc027-enrichment-feed-runtime" / "modules" / "key-verifier-rbac.bicep"
)

STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE_ID = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"


def _resource_block(source: str, resource_name: str) -> str:
    start = source.index(f"resource {resource_name} ")
    end = source.index("\n}\n", start) + 2
    return source[start:end]


def _reviewed_feed_producer_job() -> tuple[dict[str, Any], dict[str, Any], str, str]:
    broker_identity_resource_id = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
        "rg-athena/providers/Microsoft.ManagedIdentity/userAssignedIdentities/wc027-broker"
    )
    broker_identity_client_id = "10000000-0000-0000-0000-000000000001"
    configuration_json = '{"schemaVersion":"synthetic.wc027RuntimeConfiguration.v1"}'
    image = "athenawc027.azurecr.io/athena/wc027-enrichment-feed-producer@sha256:" + "a" * 64
    environment_id = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
        "rg-athena/providers/Microsoft.App/managedEnvironments/athena-private"
    )
    configuration = {
        "serviceBus": {
            "namespace": "athena-wc027.servicebus.windows.net",
            "triggerQueueName": "wc027-enrichment-feed-requests",
            "brokerIdentityClientId": broker_identity_client_id,
            "brokerIdentityResourceId": broker_identity_resource_id,
        },
        "deploymentBinding": {
            "bindingEvidenceId": "20000000-0000-0000-0000-000000000001",
            "attachedIdentityResourceIds": [broker_identity_resource_id],
        },
    }
    job = {
        "tags": {
            "runtimeConfigurationDigest": "sha256:" + "b" * 64,
            "bindingEvidenceDigest": configuration["deploymentBinding"]["bindingEvidenceId"],
        },
        "identity": {
            "type": "UserAssigned",
            "userAssignedIdentities": {broker_identity_resource_id: {}},
        },
        "properties": {
            "environmentId": environment_id,
            "configuration": {
                "replicaTimeout": 900,
                "replicaRetryLimit": 0,
                "triggerType": "Event",
                "identitySettings": [],
                "secrets": [],
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
                                "identity": broker_identity_resource_id,
                                "auth": [],
                                "metadata": {
                                    "namespace": "athena-wc027",
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
                        "server": "athenawc027.azurecr.io",
                        "identity": broker_identity_resource_id,
                    }
                ],
            },
            "template": {
                "containers": [
                    {
                        "name": "wc027-enrichment-feed-producer",
                        "image": image,
                        "command": ["athena-context"],
                        "args": ["wc027-enrichment-feed-producer"],
                        "env": [
                            {
                                "name": "AZURE_CLIENT_ID",
                                "value": broker_identity_client_id,
                            },
                            {
                                "name": "ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON",
                                "value": configuration_json,
                            },
                        ],
                        "resources": {"cpu": 1, "memory": "2Gi"},
                        "probes": [],
                        "volumeMounts": [],
                    }
                ],
                "initContainers": [],
                "volumes": [],
            },
        },
    }
    return job, configuration, configuration_json, image


def _evaluate_feed_producer_job_template(
    source: str,
    *,
    job: dict[str, Any],
    configuration: dict[str, Any],
    configuration_json: str,
    image: str,
) -> bool:
    required_predicates = (
        "var wc027ProducerImageValid",
        "var wc027ProducerIdentityTypeMatches",
        "var wc027ProducerHasExactContainerCount",
        "var wc027ProducerTemplateMatches",
        "var wc027ProducerExecutionConfigurationMatches",
        "var wc027ProducerHasExactScalerRuleCount",
        "var wc027ProducerScalerMatches",
        "var wc027ProducerHasExactRegistryCount",
        "var wc027ProducerRegistryMatches",
        "var wc027ProducerTagsMatch",
        "length(wc027ProducerJob!.properties.template.containers) == 1",
        "(wc027ProducerJob!.identity.?type ?? '') == 'UserAssigned'",
        (
            "wc027ProducerJob!.properties.template.containers[0].name == "
            "'wc027-enrichment-feed-producer'"
        ),
        (
            "wc027ProducerJob!.properties.template.containers[0].image == "
            "wc027EnrichmentFeedProducerImage"
        ),
        "length(wc027ProducerJob!.properties.template.containers[0].command) == 1",
        "wc027ProducerJob!.properties.template.containers[0].command[0] == 'athena-context'",
        "length(wc027ProducerJob!.properties.template.containers[0].args) == 1",
        (
            "wc027ProducerJob!.properties.template.containers[0].args[0] == "
            "'wc027-enrichment-feed-producer'"
        ),
        "length(wc027ProducerJob!.properties.template.containers[0].env) == 2",
        ("wc027ProducerJob!.properties.template.containers[0].env[0].name == 'AZURE_CLIENT_ID'"),
        (
            "wc027ProducerJob!.properties.template.containers[0].env[0].value == "
            "wc027ParsedConfiguration.serviceBus.brokerIdentityClientId"
        ),
        (
            "wc027ProducerJob!.properties.template.containers[0].env[1].name == "
            "'ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON'"
        ),
        (
            "wc027ProducerJob!.properties.template.containers[0].env[1].value == "
            "wc027EnrichmentFeedProducerConfigurationJson"
        ),
        "wc027ProducerJob!.properties.template.containers[0].resources.cpu == 1",
        "wc027ProducerJob!.properties.template.containers[0].resources.memory == '2Gi'",
        "empty(wc027ProducerJob!.properties.template.containers[0].?probes ?? [])",
        "empty(wc027ProducerJob!.properties.template.containers[0].?volumeMounts ?? [])",
        "empty(wc027ProducerJob!.properties.template.?initContainers ?? [])",
        "empty(wc027ProducerJob!.properties.template.?volumes ?? [])",
        (
            "wc027ProducerJob!.properties.environmentId == "
            "azureMcp.outputs.managedEnvironmentResourceId"
        ),
        "wc027ProducerJob!.properties.configuration.replicaTimeout == 900",
        "wc027ProducerJob!.properties.configuration.replicaRetryLimit == 0",
        "wc027ProducerJob!.properties.configuration.triggerType == 'Event'",
        "empty(wc027ProducerJob!.properties.configuration.?identitySettings ?? [])",
        "empty(wc027ProducerJob!.properties.configuration.?secrets ?? [])",
        ("wc027ProducerJob!.properties.configuration.eventTriggerConfig.parallelism == 1"),
        (
            "wc027ProducerJob!.properties.configuration.eventTriggerConfig."
            "replicaCompletionCount == 1"
        ),
        ("wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.minExecutions == 0"),
        ("wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.maxExecutions == 1"),
        (
            "wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale."
            "pollingInterval == 30"
        ),
        ("length(wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules) == 1"),
        (
            "wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0]."
            "name == 'wc027-signed-binding'"
        ),
        (
            "wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0]."
            "type == 'azure-servicebus'"
        ),
        (
            "wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0]."
            "identity == wc027ParsedConfiguration.serviceBus.brokerIdentityResourceId"
        ),
        (
            "empty(wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale."
            "rules[0].?auth ?? [])"
        ),
        (
            "length(items(wc027ProducerJob!.properties.configuration.eventTriggerConfig."
            "scale.rules[0].metadata)) == 5"
        ),
        (
            "wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0]."
            "metadata.namespace == first(split(wc027ParsedConfiguration.serviceBus.namespace, '.'))"
        ),
        (
            "wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0]."
            "metadata.queueName == wc027ParsedConfiguration.serviceBus.triggerQueueName"
        ),
        (
            "wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0]."
            "metadata.messageCount == '1'"
        ),
        (
            "wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0]."
            "metadata.cloud == 'AzurePublicCloud'"
        ),
        (
            "wc027ProducerJob!.properties.configuration.eventTriggerConfig.scale.rules[0]."
            "metadata.isSessionsEnabled == 'true'"
        ),
        "length(wc027ProducerJob!.properties.configuration.registries) == 1",
        (
            "wc027ProducerJob!.properties.configuration.registries[0].server == "
            "wc027ProducerImageRegistryServer"
        ),
        (
            "wc027ProducerJob!.properties.configuration.registries[0].identity == "
            "wc027ParsedConfiguration.serviceBus.brokerIdentityResourceId"
        ),
        "length(items(wc027ProducerJob!.properties.configuration.registries[0])) == 2",
        (
            "wc027ProducerJob!.tags.runtimeConfigurationDigest == "
            "wc027EnrichmentFeedProducerConfigurationDigest"
        ),
        (
            "wc027ProducerJob!.tags.bindingEvidenceDigest == "
            "wc027ParsedConfiguration.deploymentBinding.bindingEvidenceId"
        ),
    )
    if any(predicate not in source for predicate in required_predicates):
        return False

    try:
        identity = job["identity"]
        properties = job["properties"]
        job_configuration = properties["configuration"]
        template = properties["template"]
        containers = template["containers"]
        if len(containers) != 1:
            return False
        container = containers[0]
        event_trigger = job_configuration["eventTriggerConfig"]
        scale = event_trigger["scale"]
        rules = scale["rules"]
        registries = job_configuration["registries"]
        if len(rules) != 1 or len(registries) != 1:
            return False
        rule = rules[0]
        registry = registries[0]
        service_bus = configuration["serviceBus"]
        deployment = configuration["deploymentBinding"]
    except KeyError, IndexError, TypeError:
        return False

    attached_identities = {value.casefold() for value in identity["userAssignedIdentities"]}
    expected_identities = {value.casefold() for value in deployment["attachedIdentityResourceIds"]}
    image_digest = image.rpartition("@sha256:")[2]
    return all(
        (
            image == image.casefold(),
            len(image_digest) == 64,
            set(image_digest).issubset(set("0123456789abcdef")),
            image_digest != "0" * 64,
            identity.get("type", "") == "UserAssigned",
            attached_identities == expected_identities,
            container["name"] == "wc027-enrichment-feed-producer",
            container["image"] == image,
            container["command"] == ["athena-context"],
            container["args"] == ["wc027-enrichment-feed-producer"],
            container["env"]
            == [
                {
                    "name": "AZURE_CLIENT_ID",
                    "value": service_bus["brokerIdentityClientId"],
                },
                {
                    "name": "ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON",
                    "value": configuration_json,
                },
            ],
            container["resources"] == {"cpu": 1, "memory": "2Gi"},
            not container.get("probes", []),
            not container.get("volumeMounts", []),
            not template.get("initContainers", []),
            not template.get("volumes", []),
            properties["environmentId"]
            == (
                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
                "rg-athena/providers/Microsoft.App/managedEnvironments/athena-private"
            ),
            job_configuration["replicaTimeout"] == 900,
            job_configuration["replicaRetryLimit"] == 0,
            job_configuration["triggerType"] == "Event",
            not job_configuration.get("identitySettings", []),
            not job_configuration.get("secrets", []),
            event_trigger["parallelism"] == 1,
            event_trigger["replicaCompletionCount"] == 1,
            scale["minExecutions"] == 0,
            scale["maxExecutions"] == 1,
            scale["pollingInterval"] == 30,
            rule["name"] == "wc027-signed-binding",
            rule["type"] == "azure-servicebus",
            rule["identity"] == service_bus["brokerIdentityResourceId"],
            not rule.get("auth", []),
            set(rule["metadata"])
            == {
                "namespace",
                "queueName",
                "messageCount",
                "cloud",
                "isSessionsEnabled",
            },
            rule["metadata"]["namespace"] == service_bus["namespace"].split(".", maxsplit=1)[0],
            rule["metadata"]["queueName"] == service_bus["triggerQueueName"],
            rule["metadata"]["messageCount"] == "1",
            rule["metadata"]["cloud"] == "AzurePublicCloud",
            rule["metadata"]["isSessionsEnabled"] == "true",
            registry
            == {
                "server": image.split("/", maxsplit=1)[0],
                "identity": service_bus["brokerIdentityResourceId"],
            },
            job["tags"]["runtimeConfigurationDigest"] == "sha256:" + "b" * 64,
            job["tags"]["bindingEvidenceDigest"] == deployment["bindingEvidenceId"],
        )
    )


def test_wc027_runtime_is_private_keyless_and_session_ordered() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    assert "requiresSession: true" in source
    assert "requiresDuplicateDetection: true" in source
    assert "duplicateDetectionHistoryTimeWindow: 'P7D'" in source
    assert "maxMessageSizeInKilobytes: 12288" in source
    assert "type: 'azure-servicebus'" in source
    assert "isSessionsEnabled: 'true'" in source
    assert "auth: []" in source
    assert "connectionString" not in source
    assert "listKeys(" not in source
    assert "runtimeConfigurationJson" in source
    assert "triggerSubmitterIdentityResourceIds" in source
    assert "principalId: triggerSubmitterIdentities[index].properties.principalId" in source
    assert "scope: triggerQueue" in source
    assert "ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON" in source
    assert "'wc027-enrichment-feed-producer'" in source
    assert "managedEnvironmentResourceId" in source
    assert "output producerImage string = validatedProducerImage" in source


def test_wc027_runtime_uses_derived_identities_and_key_scopes() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    # Distinct, explicitly referenced identity resource IDs replace the old independent
    # client-id/principal-id/runtime-identity arrays.
    for param in (
        "param brokerIdentityResourceId string",
        "param incidentReaderIdentityResourceId string",
        "param feedV2ProducerReaderIdentityResourceId string",
        "param feedV2WriterIdentityResourceId string",
        "param feedV2ReaderIdentityResourceId string",
        "param registryWriterIdentityResourceId string",
        "param trustReaderIdentityResourceId string",
        "param reportSignerIdentityResourceId string",
        "param guidanceSignerIdentityResourceId string",
        "param enrichmentSignerIdentityResourceId string",
        "param feedSignerIdentityResourceId string",
        "param notificationSignerIdentityResourceId string",
    ):
        assert param in source

    for removed in (
        "param brokerIdentityClientId",
        "param brokerIdentityPrincipalId",
        "param runtimeIdentityResourceIds",
        "param runtimeIdentityClientIds",
        "param incidentReaderPrincipalId",
        "param incidentWriterPrincipalId",
        "param registryWriterPrincipalId",
        "param trustReaderPrincipalId",
        "param reportSignerPrincipalId",
        "param runtimeConfigurationJson",
        "param triggerSubmitterPrincipalIds",
    ):
        assert removed not in source

    for scope in (
        "scope: reportKey",
        "scope: guidanceKey",
        "scope: enrichmentKey",
        "scope: feedKey",
        "scope: notificationKey",
    ):
        assert scope in source
    assert source.count("keyVaultCryptoUserRoleDefinitionId") >= 10
    assert "module producerImagePull" in source
    assert "attached runtime identity resource IDs must be distinct" in source


def test_wc027_producer_never_receives_blob_data_contributor_on_v1_incident_assets() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    # The producer must not receive container-wide list/delete/write (Blob Data Contributor)
    # on the v1 incident lifecycle assets. That role is absent from the whole module.
    assert STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE_ID not in source
    assert "storageBlobDataContributorRoleDefinitionId" not in source

    # The only assignment scoped to the v1 incident-assets container is read-only.
    assert source.count("scope: incidentContainer") == 1
    incident_reader = _resource_block(source, "incidentReaderV1")
    assert "scope: incidentContainer" in incident_reader
    assert "storageBlobDataReaderRoleDefinitionId" in incident_reader
    assert "principalId: incidentReaderIdentity.properties.principalId" in incident_reader


def test_wc027_custom_v2_writer_role_excludes_delete_and_list() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    role = _resource_block(source, "feedV2WriterRole")
    assert "type: 'CustomRole'" in role
    assert "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read" in role
    assert "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write" in role
    # No delete data actions and no container listing.
    assert "blobs/delete" not in role
    assert "containers/delete" not in role
    assert "containers/read" not in role
    assert "blobs/move" not in role
    assert "blobs/add/action" not in role

    # The isolated v2 container binds the writer through the custom role, a distinct producer
    # read-back reader, and a separately authorized presentation/gateway reader.
    writer = _resource_block(source, "feedV2Writer")
    assert "scope: feedV2Container" in writer
    assert "roleDefinitionId: feedV2WriterRole.id" in writer
    assert "principalId: feedV2WriterIdentity.properties.principalId" in writer
    assert "SubOperationMatches{\\'Blob.List\\'}" in writer

    producer_reader = _resource_block(source, "feedV2ProducerReader")
    assert "scope: feedV2Container" in producer_reader
    assert "principalId: feedV2ProducerReaderIdentity.properties.principalId" in producer_reader
    assert "storageBlobDataReaderRoleDefinitionId" in producer_reader
    assert "SubOperationMatches{\\'Blob.List\\'}" in producer_reader

    presentation_reader = _resource_block(source, "feedV2PresentationReader")
    assert "scope: feedV2Container" in presentation_reader
    assert "principalId: feedV2ReaderIdentity.properties.principalId" in presentation_reader
    assert "storageBlobDataReaderRoleDefinitionId" in presentation_reader
    assert "SubOperationMatches{\\'Blob.List\\'}" in presentation_reader

    incident_reader = _resource_block(source, "incidentReaderV1")
    assert "SubOperationMatches{\\'Blob.List\\'}" in incident_reader


def test_wc027_runtime_configuration_is_derived_from_referenced_resources() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    assert "var runtimeConfiguration = {" in source
    assert "var runtimeConfigurationJson = string(runtimeConfiguration)" in source
    # The config is generated in Bicep, never accepted as arbitrary JSON.
    assert "param runtimeConfigurationJson" not in source

    for derived in (
        "brokerIdentityClientId: brokerIdentity.properties.clientId",
        "brokerIdentityResourceId: brokerIdentity.id",
        "blobEndpoint: replayStorage.properties.primaryEndpoints.blob",
        "tableEndpoint: replayStorage.properties.primaryEndpoints.table",
        "keyVaultKeyId: incidentKey.properties.keyUriWithVersion",
        "keyId: 'synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1'",
        "keyVaultKeyId: reportKey.properties.keyUriWithVersion",
        "keyVaultKeyId: feedKey.properties.keyUriWithVersion",
        "keyId: guidanceBindingLogicalKeyId",
        "keyId: reportKey.properties.keyUriWithVersion",
        "keyId: notificationKey.properties.keyUriWithVersion",
        "namespace: serviceBusNamespaceHostName",
        "identityClientId: registryWriterIdentity.properties.clientId",
        "identityResourceId: registryWriterIdentity.id",
        "containerName: incidentContainer.name",
        "containerName: feedV2Container.name",
        "containerName: monitoringSourceContainer.name",
        "containerName: guidanceAuthoritySourceContainer.name",
        "tableName: feedRegistry.name",
        "tableName: guidanceActivation.name",
        "identityClientId: guidanceActivationReaderIdentity.properties.clientId",
        "triggerQueueName: triggerQueue.name",
        "notificationQueueName: notificationQueue.name",
        "bindingEvidenceId: bindingEvidenceDigest",
        "attachedIdentityResourceIds: validatedAttachedIdentityResourceIds",
        "rbacResourceIds: rbacResourceIds",
    ):
        assert derived in source

    assert (
        "serviceBusNamespaceHostName = '${serviceBusNamespace.name}.servicebus.windows.net'"
        in source
    )
    # The generated config and the derived broker client ID flow into the Job.
    assert "value: runtimeConfigurationJson" in source
    assert "value: brokerIdentity.properties.clientId" in source
    assert "trustDomainMetadata.guidanceBinding.keyId" not in source
    assert "trustDomainMetadata.report.keyId" not in source


def test_wc027_source_readers_and_key_verifier_are_exact_and_non_mutating() -> None:
    source = RUNTIME.read_text(encoding="utf-8")
    blob_reader = BLOB_READER_RBAC.read_text(encoding="utf-8")

    for module_name in (
        "monitoringSourceReader",
        "changeSourceReader",
        "contextAuthoritySourceReader",
        "monitoringIntentSourceReader",
        "guidanceAuthoritySourceReader",
    ):
        assert f"module {module_name} 'modules/blob-reader-rbac.bicep'" in source
    assert "scope: container" in blob_reader
    assert "principalId: identity.properties.principalId" in blob_reader
    assert "param identityPrincipalId" not in blob_reader
    assert "SubOperationMatches{\\'Blob.List\\'}" in blob_reader
    assert "blobs/write" not in blob_reader
    assert "blobs/delete" not in blob_reader

    key_verifier = KEY_VERIFIER_RBAC.read_text(encoding="utf-8")
    verifier_role = _resource_block(key_verifier, "verifierRole")
    assert "Microsoft.KeyVault/vaults/keys/read" in verifier_role
    assert "Microsoft.KeyVault/vaults/keys/verify/action" in verifier_role
    for forbidden in (
        "keys/sign/action",
        "keys/decrypt/action",
        "keys/wrap/action",
        "keys/unwrap/action",
        "keys/delete",
    ):
        assert forbidden not in verifier_role

    assert "scope: key" in key_verifier
    assert "roleDefinitionId: verifierRole.id" in key_verifier
    assert "principalId: identity.properties.principalId" in key_verifier
    assert "param identityPrincipalId" not in key_verifier


def test_wc027_job_identity_map_and_rbac_share_exact_resources() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    assert "userAssignedIdentities: jobIdentityMap" in source
    assert "reduce(" in source
    assert "validatedAttachedIdentityResourceIds," in source
    assert "var attachedIdentityResourceIds = [" in source

    for identity in (
        "brokerIdentity",
        "incidentReaderIdentity",
        "feedV2ProducerReaderIdentity",
        "feedV2WriterIdentity",
        "registryWriterIdentity",
        "trustReaderIdentity",
        "monitoringReaderIdentity",
        "changeReaderIdentity",
        "contextAuthorityReaderIdentity",
        "monitoringIntentReaderIdentity",
        "guidanceAuthorityReaderIdentity",
        "reportSignerIdentity",
        "guidanceSignerIdentity",
        "enrichmentSignerIdentity",
        "feedSignerIdentity",
        "notificationSignerIdentity",
    ):
        # Every configured runtime identity is attached by exact referenced resource ID.
        assert f"  {identity}.id\n" in source

    for identity in (
        "brokerIdentity",
        "incidentReaderIdentity",
        "feedV2ProducerReaderIdentity",
        "feedV2WriterIdentity",
        "registryWriterIdentity",
        "reportSignerIdentity",
        "guidanceSignerIdentity",
        "enrichmentSignerIdentity",
        "feedSignerIdentity",
        "notificationSignerIdentity",
    ):
        assert f"principalId: {identity}.properties.principalId" in source

    for identity in (
        "trustReaderIdentity",
        "monitoringReaderIdentity",
        "changeReaderIdentity",
        "contextAuthorityReaderIdentity",
        "monitoringIntentReaderIdentity",
        "guidanceAuthorityReaderIdentity",
    ):
        assert f"identityResourceId: {identity}.id" in source

    # The presentation/gateway reader is separately authorized and is NOT attached to the Job.
    assert "principalId: feedV2ReaderIdentity.properties.principalId" in source
    assert "  feedV2ReaderIdentity.id\n" not in source

    # Readiness evidence tags/outputs are emitted for the root deployment.
    assert "bindingEvidenceDigest: bindingEvidenceDigest" in source
    assert (
        "output attachedIdentityResourceIds array = validatedAttachedIdentityResourceIds" in source
    )
    assert "output bindingEvidenceDigest string = bindingEvidenceDigest" in source


def test_wc027_notification_gate_requires_deployed_job_resource_id() -> None:
    source = ROOT_BICEP.read_text(encoding="utf-8")

    assert "param wc027FeedV2ProducerReady bool = false" in source
    assert "param wc027EnrichmentFeedProducerJobResourceId string = ''" in source
    assert "param wc027EnrichmentFeedProducerConfigurationDigest string = ''" in source
    assert "param wc027EnrichmentFeedProducerConfigurationJson string = ''" in source
    assert "param wc027EnrichmentFeedProducerImage string = ''" in source
    assert "validatedWc027FeedV2ProducerReady" in source
    assert "wc027ProducerJobResourceIdShapeValid" in source
    assert "wc027ProducerJobResourceIdSegments[6] == 'Microsoft.App'" in source
    assert "wc027ProducerJobResourceIdSegments[7] == 'jobs'" in source
    assert (
        "toLower(wc027ProducerJob!.id) == toLower(wc027EnrichmentFeedProducerJobResourceId)"
    ) in source
    assert "exact deployed producer configuration digest" in source
    assert "wc027ProducerImageValid" in source
    assert "wc027ProducerIdentityTypeMatches" in source
    assert "wc027ProducerHasExactContainerCount" in source
    assert "wc027ProducerTemplateMatches" in source
    assert "wc027ProducerExecutionConfigurationMatches" in source
    assert "wc027ProducerScalerMatches" in source
    assert "wc027ProducerRegistryMatches" in source
    assert "wc027ProducerTagsMatch" in source
    assert "wc027ProducerJob!.tags.runtimeConfigurationDigest" in source
    assert "ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON" in source
    assert "notificationV2ProducerReady: validatedWc027FeedV2ProducerReady" in source
    feed_gate = source.split("var validatedWc027FeedV2ProducerReady =", maxsplit=1)[1].split(
        "var expectedAcceptanceImageRegistryServer",
        maxsplit=1,
    )[0]
    assert "wc027ProducerJob!" not in feed_gate


def test_wc027_feed_producer_reviewed_job_template_evaluates_ready() -> None:
    source = ROOT_BICEP.read_text(encoding="utf-8")
    job, configuration, configuration_json, image = _reviewed_feed_producer_job()

    assert _evaluate_feed_producer_job_template(
        source,
        job=job,
        configuration=configuration,
        configuration_json=configuration_json,
        image=image,
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "extra-sidecar",
        "system-assigned-identity",
        "extra-attached-identity",
        "probe",
        "volume-mount",
        "init-container",
        "volume",
        "secret",
        "identity-lifecycle",
        "image",
        "unpinned-reviewed-image",
        "command",
        "args",
        "environment",
        "cpu",
        "memory",
        "env",
        "replica-timeout",
        "replica-retry",
        "trigger-type",
        "parallelism",
        "replica-completion",
        "min-executions",
        "max-executions",
        "polling-interval",
        "extra-scaler",
        "scaler-name",
        "scaler-type",
        "scaler-identity",
        "scaler-auth",
        "scaler-metadata",
        "registry-count",
        "registry-server",
        "registry-identity",
        "registry-shape",
        "runtime-tag",
        "binding-tag",
    ),
)
def test_wc027_feed_producer_reviewed_job_template_rejects_drift(mutation: str) -> None:
    source = ROOT_BICEP.read_text(encoding="utf-8")
    job, configuration, configuration_json, image = _reviewed_feed_producer_job()
    selected = deepcopy(job)
    properties = selected["properties"]
    job_configuration = properties["configuration"]
    template = properties["template"]
    container = template["containers"][0]
    scale = job_configuration["eventTriggerConfig"]["scale"]
    scaler = scale["rules"][0]
    registry = job_configuration["registries"][0]
    reviewed_image = image

    if mutation == "extra-sidecar":
        template["containers"].append(deepcopy(container))
    elif mutation == "system-assigned-identity":
        selected["identity"]["type"] = "SystemAssigned, UserAssigned"
    elif mutation == "extra-attached-identity":
        selected["identity"]["userAssignedIdentities"]["/synthetic/identity/extra"] = {}
    elif mutation == "probe":
        container["probes"] = [{"type": "Liveness"}]
    elif mutation == "volume-mount":
        container["volumeMounts"] = [{"volumeName": "synthetic", "mountPath": "/mnt"}]
    elif mutation == "init-container":
        template["initContainers"] = [{"name": "synthetic-init"}]
    elif mutation == "volume":
        template["volumes"] = [{"name": "synthetic"}]
    elif mutation == "secret":
        job_configuration["secrets"] = [{"name": "synthetic"}]
    elif mutation == "identity-lifecycle":
        job_configuration["identitySettings"] = [
            {
                "identity": configuration["serviceBus"]["brokerIdentityResourceId"],
                "lifecycle": "Init",
            }
        ]
    elif mutation == "image":
        container["image"] = image.replace("a" * 64, "c" * 64)
    elif mutation == "unpinned-reviewed-image":
        reviewed_image = "athenawc027.azurecr.io/athena/wc027-enrichment-feed-producer:latest"
        container["image"] = reviewed_image
    elif mutation == "command":
        container["command"] = ["python"]
    elif mutation == "args":
        container["args"] = ["different-command"]
    elif mutation == "environment":
        properties["environmentId"] = "/synthetic/managed-environment"
    elif mutation == "cpu":
        container["resources"]["cpu"] = 2
    elif mutation == "memory":
        container["resources"]["memory"] = "4Gi"
    elif mutation == "env":
        container["env"].append({"name": "EXTRA", "value": "synthetic"})
    elif mutation == "replica-timeout":
        job_configuration["replicaTimeout"] = 901
    elif mutation == "replica-retry":
        job_configuration["replicaRetryLimit"] = 1
    elif mutation == "trigger-type":
        job_configuration["triggerType"] = "Manual"
    elif mutation == "parallelism":
        job_configuration["eventTriggerConfig"]["parallelism"] = 2
    elif mutation == "replica-completion":
        job_configuration["eventTriggerConfig"]["replicaCompletionCount"] = 2
    elif mutation == "min-executions":
        scale["minExecutions"] = 1
    elif mutation == "max-executions":
        scale["maxExecutions"] = 2
    elif mutation == "polling-interval":
        scale["pollingInterval"] = 31
    elif mutation == "extra-scaler":
        scale["rules"].append(deepcopy(scaler))
    elif mutation == "scaler-name":
        scaler["name"] = "different-scaler"
    elif mutation == "scaler-type":
        scaler["type"] = "cron"
    elif mutation == "scaler-identity":
        scaler["identity"] = "/synthetic/identity"
    elif mutation == "scaler-auth":
        scaler["auth"] = [{"secretRef": "synthetic"}]
    elif mutation == "scaler-metadata":
        scaler["metadata"]["extra"] = "synthetic"
    elif mutation == "registry-count":
        job_configuration["registries"].append(deepcopy(registry))
    elif mutation == "registry-server":
        registry["server"] = "different.azurecr.io"
    elif mutation == "registry-identity":
        registry["identity"] = "/synthetic/identity"
    elif mutation == "registry-shape":
        registry["username"] = "synthetic"
    elif mutation == "runtime-tag":
        selected["tags"]["runtimeConfigurationDigest"] = "sha256:" + "c" * 64
    else:
        selected["tags"]["bindingEvidenceDigest"] = "30000000-0000-0000-0000-000000000001"

    assert not _evaluate_feed_producer_job_template(
        source,
        job=selected,
        configuration=configuration,
        configuration_json=configuration_json,
        image=reviewed_image,
    )


def test_wc027_readiness_rejects_missing_or_mismatched_publisher_and_bindings() -> None:
    source = ROOT_BICEP.read_text(encoding="utf-8")

    # An explicit binding-publisher gate, false by default and bound to a
    # deployed publisher Job plus its exact configuration.
    assert "param wc027PublisherReady bool = false" in source
    assert "param wc027PublisherJobResourceId string = ''" in source
    assert "param wc027PublisherConfigurationDigest string = ''" in source
    assert "param wc027PublisherConfigurationJson string = ''" in source
    assert "param wc027PublisherImage string = ''" in source
    assert "validatedWc027PublisherReady" in source
    assert "wc027PublisherJob!.tags.runtimeConfigurationDigest" in source
    assert "wc027PublisherJob!.properties.template.containers[0].image" in source
    assert "wc027PublisherJob!.properties.template.containers[0].command[0]" in source
    assert "wc027PublisherJob!.properties.template.containers[0].args[0]" in source
    assert "wc027PublisherJob!.tags.enrichmentRuntimeConfigurationDigest" in source
    assert "string(wc027ParsedPublisherConfiguration.enrichmentRuntimeConfiguration)" in source
    assert "wc027PublisherScalerMatches" in source
    assert "eventTriggerConfig.scale.rules) == 1" in source
    assert "wc027PublisherRegistryMatches" in source
    assert "configuration.registries) == 1" in source
    assert "ATHENA_WC027_GUIDANCE_AUTHORITY_PUBLISHER_CONFIG_JSON" in source
    assert "wc027PublisherRbacEvidenceMatches" in source
    assert "wc027PublisherIdentitiesMatch" in source
    assert "param wc027EnrichmentFeedProducerExpectedIdentityResourceIds" not in source
    assert "param wc027EnrichmentFeedProducerBindingEvidenceDigest" not in source

    # Readiness is fail-closed without the real binding publisher.
    assert "wc027FeedV2ProducerReady && !validatedWc027PublisherReady" in source
    assert "explicitly ready PublishedGuidanceAuthorityBinding.v2 publisher" in source

    # Readiness verifies the RBAC binding evidence generated by the WC-027 deployment.
    assert "empty(wc027ParsedConfiguration.deploymentBinding.bindingEvidenceId)" in source
    assert (
        "wc027ProducerJob!.tags.bindingEvidenceDigest == "
        "wc027ParsedConfiguration.deploymentBinding.bindingEvidenceId" in source
    )

    # Readiness derives the exact identity set from the deployed configuration.
    assert "items(wc027ProducerJob!.identity.?userAssignedIdentities ?? {})" in source
    assert "wc027ParsedConfiguration.deploymentBinding.attachedIdentityResourceIds" in source
    assert "wc027ConfigurationIdentitiesMatchBinding" in source
    assert "wc027ParsedConfiguration.guidanceActivation.identityResourceId" in source
    assert "wc027RbacEvidenceMatchesConfiguration" in source
    assert "guid(" in source
    assert "join(wc027RbacResourceIds, '|')" in source
    assert "wc027ProducerIdentitiesMatchExactly" in source
    assert "do not exactly match the expected identity resource IDs" in source

    # Final readiness requires both the gate and the publisher, still false by default.
    assert ": wc027FeedV2ProducerReady && validatedWc027PublisherReady" in source


def test_wc027_producer_image_and_cli_are_executable() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    cli = CLI.read_text(encoding="utf-8")

    assert "COPY requirements-wc016.lock ./" in dockerfile
    assert "--require-hashes" in dockerfile
    assert 'ENTRYPOINT ["athena-context", "wc027-enrichment-feed-producer"]' in dockerfile
    assert '"wc027-enrichment-feed-submit"' in cli
    assert '"wc027-enrichment-feed-producer"' in cli
