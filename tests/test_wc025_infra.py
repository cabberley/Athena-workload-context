from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]
BICEP = ROOT / "infra" / "wc025-change-ingestion" / "main.bicep"
BICEP_MODULES = tuple((BICEP.parent / "modules").glob("*.bicep"))
PRIVATE_TRANSPORT = BICEP.parent / "modules" / "private-transport.bicep"
RESOURCE_GROUP_ROUTING = BICEP.parent / "modules" / "resource-group-routing.bicep"
EVIDENCE_BLOB_VERSIONING_GATE = BICEP.parent / "modules" / "evidence-blob-versioning-gate.bicep"
DOCKERFILE = ROOT / "apps" / "change-event-ingester" / "Dockerfile"


def _bicep_source() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in (BICEP, *BICEP_MODULES))


def test_wc025_bicep_bounds_event_grid_to_one_resource_group_and_private_queue() -> None:
    source = _bicep_source()

    assert "targetScope = 'subscription'" in source
    assert "'rg-athena-demo-workload'" in source
    assert "source: resourceGroup().id" in source
    assert "topicType: 'Microsoft.Resources.ResourceGroups'" in source
    assert "Microsoft.EventGrid/systemTopics@2025-02-15" in source
    assert "Microsoft.EventGrid/systemTopics/eventSubscriptions@2025-02-15" in source
    assert "'Microsoft.Resources.ResourceWriteSuccess'" in source
    assert "'Microsoft.Resources.ResourceWriteFailure'" in source
    assert "'Microsoft.Resources.ResourceWriteCancel'" in source
    assert "'Microsoft.Resources.ResourceDeleteSuccess'" in source
    assert "'Microsoft.Resources.ResourceDeleteFailure'" in source
    assert "'Microsoft.Resources.ResourceDeleteCancel'" in source
    assert "'Microsoft.Resources.ResourceActionSuccess'" in source
    assert "'Microsoft.Resources.ResourceActionFailure'" in source
    assert "'Microsoft.Resources.ResourceActionCancel'" in source
    assert "key: 'data.resourceUri'" in source
    assert "operatorType: 'StringIn'" in source
    assert "Microsoft.Insights/eventtypes" not in source
    assert "activity log" not in source.casefold()
    assert "requiresDuplicateDetection: true" in source
    assert "publicNetworkAccess: 'Enabled'" in source
    assert "defaultAction: 'Deny'" in source
    assert "trustedServiceAccessEnabled: true" in source
    assert "disableLocalAuth: true" in source
    assert "privateEndpoints@2024-10-01" in source
    assert "privatelink.servicebus.windows.net" in source
    assert "userAssignedIdentity: eventGridDeliveryIdentityResourceId" in source


def test_wc025_resource_group_event_grid_topic_uses_the_global_location() -> None:
    source = RESOURCE_GROUP_ROUTING.read_text(encoding="utf-8")
    topic = source[
        source.index("resource resourceChangeSystemTopic ") : source.index(
            "resource resourceChangeSubscription "
        )
    ]

    assert "location: 'global'" in topic
    assert "location: location" not in topic
    assert "param location" not in source


def test_wc025_bicep_uses_separate_least_privilege_workers_and_persistence() -> None:
    source = _bicep_source()

    assert "param eventIngesterIdentityName string" in source
    assert "param purgeIdentityName string" in source
    assert "param queryIdentityName string" in source
    assert "param eventGridDeliveryIdentityName string" in source
    assert (
        "WC-025 Event Grid delivery, event ingestion, dead-letter purge, and query workers require"
        in source
    )
    assert "normalizedIdentityNames" in source
    assert "toLower(purgeIdentityName)" in source
    assert source.count(
        "'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing"
    ) == 4
    assert "eventGridDeliveryIdentity.properties.principalId" in source
    assert "eventIngesterIdentity.properties.clientId" in source
    assert "eventIngesterIdentity.properties.principalId" in source
    assert "purgeIdentity.properties.clientId" in source
    assert "purgeIdentity.properties.principalId" in source
    assert "queryIdentity.properties.clientId" in source
    assert "queryIdentity.properties.principalId" in source
    assert "Athena WC025 Bounded Resource Change History Reader" in source
    assert "'Microsoft.Resources/changes/read'" in source
    assert "'Microsoft.ResourceGraph/resources/read'" in source
    assert "assignableScopes: [" in source
    assert "workloadResourceGroup.id" in source
    assert "scope: evidenceContainer" in source
    assert "scope: changeSigningKey" in source
    assert source.count("Microsoft.App/jobs@2025-01-01") == 3
    assert "'wc025-change-event-ingester'" in source
    assert "'wc025-change-dead-letter-purge'" in source
    assert "'wc025-change-history-query'" in source
    assert "cronExpression: '*/1 * * * *'" in source
    assert "cronExpression: '*/5 * * * *'" in source
    assert "ATHENA_WC025_APPROVED_CHANGE_SCOPE_JSON" in source
    assert "approvedResourceIds: uniqueApprovedResourceIds" in source
    assert "@maxLength(25)" in source
    assert "length(string(resourceId)) <= 512" in source
    assert "validatedChangeSigningKeyUriWithVersion" in source
    assert "listKeys(" not in source
    assert "connectionString" not in source
    purge_job = source[
        source.index("resource deadLetterPurgeJob ") : source.index(
            "resource queryWorkerJob "
        )
    ]
    assert "'${purgeIdentityResourceId}': {}" in purge_job
    assert "identity: purgeIdentityResourceId" in purge_job
    assert "purgeIdentityClientId" in purge_job
    assert "failureReceiptContainerName" in purge_job
    assert "evidenceContainerName" not in purge_job
    assert "changeSigningKeyUriWithVersion" not in purge_job
    assert "scope: failureReceiptContainer" in source


def test_wc025_bicep_assigns_workers_the_key_vault_crypto_user_role() -> None:
    source = _bicep_source()

    assert "12338af0-0e69-4776-bea7-57ae8d297424" in source
    assert "14b46e9e-c2b7-41b4-b07b-48a6ebf60603" not in source
    assert source.count("keyVaultCryptoUserRoleId") == 5


def test_wc025_bicep_assigns_event_grid_before_creating_its_subscription() -> None:
    root_source = BICEP.read_text(encoding="utf-8")

    assert root_source.index("module eventGridDeliveryRbac") < root_source.index(
        "module resourceGroupRouting"
    )
    assert "dependsOn: [\n    eventGridDeliveryRbac\n  ]" in root_source
    assert "dependsOn: [\n    resourceGroupRouting\n  ]" not in root_source


def test_wc025_bicep_requires_evidence_blob_versioning_before_workers_deploy() -> None:
    root_source = BICEP.read_text(encoding="utf-8")
    gate_source = EVIDENCE_BLOB_VERSIONING_GATE.read_text(encoding="utf-8")
    workers_module = root_source[
        root_source.index("module workers ") : root_source.index(
            "@description('Private Service Bus namespace"
        )
    ]

    assert "resource evidenceBlobService " in root_source
    assert "name: 'default'" in root_source
    assert (
        "isVersioningEnabled: evidenceBlobService.properties.isVersioningEnabled == true"
        in root_source
    )
    assert "module evidenceBlobVersioningGate " in root_source
    assert root_source.index("module evidenceBlobVersioningGate ") < root_source.index(
        "module workers "
    )
    assert "evidenceBlobVersioningGate" in workers_module
    assert "param isVersioningEnabled bool" in gate_source
    assert "isVersioningEnabled == true" in gate_source
    assert "version-pinned replay receipts" in gate_source


def test_wc025_bicep_accepts_exact_nested_resource_ids() -> None:
    root_source = BICEP.read_text(encoding="utf-8")

    assert "length(split(toLower(string(resourceId)), '/')) >= 9" in root_source
    assert "(length(split(toLower(string(resourceId)), '/')) - 7) % 2 == 0" in root_source
    assert "length(split(toLower(string(resourceId)), '/')) == 9" not in root_source


def test_wc025_bicep_populates_service_bus_private_dns_before_vnet_linking() -> None:
    source = PRIVATE_TRANSPORT.read_text(encoding="utf-8")

    namespace_index = source.index("resource namespace ")
    queue_index = source.index("resource changeEventsQueue ")
    private_endpoint_index = source.index("resource serviceBusPrivateEndpoint ")
    zone_group_index = source.index("resource serviceBusPrivateDnsZoneGroup ")
    vnet_link_index = source.index("resource serviceBusPrivateDnsLink ")

    assert (
        namespace_index < queue_index < private_endpoint_index < zone_group_index < vnet_link_index
    )
    assert """dependsOn: [
    changeEventsQueue
  ]""" in source[private_endpoint_index:zone_group_index]
    assert """dependsOn: [
    serviceBusPrivateDnsZoneGroup
  ]""" in source[vnet_link_index:]


def test_wc025_worker_image_remains_keyless_and_hash_locked() -> None:
    source = DOCKERFILE.read_text(encoding="utf-8")

    assert "requirements-wc016.lock" in source
    assert "--require-hashes" in source
    assert "--only-binary=:all:" in source
    assert 'ENTRYPOINT ["athena-context"]' in source
    assert "connection" not in source.casefold()


def test_wc025_worker_images_allow_only_the_bound_registry_repository_and_real_digest() -> None:
    source = BICEP.read_text(encoding="utf-8")

    assert "registryName == toLower(registryName)" in source
    assert "expectedRegistryServer = '${validatedRegistryName}.azurecr.io'" in source
    assert "registryServer == toLower(registryServer)" in source
    assert "registryServer == expectedRegistryServer" in source
    assert (
        "changeIngesterImageRepositoryPrefix = "
        "'${validatedRegistryServer}/athena/wc025-change-ingester@sha256:'"
    ) in source
    assert "changeIngesterImage == toLower(changeIngesterImage)" in source
    assert "changeIngesterImageDigestCandidate\n) == 64" in source
    assert "changeIngesterImageDigestInvalidCharacters" in source
    assert "rejectedChangeIngesterImageDigestSuffix" in source
    assert "registryName: validatedRegistryName" in source
    assert "registryServer: validatedRegistryServer" in source
    assert "changeIngesterImage: validatedChangeIngesterImage" in source
