from pathlib import Path

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
KEY_SIGN_VERIFY_RBAC = (
    ROOT / "infra" / "wc027-enrichment-feed-runtime" / "modules" / "key-sign-verify-rbac.bicep"
)
PRIVATE_CONTAINER = (
    ROOT / "infra" / "wc027-enrichment-feed-runtime" / "modules" / "private-container.bicep"
)
ACR_PULL_RBAC = (
    ROOT / "infra" / "wc027-enrichment-feed-runtime" / "modules" / "acr-pull-rbac.bicep"
)

STORAGE_BLOB_DATA_CONTRIBUTOR_ROLE_ID = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"


def _resource_block(source: str, resource_name: str) -> str:
    start = source.index(f"resource {resource_name} ")
    end = source.index("\n}\n", start) + 2
    return source[start:end]


def test_wc027_runtime_is_private_keyless_and_session_ordered() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    assert "requiresSession: true" in source
    assert "requiresDuplicateDetection: true" in source
    assert "duplicateDetectionHistoryTimeWindow: 'P7D'" in source
    assert "autoDeleteOnIdle: 'P10675199DT2H48M5.4775807S'" in source
    assert "maxMessageSizeInKilobytes: 12288" in source
    assert "type: 'azure-servicebus'" in source
    assert "isSessionsEnabled: 'true'" in source
    assert "connectionString" not in source
    assert "listKeys(" not in source
    assert "runtimeConfigurationJson" in source
    assert "triggerSubmitterIdentityResourceIds" in source
    assert "principalId: triggerSubmitterIdentities[index].properties.principalId" in source
    assert "scope: triggerQueue" in source
    assert "ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON" in source
    assert "'wc027-enrichment-feed-producer'" in source
    assert "managedEnvironmentResourceId" in source


def test_wc027_runtime_uses_derived_identities_and_key_scopes() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    # Distinct, explicitly referenced identity resource IDs replace the old independent
    # client-id/principal-id/runtime-identity arrays.
    for param in (
        "param brokerIdentityResourceId string",
        "param brokerIdentityPrincipalId string",
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

    assert (
        "brokerIdentity.properties.principalId == brokerIdentityPrincipalId"
        in source
    )
    assert (
        "guid(registryScopedResourceId, brokerIdentityPrincipalId, "
        "registryPullRoleDefinitionId)"
        in source
    )

    for module_name in (
        "reportSignerRbac",
        "guidanceSignerRbac",
        "enrichmentSignerRbac",
        "feedSignerRbac",
        "notificationSignerRbac",
    ):
        assert f"module {module_name} 'modules/key-sign-verify-rbac.bicep'" in source
    assert "keyVaultCryptoUserRoleDefinitionId" not in source
    assert "module producerImagePull" in source
    assert "attached runtime identity resource IDs must be distinct" in source


def test_wc027_acr_pull_is_mode_aware_principal_seeded_and_cross_scope() -> None:
    source = RUNTIME.read_text(encoding="utf-8")
    module = ACR_PULL_RBAC.read_text(encoding="utf-8")

    for expected in (
        "param registryResourceId string",
        "param identityPrincipalId string",
        "param registryRoleAssignmentMode string",
        "reference(registry.id, '2025-04-01', 'Full')",
        "registryRuntime.properties.roleAssignmentMode == registryRoleAssignmentMode",
        "guardedPullRoleDefinitionResourceId",
        "roleDefinitionId: guardedPullRoleDefinitionResourceId",
        "b93aa761-3e63-49ed-ac28-beffa264f7ac",
        "7f951dda-4ed3-4680-a7ca-43fe172d538d",
        "guid(registry.id, identityPrincipalId, pullRoleDefinitionResourceId)",
        "principalType: 'ServicePrincipal'",
        "output registryResourceId string = runtimeRegistryResourceId",
        "output roleAssignmentMode string = validatedRoleAssignmentMode",
    ):
        assert expected in module
    assert "param identityResourceId string" not in module
    assert "guid(registry.id, identity.id" not in module

    for expected in (
        "scope: resourceGroup(",
        "split(registryResourceId, '/')[2]",
        "split(registryResourceId, '/')[4]",
        "identityPrincipalId: validatedBrokerIdentityPrincipalId",
        "registryRoleAssignmentMode: registryRoleAssignmentMode",
        "registryPullRoleAssignmentId",
        "producerImagePull.outputs.registryResourceId",
    ):
        assert expected in source
    assert "guid(registry.id, brokerIdentity.id" not in source


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
        "containerName: guidanceAuthoritySourceContainer.outputs.name",
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

    private_container = PRIVATE_CONTAINER.read_text(encoding="utf-8")
    assert "isVersioningEnabled == true" in private_container
    assert "guidance-authority storage Blob versioning must be enabled" in (private_container)


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
    ):
        assert f"principalId: {identity}.properties.principalId" in source

    sign_verify = KEY_SIGN_VERIFY_RBAC.read_text(encoding="utf-8")
    assert "principalId: identity.properties.principalId" in sign_verify
    assert "scope: key" in sign_verify
    assert "Microsoft.KeyVault/vaults/keys/sign/action" in sign_verify
    assert "Microsoft.KeyVault/vaults/keys/verify/action" in sign_verify
    for forbidden in (
        "keys/read",
        "keys/encrypt/action",
        "keys/decrypt/action",
        "keys/wrap/action",
        "keys/unwrap/action",
        "keys/delete",
    ):
        assert forbidden not in sign_verify

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
    assert "validatedWc027FeedV2ProducerReady" in source
    assert "toLower(wc027ProducerJobResourceIdSegments[6]) == 'microsoft.app'" in source
    assert "toLower(wc027ProducerJobResourceIdSegments[7]) == 'jobs'" in source
    assert "exact deployed producer configuration digest" in source
    assert "wc027ProducerJob!.tags.runtimeConfigurationDigest" in source
    assert "ATHENA_WC027_ENRICHMENT_FEED_CONFIG_JSON" in source
    assert "notificationV2ProducerReady: validatedWc027FeedV2ProducerReady" in source


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
    assert "eventTriggerConfig.scale.rules) != 1" in source
    assert "configuration.registries) != 1" in source
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
        "wc027ProducerJob!.tags.bindingEvidenceDigest != "
        "wc027ParsedConfiguration.deploymentBinding.bindingEvidenceId" in source
    )

    # Readiness derives the exact identity set from the deployed configuration.
    assert "items(wc027ProducerJob!.identity.userAssignedIdentities)" in source
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
