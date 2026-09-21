from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from azure.core.exceptions import (
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)
from pydantic import ValidationError

from athena_context.artifacts import ArtifactReadError, ArtifactWriteError
from athena_context.azure_adapters import (
    AzureBlobIncidentAssetPublisher,
    KeyVaultRsaPublicKeyVerifier,
    KeyVaultRsaSigner,
    KeyVaultTrustedKeyResolver,
)
from athena_context.contracts import (
    TrustedKeyRecord,
)
from athena_context.correlation import (
    CorrelationService,
    TrustedChangeArtifactVerifier,
    TrustedMonitoringHandoffVerifier,
    TrustedMonitoringIntentAssetVerifier,
)
from athena_context.enrichment.production import (
    Wc027EnrichmentFeedProductionConfiguration,
    _blob_source,
    _BlobSource,
    _client_id,
    _correlation_reader,
    _identity_resource_ids,
    _key_authority,
    _KeyAuthority,
    _managed_identity_resource_id,
    _mapping,
    _queue_name,
    _rbac_resource_ids,
    _require_keys,
    _service_bus_namespace,
    _signer,
    _text,
    _verifier,
    _writable_blob_source,
    _WritableBlobSource,
)
from athena_context.eventing.change_ingestion import (
    KeyVaultChangeEvidenceSigner,
)
from athena_context.guidance.azure import (
    AzureBlobGuidanceAuthorityArtifactWriter,
    AzureServiceBusGuidanceAuthorityTrigger,
    AzureTableGuidanceAuthorityActivationStore,
)
from athena_context.guidance.publication import (
    GuidanceAuthorityActivationConflictError,
    GuidanceAuthorityDeliveryExpiredError,
    GuidanceAuthorityOccurrenceConflictError,
    GuidanceAuthorityPublisher,
    GuidanceAuthoritySourceNotReadyError,
    parse_guidance_authority_publication_request,
)
from athena_context.guidance.request_publication import (
    GuidancePublicationRequestDeliveryBudget,
    validate_guidance_publication_request_broker_metadata,
    verify_guidance_publication_request_outbox,
)

_CONFIG_SCHEMA_VERSION = "athena.wc027GuidanceAuthorityPublisherConfiguration.v1"


@dataclass(frozen=True, slots=True)
class _ActivationWriter:
    endpoint: str
    table_name: str
    partition_key: str
    identity_client_id: str
    identity_resource_id: str


@dataclass(frozen=True, slots=True)
class _ImagePullBinding:
    registry_resource_id: str
    registry_server: str
    image: str
    repository_name: str
    role_assignment_mode: str
    anonymous_pull_enabled: bool
    role_definition_id: str
    role_assignment_resource_id: str
    condition_version: str | None
    condition: str | None
    identity_client_id: str
    identity_resource_id: str
    identity_principal_id: str


@dataclass(frozen=True, slots=True)
class Wc027GuidanceAuthorityPublisherConfiguration:
    service_bus_namespace: str
    request_queue_name: str
    trigger_queue_name: str
    broker_identity_client_id: str
    broker_identity_resource_id: str
    request_submitter_identity_client_id: str
    request_submitter_identity_resource_id: str
    image_pull: _ImagePullBinding
    request_outbox: _BlobSource
    authority_assets: _WritableBlobSource
    activation: _ActivationWriter
    request_key: _KeyAuthority
    binding_signing_key: _KeyAuthority
    enrichment_runtime: Wc027EnrichmentFeedProductionConfiguration
    delivery_budget: GuidancePublicationRequestDeliveryBudget
    binding_evidence_id: str
    attached_identity_resource_ids: tuple[str, ...]
    rbac_resource_ids: tuple[str, ...]

    @classmethod
    def model_validate_json(
        cls,
        value: str | bytes,
    ) -> Wc027GuidanceAuthorityPublisherConfiguration:
        try:
            payload = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("WC-027 guidance publisher configuration is not valid JSON") from exc
        root = _mapping(payload, "configuration")
        _require_keys(
            root,
            {
                "schemaVersion",
                "serviceBus",
                "imagePull",
                "requestOutbox",
                "authorityAssets",
                "guidanceActivation",
                "requestKey",
                "bindingSigningKey",
                "enrichmentRuntimeConfiguration",
                "deliveryBudget",
                "deploymentBinding",
            },
            "configuration",
        )
        if root["schemaVersion"] != _CONFIG_SCHEMA_VERSION:
            raise ValueError("WC-027 guidance publisher configuration schemaVersion is invalid")
        service_bus = _mapping(root["serviceBus"], "serviceBus")
        _require_keys(
            service_bus,
            {
                "namespace",
                "requestQueueName",
                "triggerQueueName",
                "brokerIdentityClientId",
                "brokerIdentityResourceId",
                "requestSubmitterIdentityClientId",
                "requestSubmitterIdentityResourceId",
            },
            "serviceBus",
        )
        image_pull = _mapping(root["imagePull"], "imagePull")
        _require_keys(
            image_pull,
            {
                "registryResourceId",
                "registryServer",
                "image",
                "repositoryName",
                "roleAssignmentMode",
                "anonymousPullEnabled",
                "roleDefinitionId",
                "roleAssignmentResourceId",
                "conditionVersion",
                "condition",
                "identityClientId",
                "identityResourceId",
                "identityPrincipalId",
            },
            "imagePull",
        )
        activation = _mapping(root["guidanceActivation"], "guidanceActivation")
        _require_keys(
            activation,
            {
                "tableEndpoint",
                "tableName",
                "partitionKey",
                "identityClientId",
                "identityResourceId",
            },
            "guidanceActivation",
        )
        deployment = _mapping(root["deploymentBinding"], "deploymentBinding")
        _require_keys(
            deployment,
            {
                "bindingEvidenceId",
                "attachedIdentityResourceIds",
                "rbacResourceIds",
            },
            "deploymentBinding",
        )
        configuration = cls(
            service_bus_namespace=_service_bus_namespace(service_bus["namespace"]),
            request_queue_name=_queue_name(service_bus["requestQueueName"]),
            trigger_queue_name=_queue_name(service_bus["triggerQueueName"]),
            broker_identity_client_id=_client_id(
                service_bus["brokerIdentityClientId"],
                "serviceBus.brokerIdentityClientId",
            ),
            broker_identity_resource_id=_managed_identity_resource_id(
                service_bus["brokerIdentityResourceId"],
                "serviceBus.brokerIdentityResourceId",
            ),
            request_submitter_identity_client_id=_client_id(
                service_bus["requestSubmitterIdentityClientId"],
                "serviceBus.requestSubmitterIdentityClientId",
            ),
            request_submitter_identity_resource_id=_managed_identity_resource_id(
                service_bus["requestSubmitterIdentityResourceId"],
                "serviceBus.requestSubmitterIdentityResourceId",
            ),
            image_pull=_ImagePullBinding(
                registry_resource_id=_text(
                    image_pull["registryResourceId"],
                    "imagePull.registryResourceId",
                    maximum=2048,
                ),
                registry_server=_text(
                    image_pull["registryServer"],
                    "imagePull.registryServer",
                    maximum=255,
                ),
                image=_text(
                    image_pull["image"],
                    "imagePull.image",
                    maximum=2048,
                ),
                repository_name=_text(
                    image_pull["repositoryName"],
                    "imagePull.repositoryName",
                    maximum=256,
                ),
                role_assignment_mode=_text(
                    image_pull["roleAssignmentMode"],
                    "imagePull.roleAssignmentMode",
                    maximum=64,
                ),
                anonymous_pull_enabled=_required_false(
                    image_pull["anonymousPullEnabled"],
                    "imagePull.anonymousPullEnabled",
                ),
                role_definition_id=_client_id(
                    image_pull["roleDefinitionId"],
                    "imagePull.roleDefinitionId",
                ),
                role_assignment_resource_id=_text(
                    image_pull["roleAssignmentResourceId"],
                    "imagePull.roleAssignmentResourceId",
                    maximum=2048,
                ),
                condition_version=_nullable_text(
                    image_pull["conditionVersion"],
                    "imagePull.conditionVersion",
                    maximum=16,
                ),
                condition=_nullable_text(
                    image_pull["condition"],
                    "imagePull.condition",
                    maximum=4096,
                ),
                identity_client_id=_client_id(
                    image_pull["identityClientId"],
                    "imagePull.identityClientId",
                ),
                identity_resource_id=_managed_identity_resource_id(
                    image_pull["identityResourceId"],
                    "imagePull.identityResourceId",
                ),
                identity_principal_id=_client_id(
                    image_pull["identityPrincipalId"],
                    "imagePull.identityPrincipalId",
                ),
            ),
            request_outbox=_blob_source(
                root["requestOutbox"],
                "requestOutbox",
            ),
            authority_assets=_writable_blob_source(
                _mapping(root["authorityAssets"], "authorityAssets"),
                "authorityAssets",
            ),
            activation=_ActivationWriter(
                endpoint=_table_endpoint(
                    activation["tableEndpoint"],
                    "guidanceActivation.tableEndpoint",
                ),
                table_name=_text(
                    activation["tableName"],
                    "guidanceActivation.tableName",
                    maximum=63,
                ),
                partition_key=_text(
                    activation["partitionKey"],
                    "guidanceActivation.partitionKey",
                    maximum=256,
                ),
                identity_client_id=_client_id(
                    activation["identityClientId"],
                    "guidanceActivation.identityClientId",
                ),
                identity_resource_id=_managed_identity_resource_id(
                    activation["identityResourceId"],
                    "guidanceActivation.identityResourceId",
                ),
            ),
            request_key=_key_authority(
                root["requestKey"],
                "requestKey",
                allow_logical_key_id=True,
            ),
            binding_signing_key=_key_authority(
                root["bindingSigningKey"],
                "bindingSigningKey",
                allow_logical_key_id=True,
            ),
            enrichment_runtime=(
                Wc027EnrichmentFeedProductionConfiguration.model_validate_json(
                    json.dumps(root["enrichmentRuntimeConfiguration"])
                )
            ),
            delivery_budget=GuidancePublicationRequestDeliveryBudget.model_validate(
                root["deliveryBudget"]
            ),
            binding_evidence_id=_client_id(
                deployment["bindingEvidenceId"],
                "deploymentBinding.bindingEvidenceId",
            ),
            attached_identity_resource_ids=_identity_resource_ids(
                deployment["attachedIdentityResourceIds"],
                "deploymentBinding.attachedIdentityResourceIds",
            ),
            rbac_resource_ids=_rbac_resource_ids(
                deployment["rbacResourceIds"],
                "deploymentBinding.rbacResourceIds",
            ),
        )
        configuration._validate_separation()
        return configuration

    def _validate_separation(self) -> None:
        runtime = self.enrichment_runtime
        assets = self.authority_assets
        image_pull = self.image_pull
        expected_role_definition_id = (
            "7f951dda-4ed3-4680-a7ca-43fe172d538d"
            if image_pull.role_assignment_mode == "LegacyRegistryPermissions"
            else (
                "b93aa761-3e63-49ed-ac28-beffa264f7ac"
                if image_pull.role_assignment_mode == "AbacRepositoryPermissions"
                else ""
            )
        )
        image_parts = image_pull.image.split("@sha256:")
        repository_prefix = f"{image_pull.registry_server}/"
        image_reference = image_parts[0] if len(image_parts) == 2 else ""
        image_digest = image_parts[1] if len(image_parts) == 2 else ""
        repository_name = (
            image_reference.removeprefix(repository_prefix)
            if image_reference.startswith(repository_prefix)
            else ""
        )
        expected_condition_version = (
            "2.0" if image_pull.role_assignment_mode == "AbacRepositoryPermissions" else None
        )
        expected_condition = (
            _acr_repository_condition(repository_name)
            if expected_condition_version is not None
            else None
        )
        if (
            image_pull.registry_server != image_pull.image.split("/", maxsplit=1)[0]
            or image_pull.image != image_pull.image.lower()
            or len(image_parts) != 2
            or len(image_digest) != 64
            or any(character not in "0123456789abcdef" for character in image_digest)
            or image_digest == "0" * 64
            or not repository_name
            or image_pull.repository_name != repository_name
            or image_pull.role_definition_id != expected_role_definition_id
            or image_pull.anonymous_pull_enabled is not False
            or image_pull.condition_version != expected_condition_version
            or image_pull.condition != expected_condition
            or image_pull.identity_client_id != self.broker_identity_client_id
            or image_pull.identity_resource_id != self.broker_identity_resource_id
            or not image_pull.role_assignment_resource_id.startswith(
                f"{image_pull.registry_resource_id}/providers/"
                "Microsoft.Authorization/roleAssignments/"
            )
        ):
            raise ValueError(
                "publisher image pull binding does not match its exact repository, "
                "registry mode, condition, and broker identity"
            )
        if self.delivery_budget != runtime.delivery_budget:
            raise ValueError("publisher delivery budget does not match the enrichment runtime")
        if self.request_outbox.container != "wc027-guidance-request-outbox":
            raise ValueError(
                "publisher request outbox must be exactly wc027-guidance-request-outbox"
            )
        if (
            assets.endpoint != runtime.guidance_authority_source.endpoint
            or assets.container != runtime.guidance_authority_source.container
        ):
            raise ValueError(
                "publisher authority assets do not match runtime guidance authority source"
            )
        if (
            self.activation.endpoint != runtime.guidance_activation.endpoint
            or self.activation.table_name != runtime.guidance_activation.table
            or self.activation.partition_key != runtime.guidance_activation.partition_key
        ):
            raise ValueError(
                "publisher activation store does not match runtime guidance activation source"
            )
        binding_trust = runtime.guidance_binding_key
        if (
            self.binding_signing_key.key_id != binding_trust.key_id
            or self.binding_signing_key.key_vault_key_id != binding_trust.key_vault_key_id
            or self.binding_signing_key.key_fingerprint != binding_trust.key_fingerprint
        ):
            raise ValueError("publisher binding signer does not match runtime guidance trust")
        all_runtime_keys = (
            runtime.monitoring_collector_key.authority,
            runtime.change_key,
            runtime.monitoring_intent_key,
            runtime.incident_key,
            runtime.correlation_binding_key,
            runtime.report_key,
            runtime.guidance_key,
            runtime.enrichment_key,
            runtime.feed_key,
            runtime.notification_key,
        )
        if (
            self.request_key.key_id in {item.key_id for item in (*all_runtime_keys, binding_trust)}
            or self.request_key.key_vault_key_id
            in {item.key_vault_key_id for item in (*all_runtime_keys, binding_trust)}
            or self.request_key.key_fingerprint
            in {item.key_fingerprint for item in (*all_runtime_keys, binding_trust)}
        ):
            raise ValueError("guidance publication request key must use a distinct trust domain")
        if self.binding_signing_key.identity_client_id in {
            runtime.report_key.identity_client_id,
            runtime.guidance_key.identity_client_id,
            runtime.enrichment_key.identity_client_id,
            runtime.feed_key.identity_client_id,
            runtime.notification_key.identity_client_id,
        }:
            raise ValueError("guidance authority signer identity must be distinct")
        publisher_owned_identity_pairs = (
            (
                self.broker_identity_client_id,
                self.broker_identity_resource_id,
            ),
            (
                assets.reader_identity_client_id,
                assets.reader_identity_resource_id,
            ),
            (
                assets.writer_identity_client_id,
                assets.writer_identity_resource_id,
            ),
            (
                self.activation.identity_client_id,
                self.activation.identity_resource_id,
            ),
            (
                self.request_key.identity_client_id,
                self.request_key.identity_resource_id,
            ),
            (
                self.binding_signing_key.identity_client_id,
                self.binding_signing_key.identity_resource_id,
            ),
            (
                self.request_outbox.identity_client_id,
                self.request_outbox.identity_resource_id,
            ),
        )
        publisher_identity_pairs = (
            *publisher_owned_identity_pairs,
            (
                binding_trust.identity_client_id,
                binding_trust.identity_resource_id,
            ),
        )
        if len({client_id.casefold() for client_id, _ in publisher_identity_pairs}) != len(
            publisher_identity_pairs
        ) or len({resource_id.casefold() for _, resource_id in publisher_identity_pairs}) != len(
            publisher_identity_pairs
        ):
            raise ValueError("guidance publisher managed identities must be distinct")
        runtime_identity_pairs = (
            (
                runtime.broker_identity_client_id,
                runtime.broker_identity_resource_id,
            ),
            (
                runtime.incident_lifecycle_assets.identity_client_id,
                runtime.incident_lifecycle_assets.identity_resource_id,
            ),
            (
                runtime.enrichment_feed_assets.reader_identity_client_id,
                runtime.enrichment_feed_assets.reader_identity_resource_id,
            ),
            (
                runtime.enrichment_feed_assets.writer_identity_client_id,
                runtime.enrichment_feed_assets.writer_identity_resource_id,
            ),
            (
                runtime.registry_identity_client_id,
                runtime.registry_identity_resource_id,
            ),
            (
                runtime.guidance_activation.identity_client_id,
                runtime.guidance_activation.identity_resource_id,
            ),
            *(
                (source.identity_client_id, source.identity_resource_id)
                for source in (
                    runtime.monitoring_source,
                    runtime.change_source,
                    runtime.context_authority_source,
                    runtime.monitoring_intent_source,
                    runtime.guidance_authority_source,
                )
            ),
            *(
                (key.identity_client_id, key.identity_resource_id)
                for key in (
                    runtime.monitoring_collector_key.authority,
                    runtime.change_key,
                    runtime.monitoring_intent_key,
                    runtime.incident_key,
                    runtime.correlation_binding_key,
                    runtime.guidance_binding_key,
                    runtime.report_key,
                    runtime.guidance_key,
                    runtime.enrichment_key,
                    runtime.feed_key,
                    runtime.notification_key,
                )
            ),
        )
        runtime_client_ids = {client_id.casefold() for client_id, _ in runtime_identity_pairs}
        runtime_resource_ids = {resource_id.casefold() for _, resource_id in runtime_identity_pairs}
        if {client_id.casefold() for client_id, _ in publisher_owned_identity_pairs}.intersection(
            runtime_client_ids
        ) or {
            resource_id.casefold() for _, resource_id in publisher_owned_identity_pairs
        }.intersection(runtime_resource_ids):
            raise ValueError(
                "guidance publisher identities must be separate from runtime identities"
            )
        expected = {
            self.broker_identity_resource_id,
            assets.reader_identity_resource_id,
            assets.writer_identity_resource_id,
            self.activation.identity_resource_id,
            self.request_key.identity_resource_id,
            self.binding_signing_key.identity_resource_id,
            self.request_outbox.identity_resource_id,
            runtime.incident_lifecycle_assets.identity_resource_id,
            runtime.monitoring_source.identity_resource_id,
            runtime.change_source.identity_resource_id,
            runtime.context_authority_source.identity_resource_id,
            runtime.monitoring_intent_source.identity_resource_id,
            runtime.guidance_binding_key.identity_resource_id,
            runtime.monitoring_collector_key.authority.identity_resource_id,
            runtime.change_key.identity_resource_id,
            runtime.monitoring_intent_key.identity_resource_id,
            runtime.incident_key.identity_resource_id,
            runtime.correlation_binding_key.identity_resource_id,
        }
        expected_client_ids = {
            self.broker_identity_client_id,
            assets.reader_identity_client_id,
            assets.writer_identity_client_id,
            self.activation.identity_client_id,
            self.request_key.identity_client_id,
            self.binding_signing_key.identity_client_id,
            self.request_outbox.identity_client_id,
            runtime.incident_lifecycle_assets.identity_client_id,
            runtime.monitoring_source.identity_client_id,
            runtime.change_source.identity_client_id,
            runtime.context_authority_source.identity_client_id,
            runtime.monitoring_intent_source.identity_client_id,
            runtime.guidance_binding_key.identity_client_id,
            runtime.monitoring_collector_key.authority.identity_client_id,
            runtime.change_key.identity_client_id,
            runtime.monitoring_intent_key.identity_client_id,
            runtime.incident_key.identity_client_id,
            runtime.correlation_binding_key.identity_client_id,
        }
        if self.request_submitter_identity_resource_id.casefold() in runtime_resource_ids.union(
            item.casefold() for item in expected
        ) or self.request_submitter_identity_client_id.casefold() in runtime_client_ids.union(
            item.casefold() for item in expected_client_ids
        ):
            raise ValueError("guidance publisher request submitter identity must be dedicated")
        if {item.casefold() for item in self.attached_identity_resource_ids} != {
            item.casefold() for item in expected
        }:
            raise ValueError("publisher deployment identities do not match configuration")


def _table_endpoint(value: object, name: str) -> str:
    from athena_context.enrichment.production import _https_origin

    return _https_origin(value, name, suffix=".table.core.windows.net")


def _nullable_text(
    value: object,
    name: str,
    *,
    maximum: int,
) -> str | None:
    if value is None:
        return None
    return _text(value, name, maximum=maximum)


def _required_false(value: object, name: str) -> bool:
    if value is not False:
        raise ValueError(f"{name} must be explicitly false")
    return False


def _acr_repository_condition(repository_name: str) -> str:
    if (
        type(repository_name) is not str
        or not repository_name
        or repository_name != repository_name.lower()
        or repository_name.startswith("/")
        or repository_name.endswith("/")
        or any(character in repository_name for character in "@:?#%")
        or "//" in repository_name
    ):
        raise ValueError("ACR repository name must be one exact lowercase repository")
    return (
        "((!(ActionMatches{'Microsoft.ContainerRegistry/registries/"
        "repositories/content/read'}) AND "
        "!(ActionMatches{'Microsoft.ContainerRegistry/registries/"
        "repositories/metadata/read'})) OR "
        "(@Request[Microsoft.ContainerRegistry/registries/repositories:name] "
        f"StringEqualsIgnoreCase '{repository_name}'))"
    )


def _utc_now_milliseconds() -> datetime:
    current = datetime.now(UTC)
    return current.replace(microsecond=(current.microsecond // 1000) * 1000)


def _build_correlation(
    configuration: Wc027EnrichmentFeedProductionConfiguration,
) -> CorrelationService:
    monitoring_key_verifier = _verifier(configuration.monitoring_collector_key.authority)
    monitoring_record = TrustedKeyRecord(
        anchor=configuration.monitoring_collector_key.authority.anchor,
        public_key=monitoring_key_verifier.public_key,
        enabled=True,
        activated_at=configuration.monitoring_collector_key.activated_at,
        expires_at=configuration.monitoring_collector_key.expires_at,
    )
    monitoring_resolver = KeyVaultTrustedKeyResolver(
        expected_record=monitoring_record,
        managed_identity_client_id=(
            configuration.monitoring_collector_key.authority.identity_client_id
        ),
    )
    return CorrelationService(
        monitoring_reader=_correlation_reader(
            configuration.monitoring_source,
            required_prefix="wc024-monitoring/",
        ),
        change_reader=_correlation_reader(
            configuration.change_source,
            required_prefix="change-evidence/",
        ),
        authority_reader=_correlation_reader(
            configuration.context_authority_source,
            required_prefix="context-authority/",
        ),
        monitoring_intent_reader=_correlation_reader(
            configuration.monitoring_intent_source,
            required_prefix="monitoring-intent/",
        ),
        monitoring_verifier=TrustedMonitoringHandoffVerifier(
            reviewed_contract=configuration.monitoring_collector_contract,
            trusted_key_anchor=(configuration.monitoring_collector_key.authority.anchor),
            key_resolver=monitoring_resolver,
        ),
        change_verifier=TrustedChangeArtifactVerifier(
            signer=KeyVaultChangeEvidenceSigner(
                key_vault_key_id=configuration.change_key.key_vault_key_id,
                managed_identity_client_id=(configuration.change_key.identity_client_id),
            )
        ),
        monitoring_intent_verifier=TrustedMonitoringIntentAssetVerifier(
            trusted_key_id=configuration.monitoring_intent_key.key_vault_key_id,
            signer=_signer(configuration.monitoring_intent_key),
        ),
    )


def build_wc027_guidance_authority_publisher(
    configuration: Wc027GuidanceAuthorityPublisherConfiguration,
    *,
    trigger_sender: object,
) -> GuidanceAuthorityPublisher:
    runtime = configuration.enrichment_runtime
    request_verifier = _verifier(configuration.request_key)
    lifecycle_verifier = _verifier(runtime.incident_key)
    correlation_binding_verifier = _verifier(runtime.correlation_binding_key)
    binding_verifier = KeyVaultRsaPublicKeyVerifier(
        trusted_key_anchor=runtime.guidance_binding_key.anchor,
        managed_identity_client_id=(runtime.guidance_binding_key.identity_client_id),
    )
    binding_signer = KeyVaultRsaSigner(
        trusted_key_anchor=configuration.binding_signing_key.anchor,
        managed_identity_client_id=(configuration.binding_signing_key.identity_client_id),
    )
    incident_reader = AzureBlobIncidentAssetPublisher(
        blob_endpoint=runtime.incident_lifecycle_assets.endpoint,
        container_name=runtime.incident_lifecycle_assets.container,
        managed_identity_client_id=(runtime.incident_lifecycle_assets.identity_client_id),
        signing_key_id=runtime.incident_key.key_id,
        signing_key_vault_key_id=runtime.incident_key.key_vault_key_id,
        signing_key_fingerprint=runtime.incident_key.key_fingerprint,
        signature_verifier=lifecycle_verifier.verify_preimage,
    )
    assets = configuration.authority_assets
    return GuidanceAuthorityPublisher(
        request_key_id=configuration.request_key.key_id,
        request_signature_verifier=request_verifier.verify_preimage,
        incident_key_id=runtime.incident_key.key_id,
        incident_key_vault_key_id=runtime.incident_key.key_vault_key_id,
        incident_signature_verifier=lifecycle_verifier.verify_preimage,
        correlation_binding_key_id=runtime.correlation_binding_key.key_id,
        correlation_binding_signature_verifier=(correlation_binding_verifier.verify_preimage),
        binding_key_id=configuration.binding_signing_key.key_id,
        binding_signer=binding_signer,
        binding_signature_verifier=binding_verifier.verify_preimage,
        correlation=_build_correlation(runtime),
        incident_authority=incident_reader,
        artifact_writer=AzureBlobGuidanceAuthorityArtifactWriter(
            blob_endpoint=assets.endpoint,
            container_name=assets.container,
            writer_managed_identity_client_id=assets.writer_identity_client_id,
            reader_managed_identity_client_id=assets.reader_identity_client_id,
        ),
        activation_store=AzureTableGuidanceAuthorityActivationStore(
            endpoint=configuration.activation.endpoint,
            table_name=configuration.activation.table_name,
            partition_key=configuration.activation.partition_key,
            managed_identity_client_id=configuration.activation.identity_client_id,
        ),
        trigger=AzureServiceBusGuidanceAuthorityTrigger(trigger_sender),
        delivery_budget=configuration.delivery_budget,
        clock=_utc_now_milliseconds,
    )


def load_wc027_guidance_authority_publisher_configuration(
    *,
    path: Path | None,
    environment_json: str | None = None,
) -> Wc027GuidanceAuthorityPublisherConfiguration:
    if path is not None and environment_json is not None:
        raise ValueError("provide either a config path or environment JSON")
    raw = (
        path.read_bytes()
        if path is not None
        else (
            environment_json
            if environment_json is not None
            else os.environ.get("ATHENA_WC027_GUIDANCE_AUTHORITY_PUBLISHER_CONFIG_JSON")
        )
    )
    if raw is None:
        raise ValueError("WC-027 guidance publisher configuration is required")
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not 1 <= len(raw) <= 512 * 1024:
        raise ValueError("WC-027 guidance publisher configuration is outside its byte bound")
    return Wc027GuidanceAuthorityPublisherConfiguration.model_validate_json(raw)


def _abandon_retryable_publisher_message(
    receiver: object,
    message: object,
    *,
    now: datetime,
) -> None:
    _settle_publisher_message(
        receiver,
        message,
        action="abandon",
        now=now,
    )


type _PublisherSettlementStatus = Literal[
    "settled",
    "deferred",
    "already-settled",
    "message-lock-lost",
    "session-lock-lost",
    "unconfirmed",
]


def _settle_publisher_message(
    receiver: object,
    message: object,
    *,
    action: Literal["complete", "abandon", "dead_letter"],
    now: datetime,
    reason: str | None = None,
    error_description: str | None = None,
) -> _PublisherSettlementStatus:
    from azure.servicebus.exceptions import (
        MessageAlreadySettled,
        MessageLockLostError,
        ServiceBusError,
        SessionLockLostError,
    )

    message_deadline = getattr(message, "locked_until_utc", None)
    session_deadline = getattr(
        getattr(receiver, "session", None),
        "locked_until_utc",
        None,
    )
    if message_deadline is not None:
        if (
            not isinstance(message_deadline, datetime)
            or message_deadline.tzinfo is None
            or message_deadline.utcoffset() != UTC.utcoffset(now)
        ):
            return "unconfirmed"
        if now >= message_deadline:
            return "message-lock-lost"
    if session_deadline is not None:
        if (
            not isinstance(session_deadline, datetime)
            or session_deadline.tzinfo is None
            or session_deadline.utcoffset() != UTC.utcoffset(now)
        ):
            return "unconfirmed"
        if now >= session_deadline:
            return "session-lock-lost"
    try:
        if action == "complete":
            receiver.complete_message(message)  # type: ignore[attr-defined]
            return "settled"
        if action == "abandon":
            receiver.abandon_message(message)  # type: ignore[attr-defined]
            return "deferred"
        receiver.dead_letter_message(  # type: ignore[attr-defined]
            message,
            reason=reason,
            error_description=error_description,
        )
        return "settled"
    except MessageAlreadySettled:
        return "already-settled"
    except MessageLockLostError:
        return "message-lock-lost"
    except SessionLockLostError:
        return "session-lock-lost"
    except (
        ServiceBusError,
        ServiceRequestError,
        ServiceResponseError,
        OSError,
    ):
        return "unconfirmed"


def run_wc027_guidance_authority_publisher_worker(
    *,
    configuration: Wc027GuidanceAuthorityPublisherConfiguration,
    max_wait_time_seconds: int = 30,
) -> bool:
    from azure.identity import ManagedIdentityCredential
    from azure.servicebus import NEXT_AVAILABLE_SESSION, ServiceBusClient
    from azure.servicebus.exceptions import ServiceBusError

    if not 1 <= max_wait_time_seconds <= 300:
        raise ValueError("max_wait_time_seconds must be between 1 and 300")
    credential = ManagedIdentityCredential(client_id=configuration.broker_identity_client_id)
    with (
        ServiceBusClient(
            fully_qualified_namespace=configuration.service_bus_namespace,
            credential=credential,
            logging_enable=False,
        ) as client,
        client.get_queue_receiver(
            queue_name=configuration.request_queue_name,
            session_id=NEXT_AVAILABLE_SESSION,
            max_wait_time=max_wait_time_seconds,
        ) as receiver,
        client.get_queue_sender(queue_name=configuration.trigger_queue_name) as sender,
    ):
        messages = receiver.receive_messages(
            max_message_count=1,
            max_wait_time=max_wait_time_seconds,
        )
        if not messages:
            return False
        message = messages[0]
        processing_started_at = _utc_now_milliseconds()
        try:
            request = parse_guidance_authority_publication_request(
                b"".join(bytes(part) for part in message.body)
            )
            if (
                str(message.message_id) != request.request_id
                or str(message.session_id)
                != request.incident_bound_request.incident_subject.incident_id
                or message.content_type != "application/json"
            ):
                raise ValueError("guidance publication request broker metadata is invalid")
            outbox_reference = validate_guidance_publication_request_broker_metadata(
                message,
                request,
                expected_delivery_budget=configuration.delivery_budget,
            )
            verify_guidance_publication_request_outbox(
                request,
                outbox_reference=outbox_reference,
                outbox_reader=_correlation_reader(
                    configuration.request_outbox,
                    required_prefix="guidance-publication-requests/",
                ),
            )
            publisher = build_wc027_guidance_authority_publisher(
                configuration,
                trigger_sender=sender,
            )
            current = _utc_now_milliseconds()
            if publisher.recover_trigger_delivery(request, now=current):
                return (
                    _settle_publisher_message(
                        receiver,
                        message,
                        action="complete",
                        now=_utc_now_milliseconds(),
                    )
                    == "settled"
                )
            if current < request.evaluated_at or current >= request.expires_at:
                raise ValueError("guidance publication request is stale")
            publisher.publish(request, now=processing_started_at)
            return (
                _settle_publisher_message(
                    receiver,
                    message,
                    action="complete",
                    now=_utc_now_milliseconds(),
                )
                == "settled"
            )
        except (
            GuidanceAuthorityDeliveryExpiredError,
            GuidanceAuthorityOccurrenceConflictError,
        ):
            _settle_publisher_message(
                receiver,
                message,
                action="dead_letter",
                now=_utc_now_milliseconds(),
                reason="AthenaWc027GuidanceAuthorityTerminal",
                error_description=(
                    "the signed occurrence already has a different immutable "
                    "guidance activation or its effective delivery deadline expired"
                ),
            )
            return False
        except (
            GuidanceAuthorityActivationConflictError,
            GuidanceAuthoritySourceNotReadyError,
            ArtifactReadError,
            ArtifactWriteError,
            HttpResponseError,
            ServiceRequestError,
            ServiceResponseError,
            ServiceBusError,
            OSError,
        ):
            _abandon_retryable_publisher_message(
                receiver,
                message,
                now=_utc_now_milliseconds(),
            )
            return False
        except ValidationError, ValueError:
            _settle_publisher_message(
                receiver,
                message,
                action="dead_letter",
                now=_utc_now_milliseconds(),
                reason="AthenaWc027GuidanceAuthorityRejected",
                error_description=(
                    "publication request failed bounded trust, freshness, "
                    "authority, or activation validation"
                ),
            )
            return False


__all__ = [
    "Wc027GuidanceAuthorityPublisherConfiguration",
    "build_wc027_guidance_authority_publisher",
    "load_wc027_guidance_authority_publisher_configuration",
    "run_wc027_guidance_authority_publisher_worker",
]
