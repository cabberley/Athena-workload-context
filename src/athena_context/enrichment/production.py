from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import UUID

from azure.core.exceptions import (
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)
from pydantic import ValidationError

from athena_context.artifacts import (
    MAX_ARTIFACT_TRANSFER_BYTES,
    ArtifactReadError,
    ArtifactWriteError,
)
from athena_context.azure_adapters import (
    AzureBlobIncidentAssetPublisher,
    AzureBlobIncidentAssetReader,
    AzureBlobVersionPinnedArtifactReader,
    KeyVaultRsaPublicKeyVerifier,
    KeyVaultRsaSigner,
    KeyVaultTrustedKeyResolver,
)
from athena_context.contracts import (
    MonitoringCollectorContract,
    TrustedKeyAnchor,
    TrustedKeyRecord,
)
from athena_context.correlation import (
    AzureBlobCorrelationArtifactReader,
    CorrelationService,
    TrustedChangeArtifactVerifier,
    TrustedMonitoringHandoffVerifier,
    TrustedMonitoringIntentAssetVerifier,
)
from athena_context.enrichment.azure import (
    AzureBlobIncidentEnrichmentArtifactWriter,
)
from athena_context.enrichment.feed_index_azure import (
    AzureBlobIncidentFeedIndexPublisher,
)
from athena_context.enrichment.feed_index_publication import (
    IncidentFeedIndexPublicationConflictError,
    IncidentFeedIndexPublicationError,
    IncidentFeedIndexPublicationService,
)
from athena_context.enrichment.feed_pipeline import (
    IncidentEnrichmentFeedPublicationService,
    IncidentFeedIndexPublicationPort,
)
from athena_context.enrichment.feed_registry import (
    IncidentFeedRegistryError,
    IncidentFeedRegistryIncompleteError,
)
from athena_context.enrichment.feed_registry_azure import (
    AzureTableIncidentFeedRegistry,
)
from athena_context.enrichment.publication import (
    IncidentEnrichmentPublicationService,
)
from athena_context.enrichment.runtime import (
    MAX_WC027_ENRICHMENT_TRIGGER_BYTES,
    WC027_ENRICHMENT_TRIGGER_SCHEMA_VERSION,
    Wc027EnrichmentFeedRuntime,
    Wc027EnrichmentSourceNotReadyError,
    parse_wc027_enrichment_trigger,
    utc_now_millisecond,
    validate_wc027_enrichment_broker_metadata,
)
from athena_context.eventing.change_ingestion import (
    KeyVaultChangeEvidenceSigner,
)
from athena_context.eventing.notification_v2 import (
    NotificationV2PublicationService,
    NotificationV2SourceNotReadyError,
    NotificationV2Trust,
)
from athena_context.eventing.runtime import AzureServiceBusNotificationOutbox

_CONFIG_SCHEMA_VERSION = "athena.wc027EnrichmentFeedRuntimeConfiguration.v1"


@dataclass(frozen=True, slots=True)
class _BlobSource:
    endpoint: str
    container: str
    identity_client_id: str


@dataclass(frozen=True, slots=True)
class _KeyAuthority:
    key_id: str
    key_vault_key_id: str
    key_fingerprint: str
    identity_client_id: str

    @property
    def anchor(self) -> TrustedKeyAnchor:
        return TrustedKeyAnchor.from_key_vault_key_id(
            self.key_vault_key_id,
            public_key_fingerprint=self.key_fingerprint,
        )


@dataclass(frozen=True, slots=True)
class _MonitoringCollectorKey:
    authority: _KeyAuthority
    activated_at: datetime
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class Wc027EnrichmentFeedProductionConfiguration:
    service_bus_namespace: str
    trigger_queue_name: str
    notification_queue_name: str
    broker_identity_client_id: str
    incident_assets: _BlobSource
    incident_writer_identity_client_id: str
    registry_endpoint: str
    registry_table_name: str
    registry_partition_key: str
    registry_identity_client_id: str
    presentation_url: str
    monitoring_source: _BlobSource
    change_source: _BlobSource
    context_authority_source: _BlobSource
    monitoring_intent_source: _BlobSource
    guidance_authority_source: _BlobSource
    monitoring_collector_contract: MonitoringCollectorContract
    monitoring_collector_key: _MonitoringCollectorKey
    incident_key: _KeyAuthority
    correlation_binding_key: _KeyAuthority
    guidance_binding_key: _KeyAuthority
    change_key: _KeyAuthority
    monitoring_intent_key: _KeyAuthority
    report_key: _KeyAuthority
    guidance_key: _KeyAuthority
    enrichment_key: _KeyAuthority
    feed_key: _KeyAuthority
    notification_key: _KeyAuthority

    @classmethod
    def model_validate_json(
        cls,
        value: str | bytes,
    ) -> Wc027EnrichmentFeedProductionConfiguration:
        try:
            payload = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("WC-027 runtime configuration is not valid JSON") from exc
        root = _mapping(payload, "configuration")
        _require_keys(
            root,
            {
                "schemaVersion",
                "serviceBus",
                "incidentAssets",
                "feedRegistry",
                "presentationUrl",
                "correlationSources",
                "guidanceAuthoritySource",
                "monitoringCollectorContract",
                "monitoringCollectorKey",
                "keys",
            },
            "configuration",
        )
        if root["schemaVersion"] != _CONFIG_SCHEMA_VERSION:
            raise ValueError("WC-027 runtime configuration schemaVersion is invalid")
        service_bus = _mapping(root["serviceBus"], "serviceBus")
        _require_keys(
            service_bus,
            {
                "namespace",
                "triggerQueueName",
                "notificationQueueName",
                "brokerIdentityClientId",
            },
            "serviceBus",
        )
        incident = _mapping(root["incidentAssets"], "incidentAssets")
        _require_keys(
            incident,
            {
                "blobEndpoint",
                "containerName",
                "readerIdentityClientId",
                "writerIdentityClientId",
            },
            "incidentAssets",
        )
        registry = _mapping(root["feedRegistry"], "feedRegistry")
        _require_keys(
            registry,
            {
                "tableEndpoint",
                "tableName",
                "partitionKey",
                "identityClientId",
            },
            "feedRegistry",
        )
        sources = _mapping(root["correlationSources"], "correlationSources")
        _require_keys(
            sources,
            {"monitoring", "change", "contextAuthority", "monitoringIntent"},
            "correlationSources",
        )
        keys = _mapping(root["keys"], "keys")
        key_names = {
            "incident",
            "correlationBinding",
            "guidanceBinding",
            "change",
            "monitoringIntent",
            "report",
            "guidance",
            "enrichment",
            "feed",
            "notification",
        }
        _require_keys(keys, key_names, "keys")
        configuration = cls(
            service_bus_namespace=_service_bus_namespace(service_bus["namespace"]),
            trigger_queue_name=_queue_name(service_bus["triggerQueueName"]),
            notification_queue_name=_queue_name(
                service_bus["notificationQueueName"]
            ),
            broker_identity_client_id=_client_id(
                service_bus["brokerIdentityClientId"],
                "serviceBus.brokerIdentityClientId",
            ),
            incident_assets=_blob_source(
                {
                    "blobEndpoint": incident["blobEndpoint"],
                    "containerName": incident["containerName"],
                    "identityClientId": incident["readerIdentityClientId"],
                },
                "incidentAssets",
            ),
            incident_writer_identity_client_id=_client_id(
                incident["writerIdentityClientId"],
                "incidentAssets.writerIdentityClientId",
            ),
            registry_endpoint=_https_origin(
                registry["tableEndpoint"],
                "feedRegistry.tableEndpoint",
                suffix=".table.core.windows.net",
            ),
            registry_table_name=_text(
                registry["tableName"],
                "feedRegistry.tableName",
                maximum=63,
            ),
            registry_partition_key=_text(
                registry["partitionKey"],
                "feedRegistry.partitionKey",
                maximum=256,
            ),
            registry_identity_client_id=_client_id(
                registry["identityClientId"],
                "feedRegistry.identityClientId",
            ),
            presentation_url=_https_origin_or_path(
                root["presentationUrl"],
                "presentationUrl",
            ),
            monitoring_source=_blob_source(
                sources["monitoring"],
                "correlationSources.monitoring",
            ),
            change_source=_blob_source(
                sources["change"],
                "correlationSources.change",
            ),
            context_authority_source=_blob_source(
                sources["contextAuthority"],
                "correlationSources.contextAuthority",
            ),
            monitoring_intent_source=_blob_source(
                sources["monitoringIntent"],
                "correlationSources.monitoringIntent",
            ),
            guidance_authority_source=_blob_source(
                root["guidanceAuthoritySource"],
                "guidanceAuthoritySource",
            ),
            monitoring_collector_contract=MonitoringCollectorContract.model_validate(
                root["monitoringCollectorContract"]
            ),
            monitoring_collector_key=_monitoring_collector_key(
                root["monitoringCollectorKey"]
            ),
            incident_key=_key_authority(keys["incident"], "keys.incident"),
            correlation_binding_key=_key_authority(
                keys["correlationBinding"],
                "keys.correlationBinding",
            ),
            guidance_binding_key=_key_authority(
                keys["guidanceBinding"],
                "keys.guidanceBinding",
            ),
            change_key=_key_authority(keys["change"], "keys.change"),
            monitoring_intent_key=_key_authority(
                keys["monitoringIntent"],
                "keys.monitoringIntent",
            ),
            report_key=_key_authority(keys["report"], "keys.report"),
            guidance_key=_key_authority(keys["guidance"], "keys.guidance"),
            enrichment_key=_key_authority(
                keys["enrichment"],
                "keys.enrichment",
            ),
            feed_key=_key_authority(keys["feed"], "keys.feed"),
            notification_key=_key_authority(
                keys["notification"],
                "keys.notification",
            ),
        )
        configuration._validate_separation()
        return configuration

    def _validate_separation(self) -> None:
        correlation_sources = (
            self.monitoring_source,
            self.change_source,
            self.context_authority_source,
            self.monitoring_intent_source,
        )
        if len(
            {item.identity_client_id.casefold() for item in correlation_sources}
        ) != len(correlation_sources):
            raise ValueError(
                "correlation source reader managed identities must be distinct"
            )
        if len(
            {
                (item.endpoint.casefold().rstrip("/"), item.container.casefold())
                for item in correlation_sources
            }
        ) != len(correlation_sources):
            raise ValueError("correlation source storage domains must be distinct")
        all_key_authorities = (
            self.monitoring_collector_key.authority,
            self.change_key,
            self.monitoring_intent_key,
            self.incident_key,
            self.correlation_binding_key,
            self.guidance_binding_key,
            self.report_key,
            self.guidance_key,
            self.enrichment_key,
            self.feed_key,
            self.notification_key,
        )
        if len({item.key_id for item in all_key_authorities}) != len(
            all_key_authorities
        ):
            raise ValueError("WC-027 trust-domain key IDs must be distinct")
        if len(
            {item.key_vault_key_id for item in all_key_authorities}
        ) != len(all_key_authorities):
            raise ValueError(
                "WC-027 trust-domain Key Vault key versions must be distinct"
            )
        producer_signing_authorities = (
            self.report_key,
            self.guidance_key,
            self.enrichment_key,
            self.feed_key,
            self.notification_key,
        )
        if len(
            {item.identity_client_id for item in producer_signing_authorities}
        ) != len(producer_signing_authorities):
            raise ValueError("WC-027 signing managed identities must be distinct")
        io_identities = (
            self.broker_identity_client_id,
            self.incident_assets.identity_client_id,
            self.incident_writer_identity_client_id,
            self.registry_identity_client_id,
            self.monitoring_source.identity_client_id,
            self.change_source.identity_client_id,
            self.context_authority_source.identity_client_id,
            self.monitoring_intent_source.identity_client_id,
            self.guidance_authority_source.identity_client_id,
        )
        if len(set(io_identities)) != len(io_identities):
            raise ValueError("WC-027 runtime I/O managed identities must be distinct")
        if set(io_identities).intersection(
            item.identity_client_id for item in producer_signing_authorities
        ):
            raise ValueError(
                "WC-027 signing identities must not be reused for runtime I/O"
            )


def build_wc027_enrichment_feed_runtime(
    configuration: Wc027EnrichmentFeedProductionConfiguration,
    *,
    notification_outbox: AzureServiceBusNotificationOutbox,
) -> Wc027EnrichmentFeedRuntime:
    lifecycle_verifier = _verifier(configuration.incident_key)
    correlation_binding_verifier = _verifier(
        configuration.correlation_binding_key
    )
    guidance_binding_verifier = _verifier(configuration.guidance_binding_key)
    report_signer = _signer(configuration.report_key)
    guidance_signer = _signer(configuration.guidance_key)
    enrichment_signer = _signer(configuration.enrichment_key)
    feed_signer = _signer(configuration.feed_key)
    notification_signer = _signer(configuration.notification_key)

    monitoring_key_verifier = _verifier(
        configuration.monitoring_collector_key.authority
    )
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
    correlation = CorrelationService(
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
            trusted_key_anchor=(
                configuration.monitoring_collector_key.authority.anchor
            ),
            key_resolver=monitoring_resolver,
        ),
        change_verifier=TrustedChangeArtifactVerifier(
            signer=KeyVaultChangeEvidenceSigner(
                key_vault_key_id=configuration.change_key.key_vault_key_id,
                managed_identity_client_id=(
                    configuration.change_key.identity_client_id
                ),
            )
        ),
        monitoring_intent_verifier=TrustedMonitoringIntentAssetVerifier(
            trusted_key_id=configuration.monitoring_intent_key.key_vault_key_id,
            signer=_signer(configuration.monitoring_intent_key),
        ),
    )
    incident_reader = AzureBlobIncidentAssetPublisher(
        blob_endpoint=configuration.incident_assets.endpoint,
        container_name=configuration.incident_assets.container,
        managed_identity_client_id=(
            configuration.incident_assets.identity_client_id
        ),
        signing_key_id=configuration.incident_key.key_id,
        signing_key_fingerprint=configuration.incident_key.key_fingerprint,
        signature_verifier=lifecycle_verifier.verify_preimage,
    )
    incident_exact_reader = AzureBlobVersionPinnedArtifactReader(
        blob_endpoint=configuration.incident_assets.endpoint,
        container_name=configuration.incident_assets.container,
        managed_identity_client_id=(
            configuration.incident_assets.identity_client_id
        ),
        max_payload_bytes=MAX_ARTIFACT_TRANSFER_BYTES,
    )
    guidance_authority_reader = AzureBlobVersionPinnedArtifactReader(
        blob_endpoint=configuration.guidance_authority_source.endpoint,
        container_name=configuration.guidance_authority_source.container,
        managed_identity_client_id=(
            configuration.guidance_authority_source.identity_client_id
        ),
        max_payload_bytes=MAX_ARTIFACT_TRANSFER_BYTES,
    )
    artifact_writer = AzureBlobIncidentEnrichmentArtifactWriter(
        blob_endpoint=configuration.incident_assets.endpoint,
        container_name=configuration.incident_assets.container,
        managed_identity_client_id=(
            configuration.incident_writer_identity_client_id
        ),
    )
    enrichment = IncidentEnrichmentPublicationService(
        correlation_service=correlation,
        incident_reader=incident_exact_reader,
        incident_publication_reader=incident_reader,
        guidance_authority_reader=guidance_authority_reader,
        artifact_writer=artifact_writer,
        incident_key_id=configuration.incident_key.key_id,
        incident_key_fingerprint=configuration.incident_key.key_fingerprint,
        incident_signature_verifier=lifecycle_verifier.verify_preimage,
        correlation_binding_key_id=(
            configuration.correlation_binding_key.key_id
        ),
        correlation_binding_signature_verifier=(
            correlation_binding_verifier.verify_preimage
        ),
        guidance_binding_key_id=configuration.guidance_binding_key.key_id,
        guidance_binding_signature_verifier=(
            guidance_binding_verifier.verify_preimage
        ),
        report_key_id=configuration.report_key.key_id,
        report_signer=report_signer,
        report_signature_verifier=report_signer.verify_preimage,
        guidance_key_id=configuration.guidance_key.key_id,
        guidance_signer=guidance_signer,
        guidance_signature_verifier=guidance_signer.verify_preimage,
        enrichment_key_id=configuration.enrichment_key.key_id,
        enrichment_signer=enrichment_signer,
        enrichment_signature_verifier=enrichment_signer.verify_preimage,
    )
    registry = AzureTableIncidentFeedRegistry(
        endpoint=configuration.registry_endpoint,
        table_name=configuration.registry_table_name,
        partition_key=configuration.registry_partition_key,
        managed_identity_client_id=configuration.registry_identity_client_id,
        current_incident_reader=incident_reader,
    )
    index_publisher = AzureBlobIncidentFeedIndexPublisher(
        blob_endpoint=configuration.incident_assets.endpoint,
        container_name=configuration.incident_assets.container,
        managed_identity_client_id=(
            configuration.incident_writer_identity_client_id
        ),
        feed_key_id=configuration.feed_key.key_id,
        feed_key_fingerprint=configuration.feed_key.key_fingerprint,
        signature_verifier=feed_signer.verify_preimage,
    )
    index_publication = IncidentFeedIndexPublicationService(
        active_index_reader=incident_reader,
        current_incident_reader=incident_reader,
        registry=registry,
        pointer_reader=incident_exact_reader,
        publisher=index_publisher,
        feed_key_id=configuration.feed_key.key_id,
        feed_key_fingerprint=configuration.feed_key.key_fingerprint,
        signer=feed_signer,
        signature_verifier=feed_signer.verify_preimage,
    )
    feed = IncidentEnrichmentFeedPublicationService(
        current_incident_reader=incident_reader,
        artifact_writer=artifact_writer,
        registry=registry,
        feed_index_publication=cast(
            IncidentFeedIndexPublicationPort,
            index_publication,
        ),
        feed_key_id=configuration.feed_key.key_id,
        feed_signer=feed_signer,
        feed_signature_verifier=feed_signer.verify_preimage,
    )
    notification = NotificationV2PublicationService(
        reader=AzureBlobIncidentAssetReader(
            blob_endpoint=configuration.incident_assets.endpoint,
            container_name=configuration.incident_assets.container,
            managed_identity_client_id=(
                configuration.incident_assets.identity_client_id
            ),
        ),
        trust=NotificationV2Trust(
            lifecycle_key_id=configuration.incident_key.key_id,
            lifecycle_key_fingerprint=configuration.incident_key.key_fingerprint,
            lifecycle_signature_verifier=lifecycle_verifier.verify_preimage,
            feed_key_id=configuration.feed_key.key_id,
            feed_key_fingerprint=configuration.feed_key.key_fingerprint,
            feed_signature_verifier=feed_signer.verify_preimage,
            report_key_id=configuration.report_key.key_id,
            report_signature_verifier=report_signer.verify_preimage,
            guidance_key_id=configuration.guidance_key.key_id,
            guidance_signature_verifier=guidance_signer.verify_preimage,
            enrichment_key_id=configuration.enrichment_key.key_id,
            enrichment_signature_verifier=enrichment_signer.verify_preimage,
        ),
        presentation_base_url=configuration.presentation_url,
        notification_key_id=configuration.notification_key.key_id,
        notification_signer=notification_signer,
        notification_signature_verifier=(
            notification_signer.verify_preimage
        ),
        outbox=notification_outbox,
    )
    return Wc027EnrichmentFeedRuntime(
        correlation=correlation,
        incident_authority=incident_reader,
        enrichment_publication=enrichment,
        feed_publication=feed,
        notification_publication=notification,
    )


def submit_wc027_enrichment_feed_trigger(
    *,
    binding_path: Path,
    fully_qualified_namespace: str,
    queue_name: str,
    managed_identity_client_id: str,
) -> str:
    from azure.identity import ManagedIdentityCredential
    from azure.servicebus import ServiceBusClient, ServiceBusMessage

    binding = parse_wc027_enrichment_trigger(binding_path.read_bytes())
    namespace = _service_bus_namespace(fully_qualified_namespace)
    queue = _queue_name(queue_name)
    credential = ManagedIdentityCredential(
        client_id=_client_id(
            managed_identity_client_id,
            "managed_identity_client_id",
        )
    )
    with (
        ServiceBusClient(
            fully_qualified_namespace=namespace,
            credential=credential,
            logging_enable=False,
        ) as client,
        client.get_queue_sender(queue_name=queue) as sender,
    ):
        sender.send_messages(
            ServiceBusMessage(
                binding.canonical_bytes(),
                content_type="application/json",
                message_id=binding.binding_id,
                session_id=(
                    binding.incident_bound_request.incident_subject.incident_id
                ),
                application_properties={
                    "schemaVersion": WC027_ENRICHMENT_TRIGGER_SCHEMA_VERSION,
                    "bindingDigest": binding.binding_digest,
                },
            )
        )
    return binding.binding_id


def run_wc027_enrichment_feed_worker(
    *,
    configuration: Wc027EnrichmentFeedProductionConfiguration,
    max_wait_time_seconds: int = 30,
) -> bool:
    from azure.identity import ManagedIdentityCredential
    from azure.servicebus import (
        NEXT_AVAILABLE_SESSION,
        AutoLockRenewer,
        ServiceBusClient,
    )

    if not 1 <= max_wait_time_seconds <= 300:
        raise ValueError("max_wait_time_seconds must be between 1 and 300")
    credential = ManagedIdentityCredential(
        client_id=configuration.broker_identity_client_id
    )
    with (
        AutoLockRenewer(max_workers=1) as lock_renewer,
        ServiceBusClient(
            fully_qualified_namespace=configuration.service_bus_namespace,
            credential=credential,
            logging_enable=False,
        ) as client,
        client.get_queue_receiver(
            queue_name=configuration.trigger_queue_name,
            session_id=NEXT_AVAILABLE_SESSION,
            max_wait_time=max_wait_time_seconds,
        ) as receiver,
        client.get_queue_sender(
            queue_name=configuration.notification_queue_name
        ) as notification_sender,
    ):
        session = receiver.session
        if session is None:
            raise RuntimeError("WC-027 producer requires a locked Service Bus session")
        lock_renewer.register(
            receiver,
            session,
            max_lock_renewal_duration=15 * 60,
        )
        messages = receiver.receive_messages(
            max_message_count=1,
            max_wait_time=max_wait_time_seconds,
        )
        if not messages:
            return False
        message = messages[0]
        try:
            binding = parse_wc027_enrichment_trigger(_message_body(message))
            validate_wc027_enrichment_broker_metadata(message, binding)
            runtime = build_wc027_enrichment_feed_runtime(
                configuration,
                notification_outbox=AzureServiceBusNotificationOutbox(
                    notification_sender
                ),
            )
            runtime.publish(
                binding,
                published_at=utc_now_millisecond(),
            )
            receiver.complete_message(message)
            return True
        except (
            Wc027EnrichmentSourceNotReadyError,
            NotificationV2SourceNotReadyError,
            IncidentFeedRegistryIncompleteError,
            IncidentFeedRegistryError,
            IncidentFeedIndexPublicationConflictError,
            IncidentFeedIndexPublicationError,
            ArtifactReadError,
            ArtifactWriteError,
            ServiceRequestError,
            ServiceResponseError,
            OSError,
        ):
            receiver.abandon_message(message)
            return False
        except (ValidationError, ValueError):
            receiver.dead_letter_message(
                message,
                reason="AthenaWc027EnrichmentRejected",
                error_description=(
                    "signed binding failed bounded validation, freshness, "
                    "or trust verification"
                ),
            )
            return False
        except HttpResponseError:
            receiver.abandon_message(message)
            return False


def load_wc027_enrichment_feed_configuration(
    *,
    path: Path | None,
    environment_json: str | None,
) -> Wc027EnrichmentFeedProductionConfiguration:
    if path is not None and environment_json is not None:
        raise ValueError("WC-027 runtime configuration source is ambiguous")
    if path is not None:
        payload: str | bytes = path.read_bytes()
    elif environment_json is not None:
        payload = environment_json
    else:
        raise ValueError("WC-027 runtime configuration is required")
    return Wc027EnrichmentFeedProductionConfiguration.model_validate_json(
        payload
    )


def _correlation_reader(
    source: _BlobSource,
    *,
    required_prefix: str,
) -> AzureBlobCorrelationArtifactReader:
    return AzureBlobCorrelationArtifactReader(
        reader=AzureBlobVersionPinnedArtifactReader(
            blob_endpoint=source.endpoint,
            container_name=source.container,
            managed_identity_client_id=source.identity_client_id,
            max_payload_bytes=MAX_ARTIFACT_TRANSFER_BYTES,
        ),
        required_prefix=required_prefix,
    )


def _signer(authority: _KeyAuthority) -> KeyVaultRsaSigner:
    return KeyVaultRsaSigner(
        trusted_key_anchor=authority.anchor,
        managed_identity_client_id=authority.identity_client_id,
    )


def _verifier(authority: _KeyAuthority) -> KeyVaultRsaPublicKeyVerifier:
    return KeyVaultRsaPublicKeyVerifier(
        trusted_key_anchor=authority.anchor,
        managed_identity_client_id=authority.identity_client_id,
    )


def _blob_source(value: object, label: str) -> _BlobSource:
    source = _mapping(value, label)
    _require_keys(
        source,
        {"blobEndpoint", "containerName", "identityClientId"},
        label,
    )
    return _BlobSource(
        endpoint=_https_origin(
            source["blobEndpoint"],
            f"{label}.blobEndpoint",
            suffix=".blob.core.windows.net",
        ),
        container=_text(
            source["containerName"],
            f"{label}.containerName",
            maximum=63,
        ),
        identity_client_id=_client_id(
            source["identityClientId"],
            f"{label}.identityClientId",
        ),
    )


def _key_authority(value: object, label: str) -> _KeyAuthority:
    authority = _mapping(value, label)
    _require_keys(
        authority,
        {
            "keyId",
            "keyVaultKeyId",
            "keyFingerprint",
            "identityClientId",
        },
        label,
    )
    result = _KeyAuthority(
        key_id=_text(authority["keyId"], f"{label}.keyId", maximum=512),
        key_vault_key_id=_text(
            authority["keyVaultKeyId"],
            f"{label}.keyVaultKeyId",
            maximum=512,
        ),
        key_fingerprint=_text(
            authority["keyFingerprint"],
            f"{label}.keyFingerprint",
            maximum=71,
        ),
        identity_client_id=_client_id(
            authority["identityClientId"],
            f"{label}.identityClientId",
        ),
    )
    _ = result.anchor
    return result


def _monitoring_collector_key(value: object) -> _MonitoringCollectorKey:
    payload = _mapping(value, "monitoringCollectorKey")
    _require_keys(
        payload,
        {
            "keyId",
            "keyVaultKeyId",
            "keyFingerprint",
            "identityClientId",
            "activatedAt",
            "expiresAt",
        },
        "monitoringCollectorKey",
    )
    return _MonitoringCollectorKey(
        authority=_key_authority(
            {
                key: payload[key]
                for key in (
                    "keyId",
                    "keyVaultKeyId",
                    "keyFingerprint",
                    "identityClientId",
                )
            },
            "monitoringCollectorKey",
        ),
        activated_at=_timestamp(
            payload["activatedAt"],
            "monitoringCollectorKey.activatedAt",
        ),
        expires_at=(
            None
            if payload["expiresAt"] is None
            else _timestamp(
                payload["expiresAt"],
                "monitoringCollectorKey.expiresAt",
            )
        ),
    )


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ValueError(f"{label} must be an exact JSON object")
    return value


def _require_keys(
    value: dict[str, Any],
    expected: set[str],
    label: str,
) -> None:
    if set(value) != expected:
        raise ValueError(f"{label} contains missing or unknown fields")


def _text(value: object, label: str, *, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


def _client_id(value: object, label: str) -> str:
    text = _text(value, label, maximum=36)
    try:
        parsed = UUID(text)
    except ValueError as exc:
        raise ValueError(f"{label} must be a UUID") from exc
    canonical = str(parsed)
    if text.casefold() != canonical:
        raise ValueError(f"{label} must be a canonical lowercase UUID")
    return canonical


def _queue_name(value: object) -> str:
    text = _text(value, "queue name", maximum=260)
    if text != text.casefold() or any(character.isspace() for character in text):
        raise ValueError("queue name must be lowercase without whitespace")
    return text


def _service_bus_namespace(value: object) -> str:
    text = _text(value, "service bus namespace", maximum=255)
    if (
        text != text.casefold()
        or not text.endswith(".servicebus.windows.net")
        or "/" in text
    ):
        raise ValueError("service bus namespace is invalid")
    return text


def _https_origin(value: object, label: str, *, suffix: str) -> str:
    text = _text(value, label, maximum=2048)
    parsed = urlsplit(text)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or not parsed.hostname.endswith(suffix)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} is invalid")
    return text.rstrip("/")


def _https_origin_or_path(value: object, label: str) -> str:
    text = _text(value, label, maximum=2048)
    parsed = urlsplit(text)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} is invalid")
    return text.rstrip("/")


def _timestamp(value: object, label: str) -> datetime:
    text = _text(value, label, maximum=32)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != UTC.utcoffset(parsed)
        or parsed.microsecond % 1000
    ):
        raise ValueError(f"{label} must be a canonical UTC millisecond timestamp")
    return parsed


def _message_body(message: object) -> bytes:
    body = getattr(message, "body", None)
    if isinstance(body, bytes):
        payload = body
    elif isinstance(body, bytearray):
        payload = bytes(body)
    elif body is None:
        raise ValueError("WC-027 enrichment trigger body is missing")
    else:
        try:
            payload = b"".join(bytes(item) for item in body)
        except (TypeError, ValueError) as exc:
            raise ValueError("WC-027 enrichment trigger body is invalid") from exc
    if len(payload) > MAX_WC027_ENRICHMENT_TRIGGER_BYTES:
        raise ValueError("WC-027 enrichment trigger is outside its byte bound")
    return payload


__all__ = [
    "Wc027EnrichmentFeedProductionConfiguration",
    "build_wc027_enrichment_feed_runtime",
    "load_wc027_enrichment_feed_configuration",
    "run_wc027_enrichment_feed_worker",
    "submit_wc027_enrichment_feed_trigger",
]
