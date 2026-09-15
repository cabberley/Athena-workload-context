from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from azure.core.exceptions import (
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)
from pydantic import ValidationError

from athena_context.artifacts import (
    ArtifactAlreadyExistsError,
    ArtifactReadError,
    ArtifactWriteError,
)
from athena_context.azure_adapters import (
    AzureBlobIncidentAssetPublisher,
    KeyVaultRsaPublicKeyVerifier,
    KeyVaultRsaSigner,
)
from athena_context.contracts import (
    GuidanceActionKind,
    TrustedKeyAnchor,
)
from athena_context.enrichment.production import (
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
    _text,
    _writable_blob_source,
    _WritableBlobSource,
)
from athena_context.guidance.publication import (
    GuidanceAuthoritySourceNotReadyError,
)
from athena_context.guidance.request_azure import (
    AzureBlobGuidancePublicationRequestOutbox,
    AzureServiceBusGuidancePublicationRequestSender,
    ManagedIdentityGuidancePublicationRequestSender,
)
from athena_context.guidance.request_publication import (
    GuidancePublicationRequestDeliveryBudget,
    GuidancePublicationRequestProducer,
    parse_wc027_guidance_request_input,
    validate_wc027_guidance_request_input_broker_metadata,
)
from athena_context.presentation_assets import (
    PresentationAssetUnavailableError,
)

_CONFIG_SCHEMA_VERSION = "athena.wc027GuidancePublicationRequestProducerConfiguration.v1"
_INPUT_QUEUE_NAME = "wc027-guidance-publication-inputs"
_OUTPUT_QUEUE_NAME = "wc027-guidance-authority-requests"
_ALLOWED_REQUESTED_ACTIONS = frozenset(
    {
        "investigationCheck",
        "confirmationCheck",
        "manualResolutionOption",
        "rollbackConsideration",
        "recoveryValidation",
        "escalation",
    }
)


@dataclass(frozen=True, slots=True)
class _RequestSigningKey:
    key_id: str
    key_vault_key_id: str
    key_fingerprint: str
    signer_identity_client_id: str
    signer_identity_resource_id: str
    verifier_identity_client_id: str
    verifier_identity_resource_id: str

    @property
    def anchor(self) -> TrustedKeyAnchor:
        return TrustedKeyAnchor.from_key_vault_key_id(
            self.key_vault_key_id,
            public_key_fingerprint=self.key_fingerprint,
        )


@dataclass(frozen=True, slots=True)
class Wc027GuidancePublicationRequestProducerConfiguration:
    service_bus_namespace: str
    input_queue_name: str
    output_queue_name: str
    receiver_identity_client_id: str
    receiver_identity_resource_id: str
    sender_identity_client_id: str
    sender_identity_resource_id: str
    incident_lifecycle_assets: _BlobSource
    context_authority_source: _BlobSource
    request_outbox: _WritableBlobSource
    incident_key: _KeyAuthority
    correlation_binding_key: _KeyAuthority
    request_signing_key: _RequestSigningKey
    requested_actions: tuple[GuidanceActionKind, ...]
    delivery_budget: GuidancePublicationRequestDeliveryBudget
    binding_evidence_id: str
    attached_identity_resource_ids: tuple[str, ...]
    rbac_resource_ids: tuple[str, ...]

    @classmethod
    def model_validate_json(
        cls,
        value: str | bytes,
    ) -> Wc027GuidancePublicationRequestProducerConfiguration:
        try:
            payload = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "WC-027 guidance request producer configuration is not valid JSON"
            ) from exc
        root = _mapping(payload, "configuration")
        _require_keys(
            root,
            {
                "schemaVersion",
                "serviceBus",
                "incidentLifecycleAssets",
                "contextAuthoritySource",
                "requestOutbox",
                "incidentKey",
                "correlationBindingKey",
                "requestSigningKey",
                "requestedActions",
                "deliveryBudget",
                "deploymentBinding",
            },
            "configuration",
        )
        if root["schemaVersion"] != _CONFIG_SCHEMA_VERSION:
            raise ValueError(
                "WC-027 guidance request producer configuration schemaVersion is invalid"
            )
        service_bus = _mapping(root["serviceBus"], "serviceBus")
        _require_keys(
            service_bus,
            {
                "namespace",
                "inputQueueName",
                "outputQueueName",
                "receiverIdentityClientId",
                "receiverIdentityResourceId",
                "senderIdentityClientId",
                "senderIdentityResourceId",
            },
            "serviceBus",
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
        request_signing_key = _request_signing_key(root["requestSigningKey"])
        requested_actions = _requested_actions(root["requestedActions"])
        configuration = cls(
            service_bus_namespace=_service_bus_namespace(service_bus["namespace"]),
            input_queue_name=_queue_name(service_bus["inputQueueName"]),
            output_queue_name=_queue_name(service_bus["outputQueueName"]),
            receiver_identity_client_id=_client_id(
                service_bus["receiverIdentityClientId"],
                "serviceBus.receiverIdentityClientId",
            ),
            receiver_identity_resource_id=_managed_identity_resource_id(
                service_bus["receiverIdentityResourceId"],
                "serviceBus.receiverIdentityResourceId",
            ),
            sender_identity_client_id=_client_id(
                service_bus["senderIdentityClientId"],
                "serviceBus.senderIdentityClientId",
            ),
            sender_identity_resource_id=_managed_identity_resource_id(
                service_bus["senderIdentityResourceId"],
                "serviceBus.senderIdentityResourceId",
            ),
            incident_lifecycle_assets=_blob_source(
                root["incidentLifecycleAssets"],
                "incidentLifecycleAssets",
            ),
            context_authority_source=_blob_source(
                root["contextAuthoritySource"],
                "contextAuthoritySource",
            ),
            request_outbox=_writable_blob_source(
                root["requestOutbox"],
                "requestOutbox",
            ),
            incident_key=_key_authority(
                root["incidentKey"],
                "incidentKey",
                allow_logical_key_id=True,
            ),
            correlation_binding_key=_key_authority(
                root["correlationBindingKey"],
                "correlationBindingKey",
            ),
            request_signing_key=request_signing_key,
            requested_actions=requested_actions,
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
        if (
            self.input_queue_name != _INPUT_QUEUE_NAME
            or self.output_queue_name != _OUTPUT_QUEUE_NAME
        ):
            raise ValueError("guidance request producer queues do not match the production chain")
        if self.incident_lifecycle_assets.container != "incident-assets":
            raise ValueError("incident lifecycle source must be exactly incident-assets")
        if self.context_authority_source.container != "context-authority":
            raise ValueError("context authority source must be exactly context-authority")
        if self.request_outbox.container != "wc027-guidance-request-outbox":
            raise ValueError("guidance request outbox container is invalid")
        storage_domains = {
            (
                self.incident_lifecycle_assets.endpoint.casefold().rstrip("/"),
                self.incident_lifecycle_assets.container.casefold(),
            ),
            (
                self.context_authority_source.endpoint.casefold().rstrip("/"),
                self.context_authority_source.container.casefold(),
            ),
            (
                self.request_outbox.endpoint.casefold().rstrip("/"),
                self.request_outbox.container.casefold(),
            ),
        }
        if len(storage_domains) != 3:
            raise ValueError("guidance request producer storage domains must be distinct")
        upstream_keys = (
            self.incident_key,
            self.correlation_binding_key,
        )
        request_key = self.request_signing_key
        if (
            len({item.key_id for item in upstream_keys}) != len(upstream_keys)
            or len({item.key_vault_key_id for item in upstream_keys}) != len(upstream_keys)
            or len({item.key_fingerprint for item in upstream_keys}) != len(upstream_keys)
            or request_key.key_id in {item.key_id for item in upstream_keys}
            or request_key.key_vault_key_id in {item.key_vault_key_id for item in upstream_keys}
            or request_key.key_fingerprint in {item.key_fingerprint for item in upstream_keys}
        ):
            raise ValueError("guidance request signing key must use a distinct trust domain")
        upstream_identity_pairs = {
            (
                item.identity_client_id,
                item.identity_resource_id.casefold(),
            )
            for item in upstream_keys
        }
        if len(upstream_identity_pairs) != 1:
            raise ValueError(
                "incident and correlation verification must use one dedicated trust reader"
            )
        io_identity_pairs = (
            (
                self.receiver_identity_client_id,
                self.receiver_identity_resource_id,
            ),
            (
                self.sender_identity_client_id,
                self.sender_identity_resource_id,
            ),
            (
                self.incident_lifecycle_assets.identity_client_id,
                self.incident_lifecycle_assets.identity_resource_id,
            ),
            (
                self.context_authority_source.identity_client_id,
                self.context_authority_source.identity_resource_id,
            ),
            (
                self.request_outbox.reader_identity_client_id,
                self.request_outbox.reader_identity_resource_id,
            ),
            (
                self.request_outbox.writer_identity_client_id,
                self.request_outbox.writer_identity_resource_id,
            ),
        )
        if len({client_id for client_id, _ in io_identity_pairs}) != len(io_identity_pairs) or len(
            {resource_id.casefold() for _, resource_id in io_identity_pairs}
        ) != len(io_identity_pairs):
            raise ValueError("guidance request producer I/O identities must be distinct")
        upstream_client_id, upstream_resource_id = next(iter(upstream_identity_pairs))
        isolated_pairs = (
            (
                upstream_client_id,
                upstream_resource_id,
            ),
            (
                request_key.signer_identity_client_id,
                request_key.signer_identity_resource_id.casefold(),
            ),
            (
                request_key.verifier_identity_client_id,
                request_key.verifier_identity_resource_id.casefold(),
            ),
        )
        if (
            len({client_id for client_id, _ in isolated_pairs}) != 3
            or len({resource_id for _, resource_id in isolated_pairs}) != 3
            or {client_id for client_id, _ in io_identity_pairs}.intersection(
                client_id for client_id, _ in isolated_pairs
            )
            or {resource_id.casefold() for _, resource_id in io_identity_pairs}.intersection(
                resource_id for _, resource_id in isolated_pairs
            )
        ):
            raise ValueError(
                "guidance request signing and verification identities must be isolated"
            )
        expected = {
            *(resource_id for _, resource_id in io_identity_pairs),
            self.incident_key.identity_resource_id,
            request_key.signer_identity_resource_id,
            request_key.verifier_identity_resource_id,
        }
        if {item.casefold() for item in self.attached_identity_resource_ids} != {
            item.casefold() for item in expected
        }:
            raise ValueError(
                "guidance request producer deployment identities do not match configuration"
            )


def _request_signing_key(value: object) -> _RequestSigningKey:
    payload = _mapping(value, "requestSigningKey")
    _require_keys(
        payload,
        {
            "keyId",
            "keyVaultKeyId",
            "keyFingerprint",
            "signerIdentityClientId",
            "signerIdentityResourceId",
            "verifierIdentityClientId",
            "verifierIdentityResourceId",
        },
        "requestSigningKey",
    )
    result = _RequestSigningKey(
        key_id=_text(
            payload["keyId"],
            "requestSigningKey.keyId",
            maximum=512,
        ),
        key_vault_key_id=_text(
            payload["keyVaultKeyId"],
            "requestSigningKey.keyVaultKeyId",
            maximum=512,
        ),
        key_fingerprint=_text(
            payload["keyFingerprint"],
            "requestSigningKey.keyFingerprint",
            maximum=71,
        ),
        signer_identity_client_id=_client_id(
            payload["signerIdentityClientId"],
            "requestSigningKey.signerIdentityClientId",
        ),
        signer_identity_resource_id=_managed_identity_resource_id(
            payload["signerIdentityResourceId"],
            "requestSigningKey.signerIdentityResourceId",
        ),
        verifier_identity_client_id=_client_id(
            payload["verifierIdentityClientId"],
            "requestSigningKey.verifierIdentityClientId",
        ),
        verifier_identity_resource_id=_managed_identity_resource_id(
            payload["verifierIdentityResourceId"],
            "requestSigningKey.verifierIdentityResourceId",
        ),
    )
    _ = result.anchor
    if result.key_id == result.key_vault_key_id or result.key_id.casefold().startswith("https://"):
        raise ValueError("requestSigningKey.keyId must be a stable logical key ID")
    return result


def _requested_actions(value: object) -> tuple[GuidanceActionKind, ...]:
    if (
        type(value) is not list
        or not 1 <= len(value) <= 16
        or any(type(item) is not str for item in value)
    ):
        raise ValueError("requestedActions must be one bounded string array")
    actions = tuple(value)
    if (
        actions != tuple(sorted(actions))
        or len(set(actions)) != len(actions)
        or not set(actions).issubset(_ALLOWED_REQUESTED_ACTIONS)
    ):
        raise ValueError("requestedActions must contain sorted unique governed categories")
    return cast(tuple[GuidanceActionKind, ...], actions)


def _utc_now_milliseconds() -> datetime:
    current = datetime.now(UTC)
    return current.replace(microsecond=(current.microsecond // 1000) * 1000)


def build_wc027_guidance_publication_request_producer(
    configuration: Wc027GuidancePublicationRequestProducerConfiguration,
    *,
    request_sender: object | None = None,
) -> GuidancePublicationRequestProducer:
    incident_verifier = KeyVaultRsaPublicKeyVerifier(
        trusted_key_anchor=configuration.incident_key.anchor,
        managed_identity_client_id=(configuration.incident_key.identity_client_id),
    )
    correlation_binding_verifier = KeyVaultRsaPublicKeyVerifier(
        trusted_key_anchor=configuration.correlation_binding_key.anchor,
        managed_identity_client_id=(configuration.correlation_binding_key.identity_client_id),
    )
    request_key = configuration.request_signing_key
    request_signer = KeyVaultRsaSigner(
        trusted_key_anchor=request_key.anchor,
        managed_identity_client_id=request_key.signer_identity_client_id,
    )
    request_verifier = KeyVaultRsaPublicKeyVerifier(
        trusted_key_anchor=request_key.anchor,
        managed_identity_client_id=request_key.verifier_identity_client_id,
    )
    incident_reader = AzureBlobIncidentAssetPublisher(
        blob_endpoint=configuration.incident_lifecycle_assets.endpoint,
        container_name=configuration.incident_lifecycle_assets.container,
        managed_identity_client_id=(configuration.incident_lifecycle_assets.identity_client_id),
        signing_key_id=configuration.incident_key.key_id,
        signing_key_vault_key_id=(configuration.incident_key.key_vault_key_id),
        signing_key_fingerprint=configuration.incident_key.key_fingerprint,
        signature_verifier=incident_verifier.verify_preimage,
    )
    outbox = configuration.request_outbox
    return GuidancePublicationRequestProducer(
        incident_key_id=configuration.incident_key.key_id,
        incident_key_vault_key_id=(configuration.incident_key.key_vault_key_id),
        incident_signature_verifier=incident_verifier.verify_preimage,
        correlation_binding_key_id=(configuration.correlation_binding_key.key_vault_key_id),
        correlation_binding_signature_verifier=(correlation_binding_verifier.verify_preimage),
        request_key_id=request_key.key_id,
        request_signer=request_signer,
        request_signature_verifier=request_verifier.verify_preimage,
        incident_authority=incident_reader,
        context_authority_reader=_correlation_reader(
            configuration.context_authority_source,
            required_prefix="context-authority/",
        ),
        outbox=AzureBlobGuidancePublicationRequestOutbox(
            blob_endpoint=outbox.endpoint,
            container_name=outbox.container,
            writer_managed_identity_client_id=outbox.writer_identity_client_id,
            reader_managed_identity_client_id=outbox.reader_identity_client_id,
        ),
        sender=(
            AzureServiceBusGuidancePublicationRequestSender(request_sender)
            if request_sender is not None
            else ManagedIdentityGuidancePublicationRequestSender(
                fully_qualified_namespace=(configuration.service_bus_namespace),
                queue_name=configuration.output_queue_name,
                managed_identity_client_id=(configuration.sender_identity_client_id),
            )
        ),
        requested_actions=configuration.requested_actions,
        delivery_budget=configuration.delivery_budget,
        clock=_utc_now_milliseconds,
    )


def load_wc027_guidance_publication_request_producer_configuration(
    *,
    path: Path | None,
    environment_json: str | None = None,
) -> Wc027GuidancePublicationRequestProducerConfiguration:
    if path is not None and environment_json is not None:
        raise ValueError("WC-027 guidance request producer configuration source is ambiguous")
    raw: str | bytes | None
    if path is not None:
        raw = path.read_bytes()
    elif environment_json is not None:
        raw = environment_json
    else:
        raw = os.environ.get("ATHENA_WC027_GUIDANCE_REQUEST_PRODUCER_CONFIG_JSON")
    if raw is None:
        raise ValueError("WC-027 guidance request producer configuration is required")
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not 1 <= len(raw) <= 256 * 1024:
        raise ValueError("WC-027 guidance request producer configuration is outside its byte bound")
    return Wc027GuidancePublicationRequestProducerConfiguration.model_validate_json(raw)


def run_wc027_guidance_publication_request_producer_worker(
    *,
    configuration: Wc027GuidancePublicationRequestProducerConfiguration,
    max_wait_time_seconds: int = 30,
) -> bool:
    from azure.identity import ManagedIdentityCredential
    from azure.servicebus import (
        NEXT_AVAILABLE_SESSION,
        AutoLockRenewer,
        ServiceBusClient,
    )
    from azure.servicebus.exceptions import ServiceBusError

    if not 1 <= max_wait_time_seconds <= 300:
        raise ValueError("max_wait_time_seconds must be between 1 and 300")
    receiver_credential = ManagedIdentityCredential(
        client_id=configuration.receiver_identity_client_id
    )
    with (
        AutoLockRenewer(max_workers=1) as lock_renewer,
        ServiceBusClient(
            fully_qualified_namespace=configuration.service_bus_namespace,
            credential=receiver_credential,
            logging_enable=False,
        ) as receiver_client,
        receiver_client.get_queue_receiver(
            queue_name=configuration.input_queue_name,
            session_id=NEXT_AVAILABLE_SESSION,
            max_wait_time=max_wait_time_seconds,
        ) as receiver,
    ):
        session = receiver.session
        if session is None:
            raise RuntimeError(
                "WC-027 guidance request producer requires a locked Service Bus session"
            )
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
            request = parse_wc027_guidance_request_input(_message_body(message))
            validate_wc027_guidance_request_input_broker_metadata(
                message,
                request,
            )
            producer = build_wc027_guidance_publication_request_producer(
                configuration,
            )
            producer.produce(
                request,
                now=_utc_now_milliseconds(),
            )
            receiver.complete_message(message)
            return True
        except ArtifactAlreadyExistsError:
            receiver.dead_letter_message(
                message,
                reason="AthenaWc027GuidanceRequestConflict",
                error_description=(
                    "the signed occurrence already owns a different immutable "
                    "guidance publication request"
                ),
            )
            return False
        except (
            GuidanceAuthoritySourceNotReadyError,
            PresentationAssetUnavailableError,
            ArtifactReadError,
            ArtifactWriteError,
            HttpResponseError,
            ServiceRequestError,
            ServiceResponseError,
            ServiceBusError,
            OSError,
        ):
            receiver.abandon_message(message)
            return False
        except ValidationError, TypeError, ValueError:
            receiver.dead_letter_message(
                message,
                reason="AthenaWc027GuidanceRequestRejected",
                error_description=(
                    "incident-bound request failed canonical, freshness, "
                    "signature, occurrence, context-authority, or signer validation"
                ),
            )
            return False


def _message_body(message: object) -> bytes:
    body = getattr(message, "body", None)
    if isinstance(body, bytes):
        payload = body
    elif isinstance(body, bytearray):
        payload = bytes(body)
    elif body is None:
        raise ValueError("WC-027 guidance request input body is missing")
    else:
        try:
            payload = b"".join(bytes(item) for item in body)
        except (TypeError, ValueError) as exc:
            raise ValueError("WC-027 guidance request input body is invalid") from exc
    return payload


__all__ = [
    "Wc027GuidancePublicationRequestProducerConfiguration",
    "build_wc027_guidance_publication_request_producer",
    "load_wc027_guidance_publication_request_producer_configuration",
    "run_wc027_guidance_publication_request_producer_worker",
]
