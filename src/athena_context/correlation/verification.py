from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from athena_context.artifacts import ArtifactReadRequest
from athena_context.azure_adapters import (
    AzureBlobVersionPinnedArtifactReader,
    KeyVaultTrustedKeyResolver,
)
from athena_context.contracts.change_ingestion import (
    ChangeEvidenceArtifact,
    change_evidence_attestation_preimage,
)
from athena_context.contracts.common import (
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.correlation import (
    CORRELATION_MAX_CANONICAL_BYTES,
    CORRELATION_REPORT_SCHEMA_VERSION,
    CorrelationReport,
    CorrelationRequest,
    EndpointHealthObservation,
    GuestSignalObservation,
    MonitoringEvidenceBundle,
    NetworkFlowObservation,
    PlatformHealthObservation,
    PublishedContextAuthority,
    PublishedRuntimeContextBinding,
    RootCauseHypothesis,
    validate_correlation_report_binding,
)
from athena_context.contracts.models import (
    TrustedKeyAnchor,
    UtcDateTime,
)
from athena_context.contracts.monitoring import (
    MonitoringCollectorContract,
    MonitoringEvidenceHandoff,
    verify_monitoring_evidence_handoff_attestation,
)
from athena_context.contracts.operational_phase import VersionPinnedBlobReference
from athena_context.correlation.rules import (
    CORRELATION_RULE_CATALOG,
    CORRELATION_RULE_CATALOG_DIGEST,
    assert_catalog_digest,
    assert_contract_compatibility,
)
from athena_context.eventing.change_ingestion import KeyVaultChangeEvidenceSigner

type HealthObservation = (
    GuestSignalObservation | EndpointHealthObservation | PlatformHealthObservation
)


class ImmutableArtifactReader(Protocol):
    def read(self, reference: VersionPinnedBlobReference) -> bytes: ...


class MonitoringHandoffVerifier(Protocol):
    def verify(
        self,
        handoff: MonitoringEvidenceHandoff,
        *,
        as_of: UtcDateTime,
    ) -> str: ...


class ChangeArtifactVerifier(Protocol):
    def verify(
        self,
        artifact: ChangeEvidenceArtifact,
        *,
        as_of: UtcDateTime,
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class AzureBlobCorrelationArtifactReader:
    reader: AzureBlobVersionPinnedArtifactReader
    required_prefix: str

    def __post_init__(self) -> None:
        if type(self.reader) is not AzureBlobVersionPinnedArtifactReader:
            raise TypeError("production correlation requires AzureBlobVersionPinnedArtifactReader")
        if (
            type(self.required_prefix) is not str
            or not self.required_prefix
            or not self.required_prefix.endswith("/")
            or self.required_prefix != self.required_prefix.casefold()
        ):
            raise ValueError("artifact reader prefix must be one lowercase relative path")

    @property
    def trust_domain(self) -> tuple[str, str, str]:
        return (
            self.reader.blob_endpoint,
            self.reader.container_name,
            self.reader.managed_identity_client_id,
        )

    def read(self, reference: VersionPinnedBlobReference) -> bytes:
        if not reference.name.startswith(self.required_prefix):
            raise ValueError("artifact reference is outside the configured trust domain")
        return self.reader.read(
            ArtifactReadRequest(
                blob_name=reference.name,
                version_id=reference.version,
                expected_payload_sha256=reference.content_digest,
            )
        ).payload


@dataclass(frozen=True, slots=True)
class TrustedMonitoringHandoffVerifier:
    reviewed_contract: MonitoringCollectorContract
    trusted_key_anchor: TrustedKeyAnchor
    key_resolver: KeyVaultTrustedKeyResolver

    def __post_init__(self) -> None:
        if type(self.key_resolver) is not KeyVaultTrustedKeyResolver:
            raise TypeError(
                "production monitoring verification requires KeyVaultTrustedKeyResolver"
            )

    def verify(
        self,
        handoff: MonitoringEvidenceHandoff,
        *,
        as_of: UtcDateTime,
    ) -> str:
        verify_monitoring_evidence_handoff_attestation(
            handoff,
            as_of=as_of,
            reviewed_collector_contract=self.reviewed_contract,
            trusted_key_anchor=self.trusted_key_anchor,
            key_resolver=self.key_resolver,
        )
        return handoff.compute_artifact_digest_value()


@dataclass(frozen=True, slots=True)
class TrustedChangeArtifactVerifier:
    signer: KeyVaultChangeEvidenceSigner

    def __post_init__(self) -> None:
        if type(self.signer) is not KeyVaultChangeEvidenceSigner:
            raise TypeError("production change verification requires KeyVaultChangeEvidenceSigner")

    def verify(
        self,
        artifact: ChangeEvidenceArtifact,
        *,
        as_of: UtcDateTime,
    ) -> str:
        del as_of
        if artifact.attestation.key_vault_key_id != self.signer.key_vault_key_id:
            raise ValueError("change artifact uses an unreviewed signing key")
        preimage = canonicalize_json(
            change_evidence_attestation_preimage(artifact.evidence)
        ).encode("utf-8")
        try:
            signature = base64.b64decode(
                artifact.attestation.signature,
                validate=True,
            )
        except (TypeError, ValueError, binascii.Error) as exc:
            raise ValueError("change artifact signature is malformed") from exc
        if (
            not signature
            or base64.b64encode(signature).decode("ascii") != artifact.attestation.signature
            or self.signer.verify_preimage(preimage, signature) is not True
        ):
            raise ValueError("change artifact signature verification failed")
        return sha256_hex(artifact.canonical_bytes())


@dataclass(frozen=True, slots=True)
class _CorrelationVerificationService:
    monitoring_reader: ImmutableArtifactReader
    change_reader: ImmutableArtifactReader
    authority_reader: ImmutableArtifactReader
    monitoring_verifier: MonitoringHandoffVerifier
    change_verifier: ChangeArtifactVerifier

    def compute(
        self,
        request: CorrelationRequest,
        *,
        evaluated_at: UtcDateTime,
    ) -> tuple[RootCauseHypothesis, ...]:
        if type(request) is not CorrelationRequest:
            raise TypeError("request must be an exact CorrelationRequest")
        request = CorrelationRequest.model_validate_json(request.model_dump_json(by_alias=True))
        assert_catalog_digest()
        assert_contract_compatibility()
        if evaluated_at < request.trusted_as_of:
            raise ValueError("verification time must not precede request trustedAsOf")
        if evaluated_at < request.issued_at or evaluated_at > request.expires_at:
            raise ValueError("correlation request is outside its validity window")
        if request.rule_catalog_digest != CORRELATION_RULE_CATALOG_DIGEST:
            raise ValueError("request rule catalog does not match the trusted engine catalog")
        from athena_context.correlation.engine import (
            _adverse_observation_ids,
            _compute_hypotheses,
            _enforce_candidate_budget,
        )

        adverse_observation_ids = _adverse_observation_ids(request)
        _enforce_candidate_budget(
            request,
            adverse_observation_ids=adverse_observation_ids,
        )

        monitoring_bytes = self.monitoring_reader.read(request.monitoring_handoff.evidence)
        if sha256_hex(monitoring_bytes) != request.monitoring_handoff.evidence.content_digest:
            raise ValueError("monitoring Blob bytes do not match the immutable reference")
        persisted_bundle = MonitoringEvidenceBundle.model_validate_json(monitoring_bytes)
        if persisted_bundle != request.monitoring_bundle:
            raise ValueError("monitoring bundle does not match the immutable Blob")
        _verify_canonical_incident_anchor(request)
        _verify_network_rule_parents(request)
        if (
            self.monitoring_verifier.verify(
                request.monitoring_handoff,
                as_of=evaluated_at,
            )
            != request.monitoring_handoff.compute_artifact_digest_value()
        ):
            raise ValueError("monitoring handoff verification proof is invalid")

        for artifact, handoff in zip(
            request.change_artifacts,
            request.change_handoffs,
            strict=True,
        ):
            property_paths = tuple(
                item.path.casefold() for item in artifact.evidence.changed_properties
            )
            if len(property_paths) != len(set(property_paths)):
                raise ValueError(
                    "change artifact contains case-insensitive duplicate property paths"
                )
            artifact_bytes = self.change_reader.read(handoff.artifact)
            artifact_digest = sha256_hex(artifact_bytes)
            if artifact_digest != handoff.artifact.content_digest:
                raise ValueError("change Blob bytes do not match the immutable reference")
            if ChangeEvidenceArtifact.model_validate_json(artifact_bytes) != artifact:
                raise ValueError("change artifact does not match the immutable Blob")
            if self.change_verifier.verify(artifact, as_of=evaluated_at) != artifact_digest:
                raise ValueError("change artifact verification proof is invalid")

        if isinstance(
            request.context_binding,
            PublishedRuntimeContextBinding,
        ):
            authority = request.context_binding.publication_authority
            authority_reference = request.context_binding.publication_authority_reference
            authority_bytes = self.authority_reader.read(authority_reference)
            if sha256_hex(authority_bytes) != authority_reference.content_digest:
                raise ValueError(
                    "publication authority Blob bytes do not match the immutable reference"
                )
            persisted_authority = PublishedContextAuthority.model_validate_json(authority_bytes)
            if persisted_authority != authority:
                raise ValueError("publication authority does not match immutable published state")

        return _compute_hypotheses(
            request,
            adverse_observation_ids=adverse_observation_ids,
            budget_prechecked=True,
        )


@dataclass(frozen=True, slots=True)
class VerifiedCorrelationReport:
    report: CorrelationReport
    authority_proof_digest: str
    verification_receipt: str


def _trusted_now() -> UtcDateTime:
    current = datetime.now(UTC)
    return current.replace(microsecond=(current.microsecond // 1000) * 1000)


@dataclass(frozen=True, slots=True)
class CorrelationService:
    monitoring_reader: AzureBlobCorrelationArtifactReader
    change_reader: AzureBlobCorrelationArtifactReader
    authority_reader: AzureBlobCorrelationArtifactReader
    monitoring_verifier: TrustedMonitoringHandoffVerifier
    change_verifier: TrustedChangeArtifactVerifier
    _sealing_key: bytes = field(
        default_factory=lambda: secrets.token_bytes(32),
        init=False,
        repr=False,
        compare=False,
    )
    _clock: Callable[[], UtcDateTime] = field(
        default=_trusted_now,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        readers = (
            self.monitoring_reader,
            self.change_reader,
            self.authority_reader,
        )
        if any(type(item) is not AzureBlobCorrelationArtifactReader for item in readers):
            raise TypeError("production correlation requires AzureBlobCorrelationArtifactReader")
        expected_prefixes = (
            "wc024-monitoring/",
            "change-evidence/",
            "context-authority/",
        )
        if tuple(item.required_prefix for item in readers) != expected_prefixes:
            raise ValueError("production correlation artifact readers use invalid prefixes")
        storage_domains = {
            (
                item.reader.blob_endpoint.casefold().rstrip("/"),
                item.reader.container_name.casefold(),
            )
            for item in readers
        }
        if len(storage_domains) != len(readers):
            raise ValueError("production correlation storage containers must be distinct")
        if len({item.reader.managed_identity_client_id.casefold() for item in readers}) != len(
            readers
        ):
            raise ValueError("production correlation reader identities must be distinct")
        if type(self.monitoring_verifier) is not TrustedMonitoringHandoffVerifier:
            raise TypeError("production correlation requires TrustedMonitoringHandoffVerifier")
        if type(self.change_verifier) is not TrustedChangeArtifactVerifier:
            raise TypeError("production correlation requires TrustedChangeArtifactVerifier")
        if len(self._sealing_key) != 32:
            raise ValueError("correlation report sealing key must contain 256 bits")

    def correlate(
        self,
        request: CorrelationRequest,
    ) -> VerifiedCorrelationReport:
        if not isinstance(request.context_binding, PublishedRuntimeContextBinding):
            raise ValueError("production correlation requires published runtime context")
        hypotheses = _CorrelationVerificationService(
            monitoring_reader=self.monitoring_reader,
            change_reader=self.change_reader,
            authority_reader=self.authority_reader,
            monitoring_verifier=self.monitoring_verifier,
            change_verifier=self.change_verifier,
        ).compute(
            request,
            evaluated_at=self._clock(),
        )
        report = _build_verified_report(request, hypotheses)
        authority_proof_digest = (
            request.context_binding.publication_authority_reference.content_digest
        )
        return VerifiedCorrelationReport(
            report=report,
            authority_proof_digest=authority_proof_digest,
            verification_receipt=_report_receipt(
                report,
                authority_proof_digest,
                self._sealing_key,
            ),
        )

    def validate_result(self, result: VerifiedCorrelationReport) -> CorrelationReport:
        if type(result) is not VerifiedCorrelationReport:
            raise TypeError("result must be an exact VerifiedCorrelationReport")
        validated_report = CorrelationReport.model_validate_json(
            result.report.model_dump_json(by_alias=True)
        )
        expected = _report_receipt(
            validated_report,
            result.authority_proof_digest,
            self._sealing_key,
        )
        if not hmac.compare_digest(result.verification_receipt, expected):
            raise ValueError("correlation report verification receipt is invalid")
        return validated_report


def _build_verified_report(
    request: CorrelationRequest,
    hypotheses: tuple[RootCauseHypothesis, ...],
) -> CorrelationReport:
    assert_catalog_digest()
    assert_contract_compatibility()
    bounded_hypotheses = _bound_report_hypotheses(request, hypotheses)
    document = _report_document(request, bounded_hypotheses)
    report = CorrelationReport.model_validate(document)
    if len(report.canonical_bytes()) > CORRELATION_MAX_CANONICAL_BYTES:
        raise ValueError("correlation report exceeds its canonical byte budget")
    if report.rule_catalog_digest != CORRELATION_RULE_CATALOG_DIGEST:
        raise ValueError("correlation report does not match the engine rule catalog")
    validate_correlation_report_binding(report, request)
    return report


def _report_document(
    request: CorrelationRequest,
    hypotheses: tuple[RootCauseHypothesis, ...],
) -> dict[str, object]:
    hypothesis_payloads = tuple(
        item.model_dump(mode="json", by_alias=True, exclude_none=True) for item in hypotheses
    )
    values = {
        "schemaVersion": CORRELATION_REPORT_SCHEMA_VERSION,
        "algorithmId": request.algorithm_id,
        "ruleCatalogDigest": request.rule_catalog_digest,
        "asOf": request.trusted_as_of,
        "bindingMode": request.context_binding.binding_mode,
        "contextBindingDigest": request.context_binding.binding_digest,
        "inputInventoryDigest": request.evidence_inventory.inventory_digest,
        "requestDigest": request.request_digest,
        "transitionDigest": request.incident_anchor.transition_digest,
        "incidentAnchorObservedStart": request.incident_anchor.observed_start,
        "incidentAnchorObservedEnd": request.incident_anchor.observed_end,
        "hypotheses": hypotheses,
        "previewOnly": False,
        "noAutoRemediation": True,
    }
    digest = compute_artifact_digest(
        {
            **values,
            "hypotheses": list(hypothesis_payloads),
        }
    )
    return {
        **values,
        "reportId": f"report-{digest.removeprefix('sha256:')[:32]}",
        "reportDigest": digest,
    }


def _rank_hypotheses(
    hypotheses: tuple[RootCauseHypothesis, ...],
) -> tuple[RootCauseHypothesis, ...]:
    return tuple(
        RootCauseHypothesis.model_validate(
            {
                **item.model_dump(mode="python", by_alias=True),
                "rank": index,
            }
        )
        for index, item in enumerate(hypotheses, start=1)
    )


def _report_document_size(
    request: CorrelationRequest,
    hypotheses: tuple[RootCauseHypothesis, ...],
) -> int:
    document = _report_document(request, hypotheses)
    return len(
        (
            canonicalize_json(
                {
                    **document,
                    "hypotheses": [
                        item.model_dump(
                            mode="json",
                            by_alias=True,
                            exclude_none=True,
                        )
                        for item in hypotheses
                    ],
                }
            )
            + "\n"
        ).encode("utf-8")
    )


def _bound_report_hypotheses(
    request: CorrelationRequest,
    hypotheses: tuple[RootCauseHypothesis, ...],
) -> tuple[RootCauseHypothesis, ...]:
    from athena_context.correlation.engine import _overflow_hypothesis

    maximum = CORRELATION_RULE_CATALOG.maximum_hypotheses
    if len(hypotheses) <= maximum:
        complete = _rank_hypotheses(hypotheses)
        if _report_document_size(request, complete) <= CORRELATION_MAX_CANONICAL_BYTES:
            return complete
        maximum_retained = len(hypotheses) - 1
    else:
        maximum_retained = maximum - 1

    best: tuple[RootCauseHypothesis, ...] | None = None
    minimum_retained = 1
    while minimum_retained <= maximum_retained:
        retained_count = (minimum_retained + maximum_retained) // 2
        omitted = list(hypotheses[retained_count:])
        candidate = (
            *hypotheses[:retained_count],
            _overflow_hypothesis(request, omitted),
        )
        ranked = _rank_hypotheses(tuple(candidate))
        if _report_document_size(request, ranked) <= CORRELATION_MAX_CANONICAL_BYTES:
            best = ranked
            minimum_retained = retained_count + 1
        else:
            maximum_retained = retained_count - 1
    if best is not None:
        return best
    raise ValueError(
        "top correlation hypothesis and omission record exceed the canonical report byte budget"
    )


def _report_receipt(
    report: CorrelationReport,
    authority_proof_digest: str,
    sealing_key: bytes,
) -> str:
    message_digest = compute_artifact_digest(
        {
            "domain": "athena.wc026VerifiedCorrelationReport.v1",
            "reportDigest": report.report_digest,
            "requestDigest": report.request_digest,
            "ruleCatalogDigest": report.rule_catalog_digest,
            "contextBindingDigest": report.context_binding_digest,
            "inputInventoryDigest": report.input_inventory_digest,
            "authorityProofDigest": authority_proof_digest,
        }
    )
    return (
        "hmac-sha256:"
        + hmac.new(
            sealing_key,
            message_digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
    )


def _verify_canonical_incident_anchor(request: CorrelationRequest) -> None:
    anchor = request.incident_anchor
    observation_by_id = {
        item.observation_id: item for item in request.monitoring_bundle.observations
    }
    seeds = tuple(
        _require_health_observation(observation_by_id[item.evidence_id])
        for item in anchor.current_state_evidence
    )
    candidates = tuple(
        item
        for item in request.monitoring_bundle.observations
        if isinstance(
            item,
            (
                GuestSignalObservation,
                EndpointHealthObservation,
                PlatformHealthObservation,
            ),
        )
        if item.subject_resource_id == anchor.affected_resource_id
        and _observation_health_state(item) == anchor.current_state
    )
    candidates_by_stream: dict[tuple[str, ...], list[HealthObservation]] = {}
    for candidate in candidates:
        candidates_by_stream.setdefault(
            _health_stream_key(candidate),
            [],
        ).append(candidate)

    components: list[
        tuple[
            tuple[str, ...],
            UtcDateTime,
            UtcDateTime,
            frozenset[str],
        ]
    ] = []
    observation_component: dict[str, int] = {}
    for stream_key in sorted(candidates_by_stream):
        ordered = sorted(
            candidates_by_stream[stream_key],
            key=lambda item: (
                item.observed_start,
                item.observed_end,
                item.observation_id,
            ),
        )
        component_start = ordered[0].observed_start
        component_end = ordered[0].observed_end
        component_ids = {ordered[0].observation_id}
        for candidate in ordered[1:]:
            if candidate.observed_start <= component_end:
                component_end = max(component_end, candidate.observed_end)
                component_ids.add(candidate.observation_id)
                continue
            index = len(components)
            components.append(
                (
                    stream_key,
                    component_start,
                    component_end,
                    frozenset(component_ids),
                )
            )
            for evidence_id in component_ids:
                observation_component[evidence_id] = index
            component_start = candidate.observed_start
            component_end = candidate.observed_end
            component_ids = {candidate.observation_id}
        index = len(components)
        components.append(
            (
                stream_key,
                component_start,
                component_end,
                frozenset(component_ids),
            )
        )
        for evidence_id in component_ids:
            observation_component[evidence_id] = index

    selected_components = {observation_component[seed.observation_id] for seed in seeds}
    selected_streams: dict[tuple[str, ...], int] = {}
    for index in selected_components:
        stream_key = components[index][0]
        existing = selected_streams.get(stream_key)
        if existing is not None and existing != index:
            raise ValueError("incident current-state evidence spans disconnected intervals")
        selected_streams[stream_key] = index

    selected_intervals = sorted(
        (components[index][1], components[index][2]) for index in selected_components
    )
    incident_start, incident_end = selected_intervals[0]
    for component_start, component_end in selected_intervals[1:]:
        if component_start > incident_end:
            raise ValueError("incident current-state evidence spans disconnected intervals")
        incident_end = max(incident_end, component_end)

    changed = True
    while changed:
        changed = False
        for index, (
            stream_key,
            component_start,
            component_end,
            _,
        ) in enumerate(components):
            if index in selected_components:
                continue
            if component_start <= incident_end and component_end >= incident_start:
                if stream_key in selected_streams:
                    raise ValueError("incident current-state evidence spans disconnected intervals")
                selected_components.add(index)
                selected_streams[stream_key] = index
                incident_start = min(incident_start, component_start)
                incident_end = max(incident_end, component_end)
                changed = True

    component_ids = {
        evidence_id for index in selected_components for evidence_id in components[index][3]
    }
    cited_ids = {item.evidence_id for item in anchor.current_state_evidence}
    if cited_ids != component_ids:
        raise ValueError(
            "incident anchor must include the complete current-state evidence interval"
        )


def _verify_network_rule_parents(request: CorrelationRequest) -> None:
    marker = "/securityrules/"
    for observation in request.monitoring_bundle.observations:
        if (
            not isinstance(observation, NetworkFlowObservation)
            or observation.rule_resource_id is None
        ):
            continue
        parent_nsg_id, separator, _ = observation.rule_resource_id.rpartition(marker)
        if (
            not separator
            or not parent_nsg_id
            or observation.enforcement_resource_id != parent_nsg_id
        ):
            raise ValueError("network flow rule does not belong to the enforcement NSG")


def _observation_health_state(
    observation: object,
) -> str | None:
    if isinstance(observation, GuestSignalObservation):
        return observation.state
    if isinstance(observation, EndpointHealthObservation):
        return observation.status
    if isinstance(observation, PlatformHealthObservation):
        return observation.status
    return None


def _require_health_observation(observation: object) -> HealthObservation:
    if isinstance(
        observation,
        (
            GuestSignalObservation,
            EndpointHealthObservation,
            PlatformHealthObservation,
        ),
    ):
        return observation
    raise TypeError("incident evidence is not a supported health observation")


def _health_stream_key(observation: HealthObservation) -> tuple[str, ...]:
    if isinstance(observation, GuestSignalObservation):
        return (
            "guest",
            observation.signal,
            observation.service_reference or "",
        )
    if isinstance(observation, EndpointHealthObservation):
        return (
            "endpoint",
            observation.path_id,
            *observation.backend_resource_ids,
        )
    return ("platform", observation.health_kind)


__all__ = [
    "AzureBlobCorrelationArtifactReader",
    "CorrelationService",
    "ImmutableArtifactReader",
    "TrustedChangeArtifactVerifier",
    "TrustedMonitoringHandoffVerifier",
    "VerifiedCorrelationReport",
]
