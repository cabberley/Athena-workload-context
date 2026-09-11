from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import (
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.correlation import (
    ConfidenceLevel,
    CorrelationReport,
    IncidentBoundCorrelationRequest,
    PublishedContextAuthority,
    PublishedRuntimeContextBinding,
    RootCauseCategory,
    validate_runtime_correlation_report,
)
from athena_context.contracts.models import AthenaBaseModel, Sha256Digest, UtcDateTime
from athena_context.contracts.operational_phase import VersionPinnedBlobReference

type GuidanceActionKind = Literal[
    "investigationCheck",
    "confirmationCheck",
    "manualResolutionOption",
    "rollbackConsideration",
    "recoveryValidation",
    "escalation",
]
type GuidanceNoRunbookReason = Literal[
    "noMatchingControl",
    "legacyManualFailoverRunbookInsufficient",
    "controlNotEffective",
    "reviewExpired",
    "unsupportedRunbookReference",
    "unresolvedOwner",
    "unresolvedGovernanceScope",
    "confidenceTooLow",
]
type GuidancePathScope = Literal[
    "notPathScoped",
    "anyGovernedPath",
    "specificPaths",
]
type GuidanceControlHealth = Literal[
    "effective",
    "degraded",
    "missing",
    "unknown",
    "expired",
    "notApplicable",
]

_CONFIDENCE_RANK: dict[ConfidenceLevel, int] = {
    "Unknown": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Confirmed": 4,
}


class _StrictGuidanceModel(AthenaBaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        populate_by_name=True,
        json_schema_extra={"additionalProperties": False},
    )

    def canonical_bytes(self) -> bytes:
        return (self.canonical_json() + "\n").encode("utf-8")


def _expected_digest(
    model: AthenaBaseModel,
    *,
    excluded_fields: set[str],
) -> str:
    return compute_artifact_digest(
        model.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude=excluded_fields,
        )
    )


def _sorted_unique(values: tuple[str, ...], name: str) -> tuple[str, ...]:
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        raise ValueError(f"{name} must be unique deterministic values")
    return values


def _is_visible_ascii(value: str) -> bool:
    return bool(value) and all("\x21" <= character <= "\x7e" for character in value)


class HttpsGuidanceRunbookReference(_StrictGuidanceModel):
    reference_kind: Literal["https"] = Field(alias="referenceKind")
    uri: str = Field(min_length=8, max_length=2048)

    @model_validator(mode="after")
    def validate_uri(self) -> HttpsGuidanceRunbookReference:
        try:
            parsed = urlsplit(self.uri)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("runbook URI must be one safe HTTPS origin path") from exc
        if (
            not _is_visible_ascii(self.uri)
            or not self.uri.startswith("https://")
            or parsed.scheme != "https"
            or not parsed.hostname
            or "%" in parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or port is not None
            and not 1 <= port <= 65535
            or parsed.query
            or parsed.fragment
            or "\\" in self.uri
        ):
            raise ValueError("runbook URI must be one safe HTTPS origin path")
        return self


class OpaqueGuidanceRunbookReference(_StrictGuidanceModel):
    reference_kind: Literal["opaque"] = Field(alias="referenceKind")
    opaque_ref: str = Field(
        alias="opaqueRef",
        min_length=3,
        max_length=512,
        pattern=r"^[\x21-\x7e]+$",
    )

    @model_validator(mode="after")
    def validate_reference(self) -> OpaqueGuidanceRunbookReference:
        if (
            re.fullmatch(
                r"urn:[A-Za-z0-9][A-Za-z0-9:._-]{1,508}",
                self.opaque_ref,
            )
            is None
            and re.fullmatch(
                r"synthetic://[A-Za-z0-9][A-Za-z0-9./_-]{1,498}",
                self.opaque_ref,
            )
            is None
        ):
            raise ValueError("opaque runbook reference must use an approved opaque scheme")
        return self


type GuidanceRunbookReference = Annotated[
    HttpsGuidanceRunbookReference | OpaqueGuidanceRunbookReference,
    Field(discriminator="reference_kind"),
]


class GuidanceControlProvenance(_StrictGuidanceModel):
    manifest_id: str = Field(alias="manifestId", min_length=1, max_length=128)
    manifest_version: str = Field(
        alias="manifestVersion",
        min_length=1,
        max_length=128,
    )
    profile_id: str = Field(alias="profileId", min_length=1, max_length=128)
    clause_path: str = Field(
        alias="clausePath",
        min_length=1,
        max_length=512,
        pattern=r"^/",
    )
    owner_ref: str = Field(alias="ownerRef", min_length=1, max_length=128)


class GuidanceApplicability(_StrictGuidanceModel):
    cause_categories: tuple[RootCauseCategory, ...] = Field(
        alias="causeCategories",
        min_length=1,
        max_length=16,
    )
    role_refs: tuple[str, ...] = Field(
        alias="roleRefs",
        min_length=1,
        max_length=64,
    )
    path_scope: GuidancePathScope = Field(alias="pathScope")
    path_ids: tuple[str, ...] = Field(
        default=(),
        alias="pathIds",
        max_length=64,
    )
    actions: tuple[GuidanceActionKind, ...] = Field(
        min_length=1,
        max_length=16,
    )
    minimum_confidence: ConfidenceLevel = Field(alias="minimumConfidence")

    @field_validator("cause_categories", "role_refs", "path_ids", "actions")
    @classmethod
    def validate_order(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(values, "applicability values")

    @field_validator("role_refs")
    @classmethod
    def validate_role_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is None for value in values
        ):
            raise ValueError("roleRefs must use exact bounded identifiers")
        return values

    @field_validator("path_ids")
    @classmethod
    def validate_path_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(r"path-[a-f0-9]{32}", value) is None for value in values):
            raise ValueError("pathIds must use exact governed path identifiers")
        return values

    @model_validator(mode="after")
    def validate_applicability(self) -> GuidanceApplicability:
        if (self.path_scope == "specificPaths") != bool(self.path_ids):
            raise ValueError("specificPaths must exactly match non-empty pathIds")
        prescriptive = {
            "manualResolutionOption",
            "rollbackConsideration",
        }.intersection(self.actions)
        if prescriptive and _CONFIDENCE_RANK[self.minimum_confidence] < _CONFIDENCE_RANK["High"]:
            raise ValueError("prescriptive guidance requires High or Confirmed confidence")
        if "unknown" in self.cause_categories and prescriptive:
            raise ValueError("unknown causes cannot authorize prescriptive guidance")
        return self


class PublishedRunbookGuidanceOption(_StrictGuidanceModel):
    schema_version: Literal["athena.wc027PublishedRunbookGuidanceOption.v1"] = Field(
        alias="schemaVersion"
    )
    option_id: str = Field(
        alias="optionId",
        pattern=r"^guidance-option-[a-f0-9]{32}$",
    )
    control_id: str = Field(alias="controlId", min_length=1, max_length=128)
    provenance: GuidanceControlProvenance
    applicability: GuidanceApplicability
    runbook_reference: GuidanceRunbookReference = Field(alias="runbookReference")
    control_health: GuidanceControlHealth = Field(alias="controlHealth")
    last_reviewed_at: UtcDateTime = Field(alias="lastReviewedAt")
    review_expires_at: UtcDateTime = Field(alias="reviewExpiresAt")
    execution_authorization_required: Literal[True] = Field(
        default=True,
        alias="executionAuthorizationRequired",
    )
    option_digest: Sha256Digest = Field(alias="optionDigest")

    @model_validator(mode="after")
    def validate_option(self) -> PublishedRunbookGuidanceOption:
        if self.last_reviewed_at >= self.review_expires_at:
            raise ValueError("guidance option review expiry must follow review")
        expected = _expected_digest(
            self,
            excluded_fields={"option_id", "option_digest"},
        )
        if self.option_digest != expected:
            raise ValueError("optionDigest does not bind the guidance option")
        if self.option_id != f"guidance-option-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("optionId is not digest-bound")
        return self


class PublishedGuidanceAuthority(_StrictGuidanceModel):
    schema_version: Literal["athena.wc027PublishedGuidanceAuthority.v1"] = Field(
        alias="schemaVersion"
    )
    authority_id: str = Field(
        alias="authorityId",
        pattern=r"^guidance-authority-[a-f0-9]{32}$",
    )
    workload_id: str = Field(alias="workloadId", min_length=1, max_length=128)
    manifest_id: str = Field(alias="manifestId", min_length=1, max_length=128)
    manifest_version: str = Field(
        alias="manifestVersion",
        min_length=1,
        max_length=128,
    )
    manifest_digest: Sha256Digest = Field(alias="manifestDigest")
    profile_id: str = Field(alias="profileId", min_length=1, max_length=128)
    resolved_profile_digest: Sha256Digest = Field(alias="resolvedProfileDigest")
    dependency_graph_digest: Sha256Digest = Field(alias="dependencyGraphDigest")
    context_binding_digest: Sha256Digest = Field(alias="contextBindingDigest")
    context_authority: PublishedContextAuthority = Field(alias="contextAuthority")
    context_authority_reference: VersionPinnedBlobReference = Field(
        alias="contextAuthorityReference"
    )
    publication_record_digest: Sha256Digest = Field(alias="publicationRecordDigest")
    audit_head_digest: Sha256Digest = Field(alias="auditHeadDigest")
    published_at: UtcDateTime = Field(alias="publishedAt")
    options: tuple[PublishedRunbookGuidanceOption, ...] = Field(
        default=(),
        max_length=256,
    )
    no_runbook_reasons: tuple[GuidanceNoRunbookReason, ...] = Field(
        default=(),
        alias="noRunbookReasons",
        max_length=16,
    )
    execution_authorization_required: Literal[True] = Field(
        default=True,
        alias="executionAuthorizationRequired",
    )
    authority_digest: Sha256Digest = Field(alias="authorityDigest")

    @model_validator(mode="after")
    def validate_authority(self) -> PublishedGuidanceAuthority:
        context = self.context_authority
        option_ids = tuple(item.option_id for item in self.options)
        _sorted_unique(self.no_runbook_reasons, "noRunbookReasons")
        if option_ids != tuple(sorted(option_ids)) or len(option_ids) != len(set(option_ids)):
            raise ValueError("guidance options must have unique deterministic IDs")
        if (
            context.workload_id != self.workload_id
            or context.manifest_id != self.manifest_id
            or context.manifest_version != self.manifest_version
            or context.manifest_digest != self.manifest_digest
            or context.profile_id != self.profile_id
            or context.resolved_profile_digest != self.resolved_profile_digest
            or context.dependency_graph_digest != self.dependency_graph_digest
            or self.publication_record_digest != context.publication_record_digest
            or self.audit_head_digest != context.audit_head_digest
            or self.published_at != context.published_at
            or self.context_authority_reference.name
            != f"context-authority/{context.authority_id}/authority.json"
            or self.context_authority_reference.content_digest
            != sha256_hex(context.canonical_bytes())
            or any(
                item.provenance.manifest_id != self.manifest_id
                or item.provenance.manifest_version != self.manifest_version
                or item.provenance.profile_id != self.profile_id
                or item.last_reviewed_at > self.published_at
                for item in self.options
            )
            or (not self.options and not self.no_runbook_reasons)
        ):
            raise ValueError("guidance authority does not bind the published context")
        expected = _expected_digest(
            self,
            excluded_fields={"authority_id", "authority_digest"},
        )
        if self.authority_digest != expected:
            raise ValueError("authorityDigest does not bind guidance authority")
        if self.authority_id != f"guidance-authority-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("authorityId is not digest-bound")
        return self


class SelectedRunbookGuidanceSelection(_StrictGuidanceModel):
    schema_version: Literal["athena.wc027GuidanceSelection.v1"] = Field(alias="schemaVersion")
    selection_kind: Literal["selectedRunbook"] = Field(alias="selectionKind")
    selection_id: str = Field(
        alias="selectionId",
        pattern=r"^guidance-selection-[a-f0-9]{32}$",
    )
    option_id: str = Field(alias="optionId")
    option_digest: Sha256Digest = Field(alias="optionDigest")
    runbook_reference: GuidanceRunbookReference = Field(alias="runbookReference")
    affected_role_ref: str = Field(alias="affectedRoleRef", min_length=1, max_length=128)
    cause_category: RootCauseCategory = Field(alias="causeCategory")
    affected_path_id: str | None = Field(
        default=None,
        alias="affectedPathId",
        min_length=1,
        max_length=128,
    )
    confidence: ConfidenceLevel
    requested_actions: tuple[GuidanceActionKind, ...] = Field(
        alias="requestedActions",
        min_length=1,
        max_length=16,
    )
    selection_digest: Sha256Digest = Field(alias="selectionDigest")

    @field_validator("requested_actions")
    @classmethod
    def validate_actions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(values, "requestedActions")

    @model_validator(mode="after")
    def validate_selection(self) -> SelectedRunbookGuidanceSelection:
        expected = _expected_digest(
            self,
            excluded_fields={"selection_id", "selection_digest"},
        )
        if self.selection_digest != expected:
            raise ValueError("selectionDigest does not bind guidance selection")
        if self.selection_id != f"guidance-selection-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("selectionId is not digest-bound")
        return self


class NoRunbookGuidanceSelection(_StrictGuidanceModel):
    schema_version: Literal["athena.wc027GuidanceSelection.v1"] = Field(alias="schemaVersion")
    selection_kind: Literal["noRunbook"] = Field(alias="selectionKind")
    selection_id: str = Field(
        alias="selectionId",
        pattern=r"^guidance-selection-[a-f0-9]{32}$",
    )
    reason: GuidanceNoRunbookReason
    affected_role_ref: str = Field(alias="affectedRoleRef", min_length=1, max_length=128)
    cause_category: RootCauseCategory = Field(alias="causeCategory")
    affected_path_id: str | None = Field(
        default=None,
        alias="affectedPathId",
        min_length=1,
        max_length=128,
    )
    confidence: ConfidenceLevel
    requested_actions: tuple[GuidanceActionKind, ...] = Field(
        alias="requestedActions",
        min_length=1,
        max_length=16,
    )
    selection_digest: Sha256Digest = Field(alias="selectionDigest")

    @field_validator("requested_actions")
    @classmethod
    def validate_actions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(values, "requestedActions")

    @model_validator(mode="after")
    def validate_selection(self) -> NoRunbookGuidanceSelection:
        expected = _expected_digest(
            self,
            excluded_fields={"selection_id", "selection_digest"},
        )
        if self.selection_digest != expected:
            raise ValueError("selectionDigest does not bind guidance selection")
        if self.selection_id != f"guidance-selection-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("selectionId is not digest-bound")
        return self


type GuidanceSelection = Annotated[
    SelectedRunbookGuidanceSelection | NoRunbookGuidanceSelection,
    Field(discriminator="selection_kind"),
]


class PublishedGuidanceAuthorityBindingAttestation(_StrictGuidanceModel):
    schema_version: Literal["athena.wc027PublishedGuidanceAuthorityBindingAttestation.v1"] = Field(
        alias="schemaVersion"
    )
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(alias="keyVaultKeyId", min_length=1, max_length=512)
    signed_preimage_digest: Sha256Digest = Field(alias="signedPreimageDigest")
    detached_signature: str = Field(
        alias="detachedSignature",
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=1,
        max_length=8192,
    )


def _option_failure_reasons(
    option: PublishedRunbookGuidanceOption,
    *,
    selection: GuidanceSelection,
    requested_actions: tuple[GuidanceActionKind, ...],
    evaluated_at: UtcDateTime,
) -> frozenset[GuidanceNoRunbookReason]:
    reasons: set[GuidanceNoRunbookReason] = set()
    applicability = option.applicability
    if option.control_health != "effective":
        reasons.add("controlNotEffective")
    if option.last_reviewed_at > evaluated_at or evaluated_at >= option.review_expires_at:
        reasons.add("reviewExpired")
    if (
        selection.cause_category not in applicability.cause_categories
        or selection.affected_role_ref not in applicability.role_refs
        or not set(requested_actions).issubset(applicability.actions)
        or (
            applicability.path_scope == "specificPaths"
            and selection.affected_path_id not in applicability.path_ids
        )
        or (applicability.path_scope == "notPathScoped" and selection.affected_path_id is not None)
        or (applicability.path_scope == "anyGovernedPath" and selection.affected_path_id is None)
    ):
        reasons.add("noMatchingControl")
    if _CONFIDENCE_RANK[selection.confidence] < _CONFIDENCE_RANK[applicability.minimum_confidence]:
        reasons.add("confidenceTooLow")
    return frozenset(reasons)


def _has_material_competing_cause(report: CorrelationReport) -> bool:
    return any(
        _CONFIDENCE_RANK[item.confidence] >= _CONFIDENCE_RANK["Medium"]
        for item in report.hypotheses[1:]
    )


class PublishedGuidanceAuthorityBinding(_StrictGuidanceModel):
    schema_version: Literal["athena.wc027PublishedGuidanceAuthorityBinding.v1"] = Field(
        alias="schemaVersion"
    )
    binding_id: str = Field(
        alias="bindingId",
        pattern=r"^guidance-binding-[a-f0-9]{32}$",
    )
    incident_bound_request: IncidentBoundCorrelationRequest = Field(alias="incidentBoundRequest")
    correlation_report: CorrelationReport = Field(alias="correlationReport")
    guidance_authority: PublishedGuidanceAuthority = Field(alias="guidanceAuthority")
    guidance_authority_reference: VersionPinnedBlobReference = Field(
        alias="guidanceAuthorityReference"
    )
    requested_actions: tuple[GuidanceActionKind, ...] = Field(
        alias="requestedActions",
        min_length=1,
        max_length=16,
    )
    evaluated_at: UtcDateTime = Field(alias="evaluatedAt")
    selection: GuidanceSelection
    binding_attestation: PublishedGuidanceAuthorityBindingAttestation = Field(
        alias="bindingAttestation"
    )
    binding_digest: Sha256Digest = Field(alias="bindingDigest")

    @field_validator("requested_actions")
    @classmethod
    def validate_actions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(values, "requestedActions")

    @model_validator(mode="after")
    def validate_binding(self) -> PublishedGuidanceAuthorityBinding:
        request = self.incident_bound_request.correlation_request
        report = self.correlation_report
        authority = self.guidance_authority
        context = request.context_binding
        if not isinstance(context, PublishedRuntimeContextBinding):
            raise ValueError("guidance authority requires published runtime context")
        if self.evaluated_at < report.as_of:
            raise ValueError("guidance evaluation must not precede the report")
        validate_runtime_correlation_report(
            report,
            request,
            evaluated_at=self.evaluated_at,
        )
        expected_name = f"guidance-authority/{authority.authority_id}/authority.json"
        if (
            self.evaluated_at < authority.published_at
            or authority.workload_id != context.workload_id
            or authority.manifest_id != context.manifest_id
            or authority.manifest_version != context.manifest_version
            or authority.manifest_digest != context.manifest_digest
            or authority.profile_id != context.profile_id
            or authority.resolved_profile_digest != context.resolved_profile_digest
            or authority.dependency_graph_digest != context.dependency_graph_digest
            or authority.context_binding_digest != context.binding_digest
            or authority.context_authority != context.publication_authority
            or authority.context_authority_reference != context.publication_authority_reference
            or self.guidance_authority_reference.name != expected_name
            or self.guidance_authority_reference.content_digest
            != sha256_hex(authority.canonical_bytes())
            or self.selection.affected_role_ref
            != self.incident_bound_request.incident_subject.incident_state.workload_role
            or self.selection.cause_category != report.hypotheses[0].category
            or self.selection.affected_path_id != report.hypotheses[0].affected_path_id
            or self.selection.confidence != report.hypotheses[0].confidence
            or self.selection.requested_actions != self.requested_actions
        ):
            raise ValueError("guidance binding does not match exact runtime inputs")
        option_failures = {
            item.option_id: _option_failure_reasons(
                item,
                selection=self.selection,
                requested_actions=self.requested_actions,
                evaluated_at=self.evaluated_at,
            )
            for item in authority.options
        }
        prescriptive = {
            "manualResolutionOption",
            "rollbackConsideration",
        }.intersection(self.requested_actions)
        prescriptive_allowed = not prescriptive or (
            self.selection.confidence == "Confirmed"
            and not _has_material_competing_cause(report)
            and not any(
                item.code == "competingCause" for item in report.hypotheses[0].contradictions
            )
        )
        if not prescriptive_allowed:
            option_failures = {
                option_id: frozenset((*failures, "confidenceTooLow"))
                for option_id, failures in option_failures.items()
            }
        applicable_options = {
            option_id for option_id, failures in option_failures.items() if not failures
        }
        if isinstance(self.selection, SelectedRunbookGuidanceSelection):
            option = next(
                (item for item in authority.options if item.option_id == self.selection.option_id),
                None,
            )
            if (
                option is None
                or option.option_digest != self.selection.option_digest
                or option.runbook_reference != self.selection.runbook_reference
                or option.option_id not in applicable_options
            ):
                raise ValueError("selected runbook is not applicable")
            if not prescriptive_allowed:
                raise ValueError("prescriptive runbook guidance is not authorized")
        else:
            valid_reasons = set(authority.no_runbook_reasons)
            for failures in option_failures.values():
                valid_reasons.update(failures)
            if applicable_options or self.selection.reason not in valid_reasons:
                raise ValueError("no-runbook selection reason is not justified")
        preimage = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"binding_id", "binding_digest", "binding_attestation"},
        )
        if self.binding_attestation.signed_preimage_digest != compute_artifact_digest(preimage):
            raise ValueError("guidance binding attestation is invalid")
        expected = _expected_digest(
            self,
            excluded_fields={"binding_id", "binding_digest"},
        )
        if self.binding_digest != expected:
            raise ValueError("bindingDigest does not bind guidance authority")
        if self.binding_id != f"guidance-binding-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("bindingId is not digest-bound")
        return self


__all__ = [
    "GuidanceActionKind",
    "GuidanceApplicability",
    "GuidanceControlHealth",
    "GuidanceControlProvenance",
    "GuidanceNoRunbookReason",
    "GuidancePathScope",
    "GuidanceRunbookReference",
    "GuidanceSelection",
    "HttpsGuidanceRunbookReference",
    "NoRunbookGuidanceSelection",
    "OpaqueGuidanceRunbookReference",
    "PublishedGuidanceAuthority",
    "PublishedGuidanceAuthorityBinding",
    "PublishedGuidanceAuthorityBindingAttestation",
    "PublishedRunbookGuidanceOption",
    "SelectedRunbookGuidanceSelection",
]
