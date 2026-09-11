from __future__ import annotations

import re
from collections.abc import Callable
from typing import Annotated, Literal, cast
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, field_validator, model_validator

from athena_context.contracts.common import (
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.correlation import (
    ConfidenceLevel,
    ContradictionCode,
    CorrelationReport,
    IncidentBoundCorrelationRequest,
    MissingEvidenceCode,
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
type GuidanceImpactSeverity = Literal[
    "none",
    "limited",
    "significant",
    "critical",
    "unknown",
]
type GuidanceImpactCode = Literal[
    "roleRecovered",
    "roleDegraded",
    "dataTierUnavailable",
    "ingressUnavailable",
    "unknownImpact",
]
type GuidanceTimelineKind = Literal[
    "healthTransition",
    "guestSignal",
    "networkEvidence",
    "platformHealth",
    "resourceChange",
    "recovery",
]
type GuidanceWithheldReason = Literal[
    "confidenceTooLow",
    "noRunbook",
    "competingCause",
    "missingEvidence",
    "authorityUnavailable",
]
type GuidanceTemplateCode = Literal[
    "confirmEffectiveRule",
    "confirmBackendHealth",
    "inspectGuestHealth",
    "inspectNetworkPath",
    "inspectRecentChange",
    "reviewApprovedManualOption",
    "reviewRollbackAuthority",
    "validateRecoverySignals",
    "escalateHumanReview",
]
type GuidanceTemplateParameterKind = Literal[
    "resourceId",
    "pathId",
    "evidenceId",
    "optionId",
    "roleRef",
]
type GuidanceRunbookLabelCode = Literal["approvedOperatorRunbook"]

INCIDENT_GUIDANCE_ALGORITHM_ID = "athena.wc027.incident-guidance.v1"
MAX_INCIDENT_GUIDANCE_BYTES = 64 * 1024

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
    version: str = Field(min_length=1, max_length=128)
    content_digest: Sha256Digest = Field(alias="contentDigest")

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
    version: str = Field(min_length=1, max_length=128)
    content_digest: Sha256Digest = Field(alias="contentDigest")

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
    manifest_id: str = Field(
        alias="manifestId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    manifest_version: str = Field(
        alias="manifestVersion",
        min_length=1,
        max_length=128,
    )
    profile_id: str = Field(
        alias="profileId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    clause_path: str = Field(
        alias="clausePath",
        min_length=1,
        max_length=512,
        pattern=r"^/[A-Za-z0-9._~/-]{1,511}$",
    )
    owner_ref: str = Field(
        alias="ownerRef",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )


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
    schema_version: Literal["athena.wc027PublishedRunbookGuidanceOption.v2"] = Field(
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
    schema_version: Literal["athena.wc027PublishedGuidanceAuthority.v2"] = Field(
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
    schema_version: Literal["athena.wc027GuidanceSelection.v2"] = Field(alias="schemaVersion")
    selection_kind: Literal["selectedRunbook"] = Field(alias="selectionKind")
    selection_id: str = Field(
        alias="selectionId",
        pattern=r"^guidance-selection-[a-f0-9]{32}$",
    )
    option_id: str = Field(
        alias="optionId",
        pattern=r"^guidance-option-[a-f0-9]{32}$",
    )
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
    schema_version: Literal["athena.wc027GuidanceSelection.v2"] = Field(alias="schemaVersion")
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
    schema_version: Literal["athena.wc027PublishedGuidanceAuthorityBindingAttestation.v2"] = Field(
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
    schema_version: Literal["athena.wc027PublishedGuidanceAuthorityBinding.v2"] = Field(
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


class IncidentGuidanceSourceBinding(_StrictGuidanceModel):
    source_id: str = Field(
        alias="sourceId",
        pattern=r"^guidance-source-[a-f0-9]{32}$",
    )
    incident_subject_id: str = Field(
        alias="incidentSubjectId",
        pattern=r"^incident-subject-[a-f0-9]{32}$",
    )
    incident_subject_digest: Sha256Digest = Field(alias="incidentSubjectDigest")
    incident_id: str = Field(alias="incidentId", pattern=r"^inc-[a-f0-9]{12}$")
    incident_revision: int = Field(alias="incidentRevision", ge=1)
    incident_state_digest: Sha256Digest = Field(alias="incidentStateDigest")
    incident_bound_request_id: str = Field(
        alias="incidentBoundRequestId",
        pattern=r"^incident-bound-request-[a-f0-9]{32}$",
    )
    incident_bound_request_digest: Sha256Digest = Field(alias="incidentBoundRequestDigest")
    correlation_report_id: str = Field(
        alias="correlationReportId",
        pattern=r"^report-[a-f0-9]{32}$",
    )
    correlation_report_digest: Sha256Digest = Field(alias="correlationReportDigest")
    correlation_request_digest: Sha256Digest = Field(alias="correlationRequestDigest")
    transition_digest: Sha256Digest = Field(alias="transitionDigest")
    rule_catalog_digest: Sha256Digest = Field(alias="ruleCatalogDigest")
    input_inventory_digest: Sha256Digest = Field(alias="inputInventoryDigest")
    guidance_authority_id: str = Field(
        alias="guidanceAuthorityId",
        pattern=r"^guidance-authority-[a-f0-9]{32}$",
    )
    guidance_authority_digest: Sha256Digest = Field(alias="guidanceAuthorityDigest")
    guidance_binding_id: str = Field(
        alias="guidanceBindingId",
        pattern=r"^guidance-binding-[a-f0-9]{32}$",
    )
    guidance_binding_digest: Sha256Digest = Field(alias="guidanceBindingDigest")
    selection_kind: Literal["selectedRunbook", "noRunbook"] = Field(alias="selectionKind")
    selected_option_id: str | None = Field(
        default=None,
        alias="selectedOptionId",
        pattern=r"^guidance-option-[a-f0-9]{32}$",
    )
    no_runbook_reason: GuidanceNoRunbookReason | None = Field(
        default=None,
        alias="noRunbookReason",
    )
    source_digest: Sha256Digest = Field(alias="sourceDigest")

    @model_validator(mode="after")
    def validate_source(self) -> IncidentGuidanceSourceBinding:
        if self.selection_kind == "selectedRunbook":
            if self.selected_option_id is None or self.no_runbook_reason is not None:
                raise ValueError("selected source requires exactly one option")
        elif self.selected_option_id is not None or self.no_runbook_reason is None:
            raise ValueError("no-runbook source requires exactly one reason")
        expected = _expected_digest(self, excluded_fields={"source_id", "source_digest"})
        if self.source_digest != expected:
            raise ValueError("sourceDigest does not bind guidance source")
        if self.source_id != f"guidance-source-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("sourceId is not digest-bound")
        return self


class GuidanceAffectedRoleImpact(_StrictGuidanceModel):
    role_ref: str = Field(
        alias="roleRef",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    profile_id: str = Field(
        alias="profileId",
        min_length=1,
        max_length=128,
    )
    impact_severity: GuidanceImpactSeverity = Field(alias="impactSeverity")
    impact_code: GuidanceImpactCode = Field(alias="impactCode")


class GuidanceTimelineEntry(_StrictGuidanceModel):
    entry_id: str = Field(
        alias="entryId",
        pattern=r"^guidance-timeline-[a-f0-9]{32}$",
    )
    timeline_kind: GuidanceTimelineKind = Field(alias="timelineKind")
    observed_start: UtcDateTime = Field(alias="observedStart")
    observed_end: UtcDateTime = Field(alias="observedEnd")
    summary_code: str = Field(
        alias="summaryCode",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    evidence_ids: tuple[str, ...] = Field(
        alias="evidenceIds",
        min_length=1,
        max_length=1,
    )
    entry_digest: Sha256Digest = Field(alias="entryDigest")

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(values, "evidenceIds")

    @model_validator(mode="after")
    def validate_entry(self) -> GuidanceTimelineEntry:
        if self.observed_start > self.observed_end:
            raise ValueError("timeline interval is invalid")
        expected = _expected_digest(
            self,
            excluded_fields={"entry_id", "entry_digest"},
        )
        if self.entry_digest != expected:
            raise ValueError("entryDigest does not bind timeline entry")
        if self.entry_id != f"guidance-timeline-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("entryId is not digest-bound")
        return self


class GuidanceHypothesisSummary(_StrictGuidanceModel):
    rank: int = Field(ge=1, le=64)
    hypothesis_id: str = Field(
        alias="hypothesisId",
        pattern=r"^hyp-[a-f0-9]{32}$",
    )
    hypothesis_digest: Sha256Digest = Field(alias="hypothesisDigest")
    category: RootCauseCategory
    confidence: ConfidenceLevel
    cause_resource_digest: Sha256Digest | None = Field(
        default=None,
        alias="causeResourceDigest",
    )
    affected_path_id: str | None = Field(
        default=None,
        alias="affectedPathId",
        min_length=1,
        max_length=128,
    )
    supporting_evidence_ids: tuple[str, ...] = Field(
        alias="supportingEvidenceIds",
        max_length=4,
    )
    supporting_evidence_count: int = Field(
        alias="supportingEvidenceCount",
        ge=0,
        le=128,
    )
    supporting_evidence_digest: Sha256Digest = Field(alias="supportingEvidenceDigest")
    contradiction_codes: tuple[ContradictionCode, ...] = Field(
        alias="contradictionCodes",
        max_length=64,
    )
    missing_evidence_codes: tuple[MissingEvidenceCode, ...] = Field(
        alias="missingEvidenceCodes",
        max_length=64,
    )

    @field_validator(
        "supporting_evidence_ids",
        "contradiction_codes",
        "missing_evidence_codes",
    )
    @classmethod
    def validate_order(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = _sorted_unique(values, "hypothesis projection values")
        if any(len(value) > 128 or not _is_visible_ascii(value) for value in normalized):
            raise ValueError("hypothesis projection values are invalid")
        return normalized


class GuidanceTemplateParameter(_StrictGuidanceModel):
    parameter_kind: GuidanceTemplateParameterKind = Field(alias="parameterKind")
    value: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_value(self) -> GuidanceTemplateParameter:
        patterns = {
            "resourceId": (
                r"^/subscriptions/[a-f0-9-]{36}/resourcegroups/"
                r"[a-z0-9_().-]{1,90}/providers/[a-z0-9.]+"
                r"(?:/[a-z0-9.()_-]+/[a-z0-9.()_-]+)+$"
            ),
            "pathId": r"^path-[a-f0-9]{32}$",
            "evidenceId": (
                r"^(?:obs-[a-f0-9]{32}|coverage-[a-f0-9]{32}|"
                r"chg-[a-f0-9]{12})$"
            ),
            "optionId": r"^guidance-option-[a-f0-9]{32}$",
            "roleRef": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
        }
        if re.fullmatch(patterns[self.parameter_kind], self.value) is None:
            raise ValueError("guidance template parameter is invalid")
        return self


class GuidanceStep(_StrictGuidanceModel):
    step_id: str = Field(
        alias="stepId",
        pattern=r"^guidance-step-[a-f0-9]{32}$",
    )
    action_kind: GuidanceActionKind = Field(alias="actionKind")
    template_code: GuidanceTemplateCode = Field(alias="templateCode")
    parameters: tuple[GuidanceTemplateParameter, ...] = Field(
        default=(),
        max_length=16,
    )
    evidence_ids: tuple[str, ...] = Field(
        default=(),
        alias="evidenceIds",
        max_length=32,
    )
    provenance_clause_ref: str | None = Field(
        default=None,
        alias="provenanceClauseRef",
        pattern=r"^/[A-Za-z0-9._~/-]{1,511}$",
    )
    option_id: str | None = Field(
        default=None,
        alias="optionId",
        pattern=r"^guidance-option-[a-f0-9]{32}$",
    )
    read_only: bool = Field(alias="readOnly")
    requires_authorization: bool = Field(alias="requiresAuthorization")
    step_digest: Sha256Digest = Field(alias="stepDigest")

    @field_validator("evidence_ids")
    @classmethod
    def validate_order(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(values, "guidance step references")

    @field_validator("parameters")
    @classmethod
    def validate_parameters(
        cls,
        values: tuple[GuidanceTemplateParameter, ...],
    ) -> tuple[GuidanceTemplateParameter, ...]:
        keys = tuple((item.parameter_kind, item.value) for item in values)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("guidance parameters must be unique deterministic values")
        kinds = tuple(item.parameter_kind for item in values)
        if len(kinds) != len(set(kinds)):
            raise ValueError("guidance templates allow one parameter per kind")
        return values

    @model_validator(mode="after")
    def validate_step(self) -> GuidanceStep:
        expected_action = {
            "confirmEffectiveRule": "confirmationCheck",
            "confirmBackendHealth": "confirmationCheck",
            "inspectGuestHealth": "investigationCheck",
            "inspectNetworkPath": "investigationCheck",
            "inspectRecentChange": "investigationCheck",
            "reviewApprovedManualOption": "manualResolutionOption",
            "reviewRollbackAuthority": "rollbackConsideration",
            "validateRecoverySignals": "recoveryValidation",
            "escalateHumanReview": "escalation",
        }[self.template_code]
        if self.action_kind != expected_action:
            raise ValueError("guidance template does not match action kind")
        allowed_parameter_kinds = {
            "confirmEffectiveRule": {"resourceId", "pathId", "evidenceId"},
            "confirmBackendHealth": {"resourceId", "pathId", "evidenceId"},
            "inspectGuestHealth": {"resourceId", "evidenceId", "roleRef"},
            "inspectNetworkPath": {
                "resourceId",
                "pathId",
                "evidenceId",
                "roleRef",
            },
            "inspectRecentChange": {"resourceId", "evidenceId"},
            "reviewApprovedManualOption": {"optionId", "roleRef", "pathId"},
            "reviewRollbackAuthority": {"optionId", "roleRef"},
            "validateRecoverySignals": {
                "resourceId",
                "pathId",
                "evidenceId",
            },
            "escalateHumanReview": {"roleRef", "evidenceId"},
        }[self.template_code]
        if any(item.parameter_kind not in allowed_parameter_kinds for item in self.parameters):
            raise ValueError("guidance parameter is not allowed for the template")
        prescriptive = self.action_kind in {
            "manualResolutionOption",
            "rollbackConsideration",
        }
        if (
            prescriptive
            and (
                self.read_only
                or not self.requires_authorization
                or self.option_id is None
                or self.provenance_clause_ref is None
            )
        ) or (
            not prescriptive
            and (
                not self.read_only
                or self.requires_authorization
                or self.option_id is not None
                or self.provenance_clause_ref is not None
            )
        ):
            raise ValueError("guidance step action flags are invalid")
        expected = _expected_digest(
            self,
            excluded_fields={"step_id", "step_digest"},
        )
        if self.step_digest != expected:
            raise ValueError("stepDigest does not bind guidance step")
        if self.step_id != f"guidance-step-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("stepId is not digest-bound")
        return self


class GuidanceRunbookLink(_StrictGuidanceModel):
    link_id: str = Field(
        alias="linkId",
        pattern=r"^guidance-link-[a-f0-9]{32}$",
    )
    option_id: str = Field(alias="optionId")
    option_digest: Sha256Digest = Field(alias="optionDigest")
    runbook_reference: GuidanceRunbookReference = Field(alias="runbookReference")
    label_code: GuidanceRunbookLabelCode = Field(alias="labelCode")
    reference_only: Literal[True] = Field(default=True, alias="referenceOnly")
    link_digest: Sha256Digest = Field(alias="linkDigest")

    @model_validator(mode="after")
    def validate_link(self) -> GuidanceRunbookLink:
        expected = _expected_digest(
            self,
            excluded_fields={"link_id", "link_digest"},
        )
        if self.link_digest != expected:
            raise ValueError("linkDigest does not bind guidance link")
        if self.link_id != f"guidance-link-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("linkId is not digest-bound")
        return self


class GuidanceLegality(_StrictGuidanceModel):
    confidence: ConfidenceLevel
    selection_kind: Literal["selectedRunbook", "noRunbook"] = Field(alias="selectionKind")
    manual_actions_authorized: bool = Field(alias="manualActionsAuthorized")
    rollback_authorized: bool = Field(alias="rollbackAuthorized")
    runbook_reference_authorized: bool = Field(alias="runbookReferenceAuthorized")
    execution_authorization_required: Literal[True] = Field(
        default=True,
        alias="executionAuthorizationRequired",
    )
    withheld_reasons: tuple[GuidanceWithheldReason, ...] = Field(
        default=(),
        alias="withheldReasons",
        max_length=16,
    )

    @field_validator("withheld_reasons")
    @classmethod
    def validate_reasons(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(values, "withheldReasons")

    @model_validator(mode="after")
    def validate_legality(self) -> GuidanceLegality:
        if self.selection_kind == "noRunbook" and any(
            (
                self.manual_actions_authorized,
                self.rollback_authorized,
                self.runbook_reference_authorized,
            )
        ):
            raise ValueError("no-runbook guidance cannot authorize runbook actions")
        if (
            self.manual_actions_authorized or self.rollback_authorized
        ) and self.confidence != "Confirmed":
            raise ValueError("manual and rollback actions require Confirmed confidence")
        if (
            self.runbook_reference_authorized
            and _CONFIDENCE_RANK[self.confidence] < _CONFIDENCE_RANK["High"]
        ):
            raise ValueError("runbook references require High or Confirmed confidence")
        return self


class IncidentGuidance(_StrictGuidanceModel):
    schema_version: Literal["athena.wc027IncidentGuidance.v1"] = Field(alias="schemaVersion")
    guidance_id: str = Field(
        alias="guidanceId",
        pattern=r"^incident-guidance-[a-f0-9]{32}$",
    )
    algorithm_id: Literal["athena.wc027.incident-guidance.v1"] = Field(alias="algorithmId")
    generated_at: UtcDateTime = Field(alias="generatedAt")
    source_binding: IncidentGuidanceSourceBinding = Field(alias="sourceBinding")
    affected_role_impact: GuidanceAffectedRoleImpact = Field(alias="affectedRoleImpact")
    timeline: tuple[GuidanceTimelineEntry, ...] = Field(min_length=1, max_length=128)
    hypotheses: tuple[GuidanceHypothesisSummary, ...] = Field(
        min_length=1,
        max_length=64,
    )
    confirmation_checks: tuple[GuidanceStep, ...] = Field(
        alias="confirmationChecks",
        max_length=64,
    )
    investigation_steps: tuple[GuidanceStep, ...] = Field(
        alias="investigationSteps",
        max_length=64,
    )
    safe_manual_options: tuple[GuidanceStep, ...] = Field(
        alias="safeManualOptions",
        max_length=32,
    )
    rollback_considerations: tuple[GuidanceStep, ...] = Field(
        alias="rollbackConsiderations",
        max_length=32,
    )
    recovery_validation: tuple[GuidanceStep, ...] = Field(
        alias="recoveryValidation",
        max_length=32,
    )
    escalation: tuple[GuidanceStep, ...] = Field(max_length=32)
    runbook_links: tuple[GuidanceRunbookLink, ...] = Field(
        alias="runbookLinks",
        max_length=16,
    )
    missing_evidence: tuple[MissingEvidenceCode, ...] = Field(
        alias="missingEvidence",
        max_length=64,
    )
    legality: GuidanceLegality
    no_auto_remediation: Literal[True] = Field(
        default=True,
        alias="noAutoRemediation",
    )
    guidance_digest: Sha256Digest = Field(alias="guidanceDigest")

    @field_validator("missing_evidence")
    @classmethod
    def validate_missing(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return _sorted_unique(values, "missingEvidence")

    @model_validator(mode="after")
    def validate_guidance(self) -> IncidentGuidance:
        if tuple(item.rank for item in self.hypotheses) != tuple(
            range(1, len(self.hypotheses) + 1)
        ):
            raise ValueError("guidance hypotheses require contiguous ranks")
        hypothesis_ids = tuple(item.hypothesis_id for item in self.hypotheses)
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("guidance hypothesis IDs must be unique")
        if tuple((item.observed_start, item.entry_id) for item in self.timeline) != tuple(
            sorted((item.observed_start, item.entry_id) for item in self.timeline)
        ):
            raise ValueError("guidance timeline must be deterministically ordered")
        timeline_ids = tuple(item.entry_id for item in self.timeline)
        if len(timeline_ids) != len(set(timeline_ids)):
            raise ValueError("guidance timeline entry IDs must be unique")
        for collection in (
            self.confirmation_checks,
            self.investigation_steps,
            self.safe_manual_options,
            self.rollback_considerations,
            self.recovery_validation,
            self.escalation,
        ):
            ids = tuple(item.step_id for item in collection)
            if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
                raise ValueError("guidance steps must have unique deterministic IDs")
        expected_actions = (
            (self.confirmation_checks, "confirmationCheck"),
            (self.investigation_steps, "investigationCheck"),
            (self.safe_manual_options, "manualResolutionOption"),
            (self.rollback_considerations, "rollbackConsideration"),
            (self.recovery_validation, "recoveryValidation"),
            (self.escalation, "escalation"),
        )
        if any(
            item.action_kind != expected_action
            for collection, expected_action in expected_actions
            for item in collection
        ):
            raise ValueError("guidance step is in the wrong action collection")
        link_ids = tuple(item.link_id for item in self.runbook_links)
        if link_ids != tuple(sorted(link_ids)) or len(link_ids) != len(set(link_ids)):
            raise ValueError("runbook links must have unique deterministic IDs")
        confidence = self.hypotheses[0].confidence
        if self.legality.confidence != confidence:
            raise ValueError("guidance legality must match top hypothesis confidence")
        if self.legality.selection_kind != self.source_binding.selection_kind:
            raise ValueError("guidance legality must match source selection")
        if any(
            step.option_id != self.source_binding.selected_option_id
            for step in (
                *self.safe_manual_options,
                *self.rollback_considerations,
            )
        ):
            raise ValueError("guidance option must match source selection")
        if any(
            link.option_id != self.source_binding.selected_option_id for link in self.runbook_links
        ) or any(
            parameter.value != self.source_binding.selected_option_id
            for collection in (
                self.confirmation_checks,
                self.investigation_steps,
                self.safe_manual_options,
                self.rollback_considerations,
                self.recovery_validation,
                self.escalation,
            )
            for step in collection
            for parameter in step.parameters
            if parameter.parameter_kind == "optionId"
        ):
            raise ValueError("guidance option reference must match source selection")
        if confidence in {"Unknown", "Low", "Medium"} and (
            self.safe_manual_options or self.rollback_considerations or self.runbook_links
        ):
            raise ValueError("lower confidence guidance must remain read-only")
        if confidence == "High" and (self.safe_manual_options or self.rollback_considerations):
            raise ValueError("High confidence guidance requires confirmation first")
        if (
            (self.safe_manual_options and not self.legality.manual_actions_authorized)
            or (self.rollback_considerations and not self.legality.rollback_authorized)
            or (self.runbook_links and not self.legality.runbook_reference_authorized)
        ):
            raise ValueError("guidance content exceeds its authorized legality")
        if self.legality.selection_kind == "noRunbook" and (
            self.safe_manual_options or self.rollback_considerations or self.runbook_links
        ):
            raise ValueError("no-runbook guidance cannot contain runbook actions")
        if self.legality.selection_kind == "noRunbook" and not self.escalation:
            raise ValueError("no-runbook guidance requires escalation")
        if confidence in {"Unknown", "Low", "Medium"} and (
            not self.confirmation_checks or not self.investigation_steps
        ):
            raise ValueError("lower confidence guidance requires investigation checks")
        expected = _expected_digest(
            self,
            excluded_fields={"guidance_id", "guidance_digest"},
        )
        if self.guidance_digest != expected:
            raise ValueError("guidanceDigest does not bind incident guidance")
        if self.guidance_id != f"incident-guidance-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("guidanceId is not digest-bound")
        if len(self.canonical_bytes()) > MAX_INCIDENT_GUIDANCE_BYTES:
            raise ValueError("incident guidance exceeds its canonical byte budget")
        return self


class IncidentGuidanceAttestation(_StrictGuidanceModel):
    schema_version: Literal["athena.wc027IncidentGuidanceAttestation.v1"] = Field(
        alias="schemaVersion"
    )
    guidance_id: str = Field(alias="guidanceId")
    guidance_digest: Sha256Digest = Field(alias="guidanceDigest")
    signature_algorithm: Literal["RS256"] = Field(alias="signatureAlgorithm")
    key_vault_key_id: str = Field(alias="keyVaultKeyId", min_length=1, max_length=512)
    signed_preimage_digest: Sha256Digest = Field(alias="signedPreimageDigest")
    detached_signature: str = Field(
        alias="detachedSignature",
        pattern=r"^[A-Za-z0-9_-]+$",
        min_length=1,
        max_length=8192,
    )


class IncidentGuidanceAssetReference(_StrictGuidanceModel):
    schema_version: Literal["athena.wc027IncidentGuidanceAssetReference.v1"] = Field(
        alias="schemaVersion"
    )
    reference_id: str = Field(
        alias="referenceId",
        pattern=r"^guidance-asset-[a-f0-9]{32}$",
    )
    incident_id: str = Field(alias="incidentId")
    incident_state_digest: Sha256Digest = Field(alias="incidentStateDigest")
    guidance_id: str = Field(alias="guidanceId")
    guidance_digest: Sha256Digest = Field(alias="guidanceDigest")
    guidance_reference: VersionPinnedBlobReference = Field(alias="guidanceReference")
    attestation_reference: VersionPinnedBlobReference = Field(alias="attestationReference")
    reference_digest: Sha256Digest = Field(alias="referenceDigest")

    @model_validator(mode="after")
    def validate_reference(self) -> IncidentGuidanceAssetReference:
        state_suffix = self.incident_state_digest.removeprefix("sha256:")
        prefix = f"incidents/{self.incident_id}/versions/{state_suffix}/guidance/{self.guidance_id}"
        if (
            self.guidance_reference.name != f"{prefix}/guidance.json"
            or self.attestation_reference.name != f"{prefix}/attestation.json"
        ):
            raise ValueError("guidance asset paths are invalid")
        expected = _expected_digest(
            self,
            excluded_fields={"reference_id", "reference_digest"},
        )
        if self.reference_digest != expected:
            raise ValueError("referenceDigest does not bind guidance assets")
        if self.reference_id != f"guidance-asset-{expected.removeprefix('sha256:')[:32]}":
            raise ValueError("referenceId is not digest-bound")
        return self


def build_incident_guidance_source_binding(
    binding: PublishedGuidanceAuthorityBinding,
) -> IncidentGuidanceSourceBinding:
    incident_request = binding.incident_bound_request
    subject = incident_request.incident_subject
    report = binding.correlation_report
    selection = binding.selection
    payload: dict[str, object] = {
        "incidentSubjectId": subject.subject_id,
        "incidentSubjectDigest": subject.subject_digest,
        "incidentId": subject.incident_id,
        "incidentRevision": subject.incident_revision,
        "incidentStateDigest": subject.incident_state_digest,
        "incidentBoundRequestId": incident_request.request_id,
        "incidentBoundRequestDigest": incident_request.binding_digest,
        "correlationReportId": report.report_id,
        "correlationReportDigest": report.report_digest,
        "correlationRequestDigest": report.request_digest,
        "transitionDigest": report.transition_digest,
        "ruleCatalogDigest": report.rule_catalog_digest,
        "inputInventoryDigest": report.input_inventory_digest,
        "guidanceAuthorityId": binding.guidance_authority.authority_id,
        "guidanceAuthorityDigest": binding.guidance_authority.authority_digest,
        "guidanceBindingId": binding.binding_id,
        "guidanceBindingDigest": binding.binding_digest,
        "selectionKind": selection.selection_kind,
        "selectedOptionId": (
            selection.option_id if isinstance(selection, SelectedRunbookGuidanceSelection) else None
        ),
        "noRunbookReason": (
            selection.reason if isinstance(selection, NoRunbookGuidanceSelection) else None
        ),
    }
    digest = compute_artifact_digest(
        {key: value for key, value in payload.items() if value is not None}
    )
    return IncidentGuidanceSourceBinding.model_validate(
        {
            **payload,
            "sourceId": (f"guidance-source-{digest.removeprefix('sha256:')[:32]}"),
            "sourceDigest": digest,
        }
    )


def project_guidance_hypotheses(
    report: CorrelationReport,
) -> tuple[GuidanceHypothesisSummary, ...]:
    projected: list[GuidanceHypothesisSummary] = []
    for item in report.hypotheses:
        evidence_ids = tuple(sorted(evidence.evidence_id for evidence in item.supporting_evidence))
        projected.append(
            GuidanceHypothesisSummary(
                rank=item.rank,
                hypothesisId=item.hypothesis_id,
                hypothesisDigest=item.hypothesis_digest,
                category=item.category,
                confidence=item.confidence,
                causeResourceDigest=(
                    sha256_hex(item.cause_resource_id.encode("utf-8"))
                    if item.cause_resource_id is not None
                    else None
                ),
                affectedPathId=item.affected_path_id,
                supportingEvidenceIds=evidence_ids[:4],
                supportingEvidenceCount=len(evidence_ids),
                supportingEvidenceDigest=compute_artifact_digest(list(evidence_ids)),
                contradictionCodes=tuple(
                    sorted({contradiction.code for contradiction in item.contradictions})
                ),
                missingEvidenceCodes=tuple(
                    sorted({evidence.code for evidence in item.missing_evidence})
                ),
            )
        )
    return tuple(projected)


def build_guidance_legality(
    binding: PublishedGuidanceAuthorityBinding,
) -> GuidanceLegality:
    top = binding.correlation_report.hypotheses[0]
    selected = isinstance(
        binding.selection,
        SelectedRunbookGuidanceSelection,
    )
    competing = _has_material_competing_cause(binding.correlation_report) or any(
        item.code == "competingCause" for item in top.contradictions
    )
    manual_authorized = bool(
        selected
        and top.confidence == "Confirmed"
        and not competing
        and "manualResolutionOption" in binding.requested_actions
    )
    rollback_authorized = bool(
        selected
        and top.confidence == "Confirmed"
        and not competing
        and "rollbackConsideration" in binding.requested_actions
    )
    runbook_authorized = bool(
        selected and _CONFIDENCE_RANK[top.confidence] >= _CONFIDENCE_RANK["High"]
    )
    withheld: set[GuidanceWithheldReason] = set()
    if not selected:
        withheld.add("noRunbook")
    if _CONFIDENCE_RANK[top.confidence] < _CONFIDENCE_RANK["Confirmed"]:
        withheld.add("confidenceTooLow")
    if competing:
        withheld.add("competingCause")
    if top.missing_evidence:
        withheld.add("missingEvidence")
    return GuidanceLegality(
        confidence=top.confidence,
        selectionKind=binding.selection.selection_kind,
        manualActionsAuthorized=manual_authorized,
        rollbackAuthorized=rollback_authorized,
        runbookReferenceAuthorized=runbook_authorized,
        executionAuthorizationRequired=True,
        withheldReasons=tuple(sorted(withheld)),
    )


def guidance_timeline_kind_for_evidence(
    evidence_id: str,
    binding: PublishedGuidanceAuthorityBinding,
) -> GuidanceTimelineKind:
    request = binding.incident_bound_request.correlation_request
    transition_ids = {
        item.evidence_id
        for item in (
            *request.incident_anchor.previous_state_evidence,
            *request.incident_anchor.current_state_evidence,
        )
    }
    if evidence_id in transition_ids:
        return "healthTransition"
    observation = next(
        (
            item
            for item in request.monitoring_bundle.observations
            if item.observation_id == evidence_id
        ),
        None,
    )
    if observation is not None:
        kind = observation.observation_kind
        state = getattr(observation, "state", None)
        status = getattr(observation, "status", None)
        if state == "recovered" or status == "recovered":
            return "recovery"
        if kind == "guestSignal":
            return "guestSignal"
        if kind in {"networkFlow", "connectionMonitor", "endpointHealth"}:
            return "networkEvidence"
        return "platformHealth"
    if any(item.evidence.evidence_id == evidence_id for item in request.change_artifacts):
        return "resourceChange"
    raise ValueError("timeline evidence is not present in the exact request")


def build_guidance_affected_role_impact(
    binding: PublishedGuidanceAuthorityBinding,
) -> GuidanceAffectedRoleImpact:
    state = binding.incident_bound_request.incident_subject.incident_state
    severity = cast(
        GuidanceImpactSeverity,
        {
            "normal": "none",
            "warning": "limited",
            "critical": "critical",
            "unknown": "unknown",
        }[state.availability],
    )
    impact_code: GuidanceImpactCode
    if state.lifecycle == "resolved":
        impact_code = "roleRecovered"
    elif state.availability == "unknown":
        impact_code = "unknownImpact"
    elif state.availability == "warning":
        impact_code = "roleDegraded"
    elif (
        state.availability == "critical"
        and state.workload_role == "database-primary"
        and state.blast_radius in {"data-tier", "whole-workload"}
    ):
        impact_code = "dataTierUnavailable"
    elif (
        state.availability == "critical"
        and state.workload_role == "load-balancer"
        and state.blast_radius == "ingress-edge"
    ):
        impact_code = "ingressUnavailable"
    elif state.availability == "critical":
        impact_code = "roleDegraded"
    else:
        impact_code = "unknownImpact"
    return GuidanceAffectedRoleImpact(
        roleRef=state.workload_role,
        profileId=binding.guidance_authority.profile_id,
        impactSeverity=severity,
        impactCode=impact_code,
    )


def validate_incident_guidance_binding(
    guidance: IncidentGuidance,
    binding: PublishedGuidanceAuthorityBinding,
    *,
    trusted_binding_key_id: str,
    binding_signature_verifier: Callable[[bytes, str], bool],
) -> None:
    guidance = IncidentGuidance.model_validate_json(guidance.model_dump_json(by_alias=True))
    binding = PublishedGuidanceAuthorityBinding.model_validate_json(
        binding.model_dump_json(by_alias=True)
    )
    binding_preimage = binding.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={
            "binding_id",
            "binding_digest",
            "binding_attestation",
        },
    )
    binding_preimage_bytes = canonicalize_json(binding_preimage).encode("utf-8")
    if (
        binding.binding_attestation.key_vault_key_id != trusted_binding_key_id
        or binding.binding_attestation.signed_preimage_digest
        != compute_artifact_digest(binding_preimage)
        or binding_signature_verifier(
            binding_preimage_bytes,
            binding.binding_attestation.detached_signature,
        )
        is not True
    ):
        raise ValueError("guidance authority binding signature is invalid")
    if guidance.source_binding != build_incident_guidance_source_binding(binding):
        raise ValueError("incident guidance source binding is invalid")
    if guidance.generated_at != binding.evaluated_at:
        raise ValueError("incident guidance generation time is invalid")
    if guidance.hypotheses != project_guidance_hypotheses(binding.correlation_report):
        raise ValueError("incident guidance hypotheses do not match the report")
    if guidance.affected_role_impact != build_guidance_affected_role_impact(binding):
        raise ValueError("incident guidance role impact is invalid")
    if guidance.legality != build_guidance_legality(binding):
        raise ValueError("incident guidance legality is invalid")
    citation_by_id = {
        item.evidence_id: item
        for item in binding.incident_bound_request.correlation_request.evidence_index
    }
    for entry in guidance.timeline:
        citation = citation_by_id.get(entry.evidence_ids[0])
        if (
            citation is None
            or entry.observed_start != citation.observed_start
            or entry.observed_end != citation.observed_end
            or entry.summary_code != citation.summary_code
            or entry.timeline_kind
            != guidance_timeline_kind_for_evidence(entry.evidence_ids[0], binding)
        ):
            raise ValueError("incident guidance timeline claim is invalid")
    allowed_evidence_ids = {
        item.evidence_id
        for item in binding.incident_bound_request.correlation_request.evidence_index
    }
    cited_ids = {evidence_id for entry in guidance.timeline for evidence_id in entry.evidence_ids}
    cited_ids.update(
        evidence_id
        for collection in (
            guidance.confirmation_checks,
            guidance.investigation_steps,
            guidance.safe_manual_options,
            guidance.rollback_considerations,
            guidance.recovery_validation,
            guidance.escalation,
        )
        for step in collection
        for evidence_id in step.evidence_ids
    )
    if not cited_ids.issubset(allowed_evidence_ids):
        raise ValueError("incident guidance cites evidence outside the request")
    request = binding.incident_bound_request.correlation_request
    selected_path_id = binding.selection.affected_path_id
    selected_path = next(
        (
            path
            for path in request.context_binding.dependency_paths
            if path.path_id == selected_path_id
        ),
        None,
    )
    selected_resource_ids = (
        set(selected_path.resource_ids)
        if selected_path is not None
        else {request.incident_anchor.affected_resource_id}
    )
    if binding.correlation_report.hypotheses[0].cause_resource_id is not None:
        selected_resource_ids.add(binding.correlation_report.hypotheses[0].cause_resource_id)
    selected_option_id = (
        binding.selection.option_id
        if isinstance(
            binding.selection,
            SelectedRunbookGuidanceSelection,
        )
        else None
    )
    for collection in (
        guidance.confirmation_checks,
        guidance.investigation_steps,
        guidance.safe_manual_options,
        guidance.rollback_considerations,
        guidance.recovery_validation,
        guidance.escalation,
    ):
        for step in collection:
            for parameter in step.parameters:
                valid = {
                    "resourceId": parameter.value in selected_resource_ids,
                    "pathId": parameter.value == selected_path_id,
                    "evidenceId": (
                        parameter.value in allowed_evidence_ids
                        and parameter.value in step.evidence_ids
                    ),
                    "optionId": (
                        parameter.value == selected_option_id and parameter.value == step.option_id
                    ),
                    "roleRef": (parameter.value == binding.selection.affected_role_ref),
                }[parameter.parameter_kind]
                if not valid:
                    raise ValueError("guidance template parameter is outside the binding")
    current_state_ids = {
        item.evidence_id
        for item in (
            binding.incident_bound_request.correlation_request.incident_anchor.current_state_evidence
        )
    }
    timeline_ids = {
        evidence_id for entry in guidance.timeline for evidence_id in entry.evidence_ids
    }
    if not current_state_ids.issubset(timeline_ids):
        raise ValueError("incident guidance timeline omits current-state evidence")
    expected_missing = tuple(
        sorted(
            {
                item.code
                for hypothesis in binding.correlation_report.hypotheses
                for item in hypothesis.missing_evidence
            }
        )
    )
    if guidance.missing_evidence != expected_missing:
        raise ValueError("incident guidance missing-evidence projection is invalid")
    selection = binding.selection
    if isinstance(selection, SelectedRunbookGuidanceSelection):
        if any(
            link.option_id != selection.option_id
            or link.option_digest != selection.option_digest
            or link.runbook_reference != selection.runbook_reference
            for link in guidance.runbook_links
        ):
            raise ValueError("incident guidance runbook link is invalid")
        if any(
            step.option_id != selection.option_id
            or step.provenance_clause_ref
            != next(
                item.provenance.clause_path
                for item in binding.guidance_authority.options
                if item.option_id == selection.option_id
            )
            for step in (
                *guidance.safe_manual_options,
                *guidance.rollback_considerations,
            )
        ):
            raise ValueError("incident guidance manual option is invalid")
        if guidance.safe_manual_options and (
            "manualResolutionOption" not in binding.requested_actions
        ):
            raise ValueError("manual guidance action was not requested")
        if guidance.rollback_considerations and (
            "rollbackConsideration" not in binding.requested_actions
        ):
            raise ValueError("rollback guidance action was not requested")
    elif guidance.runbook_links or guidance.safe_manual_options or guidance.rollback_considerations:
        raise ValueError("no-runbook guidance contains runbook actions")


def validate_incident_guidance_assets(
    reference: IncidentGuidanceAssetReference,
    guidance: IncidentGuidance,
    attestation: IncidentGuidanceAttestation,
    *,
    trusted_guidance_key_id: str,
    guidance_signature_verifier: Callable[[bytes, str], bool],
) -> None:
    reference = IncidentGuidanceAssetReference.model_validate_json(
        reference.model_dump_json(by_alias=True)
    )
    guidance = IncidentGuidance.model_validate_json(guidance.model_dump_json(by_alias=True))
    attestation = IncidentGuidanceAttestation.model_validate_json(
        attestation.model_dump_json(by_alias=True)
    )
    guidance_preimage = guidance.canonical_bytes()
    if (
        reference.incident_id != guidance.source_binding.incident_id
        or reference.incident_state_digest != guidance.source_binding.incident_state_digest
        or reference.guidance_id != guidance.guidance_id
        or reference.guidance_digest != guidance.guidance_digest
        or reference.guidance_reference.content_digest != sha256_hex(guidance.canonical_bytes())
        or attestation.guidance_id != guidance.guidance_id
        or attestation.guidance_digest != guidance.guidance_digest
        or attestation.key_vault_key_id != trusted_guidance_key_id
        or attestation.signed_preimage_digest != sha256_hex(guidance_preimage)
        or guidance_signature_verifier(
            guidance_preimage,
            attestation.detached_signature,
        )
        is not True
        or reference.attestation_reference.content_digest
        != sha256_hex(attestation.canonical_bytes())
    ):
        raise ValueError("incident guidance assets do not match exact content")


__all__ = [
    "GuidanceActionKind",
    "GuidanceAffectedRoleImpact",
    "GuidanceApplicability",
    "GuidanceControlHealth",
    "GuidanceControlProvenance",
    "GuidanceHypothesisSummary",
    "GuidanceImpactCode",
    "GuidanceImpactSeverity",
    "GuidanceLegality",
    "GuidanceNoRunbookReason",
    "GuidancePathScope",
    "GuidanceRunbookReference",
    "GuidanceRunbookLink",
    "GuidanceRunbookLabelCode",
    "GuidanceSelection",
    "GuidanceStep",
    "GuidanceTemplateCode",
    "GuidanceTemplateParameter",
    "GuidanceTemplateParameterKind",
    "GuidanceTimelineEntry",
    "GuidanceTimelineKind",
    "GuidanceWithheldReason",
    "HttpsGuidanceRunbookReference",
    "INCIDENT_GUIDANCE_ALGORITHM_ID",
    "IncidentGuidance",
    "IncidentGuidanceAssetReference",
    "IncidentGuidanceAttestation",
    "IncidentGuidanceSourceBinding",
    "MAX_INCIDENT_GUIDANCE_BYTES",
    "NoRunbookGuidanceSelection",
    "OpaqueGuidanceRunbookReference",
    "PublishedGuidanceAuthority",
    "PublishedGuidanceAuthorityBinding",
    "PublishedGuidanceAuthorityBindingAttestation",
    "PublishedRunbookGuidanceOption",
    "SelectedRunbookGuidanceSelection",
    "build_guidance_affected_role_impact",
    "build_incident_guidance_source_binding",
    "guidance_timeline_kind_for_evidence",
    "build_guidance_legality",
    "project_guidance_hypotheses",
    "validate_incident_guidance_assets",
    "validate_incident_guidance_binding",
]
