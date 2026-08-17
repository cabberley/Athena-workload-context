from __future__ import annotations


class ContextApiError(Exception):
    """Base class for fail-closed Context API failures."""

    code = "context_api_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class AuthenticationError(ContextApiError):
    code = "authentication_required"


class AuthorizationError(ContextApiError):
    code = "authorization_denied"


class ResourceNotFoundError(ContextApiError):
    code = "resource_not_found"


class DuplicateDraftError(ContextApiError):
    code = "duplicate_draft"


class DuplicateVersionError(ContextApiError):
    code = "duplicate_version"


class InvalidTransitionError(ContextApiError):
    code = "invalid_transition"


class StaleRevisionError(ContextApiError):
    code = "stale_revision"


class VersionMismatchError(ContextApiError):
    code = "version_mismatch"


class DigestMismatchError(ContextApiError):
    code = "digest_mismatch"


class ManifestValidationError(ContextApiError):
    code = "manifest_validation_failed"


class StaleApprovalError(ContextApiError):
    code = "stale_approval"


class IdempotencyConflictError(ContextApiError):
    code = "idempotency_conflict"


class AmbiguousLookupError(ContextApiError):
    code = "ambiguous_lookup"


class AlreadySupersededError(ContextApiError):
    code = "already_superseded"


class PersistenceConflictError(ContextApiError):
    code = "persistence_conflict"


class CohortProfileMismatchError(ContextApiError):
    code = "cohort_profile_mismatch"


class EvidenceSnapshotMismatchError(ContextApiError):
    code = "evidence_snapshot_mismatch"


class StaleEvidenceSnapshotError(ContextApiError):
    code = "stale_evidence_snapshot"


class CohortBoundaryError(ContextApiError):
    code = "cohort_boundary_exceeded"


class CohortContractError(ContextApiError):
    code = "cohort_contract_invalid"


class CohortDecisionConflictError(ContextApiError):
    code = "cohort_decision_conflict"


class RejectedProposalSetError(ContextApiError):
    code = "cohort_proposal_set_rejected"
