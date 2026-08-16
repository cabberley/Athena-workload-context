"""Athena Workload Context."""

from athena_context.contracts import (
    CanonicalWorkloadManifest,
    CompatibilityMetadata,
    ProfileDefinition,
    ResolvedProfile,
)
from athena_context.golden import (
    GoldenProfileResult,
    GoldenProofMismatchError,
    GoldenProofResult,
    run_golden_proof,
)
from athena_context.policy import (
    evaluate_manifest_profile,
    evaluate_policy,
    evaluate_profile,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "CompatibilityMetadata",
    "CanonicalWorkloadManifest",
    "GoldenProfileResult",
    "GoldenProofMismatchError",
    "GoldenProofResult",
    "ProfileDefinition",
    "ResolvedProfile",
    "WorkloadManifest",
    "evaluate_manifest_profile",
    "evaluate_policy",
    "evaluate_profile",
    "run_golden_proof",
]

WorkloadManifest = CanonicalWorkloadManifest
