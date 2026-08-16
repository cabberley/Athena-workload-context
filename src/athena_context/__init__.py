"""Athena Workload Context."""

from athena_context.contracts import (
    CanonicalWorkloadManifest,
    CompatibilityMetadata,
    ProfileDefinition,
    ResolvedProfile,
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
    "ProfileDefinition",
    "ResolvedProfile",
    "WorkloadManifest",
    "evaluate_manifest_profile",
    "evaluate_policy",
    "evaluate_profile",
]

WorkloadManifest = CanonicalWorkloadManifest
