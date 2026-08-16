"""Athena Workload Context."""

from athena_context.contracts import (
    CanonicalWorkloadManifest,
    CompatibilityMetadata,
    ProfileDefinition,
    ResolvedProfile,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "CompatibilityMetadata",
    "CanonicalWorkloadManifest",
    "ProfileDefinition",
    "ResolvedProfile",
    "WorkloadManifest",
]

WorkloadManifest = CanonicalWorkloadManifest
