from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from athena_context.contracts.common import compute_artifact_digest

type ConfidenceLevel = Literal["Confirmed", "High", "Medium", "Low", "Unknown"]
type RootCauseCategory = Literal[
    "networkSecurityChange",
    "routingChange",
    "guestResourcePressure",
    "guestServiceFailure",
    "platformHealth",
    "backendHealth",
    "deploymentChange",
    "dependencyFailure",
    "unknown",
]


@dataclass(frozen=True, slots=True)
class CorrelationRuleCatalog:
    schema_version: str
    algorithm_id: str
    confidence_thresholds: tuple[tuple[ConfidenceLevel, int], ...]
    category_order: tuple[RootCauseCategory, ...]
    nsg_property_paths: tuple[str, ...]
    routing_property_paths: tuple[str, ...]
    nsg_confirmed_gates: tuple[str, ...]
    temporal_score_windows: tuple[tuple[int, int], ...]
    score_weights: tuple[tuple[str, int], ...]
    confidence_caps: tuple[tuple[str, ConfidenceLevel], ...]
    generic_max_confidence: ConfidenceLevel
    unattributed_nsg_max_confidence: ConfidenceLevel
    maximum_hypotheses: int
    maximum_candidate_hypotheses: int
    maximum_evaluation_work_units: int
    maximum_supporting_evidence: int
    maximum_contradictions: int
    maximum_missing_evidence: int
    maximum_gates: int
    maximum_caps: int
    maximum_gate_evidence_ids: int
    maximum_contradiction_evidence_ids: int
    maximum_report_canonical_bytes: int

    def canonical_payload(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "algorithmId": self.algorithm_id,
            "confidenceThresholds": [
                {"confidence": confidence, "minimumScore": minimum}
                for confidence, minimum in self.confidence_thresholds
            ],
            "categoryOrder": list(self.category_order),
            "nsgPropertyPaths": list(self.nsg_property_paths),
            "routingPropertyPaths": list(self.routing_property_paths),
            "nsgConfirmedGates": list(self.nsg_confirmed_gates),
            "temporalScoreWindows": [
                {"maximumSeconds": maximum, "score": score}
                for maximum, score in self.temporal_score_windows
            ],
            "scoreWeights": [{"name": name, "value": value} for name, value in self.score_weights],
            "confidenceCaps": [
                {"code": code, "maximumConfidence": maximum}
                for code, maximum in self.confidence_caps
            ],
            "genericMaxConfidence": self.generic_max_confidence,
            "unattributedNsgMaxConfidence": self.unattributed_nsg_max_confidence,
            "maximumHypotheses": self.maximum_hypotheses,
            "maximumCandidateHypotheses": self.maximum_candidate_hypotheses,
            "maximumEvaluationWorkUnits": self.maximum_evaluation_work_units,
            "maximumSupportingEvidence": self.maximum_supporting_evidence,
            "maximumContradictions": self.maximum_contradictions,
            "maximumMissingEvidence": self.maximum_missing_evidence,
            "maximumGates": self.maximum_gates,
            "maximumCaps": self.maximum_caps,
            "maximumGateEvidenceIds": self.maximum_gate_evidence_ids,
            "maximumContradictionEvidenceIds": (self.maximum_contradiction_evidence_ids),
            "maximumReportCanonicalBytes": self.maximum_report_canonical_bytes,
        }


CORRELATION_RULE_CATALOG = CorrelationRuleCatalog(
    schema_version="athena.wc026CorrelationRuleCatalog.v1",
    algorithm_id="athena.wc026.correlation.v1",
    confidence_thresholds=(
        ("Low", 30),
        ("Medium", 55),
        ("High", 75),
        ("Confirmed", 90),
    ),
    category_order=(
        "networkSecurityChange",
        "routingChange",
        "guestServiceFailure",
        "guestResourcePressure",
        "platformHealth",
        "backendHealth",
        "dependencyFailure",
        "deploymentChange",
        "unknown",
    ),
    nsg_property_paths=(
        "properties.access",
        "properties.direction",
        "properties.priority",
        "properties.protocol",
        "properties.sourceaddressprefix",
        "properties.sourceaddressprefixes",
        "properties.sourceportrange",
        "properties.sourceportranges",
        "properties.destinationaddressprefix",
        "properties.destinationaddressprefixes",
        "properties.destinationportrange",
        "properties.destinationportranges",
    ),
    routing_property_paths=(
        "properties.addressprefix",
        "properties.nexthoptype",
        "properties.nexthopipaddress",
    ),
    nsg_confirmed_gates=(
        "successfulChange",
        "affectedPath",
        "semanticMatch",
        "effectiveRuleAttribution",
        "matchingDeniedFlow",
        "connectionMonitorFailure",
        "endpointDegradation",
        "independentCorroboration",
        "correctChronology",
        "noHardConflict",
    ),
    temporal_score_windows=(
        (300, 20),
        (900, 15),
        (1800, 10),
        (3600, 5),
    ),
    score_weights=(
        ("topologyExactPath", 25),
        ("topologyAffectedPath", 18),
        ("topologyDeclaredPath", 10),
        ("nsgDirectSemantic", 20),
        ("nsgCausalSemantic", 14),
        ("routingChangeSemantic", 20),
        ("genericChangeSemantic", 8),
        ("observationSemantic", 20),
        ("flowCorroboration", 10),
        ("monitorCorroboration", 8),
        ("endpointCorroboration", 7),
        ("independentCorroboration", 8),
        ("correctiveRecovery", 10),
        ("observedRecovery", 4),
        ("maximumComponent", 25),
    ),
    confidence_caps=(
        ("recentChangeOnly", "Low"),
        ("missingAffectedPath", "Low"),
        ("missingIndependentSupport", "Medium"),
        ("ambiguousObservationWindow", "Medium"),
    ),
    generic_max_confidence="Medium",
    unattributed_nsg_max_confidence="High",
    maximum_hypotheses=64,
    maximum_candidate_hypotheses=4096,
    maximum_evaluation_work_units=65536,
    maximum_supporting_evidence=128,
    maximum_contradictions=64,
    maximum_missing_evidence=64,
    maximum_gates=32,
    maximum_caps=16,
    maximum_gate_evidence_ids=64,
    maximum_contradiction_evidence_ids=64,
    maximum_report_canonical_bytes=8 * 1024 * 1024,
)

CORRELATION_RULE_CATALOG_DIGEST = compute_artifact_digest(
    CORRELATION_RULE_CATALOG.canonical_payload()
)


def assert_catalog_digest() -> None:
    if (
        compute_artifact_digest(CORRELATION_RULE_CATALOG.canonical_payload())
        != CORRELATION_RULE_CATALOG_DIGEST
    ):
        raise RuntimeError("WC-026 correlation rule catalog was mutated")


def assert_contract_compatibility() -> None:
    from athena_context.contracts import correlation as contract

    catalog_thresholds = {
        "Unknown": 0,
        **dict(CORRELATION_RULE_CATALOG.confidence_thresholds),
    }
    catalog_caps = dict(CORRELATION_RULE_CATALOG.confidence_caps)
    compatible = (
        CORRELATION_RULE_CATALOG.algorithm_id == contract.CORRELATION_ALGORITHM_ID
        and catalog_thresholds == contract.CORRELATION_CONFIDENCE_THRESHOLDS
        and tuple(contract._NSG_CAUSAL_PROPERTY_PREFIXES)
        == CORRELATION_RULE_CATALOG.nsg_property_paths
        and frozenset(contract._NETWORK_SECURITY_CONFIRMED_GATES)
        == frozenset(CORRELATION_RULE_CATALOG.nsg_confirmed_gates)
        and contract.CORRELATION_REQUIRED_CAPS["recentChangeOnly"]
        == catalog_caps["recentChangeOnly"]
        and contract.CORRELATION_REQUIRED_CAPS["missingAffectedPath"]
        == catalog_caps["missingAffectedPath"]
        and contract.CORRELATION_REQUIRED_CAPS["missingIndependentSupport"]
        == catalog_caps["missingIndependentSupport"]
        and contract.CORRELATION_REQUIRED_CAPS["ambiguousObservationWindow"]
        == catalog_caps["ambiguousObservationWindow"]
        and contract.CORRELATION_REQUIRED_CAPS["missingDirectAttribution"]
        == CORRELATION_RULE_CATALOG.unattributed_nsg_max_confidence
        and CORRELATION_RULE_CATALOG.maximum_hypotheses == contract.CORRELATION_MAX_HYPOTHESES
        and CORRELATION_RULE_CATALOG.maximum_candidate_hypotheses
        == contract.CORRELATION_MAX_CANDIDATE_HYPOTHESES
        and CORRELATION_RULE_CATALOG.maximum_supporting_evidence
        == contract.CORRELATION_MAX_SUPPORTING_EVIDENCE
        and CORRELATION_RULE_CATALOG.maximum_contradictions
        == contract.CORRELATION_MAX_CONTRADICTIONS
        and CORRELATION_RULE_CATALOG.maximum_missing_evidence
        == contract.CORRELATION_MAX_MISSING_EVIDENCE
        and CORRELATION_RULE_CATALOG.maximum_gates == contract.CORRELATION_MAX_GATES
        and CORRELATION_RULE_CATALOG.maximum_caps == contract.CORRELATION_MAX_CAPS
        and CORRELATION_RULE_CATALOG.maximum_gate_evidence_ids
        == contract.CORRELATION_MAX_GATE_EVIDENCE_IDS
        and CORRELATION_RULE_CATALOG.maximum_contradiction_evidence_ids
        == contract.CORRELATION_MAX_CONTRADICTION_EVIDENCE_IDS
        and CORRELATION_RULE_CATALOG.maximum_report_canonical_bytes
        == contract.CORRELATION_MAX_CANONICAL_BYTES
    )
    if not compatible:
        raise RuntimeError("WC-026 correlation contracts do not match the engine rule catalog")


__all__ = [
    "CORRELATION_RULE_CATALOG",
    "CORRELATION_RULE_CATALOG_DIGEST",
    "ConfidenceLevel",
    "CorrelationRuleCatalog",
    "RootCauseCategory",
    "assert_catalog_digest",
    "assert_contract_compatibility",
]
