from __future__ import annotations

import ast
import inspect
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from scripts.convert_wc022_research_draft import main as conversion_main

import athena_context.wc022_epic_proposal as proposal_package
import athena_context.wc022_epic_proposal.conversion as conversion_module
from athena_context.contracts.common import compute_artifact_digest
from athena_context.contracts.manifest import CanonicalWorkloadManifest
from athena_context.wc022_epic_proposal import (
    ResearchDraftConversionError,
    convert_canonical_public_safe_research_draft,
)
from athena_context.wc022_epic_proposal.contracts import (
    WC022_RESEARCH_DRAFT_LOCATION,
    WC022_REVIEWED_DOSSIER_DIGEST,
    WC022_REVIEWED_DRAFT_DIGEST,
    WC022_REVIEWED_PROPOSAL_DIGEST,
    WC022_SOURCE_DOSSIER,
    GovernedWorkloadContextProposal,
)
from athena_context.wc022_epic_proposal.conversion import (
    _validate_mapping_boundary,
    _validate_source_shape,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESEARCH_DRAFT_PATH = REPOSITORY_ROOT / WC022_RESEARCH_DRAFT_LOCATION


def _source() -> dict[str, object]:
    loaded = yaml.safe_load(RESEARCH_DRAFT_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _reseal(payload: dict[str, object]) -> None:
    payload.pop("proposalDigest", None)
    payload["proposalDigest"] = compute_artifact_digest(payload)


def _proposal_payload() -> dict[str, object]:
    return json.loads(convert_canonical_public_safe_research_draft().canonical_json())


def test_conversion_creates_a_closed_unpublished_governed_proposal() -> None:
    proposal = convert_canonical_public_safe_research_draft()

    assert proposal.proposal_kind == "governedWorkloadContextProposal"
    assert proposal.governance.publication_state == "unpublished"
    assert proposal.governance.runtime_use == "prohibited"
    assert proposal.governance.human_approval_required is True
    assert "approvedExceptions" not in json.loads(proposal.canonical_json())
    assert {environment.profile_id for environment in proposal.environments} == {
        "production",
        "dr",
        "development",
        "test",
        "training",
    }
    assert all(environment.criticality.state == "unknown" for environment in proposal.environments)
    assert all(
        decision.state == "humanDecisionRequired"
        for environment in proposal.environments
        for decision in (
            environment.objective,
            environment.recovery_intent,
            environment.dependency_scope,
        )
    )
    assert all(role.candidate_status == "humanApprovalRequired" for role in proposal.roles)
    database_role = next(role for role in proposal.roles if role.role_id == "operationalDatabase")
    assert any(
        decision.subject == "operationalDatabase acceptedConstraint"
        for decision in database_role.source_decisions
    )
    assert all(
        relationship.candidate_status == "humanApprovalRequired"
        for relationship in proposal.relationship_hypotheses
    )
    assert proposal.provenance.source_artifact == (
        "docs/research/drafts/epic-on-azure.draft.yaml"
    )
    assert proposal.provenance.source_dossier == WC022_SOURCE_DOSSIER
    assert proposal.provenance.source_payload_digest == WC022_REVIEWED_DRAFT_DIGEST
    assert proposal.provenance.source_dossier_digest == WC022_REVIEWED_DOSSIER_DIGEST
    assert proposal.proposal_digest == WC022_REVIEWED_PROPOSAL_DIGEST
    assert all(dependency.source_refs for dependency in proposal.dependencies)
    assert all(relationship.source_refs for relationship in proposal.relationship_hypotheses)


def test_proposal_schema_and_serialization_are_closed_and_valid() -> None:
    proposal = convert_canonical_public_safe_research_draft()
    schema = GovernedWorkloadContextProposal.model_json_schema()
    payload = json.loads(proposal.canonical_json())

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    assert schema["additionalProperties"] is False
    assert payload["proposalDigest"] == proposal.proposal_digest
    assert proposal == GovernedWorkloadContextProposal.model_validate(payload)

    payload["unrecognized"] = True
    with pytest.raises(ValidationError, match="unrecognized"):
        GovernedWorkloadContextProposal.model_validate(payload)


def test_invalid_proposal_digest_cannot_bypass_normal_contract_validation() -> None:
    payload = _proposal_payload()
    payload["proposalDigest"] = "sha256:" + "0" * 64

    with pytest.raises(ValidationError, match="proposalDigest does not match"):
        GovernedWorkloadContextProposal.model_validate(
            payload,
            context={"wc022InternalUnsealed": True},
        )


def test_contract_rejects_modified_content_even_when_self_digest_is_recomputed() -> None:
    payload = _proposal_payload()
    workload = payload["workload"]
    assert isinstance(workload, dict)
    workload["description"] = "Modified proposal content must not acquire authority."
    _reseal(payload)

    with pytest.raises(ValidationError, match="reviewed canonical proposal output"):
        GovernedWorkloadContextProposal.model_validate(payload)


def test_contract_rejects_unapproved_provenance_labels() -> None:
    payload = _proposal_payload()
    provenance = payload["provenance"]
    assert isinstance(provenance, dict)
    provenance["sourceArtifact"] = "docs/research/drafts/unreviewed.yaml"
    _reseal(payload)

    with pytest.raises(ValidationError, match="sourceArtifact is not approved"):
        GovernedWorkloadContextProposal.model_validate(payload)

    payload = _proposal_payload()
    provenance = payload["provenance"]
    assert isinstance(provenance, dict)
    provenance["sourceDossier"] = "docs/research/unreviewed-dossier.md"
    _reseal(payload)

    with pytest.raises(ValidationError, match="sourceDossier is not approved"):
        GovernedWorkloadContextProposal.model_validate(payload)

    payload = _proposal_payload()
    provenance = payload["provenance"]
    assert isinstance(provenance, dict)
    provenance["sourceDossierDigest"] = "sha256:" + "0" * 64
    _reseal(payload)

    with pytest.raises(ValidationError, match="sealed reviewed dossier"):
        GovernedWorkloadContextProposal.model_validate(payload)


def test_conversion_is_deterministic_from_canonical_reviewed_bytes() -> None:
    first = convert_canonical_public_safe_research_draft()
    second = convert_canonical_public_safe_research_draft()

    assert first.canonical_json() == second.canonical_json()
    assert first.proposal_digest == second.proposal_digest


def test_conversion_exposes_only_an_atomic_input_free_authority_boundary() -> None:
    assert tuple(inspect.signature(convert_canonical_public_safe_research_draft).parameters) == ()
    assert proposal_package.__all__ == [
        "GovernedWorkloadContextProposal",
        "ResearchDraftConversionError",
        "Wc022ContractError",
        "convert_canonical_public_safe_research_draft",
    ]
    assert not any(
        hasattr(conversion_module, name)
        for name in (
            "ReviewedResearchDraft",
            "_REVIEW_SEAL",
            "convert_public_safe_research_draft",
            "load_public_safe_research_draft",
            "load_reviewed_public_safe_research_draft",
            "_convert_sealed_research_draft",
        )
    )
    assert not any(
        name in conversion_module.__all__
        for name in (
            "ReviewedResearchDraft",
            "convert_public_safe_research_draft",
            "load_public_safe_research_draft",
            "load_reviewed_public_safe_research_draft",
        )
    )
    assert tuple(
        inspect.signature(
            conversion_module._convert_verified_canonical_research_draft
        ).parameters
    ) == ()
    assert (
        conversion_module._convert_verified_canonical_research_draft().proposal_digest
        == WC022_REVIEWED_PROPOSAL_DIGEST
    )


def test_nested_decision_provenance_must_resolve() -> None:
    payload = _proposal_payload()
    payload["environments"][0]["objective"]["sourceRefs"] = ["SRC-NOT-DECLARED"]
    payload.pop("proposalDigest")
    payload["proposalDigest"] = compute_artifact_digest(payload)

    with pytest.raises(ValidationError, match="nested decision provenance must resolve"):
        GovernedWorkloadContextProposal.model_validate(payload)

    payload = _proposal_payload()
    payload["dependencies"][0]["sourceRefs"] = ["SRC-NOT-DECLARED"]
    payload.pop("proposalDigest")
    payload["proposalDigest"] = compute_artifact_digest(payload)

    with pytest.raises(ValidationError, match="dependency provenance must resolve"):
        GovernedWorkloadContextProposal.model_validate(payload)


def test_proposal_contract_rejects_approved_exception_field() -> None:
    payload = _proposal_payload()
    payload["approvedExceptions"] = []
    _reseal(payload)

    with pytest.raises(ValidationError, match="approvedExceptions"):
        GovernedWorkloadContextProposal.model_validate(payload)


def test_contract_rejects_duplicate_identifier_and_source_reference_surfaces() -> None:
    duplicate_surfaces = (
        ("environment profile identifiers", "environments"),
        ("role identifiers", "roles"),
        ("relationship identifiers", "relationshipHypotheses"),
        ("dependency identifiers", "dependencies"),
        ("objective identifiers", "objectives"),
        ("ownership roles", "ownership"),
        ("placement constraint identifiers", "placementConstraints"),
        ("exception identifiers", "exceptionCandidates"),
    )
    for expected_error, collection_name in duplicate_surfaces:
        payload = _proposal_payload()
        collection = payload[collection_name]
        assert isinstance(collection, list)
        collection.append(deepcopy(collection[0]))
        _reseal(payload)

        with pytest.raises(ValidationError, match=expected_error):
            GovernedWorkloadContextProposal.model_validate(payload)

    payload = _proposal_payload()
    provenance = payload["provenance"]
    assert isinstance(provenance, dict)
    source_refs = provenance["sourceRefs"]
    assert isinstance(source_refs, list)
    provenance["sourceRefs"] = ["SRC-A", "src-a", *source_refs[1:]]
    _reseal(payload)

    with pytest.raises(ValidationError, match="source references must be unique"):
        GovernedWorkloadContextProposal.model_validate(payload)

    payload = _proposal_payload()
    environments = payload["environments"]
    assert isinstance(environments, list)
    first_environment = environments[0]
    assert isinstance(first_environment, dict)
    first_environment["sourceRefs"] = ["SRC-A", "src-a", "SRC-B"]
    _reseal(payload)

    with pytest.raises(ValidationError, match="source references must be unique"):
        GovernedWorkloadContextProposal.model_validate(payload)


def test_contract_requires_safe_nfc_normalized_identifiers() -> None:
    payload = _proposal_payload()
    roles = payload["roles"]
    assert isinstance(roles, list)
    first_role = roles[0]
    assert isinstance(first_role, dict)
    first_role["roleId"] = "role-e\u0301"
    _reseal(payload)

    with pytest.raises(ValidationError, match="NFC-normalized"):
        GovernedWorkloadContextProposal.model_validate(payload)

    payload = _proposal_payload()
    relationships = payload["relationshipHypotheses"]
    assert isinstance(relationships, list)
    first_relationship = relationships[0]
    assert isinstance(first_relationship, dict)
    first_relationship["relationshipId"] = "unsafe relationship id"
    _reseal(payload)

    with pytest.raises(ValidationError, match="unsupported characters"):
        GovernedWorkloadContextProposal.model_validate(payload)


def test_converted_proposals_are_deeply_immutable() -> None:
    proposal = convert_canonical_public_safe_research_draft()

    with pytest.raises(AttributeError):
        proposal.environments[0].unknowns.append(proposal.environments[0].unknowns[0])


def test_conversion_rejects_any_relaxation_of_the_non_runtime_source_boundary() -> None:
    source = _source()
    source["runtimeUse"] = "allowed"

    with pytest.raises(
        ResearchDraftConversionError,
        match="research draft runtimeUse must be 'prohibited'",
    ):
        _validate_source_shape(source)


def test_source_validator_rejects_unreviewed_shape_and_environment_names() -> None:
    source = _source()
    source["unreviewedRoot"] = "not reviewed"

    with pytest.raises(ResearchDraftConversionError, match="root has an unreviewed shape"):
        _validate_source_shape(source)

    source = _source()
    draft = source["workloadContextDraft"]
    assert isinstance(draft, dict)
    draft["unreviewedDraftField"] = "not reviewed"

    with pytest.raises(
        ResearchDraftConversionError,
        match="workloadContextDraft has an unreviewed shape",
    ):
        _validate_source_shape(source)

    source = _source()
    draft = source["workloadContextDraft"]
    assert isinstance(draft, dict)
    environments = draft["environments"]
    assert isinstance(environments, dict)
    production = environments["Production"]
    assert isinstance(production, dict)
    production["unreviewedEnvironmentField"] = "not reviewed"

    with pytest.raises(
        ResearchDraftConversionError,
        match="environment Production has an unreviewed shape",
    ):
        _validate_source_shape(source)

    source = _source()
    draft = source["workloadContextDraft"]
    assert isinstance(draft, dict)
    environments = draft["environments"]
    assert isinstance(environments, dict)
    environments["Sandbox"] = deepcopy(environments["Production"])

    with pytest.raises(
        ResearchDraftConversionError,
        match="environments has an unreviewed shape",
    ):
        _validate_source_shape(source)


def test_converter_rejects_unapproved_source_provenance_values() -> None:
    source = _source()
    source["researchDraftLocation"] = "docs/research/drafts/spoofed.yaml"

    with pytest.raises(ResearchDraftConversionError, match="researchDraftLocation"):
        _validate_source_shape(source)

    source = _source()
    source["sourceDossier"] = "docs/research/spoofed-dossier.md"

    with pytest.raises(ResearchDraftConversionError, match="sourceDossier"):
        _validate_source_shape(source)


def test_source_validator_rejects_missing_or_unknown_source_references() -> None:
    source = _source()
    draft = source["workloadContextDraft"]
    assert isinstance(draft, dict)
    dependencies = draft["dependencyCategories"]
    assert isinstance(dependencies, dict)
    identity = dependencies["identityAndAccess"]
    assert isinstance(identity, dict)
    identity["supportedBy"] = []

    with pytest.raises(ResearchDraftConversionError, match="explicit source references"):
        _validate_source_shape(source)

    source = _source()
    draft = source["workloadContextDraft"]
    assert isinstance(draft, dict)
    relationships = draft["relationshipHypotheses"]
    assert isinstance(relationships, dict)
    items = relationships["items"]
    assert isinstance(items, list)
    first_item = items[0]
    assert isinstance(first_item, dict)
    first_item["provenanceCategory"] = "SRC-NOT-DECLARED"

    with pytest.raises(ResearchDraftConversionError, match="unknown source references"):
        _validate_source_shape(source)


def test_internal_mapping_boundary_enforces_size_depth_and_item_bounds() -> None:
    source = _source()
    redaction_rules = source["redactionRules"]
    assert isinstance(redaction_rules, dict)
    redaction_rules["permittedContent"] = ["bounded-item"] * 1025

    with pytest.raises(ResearchDraftConversionError, match="item bound"):
        _validate_mapping_boundary(source)

    source = _source()
    redaction_rules = source["redactionRules"]
    assert isinstance(redaction_rules, dict)
    redaction_rules["permittedContent"] = ["x" * (128 * 1024)]

    with pytest.raises(ResearchDraftConversionError, match="canonical serialized-size bound"):
        _validate_mapping_boundary(source)

    source = _source()
    redaction_rules = source["redactionRules"]
    assert isinstance(redaction_rules, dict)
    deeply_nested: object = "bounded"
    for _ in range(16):
        deeply_nested = [deeply_nested]
    redaction_rules["permittedContent"] = deeply_nested

    with pytest.raises(ResearchDraftConversionError, match="depth bound"):
        _validate_mapping_boundary(source)


def test_atomic_conversion_rejects_changed_reviewed_source_or_dossier_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        conversion_module,
        "WC022_REVIEWED_DRAFT_DIGEST",
        "sha256:" + "0" * 64,
    )
    with pytest.raises(ResearchDraftConversionError, match="sealed reviewed source digest"):
        conversion_module._convert_verified_canonical_research_draft()

    monkeypatch.setattr(
        conversion_module,
        "WC022_REVIEWED_DRAFT_DIGEST",
        WC022_REVIEWED_DRAFT_DIGEST,
    )
    monkeypatch.setattr(
        conversion_module,
        "WC022_REVIEWED_DOSSIER_DIGEST",
        "sha256:" + "0" * 64,
    )
    with pytest.raises(ResearchDraftConversionError, match="sealed reviewed dossier digest"):
        convert_canonical_public_safe_research_draft()


def test_cli_has_no_caller_controlled_research_input(
    tmp_path: Path,
) -> None:
    foreign_input = tmp_path / "self-labeled.yaml"
    foreign_input.write_text(
        RESEARCH_DRAFT_PATH.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    output_path = tmp_path / "wc022-proposal.json"

    with pytest.raises(SystemExit) as error:
        conversion_main(["--input", str(foreign_input), "--output", str(output_path)])
    assert error.value.code == 2
    assert not output_path.exists()


def test_research_yaml_cannot_validate_as_runtime_manifest_or_cross_runtime_boundary() -> None:
    source = _source()

    with pytest.raises(ValidationError):
        CanonicalWorkloadManifest.model_validate(source)

    forbidden_package = "athena_context.wc022_epic_proposal"
    forbidden_draft = WC022_RESEARCH_DRAFT_LOCATION
    forbidden_draft_name = Path(forbidden_draft).name
    runtime_sources = [
        *sorted((REPOSITORY_ROOT / "src" / "athena_context" / "policy").rglob("*.py")),
        *sorted((REPOSITORY_ROOT / "src" / "athena_context" / "api").rglob("*.py")),
        *sorted((REPOSITORY_ROOT / "src" / "athena_context" / "eventing").rglob("*.py")),
        REPOSITORY_ROOT / "src" / "athena_context" / "golden.py",
    ]
    violations: list[str] = []
    for path in runtime_sources:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                imported_names = [
                    f"{module}.{alias.name}" if module else alias.name
                    for alias in node.names
                ]
            elif isinstance(node, ast.Constant) and node.value in {
                forbidden_draft,
                forbidden_draft_name,
            }:
                violations.append(f"{path}: research draft reference")
                continue
            else:
                continue
            if any(
                name == "wc022_epic_proposal"
                or name == forbidden_package
                or name.startswith(f"{forbidden_package}.")
                for name in imported_names
            ):
                violations.append(f"{path}: WC-022 proposal import")
    assert not violations, "\n".join(violations)

    probe = """
import importlib
import sys

sys.path.insert(0, r"src")

for module_name in (
    "athena_context.golden",
    "athena_context.policy.evaluator",
    "athena_context.api.evaluation_service",
    "athena_context.eventing.orchestrator",
):
    importlib.import_module(module_name)

forbidden = "athena_context.wc022_epic_proposal"
assert not any(
    name == forbidden or name.startswith(f"{forbidden}.")
    for name in sys.modules
)
"""
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_conversion_script_writes_only_a_new_local_unpublished_artifact(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_path = tmp_path / "wc022-proposal.json"

    assert conversion_main(["--output", str(output_path)]) == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["governance"]["publicationState"] == "unpublished"
    assert payload["governance"]["runtimeUse"] == "prohibited"
    assert "Proposal digest: sha256:" in capsys.readouterr().out
    assert conversion_main(["--output", str(output_path)]) == 1
