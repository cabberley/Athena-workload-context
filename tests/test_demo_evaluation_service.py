from __future__ import annotations

import pytest
from pydantic import ValidationError

from athena_context.api import (
    AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL,
    ActorKind,
    McpReadAssignment,
    PrivateMcpEndpointConfiguration,
)
from athena_context.api.domain import Supersession
from athena_context.api.errors import (
    AuthorizationError,
    DemoEvaluationApprovalError,
    EvaluationFailedClosedError,
    EvidenceCollectionRejectedError,
    IdempotencyConflictError,
)
from athena_context.api.evaluation_ports import SnapshotSigningRequest
from athena_context.contracts import (
    canonicalize_json,
    compute_artifact_digest,
)
from wc013_support import (
    CONTEXT_OBJECT_ID,
    MCP_OBJECT_ID,
    MCP_SERVICE_ACTOR,
    PRIVATE_ENDPOINT,
    PUBLICATION_SERVICE,
    PUBLISHER,
    build_harness,
    endpoint_configuration,
    scope,
)

EXPECTED_VERDICTS = {
    "db-singleton-supported": "expectedConstraint",
    "db-zone-loss-acceptance": "acceptedResidualRisk",
    "db-zone-loss-spof": "acceptedResidualRisk",
    "web-zone-distribution": "pass",
    "worker-db-zone-colocation": "pass",
}


def test_private_fake_endpoint_publishes_and_evaluates_exact_golden_findings() -> None:
    harness = build_harness()

    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-success",
        harness.command,
    )

    assert harness.transport.calls == 1
    assert harness.transport.endpoints == [PRIVATE_ENDPOINT]
    assert harness.transport.deployment_tools == [
        AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL
    ]
    assert harness.snapshot_signer.calls == 1
    assert harness.context_resolver.calls == 1
    assert harness.store.publication_count == 1
    assert result.publication.snapshot_id == result.snapshot.snapshot_id
    assert result.publication.approval_decision_id == harness.approval.decision_id
    assert result.publication.approved_by == harness.approval.approved_by
    assert result.publication.publication_authorized_by == PUBLISHER
    assert result.publication.published_by == PUBLICATION_SERVICE
    assert result.publication.published_by.kind is ActorKind.SERVICE
    assert result.publication.endpoint_digest == compute_artifact_digest(
        {"privateMcpEndpoint": PRIVATE_ENDPOINT}
    )
    assert result.publication.authorized_scope_digest == compute_artifact_digest(
        scope().model_dump(mode="json", by_alias=True)
    )
    assert result.publication.publication_record_digest == compute_artifact_digest(
        result.publication._digest_payload()
    )
    assert result.result_digest == compute_artifact_digest(result._digest_payload())
    assert dict((finding.clause_id, finding.verdict) for finding in result.findings) == (
        EXPECTED_VERDICTS
    )
    assert result.citation_count == 9
    assert all(finding.evidence_refs for finding in result.findings)
    for finding in result.findings:
        assert finding.manifest_id == result.publication.manifest_id
        assert finding.manifest_version == result.publication.manifest_version
        assert finding.profile_id == result.publication.profile_id
        assert (
            finding.resolved_profile_digest
            == result.publication.resolved_profile_digest
        )
        assert (
            finding.governance_scope.clause_path
            == f"/constraints/{finding.clause_id}"
        )
        assert all(
            reference.snapshot_id == result.snapshot.snapshot_id
            and reference.snapshot_artifact_digest
            == result.snapshot.compatibility.artifact_digest
            and reference.snapshot_semantic_digest
            == result.snapshot.compatibility.semantic_digest
            for reference in finding.evidence_refs
        )

    immutable_canonical_snapshot = result.snapshot.canonical_json()
    stored = harness.service.get_result(PUBLISHER, result.snapshot.snapshot_id)
    assert stored.canonical_json() == result.canonical_json()
    assert stored.snapshot.canonical_json() == immutable_canonical_snapshot
    assert harness.store.resolve_publication(
        result.snapshot.snapshot_id
    ) == result.publication.registry_record()


def test_success_result_is_idempotent_before_any_repeat_collection_or_signing() -> None:
    harness = build_harness()
    first = harness.service.evaluate(PUBLISHER, "wc013-idempotent", harness.command)
    second = harness.service.evaluate(PUBLISHER, "wc013-idempotent", harness.command)

    assert second.canonical_json() == first.canonical_json()
    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    assert harness.store.publication_count == 1

    changed = harness.command.model_copy(
        update={"reason": "Attempt a different mutation under the same key"}
    )
    with pytest.raises(IdempotencyConflictError):
        harness.service.evaluate(PUBLISHER, "wc013-idempotent", changed)
    assert harness.transport.calls == 1
    assert harness.store.publication_count == 1


@pytest.mark.parametrize(
    ("scenario", "reason"),
    [
        ("authorization", "unauthorized"),
        ("failure", "collectorUnavailable"),
        ("timeout", "missing"),
        ("stale", "stale"),
        ("malformed", "malformed"),
        ("unavailable", "collectorUnavailable"),
        ("scopeMismatch", "scopeMismatch"),
    ],
)
def test_boundary_failures_never_sign_publish_or_evaluate(
    scenario: str,
    reason: str,
) -> None:
    harness = build_harness(scenario)

    with pytest.raises(EvidenceCollectionRejectedError, match=reason):
        harness.service.evaluate(
            PUBLISHER,
            f"wc013-{scenario}",
            harness.command,
        )

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 0
    assert harness.store.publication_count == 0


def test_scope_and_approval_mismatch_fail_before_mcp_collection() -> None:
    harness = build_harness()
    other_scope = scope().model_copy(
        update={"resource_group_name": "rg-not-approved"}
    )
    changed = harness.command.model_copy(update={"authorized_scope": other_scope})

    with pytest.raises(DemoEvaluationApprovalError, match="does not authorize"):
        harness.service.evaluate(PUBLISHER, "wc013-scope-denied", changed)

    assert harness.transport.calls == 0
    assert harness.store.publication_count == 0


def test_mcp_service_identity_cannot_publish_even_with_accidental_role_grant() -> None:
    harness = build_harness()

    with pytest.raises(AuthorizationError, match="requires a human actor"):
        harness.service.evaluate(
            MCP_SERVICE_ACTOR,
            "wc013-mcp-write-denied",
            harness.command,
        )

    assert harness.transport.calls == 0
    assert harness.store.publication_count == 0


def test_untrusted_snapshot_signature_fails_before_publication() -> None:
    harness = build_harness()

    class InvalidSigner:
        def sign(self, request: SnapshotSigningRequest) -> str:
            del request
            return "bm90LWEtdHJ1c3RlZC1zaWduYXR1cmU="

    harness.service._snapshot_signer = InvalidSigner()  # type: ignore[attr-defined]

    with pytest.raises(
        EvaluationFailedClosedError,
        match="assembly or signing failed",
    ):
        harness.service.evaluate(
            PUBLISHER,
            "wc013-invalid-signature",
            harness.command,
        )

    assert harness.store.publication_count == 0


def test_superseded_context_fails_before_collection() -> None:
    harness = build_harness()
    published = harness.context_resolver.view.published

    harness.context_resolver.view = harness.context_resolver.view.model_copy(
        update={
            "supersession": Supersession(
                manifest_id=published.manifest_id,
                superseded_version=published.manifest_version,
                replacement_version="1.2.0",
                superseded_by=PUBLISHER,
                superseded_at=published.published_at,
                reason="Synthetic replacement has become authoritative",
            )
        }
    )

    with pytest.raises(EvaluationFailedClosedError, match="superseded context"):
        harness.service.evaluate(
            PUBLISHER,
            "wc013-superseded",
            harness.command,
        )

    assert harness.transport.calls == 0
    assert harness.store.publication_count == 0


def test_wc008_output_configuration_enforces_identity_and_role_separation() -> None:
    base = endpoint_configuration().model_dump(mode="python")

    with pytest.raises(ValidationError, match="context identity must not receive"):
        PrivateMcpEndpointConfiguration.model_validate(
            {**base, "context_identity_azure_roles": ("Reader",)}
        )
    with pytest.raises(ValidationError, match="must not receive context write"):
        PrivateMcpEndpointConfiguration.model_validate(
            {
                **base,
                "evidence_identity_context_permissions": ("publish",),
            }
        )
    with pytest.raises(ValidationError, match="identities must remain separate"):
        PrivateMcpEndpointConfiguration.model_validate(
            {
                **base,
                "context_identity_object_id": MCP_OBJECT_ID,
                "evidence_identity_object_id": MCP_OBJECT_ID,
            }
        )
    with pytest.raises(ValidationError, match="private MCP endpoint"):
        PrivateMcpEndpointConfiguration.model_validate(
            {**base, "private_mcp_endpoint": "https://public.example.com"}
        )
    with pytest.raises(ValidationError):
        McpReadAssignment(scope=scope(), role="Contributor")  # type: ignore[arg-type]
    assert endpoint_configuration().context_identity_object_id == CONTEXT_OBJECT_ID


def test_snapshot_and_publication_reject_post_validation_tampering() -> None:
    harness = build_harness()
    result = harness.service.evaluate(PUBLISHER, "wc013-tamper", harness.command)
    payload = result.snapshot.model_dump(mode="json", by_alias=True)
    payload["evidenceRecords"][0]["availabilityZone"] = "3"

    with pytest.raises(ValidationError):
        type(result.snapshot).model_validate(payload)

    publication_payload = result.publication.model_dump(mode="python")
    publication_payload["reason"] = "Tampered publication reason"
    with pytest.raises(ValidationError, match="publication record digest"):
        type(result.publication).model_validate(publication_payload)

    assert canonicalize_json(
        result.snapshot.model_dump(mode="json", by_alias=True, exclude_none=True)
    ) == result.snapshot.canonical_json()
