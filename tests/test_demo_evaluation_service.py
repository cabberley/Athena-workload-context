from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from email.message import Message
from inspect import stack
from io import BytesIO
from pathlib import Path
from threading import Event, Thread
from typing import Any
from urllib.request import BaseHandler
from urllib.response import addinfourl

import pytest
from pydantic import ValidationError

from athena_context.api import (
    AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL,
    Actor,
    ActorKind,
    CreateDemoEvaluationApprovalCommand,
    EnvironmentContextApiPublishedContextReader,
    EnvironmentWc007PublishedContextSelectionPort,
    EnvironmentWc008DeploymentConfigurationPort,
    McpReadAssignment,
    OperatorTrustedWc008ConfigurationPort,
    PrivateMcpEvidenceTransport,
    PublishedContextSelection,
    Role,
    RoleGrant,
    Wc008DeploymentOutputAssertion,
    Wc009EvidenceClientAdapter,
)
from athena_context.api.authorization import authorize_role_grants
from athena_context.api.domain import (
    AuditAction,
    Permission,
    Supersession,
    WorkloadGrantScope,
)
from athena_context.api.errors import (
    AuthorizationError,
    DemoEvaluationApprovalError,
    DemoEvaluationConfigurationError,
    EvaluationFailedClosedError,
    EvidenceCollectionRejectedError,
    IdempotencyConflictError,
    ResourceNotFoundError,
)
from athena_context.api.evaluation_context import (
    validate_published_context_binding,
)
from athena_context.api.evaluation_domain import EvaluationAuthorityToken
from athena_context.api.evaluation_ports import (
    EvaluationCollectionAuthority,
    EvaluationCommitAuthorityCondition,
    EvaluationTemporalValidity,
    EvaluationTrustedKeyAuthority,
    PreparedEvaluationArtifact,
    SnapshotSigningRequest,
    build_evaluation_collection_authority,
)
from athena_context.contracts import (
    EvidenceSnapshot,
    NormalizationCollisionError,
    SubscriptionScope,
    canonicalize_json,
    compute_artifact_digest,
    resolve_manifest_profile,
)
from athena_context.evidence import EvidenceCollectionCommand
from athena_context.fixtures import CANONICAL_PRIVATE_KEY
from wc013_support import (
    APPROVER,
    CONTEXT_OBJECT_ID,
    CURRENT_NOW,
    MCP_OBJECT_ID,
    MCP_SERVICE_ACTOR,
    NOW,
    PRIVATE_ENDPOINT,
    PUBLICATION_SERVICE,
    PUBLISHER,
    DemoHarness,
    DeterministicIngestionSigner,
    ReplayGuard,
    ScenarioTransport,
    build_current_synthetic_manifest,
    build_harness,
    deployment_assertion,
    key_anchor,
    key_resolver,
    operator_approval,
    scope,
    trust_configuration,
    verified_deployment_configuration,
)

EXPECTED_VERDICTS = {
    "db-singleton-supported": "expectedConstraint",
    "db-zone-loss-acceptance": "acceptedResidualRisk",
    "db-zone-loss-spof": "acceptedResidualRisk",
    "web-zone-distribution": "pass",
    "worker-db-zone-colocation": "pass",
}


def _changed_assertion_payload(**updates: object) -> dict[str, object]:
    unsigned = deployment_assertion().model_copy(
        update={
            **updates,
            "assertion_digest": "sha256:" + ("0" * 64),
        }
    )
    payload = unsigned.model_dump(mode="python", exclude={"assertion_digest"})
    return {
        **payload,
        "assertion_digest": compute_artifact_digest(unsigned._digest_payload()),
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
    assert harness.store.publication_count == 1
    receipt = harness.store.load_receipt(PUBLISHER.actor_id, "wc013-success")
    assert receipt is not None
    assert receipt.workload_id == harness.command.manifest_id
    assert receipt.material.private_mcp_endpoint == PRIVATE_ENDPOINT
    assert receipt.candidate_digest.startswith("sha256:")
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


def test_approval_read_authorization_uses_only_the_stored_workload() -> None:
    harness = build_harness()
    service = harness.context_resolver.service
    unauthorized = Actor(
        actor_id="wc013-ungranted-approval-reader",
        kind=ActorKind.HUMAN,
    )
    cross_workload = Actor(
        actor_id="wc013-foreign-workload-auditor",
        kind=ActorKind.HUMAN,
    )
    foreign_grant = RoleGrant(
        actor_id=cross_workload.actor_id,
        role=Role.AUDITOR,
        scope=WorkloadGrantScope(
            workload_id="wl-foreign-approval-authority"
        ),
    )
    harness.authorization.add_grant(foreign_grant)
    original = harness.approval_registry.resolve(
        harness.approval.decision_id
    )

    with pytest.raises(AuthorizationError):
        service.get_demo_evaluation_approval(
            unauthorized,
            harness.approval.decision_id,
        )
    with pytest.raises(AuthorizationError):
        service.get_demo_evaluation_approval(
            cross_workload,
            harness.approval.decision_id,
        )

    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-service-approval-read-publication",
        harness.command,
    )
    assert result.publication.approval_decision_id == (
        harness.approval.decision_id
    )
    publisher_grant = RoleGrant(
        actor_id=PUBLISHER.actor_id,
        role=Role.PUBLISHER,
    )
    harness.authorization.remove_grant(publisher_grant)

    with pytest.raises(AuthorizationError):
        service.get_demo_evaluation_approval(
            PUBLISHER,
            harness.approval.decision_id,
        )

    assert harness.approval_registry.resolve(
        harness.approval.decision_id
    ) == original
    harness.authorization.add_grant(publisher_grant)
    assert harness.store.publication_count == 1


def test_approval_creation_uses_authenticated_actor_and_millisecond_clock() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    harness.clock.advance(timedelta(milliseconds=123))
    service = harness.context_resolver.service
    decision_id = "approval-wc013-authoritative-provenance"
    idempotency_key = "wc013-authoritative-provenance"
    command_payload = {
        "decision_id": decision_id,
        "expires_at": harness.clock.value + timedelta(hours=1),
        "manifest_id": harness.command.manifest_id,
        "manifest_version": harness.approval.manifest_version,
        "manifest_digest": harness.command.expected_manifest_digest,
        "profile_id": harness.command.profile_id,
        "authorized_scope": harness.command.authorized_scope,
        "reason": "Authorize exact server-owned approval provenance",
    }
    forged_payload = {
        **command_payload,
        "approved_by": Actor(
            actor_id="wc013-forged-human",
            kind=ActorKind.HUMAN,
        ),
        "approved_at": datetime(2020, 1, 1, tzinfo=UTC),
    }
    audit_before = service.audit_history(
        APPROVER,
        harness.command.manifest_id,
    )

    with pytest.raises(ValidationError):
        CreateDemoEvaluationApprovalCommand.model_validate(forged_payload)
    assert not hasattr(service, "put_demo_evaluation_approval")
    assert service.get_demo_evaluation_approval(APPROVER, decision_id) is None
    assert harness.store.publication_count == 0
    assert (
        service.audit_history(APPROVER, harness.command.manifest_id)
        == audit_before
    )

    command = CreateDemoEvaluationApprovalCommand.model_validate(
        command_payload
    )
    expired = command.model_copy(
        update={"expires_at": harness.clock.value - timedelta(seconds=1)}
    )
    with pytest.raises(
        DemoEvaluationApprovalError,
        match="expiry must be after",
    ):
        service.create_demo_evaluation_approval(
            APPROVER,
            idempotency_key,
            expired,
        )
    assert service.get_demo_evaluation_approval(APPROVER, decision_id) is None
    assert harness.store.publication_count == 0
    assert (
        service.audit_history(APPROVER, harness.command.manifest_id)
        == audit_before
    )

    expected_time = harness.clock.value
    approval = service.create_demo_evaluation_approval(
        APPROVER,
        idempotency_key,
        command,
    )
    replay = service.create_demo_evaluation_approval(
        APPROVER,
        idempotency_key,
        command,
    )

    assert replay == approval
    assert approval.approved_by == APPROVER
    assert approval.approved_at == expected_time
    assert approval.approved_at.microsecond == 123_000
    assert approval.revision == 1
    assert approval.manifest_id == harness.command.manifest_id
    assert approval.manifest_digest == (
        harness.command.expected_manifest_digest
    )
    assert approval.profile_id == harness.command.profile_id
    assert approval.authorized_scope == harness.command.authorized_scope
    assert approval.private_mcp_endpoint == (
        harness.deployment_configuration.assertion.azure_mcp_internal_endpoint
    )
    assert approval.evidence_identity_object_id == MCP_OBJECT_ID
    approval_audit = service.audit_history(
        APPROVER,
        harness.command.manifest_id,
    )[-1]
    assert approval_audit.action is (
        AuditAction.DEMO_EVALUATION_APPROVAL_CREATED
    )
    assert approval_audit.actor == APPROVER
    assert approval_audit.occurred_at == expected_time

    harness.clock.advance(timedelta(milliseconds=877))
    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-authoritative-provenance-publication",
        harness.command.model_copy(
            update={"approval_decision_id": decision_id}
        ),
    )

    assert result.publication.approved_by == APPROVER
    assert result.publication.approved_at == expected_time
    assert harness.store.publication_count == 1


def test_current_2026_manifest_is_human_published_then_fully_evaluated() -> None:
    candidate = build_current_synthetic_manifest(as_of=CURRENT_NOW)
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=candidate,
    )

    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-current-2026",
        harness.command,
    )

    published = harness.context_resolver.view.published
    assert candidate.audit.published_by == "synthetic-unpublished-candidate"
    assert published.manifest.manifest_id == "wl-athena-wc013-current-demo"
    assert published.manifest.manifest_version == "2.0.0"
    assert published.manifest.audit.published_by == "athena-context-api"
    assert published.manifest.audit.published_at == published.published_at
    assert published.manifest_digest == (
        published.manifest.compute_artifact_digest_value()
    )
    assert published.approval.approved_by == APPROVER
    assert published.publication_authorized_by == PUBLISHER
    assert harness.transport.calls == 1
    assert harness.store.publication_count == 1
    assert {
        finding.clause_id: finding.verdict for finding in result.findings
    } == EXPECTED_VERDICTS


def test_manifest_defined_prod_east_profile_normalizes_and_evaluates() -> None:
    manifest = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        add_prod_east=True,
    )
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=manifest,
        profile_id="PROD-EAST",
    )

    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-prod-east",
        harness.command,
    )

    assert harness.command.profile_id == "prod-east"
    assert harness.approval.profile_id == "prod-east"
    assert result.publication.profile_id == "prod-east"
    assert {
        finding.clause_id: finding.verdict for finding in result.findings
    } == EXPECTED_VERDICTS


def test_unicode_profile_normalization_succeeds_with_versionless_atomic_commit() -> None:
    composed = "café-east"
    decomposed = "cafe\u0301-east"
    manifest = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        additional_profile_ids=(composed,),
    )
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=manifest,
        profile_id=decomposed,
    )
    command = type(harness.command).model_validate(
        {
            **harness.command.model_dump(mode="python"),
            "manifest_version": None,
            "profile_id": decomposed,
        }
    )
    resolved = harness.context_resolver.resolve(
        PublishedContextSelection(
            manifest_id=command.manifest_id,
            manifest_version=None,
            profile_id=decomposed,
        ),
        as_of=CURRENT_NOW,
    )
    decomposed_profile = resolved.profile.model_copy(
        update={"profile_id": decomposed}
    )
    decomposed_context = resolved.model_copy(
        update={"profile": decomposed_profile}
    )

    validate_published_context_binding(
        command,
        harness.approval,
        decomposed_context,
    )
    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-unicode-versionless-profile",
        command,
    )

    assert command.profile_id == composed
    assert result.publication.profile_id == composed
    assert harness.store.publication_count == 1


def test_unicode_profile_normalization_collision_is_rejected() -> None:
    with pytest.raises(
        NormalizationCollisionError,
        match="duplicate normalized",
    ):
        build_current_synthetic_manifest(
            as_of=CURRENT_NOW,
            additional_profile_ids=(
                "café-east",
                "cafe\u0301-east",
            ),
        )


def test_unknown_normalized_profile_rejects_before_mcp_collection() -> None:
    unknown_decomposed = "cafe\u0301-unknown"
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(
            as_of=CURRENT_NOW,
            additional_profile_ids=("café-east",),
        ),
    )
    command = type(harness.command).model_validate(
        {
            **harness.command.model_dump(mode="python"),
            "profile_id": unknown_decomposed,
        }
    )

    with pytest.raises(EvaluationFailedClosedError, match="missing, ambiguous"):
        harness.service.evaluate(
            PUBLISHER,
            "wc013-unknown-profile",
            command,
        )

    assert command.profile_id == "café-unknown"
    assert harness.transport.calls == 0
    assert harness.store.publication_count == 0


def _assert_no_artifact(
    *,
    harness: DemoHarness,
    idempotency_key: str,
) -> None:
    assert harness.store.load_receipt(PUBLISHER.actor_id, idempotency_key) is None
    assert harness.store.resolve_publication(harness.command.snapshot_id) is None
    assert harness.store.resolve_result(harness.command.snapshot_id) is None
    assert harness.store.publication_count == 0


def _mutate_same_uow_after_extensible_preparation(
    harness: DemoHarness,
    mutation: Callable[[Any], None],
) -> None:
    """Wrap the real transaction so mutation uses its active local state."""

    store = harness.context_resolver.store
    original_transaction = store.transaction

    @contextmanager
    def transaction() -> Iterator[Any]:
        with original_transaction() as active_transaction:
            original_insert = (
                active_transaction._put_context_service_evaluation
            )

            def insert_with_same_uow_mutation(
                capability: object,
                condition: object,
                artifact_preparation: Callable[[object], object],
            ) -> object:
                def mutate_after_preparation(
                    trusted_key: object,
                ) -> object:
                    prepared = artifact_preparation(trusted_key)
                    mutation(active_transaction)
                    return prepared

                return original_insert(
                    capability,
                    condition,
                    mutate_after_preparation,
                )

            active_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
                insert_with_same_uow_mutation
            )
            yield active_transaction

    store.transaction = transaction  # type: ignore[method-assign]


def _delay_final_authority_or_persistence(
    harness: DemoHarness,
    *,
    location: str,
    delay: timedelta,
) -> None:
    if location == "finalAuthorityResolution":
        service = harness.context_resolver.service
        service._before_evaluation_artifact_insert = (  # type: ignore[method-assign]
            lambda: harness.clock.advance(delay)
        )
        return
    if location == "persistence":
        harness.context_resolver.store._before_evaluation_commit_timestamp = (  # type: ignore[method-assign]
            lambda: harness.clock.advance(delay)
        )
        return
    raise AssertionError(f"unsupported commit delay location: {location}")


def _capture_conditional_publication_inputs(
    harness: DemoHarness,
) -> tuple[
    EvaluationCommitAuthorityCondition,
    PreparedEvaluationArtifact,
]:
    """Capture a valid request while forcing the owning service to roll back."""

    captured: dict[str, object] = {}
    store = harness.context_resolver.store
    original_transaction = store.transaction

    @contextmanager
    def transaction() -> Iterator[Any]:
        with original_transaction() as active_transaction:
            original_insert = (
                active_transaction._put_context_service_evaluation
            )

            def capture_before_insert(
                capability: object,
                condition: EvaluationCommitAuthorityCondition,
                artifact_preparation: Callable[
                    [EvaluationTrustedKeyAuthority],
                    PreparedEvaluationArtifact,
                ],
            ) -> object:
                del capability
                trusted_key = (
                    active_transaction.get_demo_evaluation_trusted_key(
                        condition.trusted_key_anchor
                    )
                )
                assert trusted_key is not None
                captured["condition"] = condition
                captured["prepared"] = artifact_preparation(trusted_key)
                raise EvaluationFailedClosedError(
                    "captured direct transaction test inputs"
                )

            active_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
                capture_before_insert
            )
            try:
                yield active_transaction
            finally:
                active_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
                    original_insert
                )

    store.transaction = transaction  # type: ignore[method-assign]
    try:
        with pytest.raises(
            EvaluationFailedClosedError,
            match="captured direct transaction",
        ):
            harness.service.evaluate(
                PUBLISHER,
                "wc013-capture-private-publication-inputs",
                harness.command,
            )
    finally:
        store.transaction = original_transaction  # type: ignore[method-assign]

    condition = captured["condition"]
    prepared = captured["prepared"]
    assert isinstance(condition, EvaluationCommitAuthorityCondition)
    assert isinstance(prepared, PreparedEvaluationArtifact)
    return condition, prepared


@pytest.mark.parametrize(
    ("authority_expiry", "expected_error", "expected_message"),
    [
        ("approval", DemoEvaluationApprovalError, "not active"),
        ("governance", EvaluationFailedClosedError, "inactive governance"),
        ("riskAcceptance", EvaluationFailedClosedError, "inactive governance"),
        ("snapshot", EvaluationFailedClosedError, "snapshot became stale"),
    ],
)
@pytest.mark.parametrize(
    "delay_location",
    ["finalAuthorityResolution", "persistence"],
)
def test_expiry_during_final_authority_or_persistence_rolls_back_atomically(
    authority_expiry: str,
    expected_error: type[Exception],
    expected_message: str,
    delay_location: str,
) -> None:
    expiring_at = CURRENT_NOW + timedelta(seconds=30)
    manifest = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        override_expires_at=(
            expiring_at if authority_expiry == "governance" else None
        ),
        risk_acceptance_expires_at=(
            expiring_at if authority_expiry == "riskAcceptance" else None
        ),
        production_extends_development=authority_expiry == "governance",
    )
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=manifest,
        approval_expires_at=(
            expiring_at if authority_expiry == "approval" else None
        ),
        snapshot_freshness_seconds=(
            30 if authority_expiry == "snapshot" else 300
        ),
    )
    idempotency_key = (
        f"wc013-{authority_expiry}-{delay_location}-commit-expiry"
    )
    _delay_final_authority_or_persistence(
        harness,
        location=delay_location,
        delay=timedelta(minutes=1),
    )

    with pytest.raises(expected_error, match=expected_message):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_approval_expiry_during_transaction_aborts_conditional_commit() -> None:
    manifest = build_current_synthetic_manifest(as_of=CURRENT_NOW)
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=manifest,
        approval_expires_at=CURRENT_NOW + timedelta(seconds=30),
    )
    idempotency_key = "wc013-approval-expiry-race"
    harness.context_resolver.store._before_evaluation_commit_timestamp = (  # type: ignore[method-assign]
        lambda: harness.clock.advance(timedelta(minutes=1))
    )

    with pytest.raises(
        DemoEvaluationApprovalError,
        match="not active",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_policy_evidence_freshness_expiry_during_commit_rolls_back() -> None:
    manifest = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        evidence_freshness_seconds=30,
    )
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=manifest,
    )
    idempotency_key = "wc013-policy-freshness-expiry-race"
    harness.context_resolver.store._before_evaluation_commit_timestamp = (  # type: ignore[method-assign]
        lambda: harness.clock.advance(timedelta(minutes=1))
    )

    with pytest.raises(
        EvaluationFailedClosedError,
        match="policy evidence freshness failed",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_signing_key_expiry_during_commit_rolls_back() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
        trusted_key_expires_at=CURRENT_NOW + timedelta(seconds=30),
    )
    idempotency_key = "wc013-signing-key-expiry-race"
    harness.context_resolver.store._before_evaluation_commit_timestamp = (  # type: ignore[method-assign]
        lambda: harness.clock.advance(timedelta(minutes=1))
    )

    with pytest.raises(
        EvaluationFailedClosedError,
        match="trusted signing key is .* expired",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_signing_key_revocation_during_persistence_delay_rolls_back() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    idempotency_key = "wc013-signing-key-revocation-race"
    harness.context_resolver.store._before_evaluation_commit_timestamp = (  # type: ignore[method-assign]
        lambda: harness.trust_registry.disable(
            revoked_at=harness.clock.value,
        )
    )

    with pytest.raises(
        EvaluationFailedClosedError,
        match="authority changed during the publication transaction",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    current_trust = harness.trust_registry.resolve()
    assert current_trust is not None
    assert current_trust.record.enabled is False
    assert current_trust.revoked_at is not None
    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


@pytest.mark.parametrize(
    ("expiring_condition", "expected_error", "expected_message"),
    [
        ("approval", DemoEvaluationApprovalError, "not active"),
        ("key", EvaluationFailedClosedError, "trusted signing key is"),
        ("snapshot", EvaluationFailedClosedError, "snapshot became stale"),
        ("governance", EvaluationFailedClosedError, "inactive governance"),
        ("riskAcceptance", EvaluationFailedClosedError, "inactive governance"),
        (
            "evidenceFreshness",
            EvaluationFailedClosedError,
            "policy evidence freshness failed",
        ),
    ],
)
def test_expiry_during_final_crypto_policy_work_rolls_back_atomically(
    expiring_condition: str,
    expected_error: type[Exception],
    expected_message: str,
) -> None:
    expiring_at = CURRENT_NOW + timedelta(seconds=30)
    manifest = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        override_expires_at=(
            expiring_at if expiring_condition == "governance" else None
        ),
        risk_acceptance_expires_at=(
            expiring_at if expiring_condition == "riskAcceptance" else None
        ),
        production_extends_development=expiring_condition == "governance",
        evidence_freshness_seconds=(
            30 if expiring_condition == "evidenceFreshness" else None
        ),
    )
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=manifest,
        approval_expires_at=(
            expiring_at if expiring_condition == "approval" else None
        ),
        trusted_key_expires_at=(
            expiring_at if expiring_condition == "key" else None
        ),
        snapshot_freshness_seconds=(
            30 if expiring_condition == "snapshot" else 300
        ),
    )
    idempotency_key = f"wc013-{expiring_condition}-crypto-policy-expiry"
    context_service = harness.context_resolver.service
    original_evaluation = (
        context_service._evaluate_demo_snapshot_for_publication
    )

    def delayed_evaluation(*args: object, **kwargs: object) -> object:
        result = original_evaluation(*args, **kwargs)  # type: ignore[arg-type]
        harness.clock.advance(timedelta(minutes=1))
        return result

    context_service._evaluate_demo_snapshot_for_publication = (  # type: ignore[method-assign]
        delayed_evaluation
    )

    with pytest.raises(expected_error, match=expected_message):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_key_record_property_delay_occurs_before_authoritative_timestamp() -> None:
    expires_at = CURRENT_NOW + timedelta(seconds=30)
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
        trusted_key_expires_at=expires_at,
    )
    current = harness.trust_registry.resolve()
    assert current is not None
    delayed = False

    class DelayedKeyRecord:
        anchor = current.record.anchor
        public_key = current.record.public_key
        activated_at = current.record.activated_at
        retired_at = current.record.retired_at
        expires_at = current.record.expires_at

        @property
        def enabled(self) -> bool:
            nonlocal delayed
            if not delayed and any(
                frame.function == "_seal_trusted_key_for_finalization"
                for frame in stack()
            ):
                delayed = True
                harness.clock.advance(timedelta(minutes=1))
            return True

    malicious_authority = EvaluationTrustedKeyAuthority(
        record=DelayedKeyRecord(),  # type: ignore[arg-type]
        revision=current.revision + 1,
    )
    harness.context_resolver.service.put_demo_evaluation_trusted_key(
        APPROVER,
        malicious_authority,
        expected_revision=current.revision,
    )
    idempotency_key = "wc013-key-property-delay"

    with pytest.raises(
        EvaluationFailedClosedError,
        match="trusted signing key is",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert delayed is True
    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


@pytest.mark.parametrize(
    ("expiring_condition", "expected_error", "expected_message"),
    [
        ("approval", DemoEvaluationApprovalError, "not active"),
        ("key", EvaluationFailedClosedError, "trusted signing key is"),
        ("snapshot", EvaluationFailedClosedError, "snapshot became stale"),
        ("governance", EvaluationFailedClosedError, "inactive governance"),
        ("riskAcceptance", EvaluationFailedClosedError, "inactive governance"),
        (
            "evidenceFreshness",
            EvaluationFailedClosedError,
            "policy evidence freshness failed",
        ),
    ],
)
def test_delay_in_former_post_timestamp_validation_is_sampled_before_commit_time(
    expiring_condition: str,
    expected_error: type[Exception],
    expected_message: str,
) -> None:
    expiring_at = CURRENT_NOW + timedelta(seconds=30)
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(
            as_of=CURRENT_NOW,
            override_expires_at=(
                expiring_at if expiring_condition == "governance" else None
            ),
            risk_acceptance_expires_at=(
                expiring_at
                if expiring_condition == "riskAcceptance"
                else None
            ),
            production_extends_development=(
                expiring_condition == "governance"
            ),
            evidence_freshness_seconds=(
                30 if expiring_condition == "evidenceFreshness" else None
            ),
        ),
        approval_expires_at=(
            expiring_at if expiring_condition == "approval" else None
        ),
        trusted_key_expires_at=(
            expiring_at if expiring_condition == "key" else None
        ),
        snapshot_freshness_seconds=(
            30 if expiring_condition == "snapshot" else 300
        ),
    )
    idempotency_key = f"wc013-{expiring_condition}-sealed-finalizer-expiry"
    context_service = harness.context_resolver.service
    original_validation = (
        context_service._validate_precomputed_finding_time_bounds
    )

    def delayed_validation(*args: object, **kwargs: object) -> None:
        original_validation(*args, **kwargs)  # type: ignore[arg-type]
        harness.clock.advance(timedelta(minutes=1))

    context_service._validate_precomputed_finding_time_bounds = (  # type: ignore[method-assign]
        delayed_validation
    )

    with pytest.raises(expected_error, match=expected_message):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


@pytest.mark.parametrize(
    "temporal_field",
    [
        "approval_active_from",
        "approval_expires_at",
        "snapshot_active_from",
        "snapshot_expires_at",
        "governance_active_from",
        "governance_expires_at",
        "risk_active_from",
        "risk_expires_at",
        "evidence_fresh_until",
    ],
)
def test_all_temporal_bounds_are_sealed_before_primitive_commit_clock(
    temporal_field: str,
) -> None:
    """Adversarial datetime behavior cannot execute after the final clock read."""

    expires_at = CURRENT_NOW + timedelta(seconds=30)
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(
            as_of=CURRENT_NOW,
            override_expires_at=expires_at,
            risk_acceptance_expires_at=expires_at,
            production_extends_development=True,
            evidence_freshness_seconds=30,
        ),
        approval_expires_at=expires_at,
        snapshot_freshness_seconds=30,
    )
    delayed = False
    armed = False
    final_clock_reads = 0
    original_final_clock = harness.clock.now_epoch_milliseconds

    def tracked_final_clock() -> int:
        nonlocal final_clock_reads
        final_clock_reads += 1
        return original_final_clock()

    harness.clock.now_epoch_milliseconds = tracked_final_clock  # type: ignore[method-assign]

    class DelayingDateTime(datetime):
        def astimezone(self, tz: object = None) -> datetime:
            nonlocal delayed
            if armed and not delayed:
                assert final_clock_reads == 0
                delayed = True
                harness.clock.advance(timedelta(minutes=1))
            return super().astimezone(tz)  # type: ignore[arg-type]

    store = harness.context_resolver.store
    original_transaction = store.transaction

    @contextmanager
    def transaction() -> Iterator[Any]:
        with original_transaction() as active_transaction:
            original_insert = (
                active_transaction._put_context_service_evaluation
            )

            def insert_with_adversarial_temporal_bound(
                capability: object,
                condition: EvaluationCommitAuthorityCondition,
                artifact_preparation: Callable[
                    [EvaluationTrustedKeyAuthority],
                    PreparedEvaluationArtifact,
                ],
            ) -> object:
                def prepare(
                    trusted_key: EvaluationTrustedKeyAuthority,
                ) -> PreparedEvaluationArtifact:
                    nonlocal armed
                    prepared = artifact_preparation(trusted_key)
                    values = {
                        field: getattr(
                            prepared.temporal_validity,
                            field,
                        )
                        for field in (
                            "approval_active_from",
                            "approval_expires_at",
                            "snapshot_active_from",
                            "snapshot_expires_at",
                            "governance_active_from",
                            "governance_expires_at",
                            "risk_active_from",
                            "risk_expires_at",
                            "evidence_fresh_until",
                        )
                    }
                    original_bound = values[temporal_field]
                    assert isinstance(original_bound, datetime)
                    values[temporal_field] = DelayingDateTime(
                        original_bound.year,
                        original_bound.month,
                        original_bound.day,
                        original_bound.hour,
                        original_bound.minute,
                        original_bound.second,
                        original_bound.microsecond,
                        tzinfo=original_bound.tzinfo or UTC,
                        fold=original_bound.fold,
                    )
                    validity = EvaluationTemporalValidity(**values)  # type: ignore[arg-type]
                    armed = True
                    return replace(
                        prepared,
                        temporal_validity=validity,
                    )

                return original_insert(
                    capability,
                    condition,
                    prepare,
                )

            active_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
                insert_with_adversarial_temporal_bound
            )
            yield active_transaction

    store.transaction = transaction  # type: ignore[method-assign]
    idempotency_key = f"wc013-sealed-temporal-{temporal_field}"
    try:
        with pytest.raises(
            (DemoEvaluationApprovalError, EvaluationFailedClosedError),
        ):
            harness.service.evaluate(
                PUBLISHER,
                idempotency_key,
                harness.command,
            )
    finally:
        store.transaction = original_transaction  # type: ignore[method-assign]
        harness.clock.now_epoch_milliseconds = original_final_clock  # type: ignore[method-assign]

    assert delayed is True
    assert final_clock_reads == 0
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_polymorphic_commit_clock_primitive_fails_before_insertion() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    original_final_clock = harness.clock.now_epoch_milliseconds

    class PolymorphicEpoch(int):
        def __le__(self, other: object) -> bool:
            del other
            harness.clock.advance(timedelta(minutes=1))
            return True

    harness.clock.now_epoch_milliseconds = (  # type: ignore[method-assign]
        lambda: PolymorphicEpoch(original_final_clock())
    )
    idempotency_key = "wc013-polymorphic-final-clock"
    try:
        with pytest.raises(
            EvaluationFailedClosedError,
            match="non-primitive",
        ):
            harness.service.evaluate(
                PUBLISHER,
                idempotency_key,
                harness.command,
            )
    finally:
        harness.clock.now_epoch_milliseconds = original_final_clock  # type: ignore[method-assign]

    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_temporal_subclass_same_uow_approval_revocation_rolls_back() -> None:
    """A temporal callback runs before time sampling and cannot commit a revocation."""

    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    original_approval = harness.approval_registry.resolve(
        harness.approval.decision_id
    )
    assert original_approval is not None
    store = harness.context_resolver.store
    original_transaction = store.transaction
    original_final_clock = harness.clock.now_epoch_milliseconds
    final_clock_reads = 0
    armed = False
    revoked = False

    def tracked_final_clock() -> int:
        nonlocal final_clock_reads
        final_clock_reads += 1
        return original_final_clock()

    harness.clock.now_epoch_milliseconds = tracked_final_clock  # type: ignore[method-assign]

    @contextmanager
    def transaction() -> Iterator[Any]:
        with original_transaction() as active_transaction:
            original_insert = (
                active_transaction._put_context_service_evaluation
            )

            class RevokingDateTime(datetime):
                def astimezone(self, tz: object = None) -> datetime:
                    nonlocal revoked
                    if armed and not revoked:
                        assert final_clock_reads == 0
                        revoked = True
                        current = (
                            active_transaction
                            .get_demo_evaluation_approval(
                                original_approval.decision_id
                            )
                        )
                        assert current is not None
                        active_transaction.put_demo_evaluation_approval(
                            current.model_copy(
                                update={
                                    "status": "revoked",
                                    "revision": current.revision + 1,
                                    "revoked_at": harness.clock.value,
                                }
                            ),
                            expected_revision=current.revision,
                        )
                    return super().astimezone(tz)  # type: ignore[arg-type]

            def insert_with_revoking_temporal_bound(
                capability: object,
                condition: EvaluationCommitAuthorityCondition,
                artifact_preparation: Callable[
                    [EvaluationTrustedKeyAuthority],
                    PreparedEvaluationArtifact,
                ],
            ) -> object:
                def prepare(
                    trusted_key: EvaluationTrustedKeyAuthority,
                ) -> PreparedEvaluationArtifact:
                    nonlocal armed
                    prepared = artifact_preparation(trusted_key)
                    original_bound = (
                        prepared.temporal_validity.approval_expires_at
                    )
                    adversarial_bound = RevokingDateTime(
                        original_bound.year,
                        original_bound.month,
                        original_bound.day,
                        original_bound.hour,
                        original_bound.minute,
                        original_bound.second,
                        original_bound.microsecond,
                        tzinfo=original_bound.tzinfo or UTC,
                        fold=original_bound.fold,
                    )
                    validity = replace(
                        prepared.temporal_validity,
                        approval_expires_at=adversarial_bound,
                    )
                    armed = True
                    return replace(
                        prepared,
                        temporal_validity=validity,
                    )

                return original_insert(
                    capability,
                    condition,
                    prepare,
                )

            active_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
                insert_with_revoking_temporal_bound
            )
            yield active_transaction

    store.transaction = transaction  # type: ignore[method-assign]
    idempotency_key = "wc013-temporal-same-uow-approval-revocation"
    try:
        with pytest.raises(DemoEvaluationApprovalError):
            harness.service.evaluate(
                PUBLISHER,
                idempotency_key,
                harness.command,
            )
    finally:
        store.transaction = original_transaction  # type: ignore[method-assign]
        harness.clock.now_epoch_milliseconds = original_final_clock  # type: ignore[method-assign]

    assert revoked is True
    assert final_clock_reads == 0
    assert (
        harness.approval_registry.resolve(original_approval.decision_id)
        == original_approval
    )
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_collection_authority_subclass_cannot_spoof_foreign_endpoint() -> None:
    """Polymorphic equality cannot replace store-pinned WC-008 authority."""

    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    foreign_configuration = verified_deployment_configuration(
        "https://foreign-mcp.internal"
    )
    foreign = build_evaluation_collection_authority(
        foreign_configuration,
        trust_configuration(),
        authorized_scope=harness.command.authorized_scope,
    )

    class AlwaysEqualCollectionAuthority(EvaluationCollectionAuthority):
        def __eq__(self, other: object) -> bool:
            del other
            return True

        def __ne__(self, other: object) -> bool:
            del other
            return False

    malicious = AlwaysEqualCollectionAuthority(
        deployment_configuration=foreign.deployment_configuration,
        trust_configuration=foreign.trust_configuration,
        reader_assignment=foreign.reader_assignment,
        reader_assignment_revision=foreign.reader_assignment_revision,
        authority_digest=foreign.authority_digest,
    )
    store = harness.context_resolver.store
    original_transaction = store.transaction

    @contextmanager
    def transaction() -> Iterator[Any]:
        with original_transaction() as active_transaction:
            original_insert = (
                active_transaction._put_context_service_evaluation
            )

            def insert_with_foreign_collection_authority(
                capability: object,
                condition: EvaluationCommitAuthorityCondition,
                artifact_preparation: Callable[
                    [EvaluationTrustedKeyAuthority],
                    PreparedEvaluationArtifact,
                ],
            ) -> object:
                return original_insert(
                    capability,
                    replace(
                        condition,
                        collection_authority=malicious,
                    ),
                    artifact_preparation,
                )

            active_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
                insert_with_foreign_collection_authority
            )
            yield active_transaction

    store.transaction = transaction  # type: ignore[method-assign]
    idempotency_key = "wc013-polymorphic-foreign-collection-authority"
    try:
        with pytest.raises(
            EvaluationFailedClosedError,
            match="canonical validation",
        ):
            harness.service.evaluate(
                PUBLISHER,
                idempotency_key,
                harness.command,
            )
    finally:
        store.transaction = original_transaction  # type: ignore[method-assign]

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_exact_foreign_collection_authority_cannot_set_persisted_endpoint() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    foreign = build_evaluation_collection_authority(
        verified_deployment_configuration(
            "https://forged-persisted-mcp.internal"
        ),
        trust_configuration(),
        authorized_scope=harness.command.authorized_scope,
    )
    store = harness.context_resolver.store
    original_transaction = store.transaction

    @contextmanager
    def transaction() -> Iterator[Any]:
        with original_transaction() as active_transaction:
            original_insert = (
                active_transaction._put_context_service_evaluation
            )

            def insert_with_foreign_collection_authority(
                capability: object,
                condition: EvaluationCommitAuthorityCondition,
                artifact_preparation: Callable[
                    [EvaluationTrustedKeyAuthority],
                    PreparedEvaluationArtifact,
                ],
            ) -> object:
                return original_insert(
                    capability,
                    replace(
                        condition,
                        collection_authority=foreign,
                    ),
                    artifact_preparation,
                )

            active_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
                insert_with_foreign_collection_authority
            )
            yield active_transaction

    store.transaction = transaction  # type: ignore[method-assign]
    idempotency_key = "wc013-exact-foreign-collection-authority"
    try:
        with pytest.raises(
            EvaluationFailedClosedError,
            match="canonical validation",
        ):
            harness.service.evaluate(
                PUBLISHER,
                idempotency_key,
                harness.command,
            )
    finally:
        store.transaction = original_transaction  # type: ignore[method-assign]

    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_context_reader_revocation_during_final_policy_work_rolls_back() -> None:
    context_reader = Actor(
        actor_id="wc013-context-reader",
        kind=ActorKind.SERVICE,
    )
    reader_grant = RoleGrant(
        actor_id=context_reader.actor_id,
        role=Role.PUBLISHER,
    )
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
        context_reader_actor=context_reader,
    )
    idempotency_key = "wc013-context-reader-revocation-during-policy"
    context_service = harness.context_resolver.service
    reader_authorization = harness.authorization.authorize(
        context_reader,
        Permission.READ,
        harness.command.manifest_id,
    )
    assert reader_authorization.actor_id == (
        context_reader.actor_id
    )
    assert reader_authorization.permission is Permission.READ
    original_evaluation = (
        context_service._evaluate_demo_snapshot_for_publication
    )

    def revoke_reader(*args: object, **kwargs: object) -> object:
        result = original_evaluation(*args, **kwargs)  # type: ignore[arg-type]
        harness.authorization.remove_grant(reader_grant)
        return result

    context_service._evaluate_demo_snapshot_for_publication = (  # type: ignore[method-assign]
        revoke_reader
    )

    with pytest.raises(
        EvaluationFailedClosedError,
        match="authority changed during the publication transaction",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    assert harness.authorization.authorize(
        PUBLISHER,
        Permission.PUBLISH,
        harness.command.manifest_id,
    ).actor_id == PUBLISHER.actor_id
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


@pytest.mark.parametrize(
    "same_uow_change",
    [
        "readerGrant",
        "publisherGrant",
        "keyDisabled",
        "keyReplaced",
        "approval",
        "context",
    ],
)
def test_same_uow_authority_mutation_after_preparation_rolls_back(
    same_uow_change: str,
) -> None:
    context_reader = Actor(
        actor_id="wc013-same-uow-reader",
        kind=ActorKind.SERVICE,
    )
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
        context_reader_actor=context_reader,
    )
    idempotency_key = f"wc013-same-uow-{same_uow_change}"
    context_service = harness.context_resolver.service
    original_grants, original_grant_revision = (
        context_service.get_demo_evaluation_grants(PUBLISHER)
    )
    original_key = harness.trust_registry.resolve()
    original_approval = harness.approval_registry.resolve(
        harness.approval.decision_id
    )
    assert original_key is not None
    assert original_approval is not None

    def mutate(active_transaction: Any) -> None:
        if same_uow_change in {"readerGrant", "publisherGrant"}:
            actor_id = (
                context_reader.actor_id
                if same_uow_change == "readerGrant"
                else PUBLISHER.actor_id
            )
            grants, revision = active_transaction.get_evaluation_grants()
            active_transaction.replace_evaluation_grants(
                tuple(grant for grant in grants if grant.actor_id != actor_id),
                expected_revision=revision,
            )
            return
        if same_uow_change in {"keyDisabled", "keyReplaced"}:
            current = active_transaction.get_demo_evaluation_trusted_key(
                original_key.record.anchor
            )
            assert current is not None
            replacement_record = replace(
                current.record,
                enabled=same_uow_change != "keyDisabled",
                expires_at=(
                    current.record.expires_at + timedelta(days=1)
                    if (
                        same_uow_change == "keyReplaced"
                        and current.record.expires_at is not None
                    )
                    else current.record.expires_at
                ),
            )
            active_transaction.put_demo_evaluation_trusted_key(
                EvaluationTrustedKeyAuthority(
                    record=replacement_record,
                    revision=current.revision + 1,
                    revoked_at=(
                        harness.clock.value
                        if same_uow_change == "keyDisabled"
                        else None
                    ),
                ),
                expected_revision=current.revision,
            )
            return
        if same_uow_change == "approval":
            current = active_transaction.get_demo_evaluation_approval(
                original_approval.decision_id
            )
            assert current is not None
            active_transaction.put_demo_evaluation_approval(
                current.model_copy(
                    update={
                        "status": "revoked",
                        "revision": current.revision + 1,
                        "revoked_at": harness.clock.value,
                    }
                ),
                expected_revision=current.revision,
            )
            return
        published = harness.context_resolver.view.published
        active_transaction.put_supersession(
            Supersession(
                manifest_id=published.manifest_id,
                superseded_version=published.manifest_version,
                replacement_version="9.9.9",
                superseded_by=PUBLISHER,
                superseded_at=harness.clock.value,
                reason="Exercise same-transaction context authority rollback",
            )
        )

    _mutate_same_uow_after_extensible_preparation(harness, mutate)

    with pytest.raises(
        (
            AuthorizationError,
            DemoEvaluationApprovalError,
            EvaluationFailedClosedError,
        )
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    current_grants, current_grant_revision = (
        context_service.get_demo_evaluation_grants(PUBLISHER)
    )
    assert current_grants == original_grants
    assert current_grant_revision == original_grant_revision
    assert harness.trust_registry.resolve() == original_key
    assert (
        harness.approval_registry.resolve(original_approval.decision_id)
        == original_approval
    )
    assert harness.context_resolver.view.supersession is None
    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


@pytest.mark.parametrize(
    "stale_grant",
    ["publisher", "contextReader"],
)
def test_polymorphic_authority_equality_cannot_mask_stale_grant(
    stale_grant: str,
) -> None:
    context_reader = Actor(
        actor_id="wc013-polymorphic-token-reader",
        kind=ActorKind.SERVICE,
    )
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
        context_reader_actor=context_reader,
    )
    store = harness.context_resolver.store
    original_transaction = store.transaction

    class AlwaysEqualAuthority(EvaluationAuthorityToken):
        def __eq__(self, other: object) -> bool:
            del other
            return True

        def __ne__(self, other: object) -> bool:
            del other
            return False

    @contextmanager
    def transaction() -> Iterator[Any]:
        with original_transaction() as active_transaction:
            original_insert = (
                active_transaction._put_context_service_evaluation
            )

            def insert_with_polymorphic_expected_authority(
                capability: object,
                condition: EvaluationCommitAuthorityCondition,
                artifact_preparation: Callable[
                    [EvaluationTrustedKeyAuthority],
                    PreparedEvaluationArtifact,
                ],
            ) -> object:
                grants, revision = (
                    active_transaction.get_evaluation_grants()
                )
                active_transaction.replace_evaluation_grants(
                    (
                        *grants,
                        RoleGrant(
                            actor_id="wc013-unrelated-revision-reader",
                            role=Role.READER,
                            scope=grants[0].scope,
                        ),
                    ),
                    expected_revision=revision,
                )
                changed_grants, changed_revision = (
                    active_transaction.get_evaluation_grants()
                )
                current_publisher = authorize_role_grants(
                    PUBLISHER,
                    Permission.PUBLISH,
                    condition.command.manifest_id,
                    grants=changed_grants,
                    grant_revision=changed_revision,
                )
                current_reader = authorize_role_grants(
                    context_reader,
                    Permission.READ,
                    condition.command.manifest_id,
                    grants=changed_grants,
                    grant_revision=changed_revision,
                )
                previous = condition.expected_authority
                assert (
                    previous.authorization.grant_revision
                    != current_publisher.grant_revision
                )
                assert (
                    previous.context_reader_authorization.grant_revision
                    != current_reader.grant_revision
                )
                forged = AlwaysEqualAuthority(
                    context=previous.context,
                    approval=previous.approval,
                    authorization=(
                        previous.authorization
                        if stale_grant == "publisher"
                        else current_publisher
                    ),
                    context_reader_authorization=(
                        previous.context_reader_authorization
                        if stale_grant == "contextReader"
                        else current_reader
                    ),
                    trusted_key=previous.trusted_key,
                )
                return original_insert(
                    capability,
                    replace(
                        condition,
                        expected_authority=forged,
                    ),
                    artifact_preparation,
                )

            active_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
                insert_with_polymorphic_expected_authority
            )
            yield active_transaction

    store.transaction = transaction  # type: ignore[method-assign]
    idempotency_key = f"wc013-polymorphic-{stale_grant}"

    with pytest.raises(
        EvaluationFailedClosedError,
        match="authority revision changed",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    _, current_revision = (
        harness.context_resolver.service.get_demo_evaluation_grants(
            PUBLISHER
        )
    )
    assert current_revision == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_direct_transaction_cannot_publish_with_no_grant_and_forged_approval() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    condition, prepared = _capture_conditional_publication_inputs(harness)
    forged_approval = harness.approval.model_copy(
        update={
            "decision_id": "approval-wc013-direct-forged",
            "revision": 1,
        }
    )

    with pytest.raises(
        EvaluationFailedClosedError,
        match="ContextService capability",
    ), harness.context_resolver.store.transaction() as transaction:
        assert not hasattr(transaction, "put_evaluation_conditionally")
        grants, revision = transaction.get_evaluation_grants()
        assert grants
        transaction.replace_evaluation_grants(
            (),
            expected_revision=revision,
        )
        transaction.put_demo_evaluation_approval(
            forged_approval,
            expected_revision=None,
        )
        transaction._put_context_service_evaluation(
            object(),
            condition,
            lambda trusted_key: prepared,
        )

    current_grants, _ = (
        harness.context_resolver.service.get_demo_evaluation_grants(
            PUBLISHER
        )
    )
    assert current_grants
    assert harness.approval_registry.resolve(
        forged_approval.decision_id
    ) is None
    _assert_no_artifact(
        harness=harness,
        idempotency_key=condition.idempotency_key,
    )


def test_direct_transaction_cannot_publish_invalid_snapshot_signature() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    condition, prepared = _capture_conditional_publication_inputs(harness)
    invalid_attestation = prepared.snapshot.snapshot_attestation.model_copy(
        update={
            "signature": "A"
            * len(prepared.snapshot.snapshot_attestation.signature)
        }
    )
    invalid_snapshot = prepared.snapshot.model_copy(
        update={"snapshot_attestation": invalid_attestation}
    )
    EvidenceSnapshot.model_validate_json(invalid_snapshot.canonical_json())
    invalid_prepared = replace(prepared, snapshot=invalid_snapshot)
    preparation_called = False

    def supply_invalid_artifact(
        trusted_key: EvaluationTrustedKeyAuthority,
    ) -> PreparedEvaluationArtifact:
        nonlocal preparation_called
        del trusted_key
        preparation_called = True
        return invalid_prepared

    with pytest.raises(
        EvaluationFailedClosedError,
        match="ContextService capability",
    ), harness.context_resolver.store.transaction() as transaction:
        transaction._put_context_service_evaluation(
            object(),
            condition,
            supply_invalid_artifact,
        )

    assert preparation_called is False
    _assert_no_artifact(
        harness=harness,
        idempotency_key=condition.idempotency_key,
    )


def test_aborted_transaction_permit_cannot_survive_reentry_or_reuse() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    store = harness.context_resolver.store
    reused_transaction = store.transaction()
    original_put = reused_transaction._put_context_service_evaluation
    captured: dict[str, object] = {}

    def capture_unconsumed_permit(
        transaction_capability: object,
        condition: EvaluationCommitAuthorityCondition,
        artifact_preparation: Callable[
            [EvaluationTrustedKeyAuthority],
            PreparedEvaluationArtifact,
        ],
    ) -> object:
        trusted_key = reused_transaction.get_demo_evaluation_trusted_key(
            condition.trusted_key_anchor
        )
        assert trusted_key is not None
        captured["permit"] = transaction_capability
        captured["condition"] = condition
        captured["prepared"] = artifact_preparation(trusted_key)
        raise EvaluationFailedClosedError(
            "abort after capturing an unconsumed transaction permit"
        )

    reused_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
        capture_unconsumed_permit
    )
    original_transaction = store.transaction

    def reuse_transaction_object() -> Any:
        return reused_transaction

    store.transaction = reuse_transaction_object  # type: ignore[method-assign]
    idempotency_key = "wc013-aborted-transaction-permit"
    try:
        with pytest.raises(
            EvaluationFailedClosedError,
            match="capturing an unconsumed",
        ):
            harness.service.evaluate(
                PUBLISHER,
                idempotency_key,
                harness.command,
            )
    finally:
        store.transaction = original_transaction  # type: ignore[method-assign]
        reused_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
            original_put
        )

    preparation_called = False

    def stale_preparation(
        trusted_key: EvaluationTrustedKeyAuthority,
    ) -> PreparedEvaluationArtifact:
        nonlocal preparation_called
        del trusted_key
        preparation_called = True
        prepared = captured["prepared"]
        assert isinstance(prepared, PreparedEvaluationArtifact)
        return prepared

    condition = captured["condition"]
    assert isinstance(condition, EvaluationCommitAuthorityCondition)
    with pytest.raises(
        EvaluationFailedClosedError,
        match="unused transaction-bound",
    ), reused_transaction:
        reused_transaction._put_context_service_evaluation(
            captured["permit"],
            condition,
            stale_preparation,
        )

    assert preparation_called is False
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_persistence_reverifies_signature_after_service_preparation() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    store = harness.context_resolver.store
    original_transaction = store.transaction

    @contextmanager
    def transaction() -> Iterator[Any]:
        with original_transaction() as active_transaction:
            original_insert = (
                active_transaction._put_context_service_evaluation
            )

            def replace_with_invalid_signature(
                transaction_capability: object,
                condition: EvaluationCommitAuthorityCondition,
                artifact_preparation: Callable[
                    [EvaluationTrustedKeyAuthority],
                    PreparedEvaluationArtifact,
                ],
            ) -> object:
                trusted_key = (
                    active_transaction.get_demo_evaluation_trusted_key(
                        condition.trusted_key_anchor
                    )
                )
                assert trusted_key is not None
                prepared = artifact_preparation(trusted_key)
                invalid_attestation = (
                    prepared.snapshot.snapshot_attestation.model_copy(
                        update={
                            "signature": "A"
                            * len(
                                prepared.snapshot
                                .snapshot_attestation.signature
                            )
                        }
                    )
                )
                invalid_snapshot = prepared.snapshot.model_copy(
                    update={
                        "snapshot_attestation": invalid_attestation
                    }
                )
                invalid_prepared = replace(
                    prepared,
                    snapshot=invalid_snapshot,
                )
                return original_insert(
                    transaction_capability,
                    condition,
                    lambda _: invalid_prepared,
                )

            active_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
                replace_with_invalid_signature
            )
            yield active_transaction

    store.transaction = transaction  # type: ignore[method-assign]
    idempotency_key = "wc013-persistence-invalid-signature"
    try:
        with pytest.raises(
            EvaluationFailedClosedError,
            match="snapshot verification or policy evaluation failed",
        ):
            harness.service.evaluate(
                PUBLISHER,
                idempotency_key,
                harness.command,
            )
    finally:
        store.transaction = original_transaction  # type: ignore[method-assign]

    _assert_no_artifact(
        harness=harness,
        idempotency_key=idempotency_key,
    )


def test_adversarial_snapshot_canonicalization_delay_cannot_backdate_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    from athena_context.api import evaluation_service as service_module

    original_finalize = service_module.finalize_signed_snapshot
    delayed = False

    class DelayingSnapshot(EvidenceSnapshot):
        def canonical_json(self) -> str:
            nonlocal delayed
            if (
                not delayed
                and any(
                    frame.function == "_normalize_evaluation_preparation"
                    for frame in stack()
                )
            ):
                delayed = True
                # Align the deterministic clock one second before expiry,
                # then reproduce the reviewer's 1001 ms serialization delay.
                harness.clock.advance(
                    self.expires_at
                    - harness.clock.value
                    - timedelta(seconds=1)
                )
                harness.clock.advance(timedelta(milliseconds=1001))
            return super().canonical_json()

    def finalize_with_adversarial_snapshot(
        *args: object,
        **kwargs: object,
    ) -> EvidenceSnapshot:
        snapshot = original_finalize(*args, **kwargs)  # type: ignore[arg-type]
        return DelayingSnapshot.model_validate(
            snapshot.model_dump(
                mode="python",
                by_alias=True,
                exclude_none=True,
            )
        )

    monkeypatch.setattr(
        service_module,
        "finalize_signed_snapshot",
        finalize_with_adversarial_snapshot,
    )
    idempotency_key = "wc013-adversarial-canonical-delay"

    with pytest.raises(
        EvaluationFailedClosedError,
        match="snapshot became stale",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert delayed is True
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_publication_timestamp_is_acquired_after_final_crypto_policy_work() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    context_service = harness.context_resolver.service
    original_evaluation = (
        context_service._evaluate_demo_snapshot_for_publication
    )

    def delayed_evaluation(*args: object, **kwargs: object) -> object:
        result = original_evaluation(*args, **kwargs)  # type: ignore[arg-type]
        harness.clock.advance(timedelta(minutes=1))
        return result

    context_service._evaluate_demo_snapshot_for_publication = (  # type: ignore[method-assign]
        delayed_evaluation
    )

    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-post-crypto-policy-timestamp",
        harness.command,
    )

    assert result.publication.published_at >= CURRENT_NOW + timedelta(minutes=1)
    assert result.evaluated_at == result.publication.published_at
    assert harness.store.publication_count == 1


def test_key_revision_change_during_final_crypto_policy_work_rolls_back() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    idempotency_key = "wc013-key-revision-during-crypto-policy"
    context_service = harness.context_resolver.service
    original_evaluation = (
        context_service._evaluate_demo_snapshot_for_publication
    )

    def revoke_during_evaluation(*args: object, **kwargs: object) -> object:
        result = original_evaluation(*args, **kwargs)  # type: ignore[arg-type]
        harness.trust_registry.disable(revoked_at=harness.clock.value)
        return result

    context_service._evaluate_demo_snapshot_for_publication = (  # type: ignore[method-assign]
        revoke_during_evaluation
    )

    with pytest.raises(
        EvaluationFailedClosedError,
        match="authority changed during the publication transaction",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    current_trust = harness.trust_registry.resolve()
    assert current_trust is not None
    assert current_trust.revision == 2
    assert current_trust.record.enabled is False
    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_approval_revoke_after_final_evaluation_aborts_conditional_commit() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    idempotency_key = "wc013-approval-revoke-race"
    harness.commit_hook.before_commit = lambda: harness.approval_registry.revoke(
        harness.approval.decision_id
    )

    with pytest.raises(DemoEvaluationApprovalError, match="not active"):
        harness.service.evaluate(PUBLISHER, idempotency_key, harness.command)

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_approval_revocation_during_transaction_fails_before_insertion() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    idempotency_key = "wc013-approval-revoke-inside-uow"

    def revoke_after_initial_read() -> None:
        harness.approval_registry.revoke(
            harness.approval.decision_id
        )

    harness.context_resolver.service._before_evaluation_artifact_insert = (  # type: ignore[method-assign]
        revoke_after_initial_read
    )

    with pytest.raises(
        EvaluationFailedClosedError,
        match="authority changed during",
    ):
        harness.service.evaluate(PUBLISHER, idempotency_key, harness.command)

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    revoked = harness.approval_registry.resolve(harness.approval.decision_id)
    assert revoked is not None
    assert revoked.status == "revoked"
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_supersession_after_final_evaluation_aborts_conditional_commit() -> None:
    manifest = build_current_synthetic_manifest(as_of=CURRENT_NOW)
    harness = build_harness(as_of=CURRENT_NOW, manifest=manifest)
    replacement = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        manifest_version="2.1.0",
    )
    idempotency_key = "wc013-supersession-race"
    harness.commit_hook.before_commit = lambda: (
        harness.context_resolver.supersede_with(replacement)
    )

    with pytest.raises(EvaluationFailedClosedError, match="superseded"):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_unique_active_selection_becoming_ambiguous_aborts_conditional_commit() -> None:
    manifest = build_current_synthetic_manifest(as_of=CURRENT_NOW)
    harness = build_harness(as_of=CURRENT_NOW, manifest=manifest)
    command = harness.command.model_copy(update={"manifest_version": None})
    concurrent = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        manifest_version="2.1.0",
    )
    idempotency_key = "wc013-unique-selection-ambiguity-race"
    harness.commit_hook.before_commit = lambda: (
        harness.context_resolver.publish_additional_active(concurrent)
    )

    with pytest.raises(EvaluationFailedClosedError, match="ambiguous"):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            command,
        )

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_explicit_selection_remains_exact_when_another_version_is_published() -> None:
    manifest = build_current_synthetic_manifest(as_of=CURRENT_NOW)
    harness = build_harness(as_of=CURRENT_NOW, manifest=manifest)
    concurrent = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        manifest_version="2.1.0",
    )
    harness.commit_hook.before_commit = lambda: (
        harness.context_resolver.publish_additional_active(concurrent)
    )

    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-exact-selection-concurrent-version",
        harness.command,
    )

    assert result.publication.manifest_version == "2.0.0"
    assert harness.store.publication_count == 1


def test_auth_removal_after_final_evaluation_aborts_conditional_commit() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    idempotency_key = "wc013-authorization-removal-race"
    grant = RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER)
    harness.commit_hook.before_commit = lambda: (
        harness.authorization.remove_grant(grant)
    )

    with pytest.raises(AuthorizationError, match="not authorized"):
        harness.service.evaluate(PUBLISHER, idempotency_key, harness.command)

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    harness.authorization.add_grant(grant)
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_lying_commit_adapter_cannot_be_injected_into_evaluation_service() -> None:
    actual = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    foreign = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )

    class LyingCommitAdapter:
        context_resolver = actual.context_resolver

        def load_receipt(self, actor_id: str, key: str) -> object | None:
            return foreign.store.load_receipt(actor_id, key)

        def resolve_result(self, snapshot_id: str) -> object | None:
            return foreign.store.resolve_result(snapshot_id)

    with pytest.raises(TypeError, match="evaluation_commit"):
        type(actual.service)(  # type: ignore[call-arg]
            context_service=actual.context_resolver.service,
            context_reader_actor=PUBLISHER,
            deployment_configuration=actual.dependencies.deployment_configuration,
            evidence_client=actual.dependencies.evidence_client,
            snapshot_signer=actual.dependencies.snapshot_signer,
            clock=actual.clock,
            evaluation_commit=LyingCommitAdapter(),
        )
    assert not hasattr(
        actual.context_resolver.service,
        "commit_demo_evaluation",
    )

    actual.commit_hook.before_commit = lambda: actual.approval_registry.revoke(
        actual.approval.decision_id
    )

    with pytest.raises(DemoEvaluationApprovalError, match="not active"):
        actual.service.evaluate(
            PUBLISHER,
            "wc013-lying-commit-adapter",
            actual.command,
        )

    assert foreign.store.publication_count == 0
    _assert_no_artifact(
        harness=actual,
        idempotency_key="wc013-lying-commit-adapter",
    )


def test_service_rejects_all_independent_authority_dependencies() -> None:
    actual = build_harness()
    foreign = build_harness()

    with pytest.raises(TypeError, match="approval_resolver"):
        type(actual.service)(  # type: ignore[call-arg]
            context_service=actual.context_resolver.service,
            context_reader_actor=PUBLISHER,
            deployment_configuration=actual.dependencies.deployment_configuration,
            evidence_client=actual.dependencies.evidence_client,
            snapshot_signer=actual.dependencies.snapshot_signer,
            clock=actual.clock,
            approval_resolver=foreign.approval_registry,
            authorization=foreign.authorization,
        )


def test_context_mutation_waits_until_authority_reads_and_artifact_insert_complete() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    barrier_reached = Event()
    mutation_attempted = Event()
    mutation_completed = Event()
    mutation_errors: list[BaseException] = []
    replacement = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        manifest_version="2.1.0",
    )

    def mutate_context() -> None:
        if not barrier_reached.wait(timeout=5):
            mutation_errors.append(AssertionError("commit barrier was not reached"))
            return
        mutation_attempted.set()
        try:
            harness.context_resolver.supersede_with(replacement)
        except BaseException as exc:  # pragma: no cover - asserted below
            mutation_errors.append(exc)
        finally:
            mutation_completed.set()

    def hold_between_authority_and_insert() -> None:
        barrier_reached.set()
        assert mutation_attempted.wait(timeout=5)
        assert not mutation_completed.wait(timeout=0.1)

    harness.context_resolver.service._before_evaluation_artifact_insert = (  # type: ignore[method-assign]
        hold_between_authority_and_insert
    )
    mutation_thread = Thread(target=mutate_context, daemon=True)
    mutation_thread.start()

    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-context-transaction-lock",
        harness.command,
    )
    mutation_thread.join(timeout=10)

    assert not mutation_thread.is_alive()
    assert mutation_completed.is_set()
    assert not mutation_errors
    assert result.publication.manifest_version == "2.0.0"
    assert harness.store.publication_count == 1
    assert harness.context_resolver.view.published.manifest_version == "2.1.0"


@pytest.mark.parametrize(
    "authority_expiry",
    ["inheritedOverride", "riskAcceptance"],
)
def test_governance_expiry_during_transaction_aborts_conditional_commit(
    authority_expiry: str,
) -> None:
    manifest = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        override_expires_at=(
            CURRENT_NOW + timedelta(seconds=30)
            if authority_expiry == "inheritedOverride"
            else None
        ),
        risk_acceptance_expires_at=(
            CURRENT_NOW + timedelta(seconds=30)
            if authority_expiry == "riskAcceptance"
            else None
        ),
        production_extends_development=True,
    )
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=manifest,
    )
    published_manifest = harness.context_resolver.view.published.manifest
    initially_resolved = resolve_manifest_profile(
        published_manifest,
        "production",
        as_of=CURRENT_NOW,
    )
    parent = published_manifest.profiles["development"]

    assert initially_resolved.inheritance_chain == [
        "development",
        "production",
    ]
    assert parent.weakening_overrides
    assert all(
        "production" not in override.profiles
        for override in parent.weakening_overrides
    )

    idempotency_key = f"wc013-{authority_expiry}-expiry-race"
    harness.context_resolver.service._before_evaluation_artifact_insert = (  # type: ignore[method-assign]
        lambda: harness.clock.advance(timedelta(minutes=1))
    )
    with pytest.raises(
        EvaluationFailedClosedError,
        match="inactive governance",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


@pytest.mark.parametrize(
    "expired_governance",
    ["override", "riskAcceptance"],
)
def test_expired_published_manifest_governance_rejects_before_collection(
    expired_governance: str,
) -> None:
    expires_at = CURRENT_NOW + timedelta(seconds=30)
    expiry_arguments = (
        {"override_expires_at": expires_at}
        if expired_governance == "override"
        else {"risk_acceptance_expires_at": expires_at}
    )
    manifest = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        **expiry_arguments,
    )
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=manifest,
    )
    harness.clock.advance(timedelta(minutes=1))

    with pytest.raises(
        EvaluationFailedClosedError,
        match="inactive governance",
    ):
        harness.service.evaluate(
            PUBLISHER,
            "wc013-expired-current-manifest",
            harness.command,
        )

    assert harness.transport.calls == 0
    assert harness.snapshot_signer.calls == 0
    assert harness.store.publication_count == 0


def test_empty_context_service_state_fails_before_collection() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
        publish_context=False,
        seed_approval=False,
    )
    approval_intent = CreateDemoEvaluationApprovalCommand(
        decision_id=harness.approval.decision_id,
        expires_at=harness.approval.expires_at,
        manifest_id=harness.approval.manifest_id,
        manifest_version=harness.approval.manifest_version,
        manifest_digest=harness.approval.manifest_digest,
        profile_id=harness.approval.profile_id,
        authorized_scope=harness.approval.authorized_scope,
        reason=harness.approval.reason,
    )
    with pytest.raises(ResourceNotFoundError):
        harness.context_resolver.service.create_demo_evaluation_approval(
            APPROVER,
            "wc013-empty-context-approval",
            approval_intent,
        )
    with pytest.raises(
        DemoEvaluationApprovalError,
        match="decision was not found",
    ):
        harness.service.evaluate(
            PUBLISHER,
            "wc013-context-resolution-failed",
            harness.command,
        )

    assert harness.transport.calls == 0
    assert harness.snapshot_signer.calls == 0
    assert harness.store.publication_count == 0


def test_multiple_real_active_versions_execute_production_ambiguity_branch() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    harness.context_resolver.publish_additional_active(
        build_current_synthetic_manifest(
            as_of=CURRENT_NOW,
            manifest_version="2.1.0",
        )
    )
    unique_selection = harness.command.model_copy(
        update={"manifest_version": None}
    )

    with pytest.raises(EvaluationFailedClosedError, match="missing, ambiguous"):
        harness.service.evaluate(
            PUBLISHER,
            "wc013-real-ambiguous-context",
            unique_selection,
        )

    assert harness.transport.calls == 0
    assert harness.snapshot_signer.calls == 0
    assert harness.store.publication_count == 0


def test_wc007_resolver_can_select_the_unique_active_published_version() -> None:
    harness = build_harness()

    resolved = harness.context_resolver.resolve(
        PublishedContextSelection(
            manifest_id=harness.command.manifest_id,
            manifest_version=None,
            profile_id=harness.command.profile_id,
        ),
        as_of=NOW,
    )

    assert resolved.view.published.manifest_version == (
        harness.command.manifest_version
    )
    assert resolved.profile.resolved_profile_digest == (
        harness.command.expected_resolved_profile_digest
    )
    assert resolved.authority_token.selection_mode == "uniqueActiveVersion"

    explicit = harness.context_resolver.resolve(
        PublishedContextSelection(
            manifest_id=harness.command.manifest_id,
            manifest_version=harness.command.manifest_version,
            profile_id=harness.command.profile_id,
        ),
        as_of=NOW,
    )
    assert explicit.authority_token.selection_mode == "exactVersion"
    assert explicit.authority_token.etag != resolved.authority_token.etag


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


def test_receipt_lookup_rejects_authorized_foreign_workload_after_revocation() -> None:
    harness = build_harness()
    idempotency_key = "wc013-cross-workload-receipt"
    result = harness.service.evaluate(
        PUBLISHER,
        idempotency_key,
        harness.command,
    )
    original_workload = harness.command.manifest_id
    foreign_workload = "wl-authorized-foreign-receipt"
    harness.authorization.remove_grant(
        RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER)
    )
    harness.authorization.add_grant(
        RoleGrant(
            actor_id=PUBLISHER.actor_id,
            role=Role.PUBLISHER,
            scope=WorkloadGrantScope(workload_id=foreign_workload),
        )
    )

    with pytest.raises(AuthorizationError):
        harness.service.get_result(PUBLISHER, result.snapshot.snapshot_id)
    with pytest.raises(
        IdempotencyConflictError,
        match="different workload",
    ):
        harness.context_resolver.service.load_demo_evaluation_receipt(
            PUBLISHER,
            idempotency_key,
            manifest_id=foreign_workload,
        )

    assert original_workload not in foreign_workload
    harness.authorization.add_grant(
        RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER)
    )
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


@pytest.mark.parametrize(
    "mismatch",
    ["snapshotId", "attemptId", "scope", "bounds", "all"],
)
def test_cryptographically_valid_foreign_snapshot_binding_fails_in_owned_uow(
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    """A valid signature cannot authorize a different scope/attempt/ID/bounds."""

    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    subscription_scope = SubscriptionScope(
        scopeType="subscription",
        tenantId=harness.command.authorized_scope.tenant_id,
        subscriptionId=harness.command.authorized_scope.subscription_id,
    )
    foreign_scope = (
        subscription_scope
        if mismatch in {"scope", "all"}
        else harness.command.authorized_scope
    )
    foreign_bounds = (
        harness.command.bounds.model_copy(
            update={"freshness_seconds": 240}
        )
        if mismatch in {"bounds", "all"}
        else harness.command.bounds
    )
    foreign_attempt_id = (
        "attempt-bbbbbbbbbbbb"
        if mismatch in {"attemptId", "all"}
        else harness.command.attempt_id
    )
    foreign_collected = harness.dependencies.evidence_client.collect(
        EvidenceCollectionCommand(
            attemptId=foreign_attempt_id,
            evidenceScope=foreign_scope,
            authorizedScopes=(foreign_scope,),
            bounds=foreign_bounds,
        )
    )
    harness.service._collect = (  # type: ignore[method-assign]
        lambda _command: foreign_collected
    )

    from athena_context.api import evaluation_service as service_module

    original_prepare = service_module.prepare_snapshot_signing_material

    def prepare_foreign_snapshot(*args: object, **kwargs: object) -> object:
        if mismatch in {"snapshotId", "all"}:
            kwargs["snapshot_id"] = "snap-bbbbbbbbbbbb"
        return original_prepare(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        service_module,
        "prepare_snapshot_signing_material",
        prepare_foreign_snapshot,
    )
    # Even a compromised/non-authoritative preflight cannot bypass the owned
    # transaction's independent collection binding and cryptographic checks.
    monkeypatch.setattr(
        service_module,
        "evaluate_manifest_profile",
        lambda *args, **kwargs: {},
    )
    idempotency_key = f"wc013-valid-foreign-snapshot-{mismatch}"

    with pytest.raises(
        EvaluationFailedClosedError,
        match="approved snapshot ID, attempt, scope, or collection bounds",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_cryptographically_valid_foreign_evidence_identity_fails_in_owned_uow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    foreign_object_id = "55555555-5555-5555-5555-555555555555"
    foreign_client_id = "66666666-6666-6666-6666-666666666666"
    foreign_assertion = Wc008DeploymentOutputAssertion.model_validate(
        _changed_assertion_payload(
            evidence_identity_object_id=foreign_object_id,
            evidence_identity_resource_id=(
                f"/subscriptions/{harness.command.authorized_scope.subscription_id}/"
                "resourceGroups/rg-athena-fixture/providers/"
                "Microsoft.ManagedIdentity/userAssignedIdentities/foreign-mcp"
            ),
        )
    )
    foreign_configuration = OperatorTrustedWc008ConfigurationPort(
        assertion=foreign_assertion,
        pinned_assertion_digest=foreign_assertion.assertion_digest,
        operator_approval=operator_approval(foreign_assertion),
    ).load_verified()
    foreign_trust = trust_configuration().model_copy(
        update={
            "managed_identity_object_id": foreign_object_id,
            "managed_identity_client_id": foreign_client_id,
        }
    )
    private_key = CANONICAL_PRIVATE_KEY
    anchor = key_anchor(private_key.public_key())
    foreign_client = Wc009EvidenceClientAdapter(
        transport=PrivateMcpEvidenceTransport(
            deployment_configuration=foreign_configuration,
            invoker=ScenarioTransport(),
        ),
        signer=DeterministicIngestionSigner(private_key),
        replay_guard=ReplayGuard(),
        clock=harness.clock,
        trust_configuration=foreign_trust,
        key_resolver=key_resolver(private_key.public_key()),
        trusted_key_anchor=anchor,
    )
    foreign_collected = foreign_client.collect(
        EvidenceCollectionCommand(
            attemptId=harness.command.attempt_id,
            evidenceScope=harness.command.authorized_scope,
            authorizedScopes=(harness.command.authorized_scope,),
            bounds=harness.command.bounds,
        )
    )
    harness.service._collect = (  # type: ignore[method-assign]
        lambda _command: foreign_collected
    )
    from athena_context.api import evaluation_service as service_module

    monkeypatch.setattr(
        service_module,
        "evaluate_manifest_profile",
        lambda *args, **kwargs: {},
    )
    idempotency_key = "wc013-valid-foreign-evidence-identity"

    with pytest.raises(
        EvaluationFailedClosedError,
        match="evidence identity or resource authority",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.snapshot_signer.calls == 1
    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


def test_public_commit_candidate_fabrication_has_no_authoritative_surface() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    from athena_context.api import evaluation_ports as ports_module

    context_service = harness.context_resolver.service
    assert not hasattr(context_service, "commit_demo_evaluation")
    assert not hasattr(ports_module, "EvaluationCommitCandidate")

    with pytest.raises(
        EvaluationFailedClosedError,
        match="fabricated or not service-issued",
    ):
        context_service._commit_prepared_demo_evaluation(
            prepared_request=object(),  # type: ignore[arg-type]
            snapshot=object(),  # type: ignore[arg-type]
            collected=object(),  # type: ignore[arg-type]
        )

    assert harness.store.publication_count == 0


def test_fabricated_reader_assignment_revision_fails_in_persistence() -> None:
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    store = harness.context_resolver.store
    original_transaction = store.transaction

    @contextmanager
    def transaction() -> Iterator[Any]:
        with original_transaction() as active_transaction:
            original_insert = (
                active_transaction._put_context_service_evaluation
            )

            def replace_reader_revision(
                capability: object,
                condition: EvaluationCommitAuthorityCondition,
                artifact_preparation: Callable[
                    [EvaluationTrustedKeyAuthority],
                    PreparedEvaluationArtifact,
                ],
            ) -> object:
                forged_authority = replace(
                    condition.collection_authority,
                    reader_assignment_revision="sha256:" + ("0" * 64),
                    authority_digest="sha256:" + ("1" * 64),
                )
                return original_insert(
                    capability,
                    replace(
                        condition,
                        collection_authority=forged_authority,
                    ),
                    artifact_preparation,
                )

            active_transaction._put_context_service_evaluation = (  # type: ignore[method-assign]
                replace_reader_revision
            )
            yield active_transaction

    store.transaction = transaction  # type: ignore[method-assign]
    idempotency_key = "wc013-forged-reader-assignment-revision"
    try:
        with pytest.raises(
            EvaluationFailedClosedError,
            match="canonical validation",
        ):
            harness.service.evaluate(
                PUBLISHER,
                idempotency_key,
                harness.command,
            )
    finally:
        store.transaction = original_transaction  # type: ignore[method-assign]

    _assert_no_artifact(harness=harness, idempotency_key=idempotency_key)


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
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=build_current_synthetic_manifest(as_of=CURRENT_NOW),
    )
    harness.context_resolver.supersede_with(
        build_current_synthetic_manifest(
            as_of=CURRENT_NOW,
            manifest_version="2.1.0",
        )
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
    assertion = deployment_assertion()

    with pytest.raises(ValidationError, match="context identity must not receive"):
        Wc008DeploymentOutputAssertion.model_validate(
            _changed_assertion_payload(
                context_identity_azure_roles=("Reader",)
            )
        )
    with pytest.raises(ValidationError, match="must not receive context write"):
        Wc008DeploymentOutputAssertion.model_validate(
            _changed_assertion_payload(
                evidence_identity_context_permissions=("publish",)
            )
        )
    with pytest.raises(ValidationError, match="identities must remain separate"):
        Wc008DeploymentOutputAssertion.model_validate(
            _changed_assertion_payload(
                context_identity_object_id=MCP_OBJECT_ID,
                evidence_identity_object_id=MCP_OBJECT_ID,
            )
        )
    with pytest.raises(ValidationError, match="external_ingress"):
        Wc008DeploymentOutputAssertion.model_validate(
            _changed_assertion_payload(external_ingress=True)
        )
    with pytest.raises(ValidationError):
        McpReadAssignment(scope=scope(), role="Contributor")  # type: ignore[arg-type]
    assert assertion.context_identity_object_id == CONTEXT_OBJECT_ID


def test_endpoint_is_derived_from_actual_transport_and_cannot_be_relabelled() -> None:
    approved_endpoint = verified_deployment_configuration(
        "https://approved-a.internal.example"
    )
    actual_endpoint = verified_deployment_configuration(
        "https://actual-b.internal.example"
    )

    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="actual evidence transport",
    ):
        build_harness(
            service_configuration=approved_endpoint,
            transport_configuration=actual_endpoint,
        )


def test_self_asserted_private_flags_cannot_make_a_public_hostname_trusted() -> None:
    class SelfAssertedConfigurationPort:
        def load_verified(self) -> Wc008DeploymentOutputAssertion:
            return deployment_assertion("https://public.example.com")

    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="operator-verified",
    ):
        build_harness(configuration_port=SelfAssertedConfigurationPort())


def test_operator_trust_not_dns_suffix_is_authoritative_for_private_ingress() -> None:
    configuration = verified_deployment_configuration(
        "https://private-gateway.corp.example"
    )
    harness = build_harness(
        service_configuration=configuration,
        transport_configuration=configuration,
    )

    result = harness.service.evaluate(
        PUBLISHER,
        "wc013-private-assertion-not-suffix",
        harness.command,
    )

    assert harness.transport.endpoints == [
        "https://private-gateway.corp.example"
    ]
    assert result.publication.endpoint_digest == compute_artifact_digest(
        {"privateMcpEndpoint": "https://private-gateway.corp.example"}
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "managed_environment_resource_id",
            (
                "/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/rg-athena-fixture/providers/Microsoft.App/"
                "managedEnvironments/other-env"
            ),
        ),
        (
            "azure_mcp_container_app_resource_id",
            (
                "/subscriptions/11111111-1111-1111-1111-111111111111/"
                "resourceGroups/rg-athena-fixture/providers/Microsoft.App/"
                "containerApps/other-app"
            ),
        ),
        ("evidence_identity_object_id", "55555555-5555-5555-5555-555555555555"),
    ],
)
def test_wc008_exact_deployment_binding_mismatches_fail_composition(
    field: str,
    value: str,
) -> None:
    trusted = verified_deployment_configuration()
    changed_assertion = Wc008DeploymentOutputAssertion.model_validate(
        _changed_assertion_payload(**{field: value})
    )
    changed = OperatorTrustedWc008ConfigurationPort(
        assertion=changed_assertion,
        pinned_assertion_digest=changed_assertion.assertion_digest,
        operator_approval=operator_approval(changed_assertion),
    ).load_verified()

    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="actual evidence transport",
    ):
        build_harness(
            service_configuration=trusted,
            transport_configuration=changed,
        )


def test_wc008_catalog_and_allowlist_are_exact_and_assertion_pin_is_required() -> None:
    with pytest.raises(ValidationError):
        Wc008DeploymentOutputAssertion.model_validate(
            _changed_assertion_payload(
                tool_catalog_hash="sha256:" + ("0" * 64)
            )
        )
    with pytest.raises(ValidationError):
        Wc008DeploymentOutputAssertion.model_validate(
            _changed_assertion_payload(
                allowed_tools=("group_resource_list",)
            )
        )

    assertion = deployment_assertion()
    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="pinned assertion digest",
    ):
        OperatorTrustedWc008ConfigurationPort(
            assertion=assertion,
            pinned_assertion_digest="sha256:" + ("0" * 64),
            operator_approval=operator_approval(assertion),
        ).load_verified()


def test_live_configuration_adapter_loads_exact_bounded_operator_outputs(
    tmp_path: Path,
) -> None:
    assertion = deployment_assertion()
    approval = operator_approval(assertion)
    assertion_path = tmp_path / "wc008-assertion.json"
    approval_path = tmp_path / "wc008-approval.json"
    assertion_path.write_text(assertion.model_dump_json(), encoding="utf-8")
    approval_path.write_text(approval.model_dump_json(), encoding="utf-8")

    configuration = EnvironmentWc008DeploymentConfigurationPort(
        {
            "ATHENA_WC013_WC008_DEPLOYMENT_ASSERTION_FILE": str(assertion_path),
            "ATHENA_WC013_WC008_OPERATOR_APPROVAL_FILE": str(approval_path),
            "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": assertion.assertion_digest,
        }
    ).load_verified()

    assert configuration.assertion == assertion
    assert configuration.operator_approval == approval


def test_live_context_selection_requires_exact_manifest_version_and_profile() -> None:
    selection = EnvironmentWc007PublishedContextSelectionPort(
        {
            "ATHENA_WC013_MANIFEST_ID": "wl-synthetic-current",
            "ATHENA_WC013_MANIFEST_VERSION": "2.1.0",
            "ATHENA_WC013_PROFILE_ID": "production",
        }
    ).load()

    assert selection.manifest_id == "wl-synthetic-current"
    assert selection.manifest_version == "2.1.0"
    assert selection.profile_id == "production"
    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="ATHENA_WC013_MANIFEST_VERSION",
    ):
        EnvironmentWc007PublishedContextSelectionPort(
            {
                "ATHENA_WC013_MANIFEST_ID": "wl-synthetic-current",
                "ATHENA_WC013_PROFILE_ID": "production",
            }
        ).load()


def test_live_context_reader_requires_https_origin_and_managed_identity_audience() -> None:
    class NoopTokenProvider:
        def get_token(self, audience: str) -> str:
            del audience
            return "synthetic-unused-token"

    with pytest.raises(DemoEvaluationConfigurationError, match="HTTPS origin"):
        EnvironmentContextApiPublishedContextReader(
            {
                "ATHENA_WC013_CONTEXT_API_ENDPOINT": "http://context.invalid",
                "ATHENA_WC013_CONTEXT_API_AUDIENCE": "api://context",
            },
            token_provider=NoopTokenProvider(),
        )
    with pytest.raises(DemoEvaluationConfigurationError, match="audience"):
        EnvironmentContextApiPublishedContextReader(
            {
                "ATHENA_WC013_CONTEXT_API_ENDPOINT": "https://context.internal",
            },
            token_provider=NoopTokenProvider(),
        )


def test_live_context_reader_rejects_redirect_without_forwarding_bearer_token() -> None:
    bearer_token = "synthetic-managed-identity-secret"
    requests: list[tuple[str, str | None]] = []

    class TokenProvider:
        def get_token(self, audience: str) -> str:
            assert audience == "api://context"
            return bearer_token

    class RedirectingTransport(BaseHandler):
        handler_order = 100

        def _open(self, request: Any) -> Any:
            requests.append(
                (
                    request.full_url,
                    request.get_header("Authorization"),
                )
            )
            if request.full_url.startswith("https://context.internal/"):
                headers = Message()
                headers["Location"] = "http://attacker.invalid/token"
                response = addinfourl(
                    BytesIO(b""),
                    headers,
                    request.full_url,
                    302,
                )
                response.msg = "Found"
                return response
            response = addinfourl(
                BytesIO(b'{"leaked":true}'),
                Message(),
                request.full_url,
                200,
            )
            response.msg = "OK"
            return response

        def https_open(self, request: Any) -> Any:
            return self._open(request)

        def http_open(self, request: Any) -> Any:
            return self._open(request)

    reader = EnvironmentContextApiPublishedContextReader(
        {
            "ATHENA_WC013_CONTEXT_API_ENDPOINT": "https://context.internal",
            "ATHENA_WC013_CONTEXT_API_AUDIENCE": "api://context",
        },
        token_provider=TokenProvider(),
    )
    reader._opener.add_handler(RedirectingTransport())  # type: ignore[attr-defined]

    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="rejected the live resolution",
    ):
        reader.list_published("wl-athena-wc013-current-demo")

    assert requests == [
        (
            "https://context.internal/v1/manifests/"
            "wl-athena-wc013-current-demo/versions",
            "Bearer " + bearer_token,
        )
    ]


def test_live_configuration_adapter_fails_closed_for_missing_or_malformed_input(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="configuration variable",
    ):
        EnvironmentWc008DeploymentConfigurationPort({}).load_verified()

    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text('{"selfAssertedPrivate":true}', encoding="utf-8")
    with pytest.raises(
        DemoEvaluationConfigurationError,
        match="malformed or untrusted",
    ):
        EnvironmentWc008DeploymentConfigurationPort(
            {
                "ATHENA_WC013_WC008_DEPLOYMENT_ASSERTION_FILE": str(
                    malformed_path
                ),
                "ATHENA_WC013_WC008_OPERATOR_APPROVAL_FILE": str(
                    malformed_path
                ),
                "ATHENA_WC013_WC008_PINNED_ASSERTION_DIGEST": (
                    "sha256:" + ("0" * 64)
                ),
            }
        ).load_verified()


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
