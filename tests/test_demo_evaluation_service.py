from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from threading import Event, Thread

import pytest
from pydantic import ValidationError

from athena_context.api import (
    AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL,
    Actor,
    ActorKind,
    EnvironmentContextApiPublishedContextReader,
    EnvironmentWc007PublishedContextSelectionPort,
    EnvironmentWc008DeploymentConfigurationPort,
    McpReadAssignment,
    OperatorTrustedWc008ConfigurationPort,
    PublishedContextSelection,
    Role,
    RoleGrant,
    Wc008DeploymentOutputAssertion,
)
from athena_context.api.domain import Permission
from athena_context.api.errors import (
    AuthorizationError,
    DemoEvaluationApprovalError,
    DemoEvaluationConfigurationError,
    EvaluationFailedClosedError,
    EvidenceCollectionRejectedError,
    IdempotencyConflictError,
)
from athena_context.api.evaluation_context import (
    validate_published_context_binding,
)
from athena_context.api.evaluation_ports import (
    EvaluationAuthorityUnitOfWorkPort,
    EvaluationCommitCandidate,
    SnapshotSigningRequest,
)
from athena_context.contracts import (
    NormalizationCollisionError,
    canonicalize_json,
    compute_artifact_digest,
    resolve_manifest_profile,
)
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
    build_current_synthetic_manifest,
    build_harness,
    deployment_assertion,
    operator_approval,
    scope,
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
    changed_approval = type(harness.approval).model_validate(
        {
            **harness.approval.model_dump(mode="python"),
            "profile_id": unknown_decomposed,
            "revision": harness.approval.revision + 1,
        }
    )
    harness.approval_registry.replace(changed_approval)
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


def _delay_final_authority_or_persistence(
    harness: DemoHarness,
    *,
    location: str,
    delay: timedelta,
) -> None:
    if location == "finalAuthorityResolution":
        service = harness.context_resolver.service
        original = service._resolve_evaluation_authority
        commit_resolutions = 0

        def delayed_resolution(*args: object, **kwargs: object) -> object:
            nonlocal commit_resolutions
            result = original(*args, **kwargs)  # type: ignore[arg-type]
            if kwargs.get("expected_authority") is not None:
                commit_resolutions += 1
                if commit_resolutions == 2:
                    harness.clock.advance(delay)
            return result

        service._resolve_evaluation_authority = delayed_resolution  # type: ignore[assignment]
        return
    if location == "persistence":
        harness.context_resolver.store._before_evaluation_commit_timestamp = (  # type: ignore[method-assign]
            lambda: harness.clock.advance(delay)
        )
        return
    raise AssertionError(f"unsupported commit delay location: {location}")


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
    _, _, authority = context_service.prepare_demo_evaluation_authority(
        reader_actor=context_reader,
        actor=PUBLISHER,
        command=harness.command,
        as_of=harness.clock.now(),
        private_mcp_endpoint=PRIVATE_ENDPOINT,
        evidence_identity_object_id=MCP_OBJECT_ID,
    )
    assert authority.context_reader_authorization.actor_id == (
        context_reader.actor_id
    )
    assert authority.context_reader_authorization.permission is Permission.READ
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
        harness.approval.decision_id,
        revoked_at=harness.clock.value,
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

    def revoke_after_initial_read(
        unit_of_work: EvaluationAuthorityUnitOfWorkPort,
    ) -> None:
        del unit_of_work
        harness.approval_registry.revoke(
            harness.approval.decision_id,
            revoked_at=harness.clock.value,
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

        def commit(
            self,
            candidate: EvaluationCommitCandidate,
        ) -> object:
            return foreign.context_resolver.service.commit_demo_evaluation(
                reader_actor=PUBLISHER,
                candidate=candidate,
            )

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

    actual.commit_hook.before_commit = lambda: actual.approval_registry.revoke(
        actual.approval.decision_id,
        revoked_at=actual.clock.value,
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

    def hold_between_authority_and_insert(
        unit_of_work: EvaluationAuthorityUnitOfWorkPort,
    ) -> None:
        del unit_of_work
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
        lambda _: harness.clock.advance(timedelta(minutes=1))
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
    expires_at = CURRENT_NOW - timedelta(days=1)
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
        profile_resolution_as_of=expires_at - timedelta(days=1),
    )

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
    )
    with pytest.raises(
        EvaluationFailedClosedError,
        match="missing, ambiguous",
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
