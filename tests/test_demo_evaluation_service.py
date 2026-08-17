from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from athena_context.api import (
    AZURE_RESOURCE_INVENTORY_DEPLOYMENT_TOOL,
    ActorKind,
    EnvironmentWc007PublishedContextSelectionPort,
    EnvironmentWc008DeploymentConfigurationPort,
    McpReadAssignment,
    OperatorTrustedWc008ConfigurationPort,
    PublishedContextSelection,
    ResolvedPublishedContext,
    Wc008DeploymentOutputAssertion,
)
from athena_context.api.domain import Supersession
from athena_context.api.errors import (
    AmbiguousLookupError,
    AuthorizationError,
    DemoEvaluationApprovalError,
    DemoEvaluationConfigurationError,
    EvaluationFailedClosedError,
    EvidenceCollectionRejectedError,
    IdempotencyConflictError,
    ResourceNotFoundError,
)
from athena_context.api.evaluation_ports import SnapshotSigningRequest
from athena_context.contracts import (
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
    assert harness.context_resolver.calls == 2
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
    assert published.manifest.audit.published_by == "human-approved-context-api"
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


def test_approval_expiry_during_collection_aborts_atomic_publication() -> None:
    manifest = build_current_synthetic_manifest(as_of=CURRENT_NOW)
    harness = build_harness(
        as_of=CURRENT_NOW,
        manifest=manifest,
        approval_expires_at=CURRENT_NOW + timedelta(seconds=1),
    )
    idempotency_key = "wc013-approval-expiry-race"

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
    assert harness.context_resolver.calls == 2
    assert harness.store.load_receipt(PUBLISHER.actor_id, idempotency_key) is None
    assert harness.store.resolve_publication(harness.command.snapshot_id) is None
    assert harness.store.resolve_result(harness.command.snapshot_id) is None
    assert harness.store.publication_count == 0


def test_supersession_during_collection_aborts_atomic_publication() -> None:
    harness = build_harness()
    resolver = harness.context_resolver

    class SupersedingResolver:
        def __init__(self) -> None:
            self.calls = 0

        def resolve(
            self,
            selection: PublishedContextSelection,
            *,
            as_of: datetime,
        ) -> ResolvedPublishedContext:
            self.calls += 1
            if self.calls == 2:
                published = resolver.view.published
                resolver.view = resolver.view.model_copy(
                    update={
                        "supersession": Supersession(
                            manifest_id=published.manifest_id,
                            superseded_version=published.manifest_version,
                            replacement_version="9.9.9",
                            superseded_by=PUBLISHER,
                            superseded_at=published.published_at,
                            reason="A human-authorized replacement won the race",
                        )
                    }
                )
            return resolver.resolve(selection, as_of=as_of)

    mutable_resolver = SupersedingResolver()
    harness.service._context_resolver = mutable_resolver  # type: ignore[attr-defined]
    idempotency_key = "wc013-supersession-race"

    with pytest.raises(EvaluationFailedClosedError, match="superseded"):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert mutable_resolver.calls == 2
    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    assert harness.store.load_receipt(PUBLISHER.actor_id, idempotency_key) is None
    assert harness.store.resolve_publication(harness.command.snapshot_id) is None
    assert harness.store.resolve_result(harness.command.snapshot_id) is None
    assert harness.store.publication_count == 0


def test_inherited_parent_override_expiry_is_canonically_reresolved_at_commit() -> None:
    manifest = build_current_synthetic_manifest(
        as_of=CURRENT_NOW,
        override_expires_at=CURRENT_NOW + timedelta(seconds=1),
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

    idempotency_key = "wc013-inherited-override-expiry-race"
    with pytest.raises(
        EvaluationFailedClosedError,
        match="inactive governance",
    ):
        harness.service.evaluate(
            PUBLISHER,
            idempotency_key,
            harness.command,
        )

    assert harness.context_resolver.calls == 2
    assert harness.transport.calls == 1
    assert harness.snapshot_signer.calls == 1
    assert harness.store.load_receipt(PUBLISHER.actor_id, idempotency_key) is None
    assert harness.store.resolve_publication(harness.command.snapshot_id) is None
    assert harness.store.resolve_result(harness.command.snapshot_id) is None
    assert harness.store.publication_count == 0


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

    assert harness.context_resolver.calls == 1
    assert harness.transport.calls == 0
    assert harness.snapshot_signer.calls == 0
    assert harness.store.publication_count == 0


@pytest.mark.parametrize(
    "resolution_error",
    [
        ResourceNotFoundError("selected published context is missing"),
        AmbiguousLookupError("selected published context is ambiguous"),
    ],
)
def test_missing_or_ambiguous_published_context_fails_before_collection(
    resolution_error: Exception,
) -> None:
    harness = build_harness()

    class FailingPublishedContextResolver:
        def resolve(self, *_args: object, **_kwargs: object) -> object:
            raise resolution_error

    harness.service._context_resolver = (  # type: ignore[attr-defined]
        FailingPublishedContextResolver()
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
