from __future__ import annotations

from fastapi.testclient import TestClient

from athena_context.api.authorization import StaticTestAuthenticator
from athena_context.api.domain import (
    Actor,
    AuthenticationMethod,
    CreateDraftCommand,
    PublishCommand,
    TransitionCommand,
    VerifiedAuthentication,
)
from athena_context.api.http import create_app
from athena_context.api.service import ContextService
from context_api_support import (
    AGENT,
    APPROVER,
    AUDITOR,
    AUTHOR,
    OUTSIDER,
    PUBLISHER,
    approve_draft,
    build_service,
    canonical_manifest,
    create_draft,
    publish_draft,
    transition,
)

BAD_DIGEST = "sha256:" + ("0" * 64)
_TOKENS = {
    AGENT.actor_id: "synthetic-agent-token",
    AUTHOR.actor_id: "synthetic-author-token",
    APPROVER.actor_id: "synthetic-approver-token",
    PUBLISHER.actor_id: "synthetic-publisher-token",
    AUDITOR.actor_id: "synthetic-auditor-token",
    OUTSIDER.actor_id: "synthetic-outsider-token",
}


def _verified(actor: Actor) -> VerifiedAuthentication:
    return VerifiedAuthentication(
        actor=actor,
        subject_id=f"synthetic-subject-{actor.actor_id}",
        issuer="https://issuer.invalid/synthetic",
        audience="api://athena-context-test",
        method=AuthenticationMethod.TEST,
    )


def _client() -> tuple[ContextService, TestClient]:
    service = build_service()
    authenticator = StaticTestAuthenticator(
        {
            _TOKENS[actor.actor_id]: _verified(actor)
            for actor in [AGENT, AUTHOR, APPROVER, PUBLISHER, AUDITOR, OUTSIDER]
        }
    )
    return service, TestClient(
        create_app(service=service, authentication=authenticator)
    )


def _headers(
    actor_id: str,
    key: str | None = None,
    *,
    spoofed_actor: str | None = None,
) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {_TOKENS[actor_id]}"}
    if key is not None:
        headers["Idempotency-Key"] = key
    if spoofed_actor is not None:
        headers["X-Athena-Actor"] = spoofed_actor
    return headers


def test_openapi_exposes_typed_lifecycle_contracts() -> None:
    _, client = _client()

    schema = client.get("/openapi.json").json()

    assert schema["info"]["title"] == "Athena Context API"
    assert "/v1/drafts/{draft_id}/approve" in schema["paths"]
    assert "/v1/drafts/{draft_id}/publish" in schema["paths"]
    assert "/v1/manifests/{manifest_id}/compare" in schema["paths"]
    assert "CanonicalWorkloadManifest" in schema["components"]["schemas"]
    create_schema = schema["components"]["schemas"]["CreateDraftCommand"]
    assert create_schema["additionalProperties"] is False
    assert set(create_schema["required"]) >= {
        "draft_id",
        "manifest",
        "manifest_digest",
        "reason",
    }


def test_unverified_or_caller_asserted_identity_is_rejected() -> None:
    _, client = _client()

    header_only = client.get(
        "/v1/drafts/nonexistent",
        headers={"X-Athena-Actor": PUBLISHER.actor_id},
    )
    unverified_bearer = client.get(
        "/v1/drafts/nonexistent",
        headers={
            "Authorization": "Bearer unverified-synthetic-token",
            "X-Athena-Actor": PUBLISHER.actor_id,
        },
    )

    assert header_only.status_code == 401
    assert unverified_bearer.status_code == 401
    assert header_only.json()["error"]["code"] == "authentication_required"
    assert unverified_bearer.json()["error"]["code"] == "authentication_required"


def test_reserved_wildcard_is_rejected_by_every_wc007_manifest_id_boundary() -> None:
    _, client = _client()
    manifest = canonical_manifest(manifest_id="*")
    manifest_payload = manifest.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    create_payload = {
        "draft_id": "reserved-wildcard-create",
        "manifest": manifest_payload,
        "manifest_digest": manifest.compatibility.artifact_digest,
        "reason": "Reject a reserved wildcard manifest identifier",
    }
    replacement_payload = {
        "expected_revision": 1,
        "expected_manifest_version": "1.0.0",
        "expected_digest": BAD_DIGEST,
        "replacement_manifest": manifest_payload,
        "replacement_digest": manifest.compatibility.artifact_digest,
        "reason": "Reject a reserved wildcard replacement identifier",
    }
    supersede_payload = {
        "expected_revision": 1,
        "expected_manifest_version": "1.0.0",
        "expected_digest": BAD_DIGEST,
        "replacement_version": "1.1.0",
        "replacement_digest": BAD_DIGEST,
        "reason": "Reject a reserved wildcard supersession identifier",
    }
    responses = [
        client.post(
            "/v1/drafts",
            headers=_headers(AGENT.actor_id, "reserved-wildcard-create"),
            json=create_payload,
        ),
        client.put(
            "/v1/drafts/nonexistent",
            headers=_headers(AGENT.actor_id, "reserved-wildcard-replace"),
            json=replacement_payload,
        ),
        client.get(
            "/v1/drafts?manifest_id=*",
            headers=_headers(AGENT.actor_id),
        ),
        client.get(
            "/v1/manifests/*/versions/1.0.0",
            headers=_headers(AGENT.actor_id),
        ),
        client.get(
            "/v1/manifests/*/versions",
            headers=_headers(AGENT.actor_id),
        ),
        client.get(
            "/v1/versions/1.0.0?manifest_id=*",
            headers=_headers(AGENT.actor_id),
        ),
        client.post(
            "/v1/manifests/*/versions/1.0.0/supersede",
            headers=_headers(PUBLISHER.actor_id, "reserved-wildcard-supersede"),
            json=supersede_payload,
        ),
        client.get(
            "/v1/manifests/*/compare?from_version=1.0.0&to_version=1.1.0",
            headers=_headers(AUDITOR.actor_id),
        ),
        client.get(
            "/v1/manifests/*/audit",
            headers=_headers(AUDITOR.actor_id),
        ),
    ]

    assert all(response.status_code == 422 for response in responses)
    assert all(
        any("reserved" in error["msg"] for error in response.json()["detail"])
        for response in responses
    )


def test_http_create_get_list_and_stale_revision_mapping() -> None:
    _, client = _client()
    manifest = canonical_manifest()
    command = CreateDraftCommand(
        draft_id="http-draft",
        manifest=manifest,
        manifest_digest=manifest.compatibility.artifact_digest,
        reason="Create through the typed HTTP boundary",
    )

    created = client.post(
        "/v1/drafts",
        headers=_headers(AGENT.actor_id, "http-create"),
        json=command.model_dump(mode="json", by_alias=True, exclude_none=True),
    )
    fetched = client.get(
        "/v1/drafts/http-draft",
        headers=_headers(AGENT.actor_id),
    )
    listed = client.get(
        f"/v1/drafts?manifest_id={manifest.manifest_id}",
        headers=_headers(AGENT.actor_id),
    )
    created_payload = created.json()
    stale = TransitionCommand(
        expected_revision=99,
        expected_manifest_version=created_payload["manifest"]["manifestVersion"],
        expected_digest=created_payload["manifest_digest"],
        reason="Use a stale revision",
    )
    stale_response = client.post(
        "/v1/drafts/http-draft/validate",
        headers=_headers(AGENT.actor_id, "http-stale"),
        json=stale.model_dump(mode="json"),
    )

    assert created.status_code == 201
    assert fetched.status_code == 200
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert stale_response.status_code == 409
    assert stale_response.json()["error"]["code"] == "stale_revision"


def test_http_digest_failure_is_typed() -> None:
    _, client = _client()
    manifest = canonical_manifest()
    bad_command = CreateDraftCommand(
        draft_id="bad-http-digest",
        manifest=manifest,
        manifest_digest=BAD_DIGEST,
        reason="Reject mismatched canonical digest",
    )
    digest_response = client.post(
        "/v1/drafts",
        headers=_headers(AGENT.actor_id, "bad-http-digest"),
        json=bad_command.model_dump(mode="json", by_alias=True, exclude_none=True),
    )

    assert digest_response.status_code == 409
    assert digest_response.json()["error"]["code"] == "digest_mismatch"


def test_verified_agent_cannot_escalate_with_spoofed_authority_headers() -> None:
    service, client = _client()
    manifest = canonical_manifest()
    draft = create_draft(service, manifest, draft_id="http-agent-approval")
    draft = service.validate_draft(
        AGENT,
        draft.draft_id,
        "http-agent-validate",
        transition(draft, "Validate proposal"),
    )
    draft = service.submit_for_review(
        AGENT,
        draft.draft_id,
        "http-agent-submit",
        transition(draft, "Submit proposal"),
    )
    approval_response = client.post(
        f"/v1/drafts/{draft.draft_id}/approve",
        headers=_headers(
            AGENT.actor_id,
            "http-agent-approve",
            spoofed_actor=APPROVER.actor_id,
        ),
        json=transition(draft, "Agent must not approve").model_dump(mode="json"),
    )
    publisher_spoof_approval_response = client.post(
        f"/v1/drafts/{draft.draft_id}/approve",
        headers=_headers(
            AGENT.actor_id,
            "http-agent-publisher-spoof-approve",
            spoofed_actor=PUBLISHER.actor_id,
        ),
        json=transition(draft, "Publisher header must not replace agent").model_dump(
            mode="json"
        ),
    )
    approved = service.approve_draft(
        APPROVER,
        draft.draft_id,
        "http-human-approve",
        transition(draft, "Human approves exact candidate"),
    )
    assert approved.approval is not None
    publication_response = client.post(
        f"/v1/drafts/{approved.draft_id}/publish",
        headers=_headers(
            AGENT.actor_id,
            "http-agent-publish",
            spoofed_actor=PUBLISHER.actor_id,
        ),
        json=PublishCommand(
            **transition(approved, "Agent must not publish").model_dump(),
            approval_id=approved.approval.decision_id,
        ).model_dump(mode="json"),
    )
    unverified_response = client.get(
        f"/v1/drafts/{approved.draft_id}",
        headers={"X-Athena-Actor": PUBLISHER.actor_id},
    )

    assert approval_response.status_code == 403
    assert approval_response.json()["error"]["code"] == "authorization_denied"
    assert publisher_spoof_approval_response.status_code == 403
    assert (
        publisher_spoof_approval_response.json()["error"]["code"]
        == "authorization_denied"
    )
    assert publication_response.status_code == 403
    assert publication_response.json()["error"]["code"] == "authorization_denied"
    assert unverified_response.status_code == 401
    assert unverified_response.json()["error"]["code"] == "authentication_required"


def test_http_ambiguous_version_lookup_requires_manifest_identity() -> None:
    service, client = _client()
    for suffix in ("one", "two"):
        manifest = canonical_manifest(manifest_id=f"wl-synthetic-{suffix}")
        approved = approve_draft(
            service,
            create_draft(service, manifest, draft_id=f"draft-{suffix}"),
            key_prefix=suffix,
        )
        publish_draft(service, approved, key_prefix=suffix)

    response = client.get(
        "/v1/versions/1.0.0",
        headers=_headers(PUBLISHER.actor_id),
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ambiguous_lookup"
