from __future__ import annotations

from fastapi.testclient import TestClient

from athena_context.api.authorization import InMemoryActorDirectory
from athena_context.api.domain import CreateDraftCommand, TransitionCommand
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


def _client() -> tuple[ContextService, TestClient]:
    service = build_service()
    directory = InMemoryActorDirectory(
        [AGENT, AUTHOR, APPROVER, PUBLISHER, AUDITOR, OUTSIDER]
    )
    return service, TestClient(create_app(service=service, actors=directory))


def _headers(actor_id: str, key: str | None = None) -> dict[str, str]:
    headers = {"X-Athena-Actor": actor_id}
    if key is not None:
        headers["Idempotency-Key"] = key
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
def test_http_digest_and_human_authority_failures_are_typed() -> None:
    service, client = _client()
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
        headers=_headers(AGENT.actor_id, "http-agent-approve"),
        json=transition(draft, "Agent must not approve").model_dump(mode="json"),
    )

    assert digest_response.status_code == 409
    assert digest_response.json()["error"]["code"] == "digest_mismatch"
    assert approval_response.status_code == 403
    assert approval_response.json()["error"]["code"] == "authorization_denied"


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
