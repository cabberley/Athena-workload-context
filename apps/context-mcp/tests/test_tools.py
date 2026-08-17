from __future__ import annotations

from conftest import AGENT, WORKLOAD_ID, Harness

from athena_context.agent import TOOL_ALLOWLIST
from athena_context.agent.models import GroundedResponse
from athena_context.api.domain import DraftState


def _assert_grounded(response: GroundedResponse) -> None:
    assert response.citations
    for citation in response.citations:
        assert citation.manifest_id == WORKLOAD_ID
        assert citation.manifest_version
        assert citation.profile_id
        assert citation.clause_id
        assert citation.clause_path.startswith("/")
        assert citation.evidence_refs


def test_exact_allowlist_and_closed_tool_contracts(harness: Harness) -> None:
    tools = harness.server.list_tools()

    assert tuple(tool.name for tool in tools) == TOOL_ALLOWLIST
    assert len(tools) == 7
    assert not {
        "publish",
        "approve",
        "supersede",
        "remediate",
        "query",
        "kql",
        "code",
        "storage",
        "logs",
        "secrets",
    } & {tool.name for tool in tools}
    for tool in tools:
        wire = tool.model_dump(mode="json", by_alias=True)
        assert "inputSchema" in wire
        assert "outputSchema" in wire
        assert wire["inputSchema"]["additionalProperties"] is False
        assert wire["outputSchema"]["additionalProperties"] is False
        assert wire["annotations"]["destructiveHint"] is False
        assert wire["annotations"]["openWorldHint"] is False


def test_every_reviewed_tool_returns_bounded_cited_results(harness: Harness) -> None:
    version = "1.1.0"
    production = harness.policy_views["production"]
    resource_id = production.evidence.resources[0].resource_id
    clause_id = production.findings[0].clause_id

    calls = [
        ("list_workloads", {}),
        (
            "resolve_resource",
            {
                "workload_id": WORKLOAD_ID,
                "manifest_version": version,
                "profile_id": "production",
                "resource_id": resource_id,
            },
        ),
        (
            "get_context",
            {
                "workload_id": WORKLOAD_ID,
                "manifest_version": version,
                "profile_id": "production",
                "limit_per_section": 10,
            },
        ),
        (
            "compare_environments",
            {
                "workload_id": WORKLOAD_ID,
                "manifest_version": version,
                "profile_ids": ["production", "development", "training"],
            },
        ),
        (
            "explain_finding",
            {
                "workload_id": WORKLOAD_ID,
                "manifest_version": version,
                "profile_id": "production",
                "clause_id": clause_id,
            },
        ),
        (
            "read_history",
            {
                "workload_id": WORKLOAD_ID,
                "manifest_version": version,
                "profile_id": "production",
                "limit": 5,
            },
        ),
        (
            "propose_manifest_patch",
            {
                "workload_id": WORKLOAD_ID,
                "base_manifest_version": version,
                "proposed_manifest_version": "1.1.1",
                "profile_id": "production",
                "draft_id": "mcp-draft-001",
                "idempotency_key": "mcp-draft-001-create",
                "reason": "Propose a clearly synthetic display-name change",
                "operations": [
                    {
                        "op": "replace",
                        "path": "/workload/displayName",
                        "value": "Synthetic MCP proposal",
                    }
                ],
            },
        ),
    ]

    responses = [
        harness.server.call_tool(name, arguments, harness.context)
        for name, arguments in calls
    ]

    assert len(responses) == len(TOOL_ALLOWLIST)
    for response in responses:
        assert isinstance(response, GroundedResponse)
        _assert_grounded(response)
        assert len(response.model_dump_json()) <= 65_536

    proposal = responses[-1]
    assert proposal.state is DraftState.DRAFT
    assert proposal.approval_allowed is False
    assert proposal.publication_allowed is False
    assert proposal.remediation_allowed is False
    stored = harness.service.get_draft(AGENT, "mcp-draft-001")
    assert stored.state is DraftState.DRAFT
    assert stored.approval is None
    assert stored.review is None
    assert stored.publication_candidate is None


def test_context_and_explanation_are_deterministic_without_raw_bodies(
    harness: Harness,
) -> None:
    context = harness.server.call_tool(
        "get_context",
        {
            "workload_id": WORKLOAD_ID,
            "profile_id": "production",
            "sections": ["constraints", "riskAcceptances"],
        },
        harness.context,
    )
    explanation = harness.server.call_tool(
        "explain_finding",
        {
            "workload_id": WORKLOAD_ID,
            "profile_id": "production",
            "clause_id": "db-zone-loss-spof",
        },
        harness.context,
    )
    context_payload = context.model_dump_json()
    explanation_payload = explanation.model_dump_json()

    assert "residual_risk_statement" not in context_payload
    assert "sourceResponseBody" not in context_payload
    assert "raw_log" not in context_payload
    assert "recommend" not in explanation_payload.casefold()
    assert "remediat" not in explanation_payload.casefold()
    assert explanation.deterministic_explanation == (
        "Clause db-zone-loss-spof evaluated as acceptedResidualRisk for profile "
        "production. The declared supportedSingleton requirement uses cardinalityProof; "
        "1 bound evidence reference(s) support this result."
    )
