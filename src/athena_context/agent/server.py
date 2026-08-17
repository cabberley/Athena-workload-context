from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from typing import Any, Final, TypeVar, cast

from pydantic import ValidationError

from athena_context.agent.errors import (
    ContextMcpError,
    ToolAuthenticationError,
    ToolAuthorizationError,
    ToolGroundingError,
    ToolInputError,
    ToolNotFoundError,
    ToolPortError,
    ToolResponseTooLargeError,
)
from athena_context.agent.models import (
    AgentModel,
    AuthoritativePolicyView,
    Citation,
    ClauseDifference,
    CompareEnvironmentsInput,
    ConstraintSummary,
    ContextOutput,
    ControlSummary,
    DraftProposalOutput,
    EnvironmentComparisonOutput,
    EnvironmentSummary,
    EvidenceRefCitation,
    ExplainFindingInput,
    FindingExplanationOutput,
    GetContextInput,
    GroundedResponse,
    HistoryEventSummary,
    HistoryOutput,
    ListWorkloadsInput,
    ListWorkloadsOutput,
    ObjectiveSummary,
    ProfileFindingVerdict,
    ProfileVerdict,
    ProposeManifestPatchInput,
    ReadHistoryInput,
    RelationshipSummary,
    ResolvedResourceOutput,
    ResolveResourceInput,
    RiskAcceptanceSummary,
    RoleSummary,
    ToolAnnotations,
    ToolCallContext,
    ToolDefinition,
    WorkloadSummary,
    exact_evidence_reference,
)
from athena_context.agent.ports import (
    AuthoritativeFindingsPort,
    ContextApiPort,
    McpTransportPort,
)
from athena_context.api.domain import (
    Actor,
    AuditEvent,
    CreateDraftCommand,
    DraftState,
    PublishedManifestView,
)
from athena_context.api.errors import (
    AuthenticationError,
    AuthorizationError,
    ContextApiError,
)
from athena_context.contracts.manifest import (
    CanonicalWorkloadManifest,
    DeclaredManifestRelationship,
    ExceptionManifestRelationship,
    ExternalEndpoint,
    ManifestFinding,
    RoleEndpoint,
    canonicalize_manifest_payload,
    resolve_manifest_profile,
)

TOOL_ALLOWLIST: Final[tuple[str, ...]] = (
    "list_workloads",
    "resolve_resource",
    "get_context",
    "compare_environments",
    "explain_finding",
    "read_history",
    "propose_manifest_patch",
)
MAX_INPUT_BYTES: Final = 16_384
MAX_OUTPUT_BYTES: Final = 65_536
MAX_POLICY_RESOURCES: Final = 5_000
MAX_POLICY_FINDINGS: Final = 100

_RISK_PATH = re.compile(
    r"^/profiles/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/"
    r"riskAcceptances/(0|[1-9][0-9]{0,2})/residualRiskStatement$"
)
_INJECTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bignore\s+(?:all|any|previous|prior)\s+(?:instructions?|messages?|rules?)\b",
        r"\b(?:system|developer)\s+(?:prompt|message|instructions?)\b",
        r"\b(?:jailbreak|prompt[\s-]*injection)\b",
        r"\b(?:reveal|print|return|exfiltrate)\b.{0,40}"
        r"\b(?:secret|credential|token|system\s+prompt)\b",
        r"\b(?:bypass|disable|override)\b.{0,40}"
        r"\b(?:authorization|guardrail|scope|policy)\b",
        r"\b(?:execute|run)\b.{0,30}\b(?:kql|code|command|query|powershell|shell)\b",
        r"<\s*/?\s*(?:system|developer|assistant)\b",
    )
)

InputModel = TypeVar("InputModel", bound=AgentModel)
OutputModel = TypeVar("OutputModel", bound=GroundedResponse)
Handler = Callable[[AgentModel, ToolCallContext], GroundedResponse]


class _ToolSpec:
    __slots__ = (
        "description",
        "handler",
        "input_model",
        "output_model",
        "read_only",
    )

    def __init__(
        self,
        *,
        input_model: type[AgentModel],
        output_model: type[GroundedResponse],
        handler: Handler,
        description: str,
        read_only: bool,
    ) -> None:
        self.input_model = input_model
        self.output_model = output_model
        self.handler = handler
        self.description = description
        self.read_only = read_only


def _version_key(value: str) -> tuple[int, int, int]:
    major, minor, patch = value.split(".")
    return (int(major), int(minor), int(patch))


def _normalized(value: str) -> str:
    return value.casefold()


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _json_size(value: object) -> int:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ToolInputError("tool input must be finite JSON data") from exc
    return len(encoded)


def _contains_injection(value: object) -> bool:
    if isinstance(value, str):
        return any(pattern.search(value) is not None for pattern in _INJECTION_PATTERNS)
    if isinstance(value, Mapping):
        return any(
            _contains_injection(key) or _contains_injection(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_injection(item) for item in value)
    return False


def _endpoint_ref(endpoint: RoleEndpoint | ExternalEndpoint) -> str:
    if isinstance(endpoint, RoleEndpoint):
        return f"role:{endpoint.role_ref}"
    return f"external:{endpoint.external_ref}"


def _profile_key(
    manifest: CanonicalWorkloadManifest,
    requested: str,
) -> str:
    matches = [
        key for key in manifest.profiles if key.casefold() == requested.casefold()
    ]
    if len(matches) != 1:
        raise ToolGroundingError("requested profile is not uniquely present in the manifest")
    return matches[0]


def _manifest_citation(
    view: PublishedManifestView,
    *,
    profile_id: str,
    clause_id: str,
    clause_path: str,
) -> Citation:
    published = view.published
    return Citation(
        manifest_id=published.manifest_id,
        manifest_version=published.manifest_version,
        profile_id=profile_id,
        clause_id=clause_id,
        clause_path=clause_path,
        evidence_refs=(
            EvidenceRefCitation(
                ref_type="publishedManifest",
                reference=published.manifest_digest,
            ),
        ),
    )


def _finding_citation(finding: ManifestFinding) -> Citation:
    if len(finding.evidence_refs) > 50:
        raise ToolGroundingError("finding evidence references exceed the MCP citation bound")
    return Citation(
        manifest_id=finding.manifest_id,
        manifest_version=finding.manifest_version,
        profile_id=finding.profile_id,
        clause_id=finding.clause_id,
        clause_path=finding.governance_scope.clause_path,
        evidence_refs=tuple(
            exact_evidence_reference(reference) for reference in finding.evidence_refs
        ),
    )


class ContextMcpServer:
    """Exact, transport-neutral MCP tool registry over authoritative ports."""

    def __init__(
        self,
        *,
        context_api: ContextApiPort,
        findings: AuthoritativeFindingsPort,
        max_input_bytes: int = MAX_INPUT_BYTES,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
    ) -> None:
        if not 256 <= max_input_bytes <= MAX_INPUT_BYTES:
            raise ValueError("max_input_bytes is outside the supported bound")
        if not 256 <= max_output_bytes <= MAX_OUTPUT_BYTES:
            raise ValueError("max_output_bytes is outside the supported bound")
        self._context_api = context_api
        self._findings = findings
        self._max_input_bytes = max_input_bytes
        self._max_output_bytes = max_output_bytes
        self._specs: dict[str, _ToolSpec] = {
            "list_workloads": _ToolSpec(
                input_model=ListWorkloadsInput,
                output_model=ListWorkloadsOutput,
                handler=self._list_workloads,
                description=(
                    "List only published workloads in the verified caller workload scope."
                ),
                read_only=True,
            ),
            "resolve_resource": _ToolSpec(
                input_model=ResolveResourceInput,
                output_model=ResolvedResourceOutput,
                handler=self._resolve_resource,
                description=(
                    "Resolve one scoped Azure resource to one authoritative workload role."
                ),
                read_only=True,
            ),
            "get_context": _ToolSpec(
                input_model=GetContextInput,
                output_model=ContextOutput,
                handler=self._get_context,
                description=(
                    "Read a bounded published profile projection and deterministic findings."
                ),
                read_only=True,
            ),
            "compare_environments": _ToolSpec(
                input_model=CompareEnvironmentsInput,
                output_model=EnvironmentComparisonOutput,
                handler=self._compare_environments,
                description=(
                    "Compare two or three resolved environments through authoritative findings."
                ),
                read_only=True,
            ),
            "explain_finding": _ToolSpec(
                input_model=ExplainFindingInput,
                output_model=FindingExplanationOutput,
                handler=self._explain_finding,
                description=(
                    "Render a deterministic explanation of one cited authoritative finding."
                ),
                read_only=True,
            ),
            "read_history": _ToolSpec(
                input_model=ReadHistoryInput,
                output_model=HistoryOutput,
                handler=self._read_history,
                description=(
                    "Read bounded manifest lifecycle history without reasons, logs, or payloads."
                ),
                read_only=True,
            ),
            "propose_manifest_patch": _ToolSpec(
                input_model=ProposeManifestPatchInput,
                output_model=DraftProposalOutput,
                handler=self._propose_manifest_patch,
                description=(
                    "Create only a draft from bounded replace operations on approved paths; "
                    "never approve, publish, remediate, or execute code."
                ),
                read_only=False,
            ),
        }
        if tuple(self._specs) != TOOL_ALLOWLIST:
            raise RuntimeError("Context MCP tool registry differs from the reviewed allowlist")

    def list_tools(self) -> tuple[ToolDefinition, ...]:
        return tuple(
            ToolDefinition(
                name=name,
                description=spec.description,
                inputSchema=spec.input_model.model_json_schema(),
                outputSchema=spec.output_model.model_json_schema(),
                annotations=ToolAnnotations(
                    readOnlyHint=spec.read_only,
                    idempotentHint=(
                        spec.read_only or name == "propose_manifest_patch"
                    ),
                ),
            )
            for name, spec in self._specs.items()
        )

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, object],
        context: ToolCallContext,
    ) -> AgentModel:
        spec = self._specs.get(name)
        if spec is None:
            raise ToolNotFoundError("tool name is not in the reviewed allowlist")
        if not isinstance(context, ToolCallContext):
            raise ToolAuthenticationError("verified transport authentication is required")
        if not context.authorized_workload_ids:
            raise ToolAuthenticationError("an explicit workload scope is required")
        if _json_size(arguments) > self._max_input_bytes:
            raise ToolInputError("tool input exceeds the byte bound")
        if _contains_injection(arguments):
            raise ToolInputError("instruction-like content is not accepted by Context MCP")
        try:
            request = spec.input_model.model_validate(dict(arguments))
        except (ValidationError, ValueError, TypeError) as exc:
            raise ToolInputError("tool input failed its closed typed schema") from exc

        try:
            response = spec.handler(request, context)
        except ContextMcpError:
            raise
        except AuthenticationError as exc:
            raise ToolAuthenticationError("authoritative authentication was rejected") from exc
        except AuthorizationError as exc:
            raise ToolAuthorizationError("authoritative workload authorization was denied") from exc
        except ContextApiError as exc:
            raise ToolPortError("authoritative Context API rejected the operation") from exc
        except (ValidationError, ValueError, TypeError, KeyError, IndexError) as exc:
            raise ToolGroundingError("authoritative data failed deterministic grounding") from exc

        if not isinstance(response, spec.output_model):
            raise ToolGroundingError("tool handler returned an unexpected response contract")
        payload = response.model_dump(mode="json", exclude_none=True)
        if _contains_injection(payload):
            raise ToolGroundingError("authoritative output contains instruction-like text")
        if _json_size(payload) > self._max_output_bytes:
            raise ToolResponseTooLargeError("tool response exceeds the byte bound")
        return response

    def serve(self, transport: McpTransportPort) -> None:
        transport.run(tools=self.list_tools(), dispatch=self.call_tool)

    def _require_scope(self, context: ToolCallContext, workload_id: str) -> Actor:
        if workload_id.casefold() not in {
            item.casefold() for item in context.authorized_workload_ids
        }:
            raise ToolAuthorizationError("requested workload is outside caller scope")
        return context.authentication.actor

    def _published(
        self,
        actor: Actor,
        workload_id: str,
        manifest_version: str | None,
    ) -> PublishedManifestView:
        if manifest_version is not None:
            return self._context_api.get_published(
                actor,
                manifest_version,
                manifest_id=workload_id,
            )
        versions = self._context_api.list_published(actor, workload_id)
        active = [view for view in versions if view.supersession is None]
        if len(active) != 1:
            raise ToolGroundingError(
                "workload must have exactly one unsuperseded published manifest"
            )
        return active[0]

    def _policy_view(
        self,
        actor: Actor,
        published: PublishedManifestView,
        profile_id: str,
    ) -> AuthoritativePolicyView:
        candidate = self._findings.get_policy_view(
            actor,
            manifest_id=published.published.manifest_id,
            manifest_version=published.published.manifest_version,
            profile_id=profile_id,
        )
        validated = AuthoritativePolicyView.model_validate(
            candidate.model_dump(mode="python", by_alias=True)
        )
        evidence = validated.evidence
        if (
            len(evidence.resources) > MAX_POLICY_RESOURCES
            or len(validated.findings) > MAX_POLICY_FINDINGS
        ):
            raise ToolGroundingError("authoritative policy view exceeds MCP bounds")
        resolved = resolve_manifest_profile(
            published.published.manifest,
            profile_id,
            as_of=validated.evaluated_at,
        )
        if resolved.canonical_json() != validated.profile.canonical_json():
            raise ToolGroundingError(
                "findings port profile differs from the published manifest"
            )
        return validated

    def _list_workloads(
        self,
        raw: AgentModel,
        context: ToolCallContext,
    ) -> ListWorkloadsOutput:
        request = cast(ListWorkloadsInput, raw)
        actor = context.authentication.actor
        scoped = sorted(context.authorized_workload_ids, key=_normalized)
        page_ids = scoped[request.offset : request.offset + request.limit]
        if not page_ids:
            raise ToolGroundingError("requested workload page is empty")

        summaries: list[WorkloadSummary] = []
        citations: list[Citation] = []
        for workload_id in page_ids:
            view = self._published(actor, workload_id, None)
            manifest = view.published.manifest
            profile_id = _profile_key(manifest, request.profile_id)
            summaries.append(
                WorkloadSummary(
                    workload_id=workload_id,
                    display_name=manifest.workload.display_name,
                    manifest_version=view.published.manifest_version,
                    manifest_digest=view.published.manifest_digest,
                    profile_ids=tuple(
                        sorted(
                            (profile.profile_id for profile in manifest.profiles.values()),
                            key=_normalized,
                        )
                    ),
                )
            )
            citations.append(
                _manifest_citation(
                    view,
                    profile_id=profile_id,
                    clause_id="workload",
                    clause_path="/workload",
                )
            )
        next_offset = request.offset + len(page_ids)
        return ListWorkloadsOutput(
            workloads=tuple(summaries),
            total_scoped=len(scoped),
            next_offset=next_offset if next_offset < len(scoped) else None,
            citations=tuple(citations),
        )

    def _resolve_resource(
        self,
        raw: AgentModel,
        context: ToolCallContext,
    ) -> ResolvedResourceOutput:
        request = cast(ResolveResourceInput, raw)
        actor = self._require_scope(context, request.workload_id)
        published = self._published(actor, request.workload_id, request.manifest_version)
        policy = self._policy_view(actor, published, request.profile_id)
        normalized_resource = request.resource_id.rstrip("/").casefold()
        resources = [
            resource
            for resource in policy.evidence.resources
            if resource.resource_id.rstrip("/").casefold() == normalized_resource
        ]
        bindings = [
            binding
            for binding in policy.evidence.role_bindings
            if normalized_resource
            in {item.rstrip("/").casefold() for item in binding.selected_resource_ids}
        ]
        if len(resources) != 1 or len(bindings) != 1:
            raise ToolGroundingError("resource binding is missing or ambiguous")
        resource = resources[0]
        binding = bindings[0]
        if (
            resource.state != "complete"
            or resource.proof_source != "observed"
            or binding.state != "complete"
            or resource.role_ref.casefold() != binding.role_ref.casefold()
        ):
            raise ToolGroundingError("resource binding is not complete observed evidence")
        roles = [
            role
            for role in policy.profile.roles
            if role.role_id.casefold() == binding.role_ref.casefold()
        ]
        if len(roles) != 1:
            raise ToolGroundingError("resource role is not uniquely declared")
        role = roles[0]
        citation = Citation(
            manifest_id=policy.profile.manifest_id,
            manifest_version=policy.profile.manifest_version,
            profile_id=policy.profile.profile_id,
            clause_id=role.role_id,
            clause_path=(
                f"/resolvedProfiles/{_pointer_token(policy.profile.profile_id)}/"
                f"roles/{_pointer_token(role.role_id)}"
            ),
            evidence_refs=(exact_evidence_reference(resource.evidence_ref),),
        )
        return ResolvedResourceOutput(
            workload_id=request.workload_id,
            manifest_version=policy.profile.manifest_version,
            profile_id=policy.profile.profile_id,
            resource_id=resource.resource_id,
            role_id=role.role_id,
            role_kind=role.kind,
            binding_state="complete",
            proof_source="observed",
            selector_result_digest=binding.selector_result_digest,
            citations=(citation,),
        )

    def _get_context(
        self,
        raw: AgentModel,
        context: ToolCallContext,
    ) -> ContextOutput:
        request = cast(GetContextInput, raw)
        actor = self._require_scope(context, request.workload_id)
        published = self._published(actor, request.workload_id, request.manifest_version)
        policy = self._policy_view(actor, published, request.profile_id)
        profile = policy.profile
        finding_by_clause = {
            finding.clause_id.casefold(): finding for finding in policy.findings
        }
        limit = request.limit_per_section
        included = set(request.sections)
        truncated: list[str] = []

        def bounded[T](name: str, values: Sequence[T]) -> tuple[T, ...]:
            if len(values) > limit:
                truncated.append(name)
            return tuple(values[:limit])

        roles = [
            RoleSummary(
                role_id=role.role_id,
                kind=role.kind,
                cardinality=role.cardinality.cardinality_kind,
                owner_ref=role.owner_ref,
                clause_path=(
                    f"/resolvedProfiles/{_pointer_token(profile.profile_id)}/"
                    f"roles/{_pointer_token(role.role_id)}"
                ),
            )
            for role in sorted(profile.roles, key=lambda item: _normalized(item.role_id))
        ]
        relationships: list[RelationshipSummary] = []
        for relationship in sorted(
            profile.relationships,
            key=lambda item: _normalized(
                item.relationship_id
                if isinstance(item, DeclaredManifestRelationship)
                else item.exception_id
            ),
        ):
            if isinstance(relationship, DeclaredManifestRelationship):
                relationships.append(
                    RelationshipSummary(
                        relationship_id=relationship.relationship_id,
                        relationship_class="declared",
                        kind=relationship.kind,
                        source_ref=_endpoint_ref(relationship.source),
                        target_ref=_endpoint_ref(relationship.target),
                        owner_ref=relationship.owner_ref,
                        clause_path=relationship.source_clause,
                    )
                )
            elif isinstance(relationship, ExceptionManifestRelationship):
                relationships.append(
                    RelationshipSummary(
                        relationship_id=relationship.exception_id,
                        relationship_class="exception",
                        kind="exception",
                        target_ref=(
                            relationship.applies_to_relationship_ref
                            or cast(str, relationship.applies_to_clause_ref)
                        ),
                        owner_ref=relationship.owner_ref,
                        clause_path=relationship.governance_scope.clause_path,
                    )
                )
        constraints = [
            ConstraintSummary(
                clause_id=constraint.constraint_id,
                constraint_type=constraint.constraint_type,
                finding_kind=constraint.finding_kind,
                verdict=finding_by_clause[constraint.constraint_id.casefold()].verdict,
                owner_ref=constraint.owner_ref,
                clause_path=constraint.governance_scope.clause_path,
            )
            for constraint in sorted(
                profile.constraints,
                key=lambda item: _normalized(item.constraint_id),
            )
        ]
        controls = [
            ControlSummary(
                control_id=control.control_id,
                control_kind=control.control_kind,
                health=control.health,
                owner_ref=control.owner_ref,
                clause_path=control.governance_scope.clause_path,
            )
            for control in sorted(
                profile.controls,
                key=lambda item: _normalized(item.control_id),
            )
        ]
        risks = [
            RiskAcceptanceSummary(
                risk_acceptance_id=risk.risk_acceptance_id,
                risk_kind=risk.risk_kind,
                risk_rating=risk.risk_rating,
                status=risk.status,
                owner_ref=risk.owned_by,
                clause_path=risk.governance_scope.clause_path,
            )
            for risk in sorted(
                profile.risk_acceptances,
                key=lambda item: _normalized(item.risk_acceptance_id),
            )
        ]
        objectives = [
            ObjectiveSummary(
                objective_id=objective.objective_id,
                objective_type=objective.objective_type,
                target=objective.target,
                owner_ref=objective.owner_ref,
                clause_path=(
                    f"/resolvedProfiles/{_pointer_token(profile.profile_id)}/"
                    f"objectives/{_pointer_token(objective.objective_id)}"
                ),
            )
            for objective in sorted(
                profile.objectives,
                key=lambda item: _normalized(item.objective_id),
            )
        ]
        output_constraints = (
            bounded("constraints", constraints) if "constraints" in included else ()
        )
        citations = [
            _manifest_citation(
                published,
                profile_id=profile.profile_id,
                clause_id="resolved-profile",
                clause_path=f"/resolvedProfiles/{_pointer_token(profile.profile_id)}",
            )
        ]
        citations.extend(
            _finding_citation(finding_by_clause[item.clause_id.casefold()])
            for item in output_constraints
        )
        return ContextOutput(
            workload_id=request.workload_id,
            manifest_version=profile.manifest_version,
            manifest_digest=published.published.manifest_digest,
            profile_id=profile.profile_id,
            profile_type=profile.profile_type,
            resolved_profile_digest=profile.resolved_profile_digest,
            zone_loss_continuity_required=(
                profile.settings.continuity.zone_loss_continuity_required
            ),
            roles=bounded("roles", roles) if "roles" in included else (),
            relationships=(
                bounded("relationships", relationships)
                if "relationships" in included
                else ()
            ),
            constraints=output_constraints,
            controls=bounded("controls", controls) if "controls" in included else (),
            risk_acceptances=(
                bounded("riskAcceptances", risks)
                if "riskAcceptances" in included
                else ()
            ),
            objectives=(
                bounded("objectives", objectives) if "objectives" in included else ()
            ),
            truncated_sections=cast(tuple[Any, ...], tuple(truncated)),
            citations=tuple(citations),
        )

    def _compare_environments(
        self,
        raw: AgentModel,
        context: ToolCallContext,
    ) -> EnvironmentComparisonOutput:
        request = cast(CompareEnvironmentsInput, raw)
        actor = self._require_scope(context, request.workload_id)
        published = self._published(actor, request.workload_id, request.manifest_version)
        policies = [
            self._policy_view(actor, published, profile_id)
            for profile_id in request.profile_ids
        ]
        findings_by_profile = [
            {finding.clause_id.casefold(): finding for finding in policy.findings}
            for policy in policies
        ]
        all_clauses = sorted(
            set().union(*(set(findings) for findings in findings_by_profile))
        )
        selected_clauses = all_clauses[: request.max_clauses]
        truncated = len(all_clauses) > len(selected_clauses)
        environments = tuple(
            EnvironmentSummary(
                profile_id=policy.profile.profile_id,
                profile_type=policy.profile.profile_type,
                resolved_profile_digest=policy.profile.resolved_profile_digest,
                zone_loss_continuity_required=(
                    policy.profile.settings.continuity.zone_loss_continuity_required
                ),
                role_count=len(policy.profile.roles),
                findings=tuple(
                    ProfileFindingVerdict(
                        clause_id=finding.clause_id,
                        verdict=finding.verdict,
                        clause_path=finding.governance_scope.clause_path,
                    )
                    for key in selected_clauses
                    if (finding := findings_by_profile[index].get(key)) is not None
                ),
            )
            for index, policy in enumerate(policies)
        )
        differences: list[ClauseDifference] = []
        citations: list[Citation] = []
        for clause in selected_clauses:
            present = [
                findings.get(clause) for findings in findings_by_profile
            ]
            verdicts = [
                finding.verdict if finding is not None else "notDeclared"
                for finding in present
            ]
            if len(set(verdicts)) == 1:
                continue
            differences.append(
                ClauseDifference(
                    clause_id=next(
                        finding.clause_id
                        for finding in present
                        if finding is not None
                    ),
                    clause_paths=tuple(
                        sorted(
                            {
                                finding.governance_scope.clause_path
                                for finding in present
                                if finding is not None
                            }
                        )
                    ),
                    verdicts=tuple(
                        ProfileVerdict(
                            profile_id=policy.profile.profile_id,
                            verdict=cast(Any, verdict),
                        )
                        for policy, verdict in zip(policies, verdicts, strict=True)
                    ),
                )
            )
            citations.extend(
                _finding_citation(finding)
                for finding in present
                if finding is not None
            )
        if not citations:
            citations = [
                _manifest_citation(
                    published,
                    profile_id=policy.profile.profile_id,
                    clause_id="environment-comparison",
                    clause_path=(
                        f"/resolvedProfiles/{_pointer_token(policy.profile.profile_id)}"
                    ),
                )
                for policy in policies
            ]
        return EnvironmentComparisonOutput(
            workload_id=request.workload_id,
            manifest_version=published.published.manifest_version,
            environments=environments,
            differences=tuple(differences),
            truncated=truncated,
            citations=tuple(citations),
        )

    def _explain_finding(
        self,
        raw: AgentModel,
        context: ToolCallContext,
    ) -> FindingExplanationOutput:
        request = cast(ExplainFindingInput, raw)
        actor = self._require_scope(context, request.workload_id)
        published = self._published(actor, request.workload_id, request.manifest_version)
        policy = self._policy_view(actor, published, request.profile_id)
        findings = [
            finding
            for finding in policy.findings
            if finding.clause_id.casefold() == request.clause_id.casefold()
        ]
        constraints = [
            constraint
            for constraint in policy.profile.constraints
            if constraint.constraint_id.casefold() == request.clause_id.casefold()
        ]
        if len(findings) != 1 or len(constraints) != 1:
            raise ToolGroundingError("finding clause is not uniquely authoritative")
        finding = findings[0]
        constraint = constraints[0]
        explanation = (
            f"Clause {finding.clause_id} evaluated as {finding.verdict} for profile "
            f"{finding.profile_id}. The declared {constraint.constraint_type} requirement "
            f"uses {constraint.proof_requirement.proof_kind}; "
            f"{len(finding.evidence_refs)} bound evidence reference(s) support this result."
        )
        return FindingExplanationOutput(
            workload_id=request.workload_id,
            manifest_version=finding.manifest_version,
            profile_id=finding.profile_id,
            clause_id=finding.clause_id,
            finding_kind=finding.finding_kind,
            verdict=finding.verdict,
            deterministic_explanation=explanation,
            requires_human_review=finding.verdict
            in {"violation", "unknown", "conflicting"},
            citations=(_finding_citation(finding),),
        )

    def _read_history(
        self,
        raw: AgentModel,
        context: ToolCallContext,
    ) -> HistoryOutput:
        request = cast(ReadHistoryInput, raw)
        actor = self._require_scope(context, request.workload_id)
        published = self._published(actor, request.workload_id, request.manifest_version)
        profile_id = _profile_key(published.published.manifest, request.profile_id)
        events = self._context_api.audit_history(actor, request.workload_id)
        eligible = sorted(
            (
                event
                for event in events
                if request.before_sequence is None
                or event.sequence < request.before_sequence
            ),
            key=lambda event: event.sequence,
            reverse=True,
        )
        selected = eligible[: request.limit]
        if not selected:
            raise ToolGroundingError("requested history page is empty")
        citations = tuple(
            Citation(
                manifest_id=request.workload_id,
                manifest_version=(
                    event.manifest_version or published.published.manifest_version
                ),
                profile_id=profile_id,
                clause_id=event.event_id,
                clause_path=f"/audit/{event.sequence}",
                evidence_refs=(
                    EvidenceRefCitation(
                        ref_type="historyEvent",
                        reference=event.event_id,
                    ),
                ),
            )
            for event in selected
        )
        next_before = selected[-1].sequence if len(eligible) > len(selected) else None
        return HistoryOutput(
            workload_id=request.workload_id,
            profile_id=profile_id,
            events=tuple(self._history_summary(event) for event in selected),
            next_before_sequence=next_before,
            citations=citations,
        )

    @staticmethod
    def _history_summary(event: AuditEvent) -> HistoryEventSummary:
        return HistoryEventSummary(
            event_id=event.event_id,
            sequence=event.sequence,
            action=event.action,
            actor_kind=event.actor.kind,
            occurred_at=event.occurred_at,
            manifest_version=event.manifest_version,
            manifest_digest=event.manifest_digest,
        )

    def _propose_manifest_patch(
        self,
        raw: AgentModel,
        context: ToolCallContext,
    ) -> DraftProposalOutput:
        request = cast(ProposeManifestPatchInput, raw)
        actor = self._require_scope(context, request.workload_id)
        if _version_key(request.proposed_manifest_version) <= _version_key(
            request.base_manifest_version
        ):
            raise ToolInputError("proposed manifest version must be newer than its base")
        published = self._published(
            actor,
            request.workload_id,
            request.base_manifest_version,
        )
        profile_id = _profile_key(published.published.manifest, request.profile_id)
        patched = self._apply_patch(
            published.published.manifest,
            request,
            profile_id=profile_id,
        )
        command = CreateDraftCommand(
            draft_id=request.draft_id,
            manifest=patched,
            manifest_digest=patched.compatibility.artifact_digest,
            previous_version=request.base_manifest_version,
            reason=request.reason,
        )
        draft = self._context_api.create_draft(
            actor,
            request.idempotency_key,
            command,
        )
        if (
            draft.state is not DraftState.DRAFT
            or draft.manifest_id != request.workload_id
            or draft.manifest.manifest_version != request.proposed_manifest_version
            or draft.previous_version != request.base_manifest_version
            or draft.created_by != actor
            or draft.approval is not None
            or draft.review is not None
            or draft.publication_candidate is not None
        ):
            raise ToolGroundingError("Context API returned a non-draft proposal result")
        citations = tuple(
            Citation(
                manifest_id=draft.manifest_id,
                manifest_version=draft.manifest.manifest_version,
                profile_id=profile_id,
                clause_id="draft-proposal",
                clause_path=operation.path,
                evidence_refs=(
                    EvidenceRefCitation(
                        ref_type="draftProposal",
                        reference=draft.draft_id,
                    ),
                ),
            )
            for operation in request.operations
        )
        return DraftProposalOutput(
            workload_id=request.workload_id,
            base_manifest_version=request.base_manifest_version,
            proposed_manifest_version=request.proposed_manifest_version,
            draft_id=draft.draft_id,
            revision=draft.revision,
            state=DraftState.DRAFT,
            manifest_digest=draft.manifest_digest,
            changed_paths=tuple(operation.path for operation in request.operations),
            citations=citations,
        )

    @staticmethod
    def _apply_patch(
        manifest: CanonicalWorkloadManifest,
        request: ProposeManifestPatchInput,
        *,
        profile_id: str,
    ) -> CanonicalWorkloadManifest:
        payload = deepcopy(
            manifest.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=False,
                exclude_unset=True,
            )
        )
        for operation in request.operations:
            if operation.path == "/workload/displayName":
                if len(operation.value) > 200:
                    raise ToolInputError("workload display name exceeds its field bound")
                workload = cast(dict[str, object], payload["workload"])
                workload["displayName"] = operation.value
                continue
            match = _RISK_PATH.fullmatch(operation.path)
            if match is None or match.group(1) != profile_id:
                raise ToolInputError("patch path is not in the approved editable allowlist")
            index = int(match.group(2))
            profiles = cast(dict[str, dict[str, object]], payload["profiles"])
            profile = profiles.get(profile_id)
            if profile is None:
                raise ToolInputError("patch profile does not exist")
            risks = cast(list[dict[str, object]], profile["riskAcceptances"])
            if index >= len(risks):
                raise ToolInputError("patch risk-acceptance index does not exist")
            risks[index]["residualRiskStatement"] = operation.value
        payload["manifestVersion"] = request.proposed_manifest_version
        try:
            canonical = canonicalize_manifest_payload(payload)
            return CanonicalWorkloadManifest.model_validate(canonical)
        except (ValidationError, ValueError, TypeError) as exc:
            raise ToolInputError("patched manifest failed canonical validation") from exc


def build_context_mcp_server(
    *,
    context_api: ContextApiPort,
    findings: AuthoritativeFindingsPort,
) -> ContextMcpServer:
    return ContextMcpServer(context_api=context_api, findings=findings)


__all__ = [
    "MAX_INPUT_BYTES",
    "MAX_OUTPUT_BYTES",
    "TOOL_ALLOWLIST",
    "ContextMcpServer",
    "build_context_mcp_server",
]
