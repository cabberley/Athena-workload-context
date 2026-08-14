from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "README.md",
    "ARCHITECTURE.md",
    "AGENTS.md",
    ".github/copilot-instructions.md",
    ".github/agents/team.md",
    ".github/agents/routing.md",
    ".github/agents/coordinator.agent.md",
    "docs/planning/initial-build-plan.md",
    "docs/planning/model-allocation.md",
    "pyproject.toml",
)

FRONTMATTER_PATTERN = re.compile(r"\A---\n(?P<body>.*?)\n---\n", re.DOTALL)
MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]+\]\((?!https?://|mailto:|#)([^)]+)\)")
ALLOWED_MODELS = {
    "mai-code-1.1-flash",
    "gpt-5.3-codex",
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.5",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
}
ALLOWED_TOOLS = {"read", "search", "edit", "execute", "agent", "web", "todo"}
EXPECTED_AGENT_MODELS = {
    "coordinator": "gpt-5.6-sol",
    "architect": "gpt-5.5",
    "contract-manifest-engineer": "mai-code-1.1-flash",
    "backend-context-api-engineer": "mai-code-1.1-flash",
    "azure-platform-mcp-engineer": "mai-code-1.1-flash",
    "cohort-binding-engineer": "mai-code-1.1-flash",
    "contextual-policy-engineer": "mai-code-1.1-flash",
    "event-forecast-engineer": "mai-code-1.1-flash",
    "ux-engineer": "mai-code-1.1-flash",
    "agent-mcp-engineer": "mai-code-1.1-flash",
    "test-engineer": "mai-code-1.1-flash",
    "architecture-reviewer": "gpt-5.6-sol",
    "code-reviewer": "gpt-5.6-sol",
    "integration-validator": "gpt-5.6-sol",
    "security-reviewer": "gpt-5.6-sol",
    "release-reviewer": "gpt-5.6-sol",
}
EXPECTED_AGENT_TOOLS = {
    "coordinator": {"read", "search", "edit", "execute", "agent"},
    "architect": {"read", "search", "edit", "web"},
    "contract-manifest-engineer": {"read", "search", "edit", "execute"},
    "backend-context-api-engineer": {"read", "search", "edit", "execute"},
    "azure-platform-mcp-engineer": {"read", "search", "edit", "execute", "web"},
    "cohort-binding-engineer": {"read", "search", "edit", "execute"},
    "contextual-policy-engineer": {"read", "search", "edit", "execute"},
    "event-forecast-engineer": {"read", "search", "edit", "execute"},
    "ux-engineer": {"read", "search", "edit", "execute"},
    "agent-mcp-engineer": {"read", "search", "edit", "execute"},
    "test-engineer": {"read", "search", "edit", "execute"},
    "architecture-reviewer": {"read", "search"},
    "code-reviewer": {"read", "search"},
    "integration-validator": {"read", "search"},
    "security-reviewer": {"read", "search", "web"},
    "release-reviewer": {"read", "search"},
}
REVIEWER_AGENTS = {
    "architecture-reviewer",
    "code-reviewer",
    "integration-validator",
    "security-reviewer",
    "release-reviewer",
}
EXPECTED_PLAN_MODELS = {
    "WC-001": (
        "GPT-5.5 design, GPT-5.6 Sol architecture challenge, then "
        "MAI-Code-1.1-Flash implementation"
    ),
    **{f"WC-{number:03d}": "MAI-Code-1.1-Flash" for number in range(2, 20)},
    "WC-020": "GPT-5.6 Sol review and validation; MAI-Code-1.1-Flash fixes",
}
REQUIRED_AGENTS = {
    "coordinator",
    "architect",
    "contract-manifest-engineer",
    "backend-context-api-engineer",
    "azure-platform-mcp-engineer",
    "cohort-binding-engineer",
    "contextual-policy-engineer",
    "event-forecast-engineer",
    "ux-engineer",
    "agent-mcp-engineer",
    "test-engineer",
    "architecture-reviewer",
    "code-reviewer",
    "integration-validator",
    "security-reviewer",
    "release-reviewer",
}
REQUIRED_SKILLS = {
    "issue-triage",
    "architecture-adr",
    "architecture-review",
    "manifest-author",
    "context-api",
    "azure-mcp-integration",
    "cohort-binding",
    "contextual-policy",
    "event-forecast",
    "context-studio",
    "context-mcp",
    "test-hardening",
    "code-review",
    "integration-validation",
    "security-review",
    "release-review",
}


def validate_required_files(errors: list[str]) -> None:
    for relative_path in REQUIRED_FILES:
        if not (ROOT / relative_path).is_file():
            errors.append(f"missing required file: {relative_path}")


def validate_agents(errors: list[str]) -> None:
    agents = sorted((ROOT / ".github" / "agents").glob("*.agent.md"))
    identifiers = {path.name.removesuffix(".agent.md") for path in agents}
    missing_agents = REQUIRED_AGENTS - identifiers
    if missing_agents:
        errors.append(f"missing required agents: {', '.join(sorted(missing_agents))}")
    unexpected_agents = identifiers - set(EXPECTED_AGENT_MODELS)
    if unexpected_agents:
        errors.append(
            f"agents missing explicit model policy: {', '.join(sorted(unexpected_agents))}"
        )

    display_names: set[str] = set()
    for path in agents:
        text = path.read_text(encoding="utf-8")
        match = FRONTMATTER_PATTERN.match(text)
        if match is None:
            errors.append(f"{path.relative_to(ROOT)}: missing YAML frontmatter")
            continue
        try:
            frontmatter = yaml.safe_load(match.group("body"))
        except yaml.YAMLError as exc:
            errors.append(f"{path.relative_to(ROOT)}: invalid YAML: {exc}")
            continue
        if not isinstance(frontmatter, dict):
            errors.append(f"{path.relative_to(ROOT)}: frontmatter must be a mapping")
            continue

        description = frontmatter.get("description")
        if not isinstance(description, str) or not description.strip():
            errors.append(f"{path.relative_to(ROOT)}: missing description")

        name = frontmatter.get("name")
        if isinstance(name, str):
            if name in display_names:
                errors.append(f"{path.relative_to(ROOT)}: duplicate agent name {name}")
            display_names.add(name)

        model = frontmatter.get("model")
        if model not in ALLOWED_MODELS:
            errors.append(f"{path.relative_to(ROOT)}: unsupported model {model!r}")
        identifier = path.name.removesuffix(".agent.md")
        expected_model = EXPECTED_AGENT_MODELS.get(identifier)
        if expected_model is not None and model != expected_model:
            errors.append(
                f"{path.relative_to(ROOT)}: expected model {expected_model}, found {model!r}"
            )

        tools = frontmatter.get("tools", [])
        if not isinstance(tools, list) or any(tool not in ALLOWED_TOOLS for tool in tools):
            errors.append(f"{path.relative_to(ROOT)}: unsupported tools {tools!r}")
        expected_tools = EXPECTED_AGENT_TOOLS.get(identifier)
        if expected_tools is not None and set(tools) != expected_tools:
            errors.append(
                f"{path.relative_to(ROOT)}: expected tools "
                f"{sorted(expected_tools)}, found {sorted(tools)}"
            )

        disabled = frontmatter.get("disable-model-invocation", False)
        if identifier in REVIEWER_AGENTS and disabled is not True:
            errors.append(
                f"{path.relative_to(ROOT)}: reviewer must disable automatic invocation"
            )
        if identifier not in REVIEWER_AGENTS and disabled is True:
            errors.append(
                f"{path.relative_to(ROOT)}: builder/coordinator cannot disable invocation"
            )


def validate_skills(errors: list[str]) -> None:
    skills = sorted((ROOT / ".github" / "skills").glob("*/SKILL.md"))
    identifiers = {path.parent.name for path in skills}
    missing_skills = REQUIRED_SKILLS - identifiers
    if missing_skills:
        errors.append(f"missing required skills: {', '.join(sorted(missing_skills))}")

    declared_names: set[str] = set()
    for path in skills:
        text = path.read_text(encoding="utf-8")
        match = FRONTMATTER_PATTERN.match(text)
        if match is None:
            errors.append(f"{path.relative_to(ROOT)}: missing YAML frontmatter")
            continue
        try:
            frontmatter = yaml.safe_load(match.group("body"))
        except yaml.YAMLError as exc:
            errors.append(f"{path.relative_to(ROOT)}: invalid YAML: {exc}")
            continue
        if not isinstance(frontmatter, dict):
            errors.append(f"{path.relative_to(ROOT)}: frontmatter must be a mapping")
            continue
        name = frontmatter.get("name")
        description = frontmatter.get("description")
        if name != path.parent.name:
            errors.append(
                f"{path.relative_to(ROOT)}: name must match directory {path.parent.name}"
            )
        if name in declared_names:
            errors.append(f"{path.relative_to(ROOT)}: duplicate skill name {name}")
        if isinstance(name, str):
            declared_names.add(name)
        if not isinstance(description, str) or not description.strip():
            errors.append(f"{path.relative_to(ROOT)}: missing description")


def validate_instructions(errors: list[str]) -> None:
    for path in sorted((ROOT / ".github" / "instructions").glob("*.instructions.md")):
        text = path.read_text(encoding="utf-8")
        match = FRONTMATTER_PATTERN.match(text)
        if match is None:
            errors.append(f"{path.relative_to(ROOT)}: missing YAML frontmatter")
            continue
        try:
            frontmatter = yaml.safe_load(match.group("body"))
        except yaml.YAMLError as exc:
            errors.append(f"{path.relative_to(ROOT)}: invalid YAML: {exc}")
            continue
        apply_to = frontmatter.get("applyTo") if isinstance(frontmatter, dict) else None
        if not isinstance(apply_to, list) or not apply_to:
            errors.append(f"{path.relative_to(ROOT)}: applyTo must be a non-empty list")
        elif any(not isinstance(pattern, str) or not pattern for pattern in apply_to):
            errors.append(f"{path.relative_to(ROOT)}: applyTo contains an invalid pattern")


def validate_model_strategy_text(errors: list[str]) -> None:
    copilot_text = (ROOT / ".github" / "copilot-instructions.md").read_text(
        encoding="utf-8"
    )
    required_copilot_phrases = (
        "MAI-Code-1.1-Flash is the required initial implementation model",
        "GPT-5.6 Sol performs the independent fresh-context architecture",
        "GPT-5.6 Sol coordinates integration, performs independent code review",
    )
    for phrase in required_copilot_phrases:
        if phrase not in copilot_text:
            errors.append(f".github/copilot-instructions.md: missing strategy text {phrase!r}")

    plan_text = (ROOT / "docs" / "planning" / "initial-build-plan.md").read_text(
        encoding="utf-8"
    )
    if "independent GPT-5.6 Sol integration validation" not in plan_text:
        errors.append("initial build plan: missing independent integration validation gate")
    observed_plan_models: dict[str, str] = {}
    for line in plan_text.splitlines():
        if not line.startswith("| WC-"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) >= 4:
            issue_id = cells[0]
            if issue_id in observed_plan_models:
                errors.append(f"initial build plan: duplicate model assignment for {issue_id}")
            else:
                observed_plan_models[issue_id] = cells[3]
    for issue_id, expected_model in EXPECTED_PLAN_MODELS.items():
        observed_model = observed_plan_models.get(issue_id)
        if observed_model != expected_model:
            errors.append(
                f"initial build plan: {issue_id} expected model {expected_model!r}, "
                f"found {observed_model!r}"
            )

    launch_text = (
        ROOT / "docs" / "planning" / "copilot-launch-playbook.md"
    ).read_text(encoding="utf-8")
    required_review_launches = (
        "/agent architecture-reviewer",
        "/agent code-reviewer",
        "/agent security-reviewer",
        "/agent integration-validator",
        "/agent release-reviewer",
        "approved-for-implementation",
        "Run the architecture reviewer in a fresh Copilot session",
        "MAI implementation must not begin until it records",
        "launch the disabled reviewer agents manually in fresh Copilot sessions",
    )
    for launch in required_review_launches:
        if launch not in launch_text:
            errors.append(f"Copilot launch playbook: missing required gate {launch!r}")

    architecture_template = (
        ROOT / ".github" / "ISSUE_TEMPLATE" / "architecture.md"
    ).read_text(encoding="utf-8")
    required_architecture_fields = (
        "GPT-5.6 Sol Architecture Reviewer",
        "approved-for-implementation",
    )
    for field in required_architecture_fields:
        if field not in architecture_template:
            errors.append(f"architecture issue template: missing required field {field!r}")


def validate_local_markdown_links(errors: list[str]) -> None:
    for path in ROOT.rglob("*.md"):
        if ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for raw_target in MARKDOWN_LINK_PATTERN.findall(text):
            target = raw_target.split("#", maxsplit=1)[0]
            if not target:
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                errors.append(
                    f"{path.relative_to(ROOT)}: broken local link to {raw_target}"
                )


def main() -> int:
    errors: list[str] = []
    validate_required_files(errors)
    validate_agents(errors)
    validate_skills(errors)
    validate_instructions(errors)
    validate_model_strategy_text(errors)
    validate_local_markdown_links(errors)

    if errors:
        print("Repository validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("Repository validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
