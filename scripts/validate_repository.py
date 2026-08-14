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
    "gpt-5.3-codex",
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.5",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
}
ALLOWED_TOOLS = {"read", "search", "edit", "execute", "agent", "web", "todo"}
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
    "security-reviewer",
    "release-reviewer",
}
REQUIRED_SKILLS = {
    "issue-triage",
    "architecture-adr",
    "manifest-author",
    "context-api",
    "azure-mcp-integration",
    "cohort-binding",
    "contextual-policy",
    "event-forecast",
    "context-studio",
    "context-mcp",
    "test-hardening",
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

        tools = frontmatter.get("tools", [])
        if not isinstance(tools, list) or any(tool not in ALLOWED_TOOLS for tool in tools):
            errors.append(f"{path.relative_to(ROOT)}: unsupported tools {tools!r}")

        if path.stem in {"security-reviewer.agent", "release-reviewer.agent"}:
            forbidden = {"edit", "execute"} & set(tools)
            if forbidden:
                errors.append(
                    f"{path.relative_to(ROOT)}: read-only reviewer has {sorted(forbidden)}"
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
