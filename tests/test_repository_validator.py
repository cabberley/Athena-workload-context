from pathlib import Path

from scripts.validate_repository import _iter_repository_markdown


def test_repository_markdown_excludes_generated_and_dependency_trees(
    tmp_path: Path,
) -> None:
    included = tmp_path / "docs" / "guide.md"
    excluded = (
        tmp_path / "apps" / "web" / "node_modules" / "package" / "README.md"
    )
    virtual_environment = tmp_path / ".venv" / "README.md"
    git_metadata = tmp_path / ".git" / "README.md"
    for path in (included, excluded, virtual_environment, git_metadata):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Test\n", encoding="utf-8")

    assert _iter_repository_markdown(tmp_path) == [included]
