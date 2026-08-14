from athena_context import __version__
from athena_context.cli import main


def test_package_version_is_available() -> None:
    assert __version__ == "0.1.0"


def test_cli_bootstrap_runs() -> None:
    assert main([]) == 0
