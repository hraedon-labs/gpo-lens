from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from gpo_lens import __version__


def test_version_sync() -> None:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    pyproject_version = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    assert __version__ == pyproject_version, (
        f"__init__.__version__={__version__!r} != pyproject.toml version={pyproject_version!r}"
    )


def test_changelog_top_version_matches() -> None:
    changelog = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
    text = changelog.read_text(encoding="utf-8")
    _assert_changelog_version(text, __version__)


def _assert_changelog_version(text: str, package_version: str) -> None:
    # An Unreleased section must declare its target, never fall through to an
    # older released heading (which masked the v1.3 candidate's stale version).
    sections = re.split(r"^## ", text, flags=re.MULTILINE)[1:]
    top = sections[0]
    if top.startswith("Unreleased"):
        match = re.search(r"Draft \*\*v(\d+\.\d+\.\d+)\*\*", top)
        assert match, "Top changelog section must declare a release target"
        target = match.group(1)
        assert tuple(map(int, target.split("."))) >= tuple(map(int, package_version.split("."))), (
            "Unreleased target must not precede package metadata"
        )
        if target != package_version:
            # Feature streams can target the next release before its version
            # bump. Their package metadata must still match the latest release.
            assert len(sections) > 1, "Future target requires a released version section"
            match = re.match(r"v(\d+\.\d+\.\d+)", sections[1])
    else:
        match = re.match(r"v(\d+\.\d+\.\d+)", top)
    assert match, "Top changelog section must declare a release target"
    changelog_version = match.group(1)
    assert package_version == changelog_version, (
        f"__init__.__version__={package_version!r} != CHANGELOG version={changelog_version!r}"
    )


@pytest.mark.parametrize(
    "text,valid",
    [
        ("## v1.3.1\n", True),
        ("## Unreleased\nDraft **v1.3.1**\n## v1.3.0\n", True),
        ("## Unreleased\nDraft **v1.4.0**\n## v1.3.1\n", True),
        ("## Unreleased\n## v1.3.1\n", False),
        ("## Unreleased\nDraft **v1.4.0**\n## v1.3.0\n", False),
        ("## Unreleased\nDraft **v1.3.0**\n## v1.3.1\n", False),
        ("## Unreleased\nDraft **v1.4.0**\n", False),
    ],
)
def test_changelog_future_target_retains_metadata_guard(text, valid):
    if valid:
        _assert_changelog_version(text, "1.3.1")
    else:
        with pytest.raises(AssertionError):
            _assert_changelog_version(text, "1.3.1")


def test_lock_version_matches_package() -> None:
    lock = Path(__file__).resolve().parents[1] / "uv.lock"
    packages = tomllib.loads(lock.read_text())["package"]
    assert next(p["version"] for p in packages if p["name"] == "gpo-lens") == __version__


def test_release_handover_reports_current_metadata() -> None:
    root = Path(__file__).resolve().parents[1]
    for name in ("docs/release-v1.3.0-verification.md", "plans/027-road-to-generous-1x.md"):
        text = (root / name).read_text()
        assert f"Package metadata reports **{__version__}**" in text
        assert "bump package metadata" not in text
        assert "metadata remains\n1.2.0" not in text
        assert "metadata currently reports **1.2.0**" not in text


def test_cli_version_flag() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "gpo_lens", "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Exit code {result.returncode}: {result.stderr}"
    assert __version__ in result.stdout.strip(), (
        f"CLI --version output {result.stdout.strip()!r} does not contain {__version__!r}"
    )
