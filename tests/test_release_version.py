"""The release identity gate used by .github/workflows/release.yml."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

from gpo_lens import __version__

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "check_release_version.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_release_version", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load()


def _released_changelog(text: str) -> str:
    """The CHANGELOG as a tag would see it: a leading ``## Unreleased`` section is
    allowed during development (tests/test_version.py enforces its ``Draft
    **vX.Y.Z**`` target) and refused by the gate at tag time
    (test_unreleased_top_section_is_refused_at_tag_time), so the copy drops it
    and these tests exercise the latest released heading against every version
    source."""
    if text.startswith("# ") or text.lstrip().startswith("## Unreleased"):
        head, sep, rest = text.partition("## Unreleased")
        if sep:
            nxt = rest.find("\n## ")
            return head + (rest[nxt + 1 :] if nxt != -1 else "")
    return text


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    for name in ("pyproject.toml", "uv.lock"):
        shutil.copy(_ROOT / name, tmp_path / name)
    changelog = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(_released_changelog(changelog), encoding="utf-8")
    (tmp_path / "src" / "gpo_lens").mkdir(parents=True)
    shutil.copy(_ROOT / "src" / "gpo_lens" / "__init__.py", tmp_path / "src" / "gpo_lens")
    return tmp_path


def test_unreleased_top_section_is_refused_at_tag_time(repo: Path) -> None:
    changelog = repo / "CHANGELOG.md"
    changelog.write_text(
        "# Changelog\n\n## Unreleased\n\nDraft **v9.9.9**\n\n"
        + changelog.read_text(encoding="utf-8").split("\n", 1)[1],
        encoding="utf-8",
    )
    problems, _ = gate.check(f"v{__version__}", repo)
    assert any("Unreleased" in p for p in problems), problems


def test_current_tree_agrees_with_its_own_tag(repo: Path) -> None:
    problems, notes = gate.check(f"v{__version__}", repo)
    assert problems == []
    assert notes.strip() and not notes.startswith("## ")


@pytest.mark.parametrize("tag", ["1.4.0", "v1.4", "v1.4.0rc1", "v1.4.0-rc.1", "release"])
def test_malformed_tags_are_refused(repo: Path, tag: str) -> None:
    problems, _ = gate.check(tag, repo)
    assert problems and "vX.Y.Z" in problems[0]


def test_wrong_tag_reports_every_disagreeing_source(repo: Path) -> None:
    problems, _ = gate.check("v99.0.0", repo)
    assert len(problems) == 4, problems  # __init__, pyproject, uv.lock, CHANGELOG


@pytest.mark.parametrize(
    "path,old,new",
    [
        ("src/gpo_lens/__init__.py", '__version__ = "{v}"', '__version__ = "0.0.1"'),
        ("pyproject.toml", 'version = "{v}"', 'version = "0.0.1"'),
        ("CHANGELOG.md", "## v{v} — ", "## v0.0.1 — "),
    ],
)
def test_single_source_drift_fails(repo: Path, path: str, old: str, new: str) -> None:
    target = repo / path
    text = target.read_text(encoding="utf-8")
    assert old.format(v=__version__) in text
    target.write_text(text.replace(old.format(v=__version__), new, 1), encoding="utf-8")
    problems, _ = gate.check(f"v{__version__}", repo)
    assert len(problems) == 1, problems


def test_unreleased_top_section_is_refused(repo: Path) -> None:
    changelog = repo / "CHANGELOG.md"
    text = changelog.read_text(encoding="utf-8")
    changelog.write_text(
        text.replace(
            "# Changelog\n", f"# Changelog\n\n## Unreleased\n\nDraft **v{__version__}**\n"
        ),
        encoding="utf-8",
    )
    problems, _ = gate.check(f"v{__version__}", repo)
    assert any("not a released" in p for p in problems)


def test_built_metadata_must_match(repo: Path, tmp_path: Path) -> None:
    wheel = tmp_path / "gpo_lens-x-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("gpo_lens-x.dist-info/METADATA", "Metadata-Version: 2.4\nVersion: 0.0.1\n")
    problems, _ = gate.check(f"v{__version__}", repo, wheel=wheel)
    assert problems == [f"{wheel.name} METADATA is '0.0.1', tag says '{__version__}'"]


def test_cli_exit_codes_and_notes(repo: Path, tmp_path: Path) -> None:
    # Run a copy of the CLI from inside the released-state tree (its ROOT is its
    # own parent directory), so the exit codes are exercised even while the real
    # tree carries a development `## Unreleased` section.
    (repo / "scripts").mkdir()
    script = repo / "scripts" / "check_release_version.py"
    shutil.copy(_SCRIPT, script)
    notes = tmp_path / "notes.md"
    ok = subprocess.run(
        [sys.executable, str(script), "--tag", f"v{__version__}", "--notes-out", str(notes)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stderr
    assert notes.read_text(encoding="utf-8").strip()
    bad = subprocess.run(
        [sys.executable, str(script), "--tag", "v0.0.1"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode == 1
    assert "release identity:" in bad.stderr
