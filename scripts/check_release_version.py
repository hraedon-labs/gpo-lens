"""Release identity gate: the tag, every version source and the built artifacts agree.

Used by ``.github/workflows/release.yml``. For tag ``vX.Y.Z`` it requires:

* ``__version__`` in ``src/gpo_lens/__init__.py`` == ``X.Y.Z``;
* ``[project].version`` in ``pyproject.toml`` == ``X.Y.Z``;
* the ``gpo-lens`` package version in ``uv.lock`` == ``X.Y.Z``;
* the top ``CHANGELOG.md`` section is a *released* heading ``## vX.Y.Z — <date>``
  (an ``Unreleased`` top section is refused: ``tests/test_version.py`` allows it
  during development, a release does not);
* with ``--wheel`` / ``--sdist``, the ``Version:`` that the build backend wrote
  into the wheel's ``METADATA`` and the sdist's ``PKG-INFO`` == ``X.Y.Z``.

With ``--notes-out`` it writes that CHANGELOG section (without its heading) for
the GitHub release body. Reads files only; imports nothing from the package so
it runs before installation. Exit 0 on agreement, 1 with the reasons otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TAG = re.compile(r"^v(\d+\.\d+\.\d+)$")
_INIT_VERSION = re.compile(r'^__version__ = "([^"]+)"$', re.MULTILINE)
_RELEASED_HEADING = re.compile(r"^v(\d+\.\d+\.\d+) — \d{4}-\d{2}-\d{2}\s*$")


def tag_version(tag: str) -> str:
    match = _TAG.fullmatch(tag)
    if match is None:
        raise ValueError(f"tag {tag!r} is not of the form vX.Y.Z")
    return match.group(1)


def init_version(root: Path) -> str:
    text = (root / "src" / "gpo_lens" / "__init__.py").read_text(encoding="utf-8")
    found = _INIT_VERSION.findall(text)
    if len(found) != 1:
        raise ValueError("src/gpo_lens/__init__.py must assign __version__ exactly once")
    return str(found[0])


def pyproject_version(root: Path) -> str:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def lock_version(root: Path) -> str:
    data = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    versions = [p["version"] for p in data["package"] if p["name"] == "gpo-lens"]
    if len(versions) != 1:
        raise ValueError("uv.lock must contain exactly one gpo-lens package")
    return str(versions[0])


def changelog_top(text: str) -> tuple[str, str]:
    """Return ``(version, body)`` of the top section, which must be released."""
    sections = re.split(r"^## ", text, flags=re.MULTILINE)[1:]
    if not sections:
        raise ValueError("CHANGELOG.md has no '## ' sections")
    heading, _, body = sections[0].partition("\n")
    match = _RELEASED_HEADING.fullmatch(heading)
    if match is None:
        raise ValueError(
            f"top CHANGELOG section {heading!r} is not a released 'vX.Y.Z — YYYY-MM-DD' heading"
        )
    return match.group(1), body.strip() + "\n"


def wheel_version(path: Path) -> str:
    with zipfile.ZipFile(path) as zf:
        names = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError(f"{path.name}: expected one .dist-info/METADATA")
        return _metadata_version(zf.read(names[0]).decode("utf-8"), path.name)


def sdist_version(path: Path) -> str:
    with tarfile.open(path, "r:gz") as tf:
        members = [m for m in tf.getmembers() if m.name.count("/") == 1]
        infos = [m for m in members if m.name.endswith("/PKG-INFO")]
        if len(infos) != 1:
            raise ValueError(f"{path.name}: expected one top-level PKG-INFO")
        handle = tf.extractfile(infos[0])
        if handle is None:
            raise ValueError(f"{path.name}: PKG-INFO is not a regular file")
        return _metadata_version(handle.read().decode("utf-8"), path.name)


def _metadata_version(text: str, label: str) -> str:
    found = re.findall(r"^Version: (\S+)$", text, flags=re.MULTILINE)
    if len(found) != 1:
        raise ValueError(f"{label}: expected exactly one Version: header")
    return str(found[0])


def check(
    tag: str,
    root: Path = ROOT,
    *,
    wheel: Path | None = None,
    sdist: Path | None = None,
) -> tuple[list[str], str]:
    """Return ``(problems, release_notes)``; no problems means the identity holds."""
    problems: list[str] = []
    notes = ""
    try:
        expected = tag_version(tag)
    except ValueError as exc:
        return [str(exc)], notes
    sources: dict[str, Callable[[], str]] = {
        "src/gpo_lens/__init__.py __version__": lambda: init_version(root),
        "pyproject.toml [project].version": lambda: pyproject_version(root),
        "uv.lock gpo-lens version": lambda: lock_version(root),
    }
    if wheel is not None:
        sources[f"{wheel.name} METADATA"] = lambda: wheel_version(wheel)
    if sdist is not None:
        sources[f"{sdist.name} PKG-INFO"] = lambda: sdist_version(sdist)
    for label, read in sources.items():
        try:
            actual = read()
        except (OSError, KeyError, ValueError, tomllib.TOMLDecodeError) as exc:
            problems.append(f"{label}: {exc}")
            continue
        if actual != expected:
            problems.append(f"{label} is {actual!r}, tag says {expected!r}")
    try:
        version, notes = changelog_top((root / "CHANGELOG.md").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        problems.append(f"CHANGELOG.md: {exc}")
    else:
        if version != expected:
            problems.append(f"CHANGELOG.md top section is v{version}, tag says v{expected}")
    return problems, notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", required=True, help="release tag, e.g. v1.4.0")
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--sdist", type=Path)
    parser.add_argument("--notes-out", type=Path, help="write the CHANGELOG section here")
    args = parser.parse_args(argv)
    problems, notes = check(args.tag, wheel=args.wheel, sdist=args.sdist)
    if problems:
        for problem in problems:
            print(f"release identity: {problem}", file=sys.stderr)
        return 1
    if args.notes_out is not None:
        args.notes_out.write_text(notes, encoding="utf-8")
    print(f"release identity OK: {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
