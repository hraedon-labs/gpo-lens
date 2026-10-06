"""Test fixtures.

Sample-backed fixtures extract the three artifacts the Tier-1 ingest needs
(`AllGPOs.xml`, `gp-inheritance.json`, `gpo-metadata.json`) from the gitignored
zips in ``samples/`` into a tmp dir, then build an ``Estate`` via
``ingest.load_estate``. They skip cleanly when ``samples/`` is absent, so the
suite runs anywhere — but the calibration numbers (which prove the parser against
reality) only assert when the real exports are present.

Sample identity: WORK-DOMAIN.local = work (the 129-GPO mess); lab.example.com = lab.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
_NEEDED = ("AllGPOs.xml", "gp-inheritance.json", "gpo-metadata.json")

# Real exports are named by their domain (e.g. WORKDOMAIN.local-*.zip), and samples/
# is gitignored precisely so those names never reach git. This conftest IS
# committed, so it must not hard-code a real domain. An optional gitignored
# manifest (samples/calibration.json: {"work": "<file>.zip", "lab": "<file>.zip"})
# points the calibration fixtures at the local exports by name. Without it we
# fall back to the sanitized-substring glob; if neither resolves the fixture
# skips, so the suite still runs on a checkout that has no samples.
_MANIFEST = SAMPLES / "calibration.json"


def _manifest() -> dict[str, str]:
    if _MANIFEST.is_file():
        try:
            data = json.loads(_MANIFEST.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}
    return {}


def _find_zip(key: str, substr: str) -> Path | None:
    name = _manifest().get(key)
    if name:
        p = SAMPLES / name
        if p.is_file():
            return p
    hits = sorted(SAMPLES.glob(f"*{substr}*.zip"))
    return hits[0] if hits else None


def _extract(zip_path: Path, dest: Path) -> Path:
    with zipfile.ZipFile(zip_path) as z:
        present = set(z.namelist())
        for name in _NEEDED:
            if name in present:
                z.extract(name, dest)
    return dest


def _estate(key: str, substr: str, label: str, tmp_factory):
    zip_path = _find_zip(key, substr)
    if zip_path is None:
        pytest.skip(f"{label} sample ({substr}) not present in samples/")
    src = _extract(zip_path, tmp_factory.mktemp(label))
    from gpo_lens.ingest import load_estate

    return load_estate(src)


@pytest.fixture(scope="session")
def work_estate(tmp_path_factory):
    """WORK-DOMAIN.local — the messy work domain."""
    return _estate("work", "WORKDOMAIN", "work", tmp_path_factory)


@pytest.fixture(scope="session")
def lab_estate(tmp_path_factory):
    """lab.example.com — the clean lab domain."""
    return _estate("lab", "LABDOMAIN", "lab", tmp_path_factory)


@pytest.fixture(scope="session")
def secret_corpus():
    """One corpus for HTML/CSV/Markdown/API/narration secret tests.

    Reuse the established synthetic cpassword carriers, including the golden
    estate; add a synthetic plaintext credential to cover non-cpassword data.
    """
    import xml.etree.ElementTree as ET

    base = Path(__file__).parent
    values = set()
    for directory in (base / "fixtures", base / "golden_estate"):
        for path in directory.rglob("Groups.xml"):
            for elem in ET.parse(path).iter():
                if elem.get("cpassword"):
                    values.add(elem.get("cpassword"))
    return tuple(sorted(values)) + ("synthetic-credential-027-ONLY-FOR-TESTS",)
