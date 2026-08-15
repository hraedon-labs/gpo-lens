"""The patina conformance gate (patina Plan 005).

gpo-lens vendors patina's token contract into
``src/gpo_lens/web/static/css/tokens.css``; its own component layer lives
beside it in ``css/gp.css``. This test runs the vendored checker
(``scripts/patina-check.py``, stamped by patina's sync.sh) and fails if:

* the vendored patina block, ``theme.js``, or the checker's own bytes were
  edited in this repo (fix in patina, then re-run its ``sync.sh``);
* any ``var(--x)`` in gp.css or in a template's ``<style>``/``style=""`` does
  not resolve;
* gpo-lens redefines a contract token, or defines a local token without the
  ``--gp-`` prefix;
* a colour literal appears that is not fingerprinted in
  ``tests/patina-ratchet.json``. Swapping one literal for another does not
  pass; removing one always does — re-baseline with ``--update-ratchet`` to
  lock a fix in.

Drift note: without ``--upstream`` the gate proves integrity, not currency —
the block hash is stored beside the block, so it cannot tell a current
vendored copy from a stale one. Set ``PATINA_CHECKOUT`` to a patina working
copy for real drift detection. CI does not set it today; that needs gpo-lens
CI to have read access to the patina repo, which is an open decision.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from subprocess import CompletedProcess

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _run(*extra: str) -> CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "patina-check.py"),
            str(ROOT / "src" / "gpo_lens" / "web" / "static"),
            "--prefix",
            "gp",
            # Templates live outside static/, so their <style> blocks and
            # style="..." attributes would otherwise never reach the gate.
            "--extra",
            str(ROOT / "src" / "gpo_lens" / "web" / "templates"),
            # Kept out of the served static root, like patina-check.py itself.
            "--ratchet-file",
            str(ROOT / "tests" / "patina-ratchet.json"),
            # gpo-lens's own claims. Validated (legal state per facet, required
            # fields present) and reported as a matrix, not a score.
            "--declaration",
            str(ROOT / "patina.toml"),
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_patina_conformance() -> None:
    proc = _run()
    assert proc.returncode == 0, f"\n{proc.stdout}{proc.stderr}"


def test_patina_no_drift_from_upstream() -> None:
    """Real drift detection, when a patina checkout is available to compare
    against. Skipped rather than silently passing when it isn't."""
    checkout = os.environ.get("PATINA_CHECKOUT")
    if not checkout or not Path(checkout).is_dir():
        pytest.skip("PATINA_CHECKOUT not set to a patina working copy")
    proc = _run("--upstream", checkout)
    assert proc.returncode == 0, f"\n{proc.stdout}{proc.stderr}"
