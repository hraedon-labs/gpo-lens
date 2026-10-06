"""Enumerate actual FastAPI routes from a git revision (no hand-kept URL list).

Run with the web extra installed. Output is the mechanically collected source
of docs/web-route-inventory.json; migration decisions are recorded separately
in that inventory's destination/discover_via/translation fields.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def enumerate_revision(ref: str) -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(["git", "rev-parse", ref], cwd=root, text=True).strip()
    files = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", commit, "src"], cwd=root, text=True
    ).splitlines()
    with tempfile.TemporaryDirectory(prefix=".route-inventory-", dir=root) as scratch:
        for name in files:
            target = Path(scratch) / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(
                subprocess.check_output(["git", "show", f"{commit}:{name}"], cwd=root)
            )
        code = (
            "import json; from gpo_lens.web.app import create_app; "
            "app=create_app(':memory:'); "
            "print(json.dumps([dict(path=r.path,name=r.name,methods=sorted(r.methods) "
            "if hasattr(r,'methods') else ['MOUNT']) for r in app.routes]))"
        )
        env = dict(os.environ, PYTHONPATH=str(Path(scratch) / "src"))
        routes = json.loads(
            subprocess.check_output([sys.executable, "-c", code], env=env, cwd=scratch)
        )
    return {"source_commit": commit, "routes": routes}


if __name__ == "__main__":
    print(
        json.dumps(
            enumerate_revision(sys.argv[1] if len(sys.argv) > 1 else "origin/main"), indent=2
        )
    )
