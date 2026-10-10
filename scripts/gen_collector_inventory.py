"""Regenerate tests/powershell/collector-inventory.json (the closed-world
collector call-site inventory).

It runs the PowerShell AST dumper over the in-scope collector scripts, applies
the full semantic gate (``run_all_checks`` in tests/test_collector_readonly.py)
to every script, and writes the normalized inventory ONLY if the gate passes —
so a regeneration can never launder a read-only violation into the committed
golden file. Needs ``pwsh``.

Usage: python scripts/gen_collector_inventory.py
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _load_gate():  # type: ignore[no-untyped-def]
    path = _ROOT / "tests" / "test_collector_readonly.py"
    spec = importlib.util.spec_from_file_location("collector_gate", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    exe = shutil.which("pwsh")
    if exe is None:
        print("pwsh is required to regenerate the collector inventory", file=sys.stderr)
        return 2
    gate = _load_gate()
    try:
        gate.write_golden_inventory(exe)
    except AssertionError as exc:
        print(
            "refusing to write: the semantic collector gate failed:\n" + str(exc), file=sys.stderr
        )
        return 1
    print(f"wrote {gate.GOLDEN_PATH.relative_to(_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
