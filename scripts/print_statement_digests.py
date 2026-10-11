"""Print candidate STATEMENT_DIGESTS (and the other hand-maintained pin tables)
for the collector read-only gate.

PRINT ONLY. This never writes a file and is NOT referenced by
scripts/gen_collector_inventory.py or by the test module. When a collector
script legitimately changes, a human runs this, reviews the diff against the
committed table in tests/test_collector_readonly.py, and pastes the new block.

Usage:
    python scripts/print_statement_digests.py [statements|bodies|headers]

Default is ``statements`` (the STATEMENT_DIGESTS table).
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _load_gate():  # type: ignore[no-untyped-def]
    path = _ROOT / "tests" / "test_collector_readonly.py"
    spec = importlib.util.spec_from_file_location("collector_gate_print", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _lit(text: str, indent: int) -> str:
    r = repr(text)
    if len(r) + indent + 2 <= 99:
        return r
    width = max(30, 96 - indent - 4)
    chunks, rest = [], text
    while len(repr(rest)) > width:
        cut = next(
            (
                i
                for i in range(len(rest), 0, -1)
                if len(repr(rest[:i])) <= width and rest[i - 1] == " "
            ),
            None,
        )
        if cut is None:
            cut = max(i for i in range(1, len(rest)) if len(repr(rest[:i])) <= width)
        chunks.append(rest[:cut])
        rest = rest[cut:]
    chunks.append(rest)
    pad = " " * (indent + 4)
    return "(\n" + "".join(f"{pad}{c!r}\n" for c in chunks) + " " * indent + ")"


def main() -> int:
    what = sys.argv[1] if len(sys.argv) > 1 else "statements"
    exe = shutil.which("pwsh")
    if exe is None:
        print("pwsh is required", file=sys.stderr)
        return 2
    gate = _load_gate()
    inv = gate._run_dumper(exe, [str(gate._SCRIPTS / name) for name in sorted(gate.POLICIES)])
    order = list(gate.POLICIES)
    out: list[str] = []
    if what == "statements":
        out.append("STATEMENT_DIGESTS: dict[str, dict[str, str]] = {")
        for script in order:
            out.append(f"    {script!r}: {{")
            for st in gate._statements(inv[script]):
                out.append(f"        # [{st['path']}] {st['kind']}: {st['preview'][:70]}"[:99])
                out.append(f"        {str(st['seq'])!r}: {st['digest']!r},")
            out.append("    },")
        out.append("}")
    elif what == "headers":
        out.append("SCRIPT_HEADERS: dict[str, str] = {")
        for script in order:
            out.append(f"    {script!r}: {gate._header_digest(inv[script])!r},")
        out.append("}")
    elif what == "bodies":
        out.append("LOCAL_FUNCTION_BODIES: dict[str, dict[str, str]] = {")
        for script in order:
            defined = {f["name"]: f for f in inv[script]["function_params"]}
            out.append(f"    {script!r}: {{")
            for name in gate.LOCAL_FUNCTIONS[script]:
                digest = gate._function_body_digest(defined[name.casefold()])
                out.append(f"        {name!r}: {digest!r},")
            out.append("    },")
        out.append("}")
    else:
        print(f"unknown table {what!r}; use statements|bodies|headers", file=sys.stderr)
        return 2
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
