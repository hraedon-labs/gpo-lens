"""Deliberately break F1 invariants and require focused tests to reject each.

Run from the repo root after installing dev dependencies. Original source bytes
are restored even on failure. Run CI gates afterward; never run concurrently
with another task editing these files.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INGEST = "src/gpo_lens/ingest.py"
DANGER = "src/gpo_lens/danger.py"
MUTATIONS = (
    ("audit value mapping", INGEST, '"1": "Success"', '"1": "No Auditing"'),
    ("audit GUID identity", INGEST, "identity = canonical_guid(guid)", "identity = name"),
    (
        "retain XML on disagreement",
        INGEST,
        'existing.raw["audit_csv"] = row',
        'existing.display_value = value\n                existing.raw["audit_csv"] = row',
    ),
    (
        "flag source disagreement",
        INGEST,
        'existing.raw["audit_disagreement"] = True',
        'existing.raw["audit_disagreement"] = False',
    ),
    (
        "retain duplicate evidence",
        INGEST,
        "evidence_rows.append(row)",
        "evidence_rows.clear()",
    ),
    (
        "PKI value-independent identity",
        INGEST,
        "out.append((key, name, value, raw))",
        'out.append((key + ":" + value, name, value, raw))',
    ),
    (
        "exact force-option path",
        DANGER,
        "if key != registry_key:",
        'if not key.endswith("scenoapplylegacyauditpolicy"):',
    ),
    (
        "force enabled value",
        DANGER,
        'value in {"1", "true", "enabled", "0x00000001"}',
        'value not in {"1", "true", "enabled", "0x00000001"}',
    ),
    (
        "disabled-side exclusion",
        DANGER,
        's.side == "Computer" and not s.from_disabled_side and s.source_state != "blocked"',
        's.side == "Computer" and s.source_state != "blocked"',
    ),
)


def main() -> None:
    for label, filename, before, after in MUTATIONS:
        path = ROOT / filename
        original = path.read_bytes()
        text = original.decode()
        if text.count(before) != 1:
            raise RuntimeError(f"Mutation anchor drifted: {label}")
        try:
            path.write_text(text.replace(before, after, 1))
            result = subprocess.run(
                [str(ROOT / ".venv/bin/pytest"), "-n0", "tests/test_cse_audit_pki.py"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 1 or "AssertionError" not in result.stdout:
                raise RuntimeError(
                    f"Mutation survived or tests could not run: {label}\n"
                    f"{result.stdout}\n{result.stderr}"
                )
            print(f"KILLED: {label}", flush=True)
        finally:
            path.write_bytes(original)
    print(f"{len(MUTATIONS)}/{len(MUTATIONS)} mutations killed; original sources restored.")


if __name__ == "__main__":
    main()
