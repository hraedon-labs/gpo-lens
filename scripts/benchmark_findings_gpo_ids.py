"""Reproduce WI-093's GPO-link lookup measurement on synthetic data.

Run: .venv/bin/python scripts/benchmark_findings_gpo_ids.py
Reports median lookup time and peak Python allocation; no timing gate is used.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
import tempfile
import time
import tracemalloc
from dataclasses import replace
from pathlib import Path
from uuid import UUID

from gpo_lens.ingest import load_estate as ingest
from gpo_lens.model import Estate
from gpo_lens.store import init_db, load_estate, save_estate
from gpo_lens.web.routes.findings import _latest_snapshot_gpo_ids


def measure(lookup, conn, repeats: int) -> dict[str, float | int]:
    times = []
    for _ in range(repeats):
        start = time.perf_counter()
        lookup(conn)
        times.append(time.perf_counter() - start)
    tracemalloc.start()
    lookup(conn)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"median_ms": round(statistics.median(times) * 1000, 3), "peak_bytes": peak}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gpos", type=int, default=256)
    parser.add_argument("--settings", type=int, default=200, help="Settings per GPO")
    parser.add_argument("--repeats", type=int, default=7)
    args = parser.parse_args()
    if min(args.gpos, args.settings, args.repeats) < 1:
        parser.error("all sizes must be positive")
    seed = ingest(Path(__file__).resolve().parents[1] / "tests/fixtures").gpos[0]
    gpos = []
    for i in range(args.gpos):
        gid = str(UUID(int=i + 1))
        gpos.append(
            replace(
                seed,
                id=gid,
                name=f"Lab policy {i}",
                sysvol_path=None,
                links=[replace(link, gpo_id=gid) for link in seed.links],
                delegation=[replace(entry, gpo_id=gid) for entry in seed.delegation],
                settings=[
                    replace(seed.settings[0], gpo_id=gid, identity=f"Lab setting {j}")
                    for j in range(args.settings)
                ],
            )
        )
    with tempfile.TemporaryDirectory(prefix="gpo-inbox-bench-") as temporary:
        with sqlite3.connect(Path(temporary) / "bench.sqlite3") as conn:
            init_db(conn)
            save_estate(conn, Estate(domain="lab.example.com", gpos=gpos))

            def reconstruct(connection):
                return {g.id for g in load_estate(connection).gpos}

            assert reconstruct(conn) == _latest_snapshot_gpo_ids(conn)
            baseline = measure(reconstruct, conn, args.repeats)
            targeted = measure(_latest_snapshot_gpo_ids, conn, args.repeats)
            print(
                json.dumps(
                    {
                        "gpos": args.gpos,
                        "settings": args.gpos * args.settings,
                        "repeats": args.repeats,
                        "reconstruct": baseline,
                        "targeted": targeted,
                    },
                    indent=2,
                )
            )


if __name__ == "__main__":
    main()
