# Released database upgrade fixtures

These six small SQLite databases were created by **installed released code**,
not hand-built schemas or today's `init_db`. Each adjacent JSON manifest records
the release tag, exact commit, original schema version, and all table counts.
All input data is synthetic. There are no workplace exports in this corpus.

Regenerate from the project root (requires `uv`, local tags and a package index
or populated package cache):

```bash
.venv/bin/python scripts/build_released_db_fixtures.py
.venv/bin/pytest -q tests/test_released_db_upgrades.py
```

The generator makes a detached scratch worktree per tag, installs that checkout
with its web extra into a separate scratch venv, and runs a worker with that
venv's Python. It verifies that the imported package does not resolve to today's
source. It removes scratch worktrees on completion or error. It never modifies
release tags or ingests a production database. Output DBs are vacuumed before
copying; operational timestamps and request IDs remain those emitted by the
released code, so regeneration is semantically reproducible, not byte-identical.

The lab export is reduced from `tests/fixtures/`: two GPOs with settings and
delegation, two SOMs, OU links, and inventory/error coverage gaps. Snapshot one
is ingested through the release's public CLI. A GPO name and a setting value
change, then snapshot two is ingested through its web upload endpoint. The web
upload produces an audit record. No SYSVOL files are included: there is no raw
credential material or dependency on a scratch SYSVOL path.

| Release | Original schema | Findings/triage | Web audit storage |
|---------|-----------------|-----------------|-------------------|
| v0.5.0 | 0 (unstamped) | Not available | `events` table (`audit.ingest`) |
| v0.7.0 | 3 | Not available | Separate `audit.log` |
| v0.7.1 | 3 | Not available | Separate `audit.log` |
| v1.0.0 | 3 | Not available | Separate `audit.log` |
| v1.1.0 | 6 | Legacy triage and Plan 024 events | Separate `audit.log` |
| v1.2.0 | 7 | Legacy triage and Plan 024 events | Separate `audit.log` |

Where available, released ingest evaluates real synthetic findings. Its public
`triage_finding` API acknowledges one occurrence and accepts risk on another.
Its public `append_triage_event` API accepts a third occurrence's risk with an
explicit rationale. This deliberately tests legacy triage migration even when
the operator also used the newer public API before upgrading. Migrations must
preserve the existing event and both legacy annotations.

Tests compare **every old column of every row in every table**, including event
payloads, timestamps, finding identity, evidence, run provenance and triage
attribution. Added converted triage events are permitted; original events must
remain exact. Both historical estates are loaded through the current public
API before/after migration. Accepted risks and triage states are queried through
the current API. Opening a second time must leave all rows unchanged.

The IIS backup test keeps an app connection open in WAL mode, disables automatic
checkpointing, commits a third snapshot, then uses a distinct connection's
`backup` call (the README's Python equivalent of SQLite `.backup`). It restores
the backup and copies the separate audit log, then checks every row and the
newest estate. SQLite backup alone does **not** copy `audit.log`.

Migrations run automatically on open. **Back up first**, including `audit.log`.
Downgrading an upgraded DB into older code is not tested or guaranteed. Restore
the matching pre-upgrade backup when rolling back the application.

## Validation evidence (S4)

All twelve released-DB upgrade/backup cases pass. No migration defect was found
in this corpus. Failing-first creation produced twelve failures before the
fixtures existed. Mutation checks ran the tests against independent scratch
copies of `src/` and `tests/`, leaving the working source untouched:

| Mutation | Test that failed | Failure |
|----------|------------------|---------|
| Omit copying rows into `coverage_gap_new` before replacing the old table | Upgrade preservation, v0.5.0 | Original coverage rows disappeared |
| Change added `subject_stable` default from 1 to 0 | Upgrade preservation, v1.1.0 | Stored stable subjects became unstable |
| Restore full `load_estate` in the inbox ID helper | Targeted lookup SQL-authorizer test | Reading `snapshot.domain` was denied |

WI-093's production change already existed in `1b6f78f`; this stream adds an
exact HTML equivalence test against the old resolver and a query-boundary test.
Reproduce the lookup benchmark with:

```bash
.venv/bin/python scripts/benchmark_findings_gpo_ids.py
```

Measured on Python 3.14.8, 256 GPOs / 51,200 settings, seven repetitions:

| Resolver | Median lookup time | Peak Python allocation |
|----------|--------------------|------------------------|
| Reconstruct estate | 458.590 ms | 87,425,106 bytes |
| Targeted GPO IDs | 0.103 ms | 28,363 bytes |

Both return identical ID sets. This measures only GPO-link resolution, not total
request latency, and deliberately has no flaky wall-clock threshold in CI.

## Mixed API reopen upgrade regression (F-01)

`v1.2.0-with-reopen.sqlite3` starts as a copy of `v1.2.0.sqlite3`.
`scripts/build_v120_reopen_fixture.py` archives the `v1.2.0` tag into a temporary
source directory and runs that release's public `triage_finding` (legacy risk
acceptance) and `append_triage_event` (newer reopen) on the same occurrence.
The fixture contains only the original synthetic lab estate. Existing released
rows and IDs remain intact; operational timestamps come from the released API.
The upgrade regression verifies the latest withdrawal wins, the actionable
inbox and risk register agree, reversed fold input gives the same answer, and
reopening the upgraded DB is idempotent. It does not require git tags at test
time: the fixture is prepared by released code, never today's schema builder.
