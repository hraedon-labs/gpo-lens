# F3 synthetic performance calibration

The fixture in `tests/performance_estate.py` uses a local seeded PRNG, canonical
lab GUIDs, synthetic Registry, audit, Public Key, drive and printer settings,
and fixed persisted evaluation times.
No sample estate or external export is required. Defaults produce about 130
GPOs, 1,500 SOMs and roughly 4,700 settings per snapshot, thousands of finding
occurrences, about 14,000 observations and 100,000 SOM links across three
snapshots. The comparator changes non-secret setting values so comparisons
exercise the drift tables. A collector-format upload exercises ingest too.

Run the opt-in benchmark with the installed dev and web extras:

```bash
GPO_LENS_BENCHMARK=1 .venv/bin/pytest -n0 -s tests/test_performance.py -m slow
```

Ordinary CI runs the small estate with the same relationships. Its budgets
count SQL statements, credential-discovery passes and threadpool handoffs;
loose time limits additionally catch gross regressions. The slow benchmark
checks the generated population, findings and dependency inventory exports,
comparison uploads, enforced-links
API, collector upload, and danger/doctor CLI commands. It skips unless explicitly
enabled, so the full calibration does not burden ordinary CI.

## Measurements

Python 3.14.8, locked web dependencies, Linux TestClient, synthetic fixtures.
Before measurements used archived v1.3.0 source; after used this worktree.
These are single wall-clock samples on a shared host, not stable throughput
claims. Host load varied substantially: a later original CSV run took more
than two minutes, and an optimized run took about seven seconds. Structural
budgets and byte comparisons provide the reproducible regression evidence.

| Path | Before (seconds) | After (seconds) |
| --- | ---: | ---: |
| Full findings Markdown | 40.965 | 4.544 |
| Full findings CSV | 43.369 | 3.444 |
| Golden diff, drift comparator | 5.269 | 1.629 |
| Baseline, drift comparator | 8.151 | 3.636 |
| Enforced-links API | 12.844 | 5.125 |

The final benchmark also measured ingest at 3.991 seconds, danger at 2.969
seconds and doctor at 2.918 seconds. Those paths are exercised for hygiene and
calibration; their algorithms were not rewritten. No before/after speedup is
claimed for them.

Full Markdown/CSV bodies, golden/baseline HTML, and enforced-links JSON were
byte-identical to v1.3.0 on the same generated database/comparator inputs.
Regular tests retain the original provenance lookup and compare both export
formats with the original line transport; frozen export goldens and a
reference implementation of per-string masking cover rendering/redaction.

## Profile and changes

- Finding provenance performed two indexed reads per occurrence. Batches of
  at most 500 IDs retain first-seen, last-seen, resolution and all intermediate
  observation runs while staying below the historical SQLite variable limit.
  The large fixture reduces thousands of reads to a few dozen; the small
  fixture's query budget rejects a return to per-occurrence reads.
- Starlette handed every exported field to a worker separately. Transport now
  groups the unchanged lazy line renderer into bounded 64 KiB byte chunks,
  preserving UTF-8 artifact bytes, final partial chunks and streaming laziness.
- The enforced-links profile repeatedly rediscovered credential context and
  prepared escaped spellings for every string. A projection now prepares those
  spellings once; discovery visits each shared source container once per call.
  Masking still processes longest spellings first, includes encoded credential
  copies, and discovers raw credential context before omitting raw evidence.
  This benefits comparison projections too. Their comparison algorithms remain
  unchanged: profiles did not justify another rewrite.
- All SQLite owners in `src/` and `scripts/` were audited. Changelog errors and
  failed web connection setup now close their connections. The benchmark and
  released-fixture builders use `contextlib.closing`; their transaction contexts
  remain where previously present. The original stream did not regenerate released databases. The 1.4
  integration adds a v1.3.1-created fixture through the same public-API generator;
  older released artifacts remain unchanged.
  Existing test contexts now also close explicitly, including the upgrade/backup
  fixtures; event/store tests release their previously unowned connections.

## Regression evidence

Failing-first runs exposed per-occurrence queries, per-field worker handoffs,
per-string discovery, repeated shared evidence, exception-path leaks and the
SQLite transaction-context trap. Connection tests explicitly track closure on
successful routes/commands, query failures, setup failures and collector uploads;
they also run with ResourceWarning treated as an error, independent of GC timing.
The suite treats SQLite ResourceWarnings and their unraisable-exception warnings
as errors, and an AST regression rejects bare SQLite transaction contexts in test
and script code. Changelog checks distinguish the next Unreleased target from
the latest released version, allowing parallel features without a metadata bump.

All 14 isolated source mutations were killed by the targeted tests: per-row
reads, omitted first/resolution/observation provenance, dropped final batches,
per-field HTTP yields, dropped partial chunks, corrupted UTF-8, skipped secret
discovery, plaintext leaks, reversed masking order, repeated shared discovery,
changelog leaks and setup leaks. The first mutation pass exposed an exact-multiple
chunk fixture; an explicit partial-chunk assertion now rejects that mutant.

No new dependencies, database migrations, routes or live-directory operations
were introduced. Production-estate reruns remain the coordinator's calibration
step; this stream only has synthetic inputs.
Unrelated HTTP/socket and mocked HTTPError teardown warnings exposed by broader
warning enforcement are outside the SQLite scope; their cleanup is deferred.
