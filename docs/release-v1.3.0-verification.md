# v1.3.0 candidate documentation verification

Verified **2026-10-06** on `release/v1.3.0-candidate`, integrated product base
`d271cf7`. This pass changes documentation and plan bookkeeping only; no
product, dependency, CI or test file was changed in that documentation pass.
Package metadata reports **1.3.1** for the broken-reference hotfix; the v1.3.0
candidate checks below remain historical evidence.
No tracker write, PR or tag was made.

## Live IIS validation (2026-10-06)

Two in-place upgrades on a Windows Server 2025 IIS lab VM with the release-candidate installer (`-ConfigureIIS`, no other flags):
(1) an anonymous site, 1.0.0 → 1.3.0: binding, certificate and existing web.config variables preserved; `GPO_LENS_ALLOWED_HOSTS` auto-added; site served 200; foreign Host rejected.
(2) a mirror of the production configuration: real v1.0.0 installed with `-WindowsAuth`, a lab estate ingested (12 GPOs, 29 SOMs, 138 settings, 1 coverage gap, 42 doctor findings), then upgraded. Windows Authentication stayed on and anonymous stayed off (anonymous → 401 Negotiate), `GPO_LENS_ALLOWED_HOSTS` was auto-added, and Kerberos-authenticated requests returned 200 on /, /briefing, /findings, /explore, /api/version (1.3.0) and a CSV export. The first authenticated request migrated schema 3 → 9 with every row preserved and `integrity_check` ok.

The round-2 installer changes (build-closure pinning, endpoint/SNI transitions) are re-validated live by the coordinator before release.

See [Plan 027](../plans/027-road-to-generous-1x.md) for the complete old/new
plan-status table, all 12 nonterminal WI dispositions and the coordinator's
remaining review/release/rollout checklist.

## Results

| Gate / verification | Result |
|---------------------|--------|
| Ruff lint and format | Pass; authoritative formatter made no changes |
| Mypy | Pass; 89 source files |
| Python 3.12.13 | 2866 passed, 31 skipped, 1 xfailed; 67 subtests passed; 93.04% coverage; 130.22s |
| Python 3.13.13 | 2866 passed, 31 skipped, 1 xfailed; 67 subtests passed; 93.04% coverage; 127.54s |
| Python 3.14.8 | Exit 0; 93.02% coverage (repository double-quiet options omit a count/duration summary) |
| pip-audit, locked runtime + web | No known vulnerabilities found |
| Identifier gate | Exit 0 with the real local denylist; no gate bypass; empty stdout/stderr |
| Pester 5.7.1 | 72 passed, 0 failed (Linux PowerShell; authoritative Windows CI remains a release step) |
| Container build / acceptance | Exit 0; loopback, non-root/read-only image, TLS/proxy auth, upload/restart and WAL-safe backup/restore passed |
| README commands | Top-level and all 53 subcommand help calls exited 0; ingest/doctor/exports/report/JSON/server examples passed using synthetic fixtures |
| Local links/anchors | All resolve, including all three deployment guides |
| External Markdown links | All six HTTP 200, including the historical GitHub URL's redirect |

The 3.12/3.13 runs use isolated temporary venvs created with
`UV_PROJECT_ENVIRONMENT=/tmp/gpo-docs-py312 uv sync --locked --python 3.12 --extra dev --extra web`
and the corresponding `py313` / `3.13` command. The default venv was synchronized
with `uv sync --locked --extra dev --extra web`. Coverage/cache paths are
isolated between matrix runs. The transient addopts override preserves xdist
and removes the second quiet flag to expose counts/duration; no repository
setting was changed.

The exact logs below retain observed warnings (including unclosed SQLite
connections on newer Python), skips and the expected failure. These are passing
runs, not a claim that warnings disappeared. Real-sample tests skip without
`samples/`. The collector's live AD invocation was not attempted on Linux;
its `OutputRoot` parameter and PowerShell syntax were verified, and the Pester
suite passed. The README server smoke suppressed GUI launch with `BROWSER=true`
and shut down the disposable local process after HTTP checks.

## Exact command output

Each command below completed with **exit 0**. Empty gate output is stated
outside its code block; non-empty output is copied without normalization,
except Compose progress output, which is encoded losslessly as documented below.

<details>
<summary>Ruff lint — exit 0</summary>

Command: `.venv/bin/ruff check .`

```text
All checks passed!
```

</details>

<details>
<summary>Ruff format (authoritative formatter) — exit 0</summary>

Command: `.venv/bin/ruff format .`

```text
286 files left unchanged
```

</details>

<details>
<summary>Ruff format check — exit 0</summary>

Command: `.venv/bin/ruff format --check .`

```text
286 files already formatted
```

</details>

<details>
<summary>Mypy — exit 0</summary>

Command: `.venv/bin/mypy src`

```text
Success: no issues found in 89 source files
```

</details>

<details>
<summary>Python 3.14.8 coverage — exit 0</summary>

Command: `.venv/bin/pytest -q --cov=src --cov-report=term-missing --cov-fail-under=85`

```text
bringing up nodes...
bringing up nodes...

..sss................................................................... [  2%]
........................................................................ [  4%]
........................................................................ [  7%]
............sssssssssssssssssssssss..................................... [  9%]
........................................................................ [ 12%]
........................................................................ [ 14%]
........................................................................ [ 17%]
........................................................................ [ 19%]
..........................................s............................. [ 22%]
.....u..........u.......u...........u.......u...u....................... [ 24%]
........................................................................ [ 27%]
........................................................................ [ 29%]
...................u...u.......u.u......u..u.u....u....u................ [ 31%]
........................................................................ [ 34%]
..ssss.................................................................. [ 36%]
........................................................................ [ 39%]
........................................................................ [ 41%]
........................................................................ [ 44%]
........................................................................ [ 46%]
........................................................................ [ 49%]
......................................................................u. [ 51%]
..u...u....u...................u........................................ [ 54%]
.u..u...u...........................u................................... [ 56%]
............................................................u........... [ 58%]
..........................................................u............. [ 61%]
........................................................................ [ 63%]
........................................................................ [ 66%]
........................................................................ [ 68%]
........................................................................ [ 71%]
........................................................................ [ 73%]
.............................u........u................................. [ 76%]
....u................................................................... [ 78%]
..............................u...............u.........u............u.. [ 80%]
................................u.........u...............u............. [ 83%]
u...............u....u..u........u..............u............u.......... [ 85%]
..x...........u.............u.......u......u...............u............ [ 87%]
...u..............................u..................................... [ 90%]
.........u................................................u...........u. [ 92%]
.........u........u............u.....u.........u......u................. [ 94%]
...................u...........u...........................u.........u.. [ 97%]
...u........u......u......u............................................. [ 99%]
.............                                                            [100%]
=============================== warnings summary ===============================
tests/test_events.py::TestDoubleIngestEvents::test_delta_capping_over_100_changes
  /home/itadmin/.local/share/uv/python/cpython-3.14.8-linux-x86_64-gnu/lib/python3.14/json/encoder.py:254: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x7c0881fd9e40>
    _iterencode = c_make_encoder(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_events.py::TestDoubleIngestEvents::test_delta_capping_over_100_changes
  /home/itadmin/.local/share/uv/python/cpython-3.14.8-linux-x86_64-gnu/lib/python3.14/json/encoder.py:254: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x7c0881fda020>
    _iterencode = c_make_encoder(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_events.py::TestDoubleIngestEvents::test_delta_capping_over_100_changes
  /home/itadmin/.local/share/uv/python/cpython-3.14.8-linux-x86_64-gnu/lib/python3.14/json/encoder.py:254: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x7c0881fdae30>
    _iterencode = c_make_encoder(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ingest.py::test_parse_report_skips_malformed_guid
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/ingest.py:992: UserWarning: GPO 'Bad GUID GPO' has no valid identifier; skipping
    warnings.warn(

tests/test_explore_tools.py::TestDirectoryPages::test_explore_renders
  /home/itadmin/.local/share/uv/python/cpython-3.14.8-linux-x86_64-gnu/lib/python3.14/inspect.py:2433: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x7c0881fdad40>
    _get_signature_of = functools.partial(_signature_from_callable,
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.5.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a46dd8220>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.7.1]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a46ddbb50>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.7.1]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a479262f0>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.7.1]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47927b50>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.7.1]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47924130>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.7.1]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47927c40>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.7.1]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47927f10>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:443: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47925c60>
    row = conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:443: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47924d60>
    row = conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:443: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47925b70>
    row = conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:443: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47925d50>
    row = conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:443: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47927970>
    row = conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:443: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a475ec130>
    row = conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:443: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47926020>
    row = conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a475ee020>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a479258a0>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a479254e0>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47926f20>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47924c70>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47924b80>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47927a60>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47927790>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47925e40>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47924400>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47927e20>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a479247c0>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47925120>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a475ed4e0>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a475ee110>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:218: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a475ece50>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_nav[/ask]
  /home/itadmin/.local/share/uv/python/cpython-3.14.8-linux-x86_64-gnu/lib/python3.14/xml/etree/ElementTree.py:1671: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a46dd8040>
    return self.target.start(tag, attrib)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_nav[/ask]
  /home/itadmin/.local/share/uv/python/cpython-3.14.8-linux-x86_64-gnu/lib/python3.14/xml/etree/ElementTree.py:1671: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47926110>
    return self.target.start(tag, attrib)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_nav[/ask]
  /home/itadmin/.local/share/uv/python/cpython-3.14.8-linux-x86_64-gnu/lib/python3.14/xml/etree/ElementTree.py:1671: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a47925990>
    return self.target.start(tag, attrib)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_nav[/ask]
  /home/itadmin/.local/share/uv/python/cpython-3.14.8-linux-x86_64-gnu/lib/python3.14/xml/etree/ElementTree.py:1671: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a475ec220>
    return self.target.start(tag, attrib)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_nav[/ask]
  /home/itadmin/.local/share/uv/python/cpython-3.14.8-linux-x86_64-gnu/lib/python3.14/xml/etree/ElementTree.py:1671: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a475ee200>
    return self.target.start(tag, attrib)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_nav[/ask]
  /home/itadmin/.local/share/uv/python/cpython-3.14.8-linux-x86_64-gnu/lib/python3.14/xml/etree/ElementTree.py:1671: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a475ee3e0>
    return self.target.start(tag, attrib)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_nav[/ask]
  /home/itadmin/.local/share/uv/python/cpython-3.14.8-linux-x86_64-gnu/lib/python3.14/xml/etree/ElementTree.py:1671: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x728a479244f0>
    return self.target.start(tag, attrib)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_no_traceback_in_output[/baseline]
  <string>:2: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x7db6da2b3a60>
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
================================ tests coverage ================================
_______________ coverage: platform linux, python 3.14.8-final-0 ________________

Name                                       Stmts   Miss  Cover   Missing
------------------------------------------------------------------------
src/gpo_lens/__init__.py                       4      0   100%
src/gpo_lens/__main__.py                       5      5     0%   3-10
src/gpo_lens/_legacy_findings.py              75      3    96%   211-213
src/gpo_lens/admx_parser.py                  128     15    88%   100, 109, 141-142, 156-157, 164-165, 177-178, 182-183, 194-195, 203
src/gpo_lens/authz.py                        228      8    96%   456, 458, 481, 662, 682, 711, 756-760
src/gpo_lens/briefing.py                     158      8    95%   228-229, 378, 380, 387, 403, 416, 422
src/gpo_lens/cli/__init__.py                   2      0   100%
src/gpo_lens/cli/__main__.py                   4      4     0%   1-6
src/gpo_lens/cli/_core.py                     98     11    89%   706-707, 712-719, 723
src/gpo_lens/cli/_danger.py                   15      1    93%   36
src/gpo_lens/cli/_delegation.py               96     21    78%   27-63
src/gpo_lens/cli/_diff.py                    167      6    96%   24, 238-239, 275-276, 283
src/gpo_lens/cli/_estate.py                  119     49    59%   18-56, 159-172, 181-186
src/gpo_lens/cli/_events.py                   35      7    80%   28-31, 53, 63-64
src/gpo_lens/cli/_export.py                  146      8    95%   60, 65, 68, 87, 95, 132, 281, 283
src/gpo_lens/cli/_helpers.py                  46      3    93%   44, 47, 103
src/gpo_lens/cli/_hygiene.py                 120     15    88%   19, 28, 37, 51, 63, 75, 96, 122, 151, 178, 212-213, 252-254
src/gpo_lens/cli/_narration.py                90     15    83%   50-54, 66-67, 85-89, 96-97, 123, 141-143
src/gpo_lens/cli/_repl.py                      9      3    67%   13-15
src/gpo_lens/cli/_report.py                   56      4    93%   62-63, 68-69
src/gpo_lens/cli/_resultant.py                50     11    78%   29-30, 107-109, 111-113, 115-117
src/gpo_lens/cli/_serve.py                    31      3    90%   46-48
src/gpo_lens/cli/_settings.py                159     44    72%   32, 58-62, 73-74, 86-87, 111-118, 147-148, 166-167, 192-196, 240-242, 275, 311-324, 346-349
src/gpo_lens/cli/_topology.py                105     52    50%   30, 55, 78, 105, 121, 132, 144-147, 196-226, 254-266
src/gpo_lens/cli/_trends.py                   18      0   100%
src/gpo_lens/danger.py                       286      9    97%   319, 344, 353, 362, 423, 491, 493, 641, 658
src/gpo_lens/detection/__init__.py            10      0   100%
src/gpo_lens/detection/_acl.py                54      4    93%   51-53, 89
src/gpo_lens/detection/_admx.py               42      2    95%   51, 53
src/gpo_lens/detection/_gpp.py               314     14    96%   158-159, 172, 174, 180, 201, 230, 295, 302, 341, 375, 393, 455, 561
src/gpo_lens/detection/_hygiene.py            77      2    97%   36, 149
src/gpo_lens/display.py                       75      1    99%   64
src/gpo_lens/events.py                        80      2    98%   121-122
src/gpo_lens/exports.py                      140      6    96%   81, 155-159, 306-307
src/gpo_lens/finding_model.py                168      0   100%
src/gpo_lens/findings.py                     487     33    93%   186, 188, 305, 338, 364-366, 453, 669-671, 912, 934-936, 1014-1015, 1045-1046, 1055, 1070-1071, 1089, 1415, 1452, 1479, 1488, 1556, 1705, 1707, 1900-1907
src/gpo_lens/ingest.py                       880     77    91%   120, 134, 153-157, 190-191, 201-205, 242, 261, 297, 319, 407, 467-470, 472, 531-534, 576, 659-669, 678, 680, 682, 684, 739, 750, 762, 823, 849, 851, 1114, 1117-1121, 1152, 1155-1156, 1178, 1202, 1204, 1249-1250, 1315-1316, 1331, 1335, 1347, 1374, 1378, 1390, 1394, 1398, 1429-1430, 1489-1490, 1508, 1511-1512, 1565-1568, 1696-1697, 1716-1717
src/gpo_lens/merge.py                        570     24    96%   163, 171, 181, 212, 229, 244, 513, 530-532, 572, 586, 677, 687, 693, 710, 772, 790-791, 893, 913, 915, 925, 1096
src/gpo_lens/model.py                        182      1    99%   314
src/gpo_lens/narration.py                    135      9    93%   93, 103, 106, 145, 176-177, 243, 254, 270
src/gpo_lens/normalize.py                     52      3    94%   76, 84-85
src/gpo_lens/paths.py                         22      0   100%
src/gpo_lens/queries/__init__.py              16      0   100%
src/gpo_lens/queries/_admx_coverage.py        76      6    92%   101, 112-115, 150
src/gpo_lens/queries/_baseline.py             76      0   100%
src/gpo_lens/queries/_delegation.py          101      3    97%   108, 162, 190
src/gpo_lens/queries/_doctor.py               72      7    90%   138-139, 165, 255-256, 270-271
src/gpo_lens/queries/_golden.py              101      2    98%   132-134
src/gpo_lens/queries/_search.py               70      3    96%   61, 75, 116
src/gpo_lens/queries/_settings.py            142      1    99%   102
src/gpo_lens/queries/_summary.py              41      0   100%
src/gpo_lens/queries/_topology.py             23      0   100%
src/gpo_lens/queries/_wmi.py                  38      1    97%   60
src/gpo_lens/query_dispatch.py                45      2    96%   225, 239
src/gpo_lens/registry_pol.py                 105      0   100%
src/gpo_lens/report.py                       474     37    92%   190, 280, 380, 405, 460-481, 548, 580, 619, 641, 657-683
src/gpo_lens/safe_output.py                   76      1    99%   149
src/gpo_lens/sinks.py                        133     21    84%   27, 29, 35, 41, 43, 48, 56, 64, 84, 107-109, 124-126, 131, 146, 154, 173-175
src/gpo_lens/snapshot_diff.py                234      2    99%   196, 474
src/gpo_lens/store.py                        215      6    97%   65, 435, 452, 646, 851, 988
src/gpo_lens/topology.py                     483     16    97%   216, 226, 235, 240, 244, 247, 251, 254, 370, 499, 655, 766, 826, 974-989, 993
src/gpo_lens/trend.py                         53      0   100%
src/gpo_lens/web/__init__.py                   2      0   100%
src/gpo_lens/web/_helpers.py                 194     12    94%   149-150, 155-156, 201, 260, 307, 311, 313, 321, 323, 326
src/gpo_lens/web/app.py                      310     32    90%   101-102, 114, 116, 119, 135-136, 187, 236-237, 259-262, 266-269, 279-283, 287, 291-293, 298-299, 331, 422, 476, 506-507
src/gpo_lens/web/auth.py                      71      3    96%   108, 137, 139
src/gpo_lens/web/navigation.py                11      0   100%
src/gpo_lens/web/page_narration.py            87      3    97%   111, 129, 139
src/gpo_lens/web/rate_limit.py                58      0   100%
src/gpo_lens/web/routes/__init__.py            0      0   100%
src/gpo_lens/web/routes/admx_coverage.py      23      0   100%
src/gpo_lens/web/routes/api.py                82      7    91%   152-153, 183-190
src/gpo_lens/web/routes/ask.py                72      5    93%   102-103, 106, 109-110
src/gpo_lens/web/routes/baseline.py           58      4    93%   107-118
src/gpo_lens/web/routes/briefing.py           40      0   100%
src/gpo_lens/web/routes/changelog.py          31      0   100%
src/gpo_lens/web/routes/conflicts.py          47      1    98%   74
src/gpo_lens/web/routes/dashboard.py          53      0   100%
src/gpo_lens/web/routes/delegation.py         21      0   100%
src/gpo_lens/web/routes/explore.py            42      0   100%
src/gpo_lens/web/routes/export.py            123     13    89%   63-64, 89, 93-94, 260-261, 308, 310-321
src/gpo_lens/web/routes/findings.py          111     12    89%   287-288, 300-301, 342-344, 398, 403-406
src/gpo_lens/web/routes/golden.py             60      0   100%
src/gpo_lens/web/routes/gpo.py               123      6    95%   116-117, 171-172, 301-302
src/gpo_lens/web/routes/ingest.py             95      6    94%   107-110, 137-138
src/gpo_lens/web/routes/ou.py                 54      0   100%
src/gpo_lens/web/routes/resultant.py          34      2    94%   73, 89
src/gpo_lens/web/routes/search.py             61      0   100%
src/gpo_lens/web/routes/trends.py             29      1    97%   49
------------------------------------------------------------------------
TOTAL                                      10004    698    93%
Required test coverage of 85% reached. Total coverage: 93.02%
```

</details>

<details>
<summary>Python 3.12.13 coverage — exit 0</summary>

Command: `COVERAGE_FILE=/tmp/gpo-docs-3.12.coverage /tmp/gpo-docs-py312/bin/pytest -q -o 'addopts=-n auto' -o cache_dir=/tmp/gpo-docs-cache-3.12 --cov=src --cov-report=term-missing --cov-fail-under=85 --junitxml=/tmp/gpo-docs-3.12.xml`

```text
bringing up nodes...
bringing up nodes...

...s.....ss............................................................. [  2%]
........................................................................ [  4%]
........................................................s.s.ss...s..s... [  7%]
s..s..s..s..s..s.s.s.s.s.s.ss.ss..ss.................................... [  9%]
........................................................................ [ 12%]
........................................................................ [ 14%]
........................................................................ [ 17%]
........................................................................ [ 19%]
........................................................................ [ 22%]
..........s................u........u..........u....u........u...u...... [ 24%]
........................................................................ [ 27%]
........................................................................ [ 29%]
........................................................................ [ 32%]
........................................................................ [ 34%]
.............................................................ssss....... [ 37%]
........................................................................ [ 39%]
........................................................................ [ 42%]
........................................................................ [ 44%]
........................................................................ [ 46%]
........................................................................ [ 49%]
........................................................................ [ 51%]
........................................................................ [ 54%]
........................................................................ [ 56%]
........................................................................ [ 59%]
........................................................................ [ 61%]
........................................................................ [ 64%]
........................................................................ [ 66%]
........................................................................ [ 69%]
.......................u..........u.............u.................u..... [ 71%]
...u...........u.................................u...................... [ 74%]
.........u.....................................u........u....u..u....u.. [ 76%]
......u.......u...u.........u...u............u.u........................ [ 78%]
.............................................u.........u........u....... [ 80%]
..................................................u........u.........u.. [ 83%]
.....u.........................u.....u..............u...x........u...... [ 85%]
........u....u..u......u.............u.........u......................u. [ 87%]
...................................u........u........u.................. [ 90%]
.......................u.........u..........u........u.................. [ 92%]
.................................u.....u......u......u....u..u.........u [ 94%]
....u............................u........u............................u [ 97%]
......u......u.u.........u.u............................................ [ 99%]
.............                                                            [100%]
=============================== warnings summary ===============================
tests/test_ingest.py::test_parse_report_skips_malformed_guid
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/ingest.py:992: UserWarning: GPO 'Bad GUID GPO' has no valid identifier; skipping
    warnings.warn(

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
================================ tests coverage ================================
_______________ coverage: platform linux, python 3.12.13-final-0 _______________

Name                                       Stmts   Miss  Cover   Missing
------------------------------------------------------------------------
src/gpo_lens/__init__.py                       4      0   100%
src/gpo_lens/__main__.py                       5      5     0%   3-10
src/gpo_lens/_legacy_findings.py              75      3    96%   211-213
src/gpo_lens/admx_parser.py                  128     13    90%   100, 109, 141-142, 156-157, 177-178, 182-183, 194-195, 203
src/gpo_lens/authz.py                        228      8    96%   456, 458, 481, 662, 682, 711, 756-760
src/gpo_lens/briefing.py                     158      8    95%   228-229, 378, 380, 387, 403, 416, 422
src/gpo_lens/cli/__init__.py                   2      0   100%
src/gpo_lens/cli/__main__.py                   4      4     0%   1-6
src/gpo_lens/cli/_core.py                     98     11    89%   706-707, 712-719, 723
src/gpo_lens/cli/_danger.py                   15      1    93%   36
src/gpo_lens/cli/_delegation.py               96     21    78%   27-63
src/gpo_lens/cli/_diff.py                    167      6    96%   24, 238-239, 275-276, 283
src/gpo_lens/cli/_estate.py                  119     49    59%   18-56, 159-172, 181-186
src/gpo_lens/cli/_events.py                   35      7    80%   28-31, 53, 63-64
src/gpo_lens/cli/_export.py                  146      8    95%   60, 65, 68, 87, 95, 132, 281, 283
src/gpo_lens/cli/_helpers.py                  46      3    93%   44, 47, 103
src/gpo_lens/cli/_hygiene.py                 120     15    88%   19, 28, 37, 51, 63, 75, 96, 122, 151, 178, 212-213, 252-254
src/gpo_lens/cli/_narration.py                90     15    83%   50-54, 66-67, 85-89, 96-97, 123, 141-143
src/gpo_lens/cli/_repl.py                      9      3    67%   13-15
src/gpo_lens/cli/_report.py                   56      4    93%   62-63, 68-69
src/gpo_lens/cli/_resultant.py                50     11    78%   29-30, 107-109, 111-113, 115-117
src/gpo_lens/cli/_serve.py                    31      3    90%   46-48
src/gpo_lens/cli/_settings.py                159     44    72%   32, 58-62, 73-74, 86-87, 111-118, 147-148, 166-167, 192-196, 240-242, 275, 311-324, 346-349
src/gpo_lens/cli/_topology.py                105     52    50%   30, 55, 78, 105, 121, 132, 144-147, 196-226, 254-266
src/gpo_lens/cli/_trends.py                   18      0   100%
src/gpo_lens/danger.py                       286      9    97%   319, 344, 353, 362, 423, 491, 493, 641, 658
src/gpo_lens/detection/__init__.py            10      0   100%
src/gpo_lens/detection/_acl.py                54      4    93%   51-53, 89
src/gpo_lens/detection/_admx.py               42      2    95%   51, 53
src/gpo_lens/detection/_gpp.py               314     14    96%   158-159, 172, 174, 180, 201, 230, 295, 302, 341, 375, 393, 455, 561
src/gpo_lens/detection/_hygiene.py            77      2    97%   36, 149
src/gpo_lens/display.py                       75      1    99%   64
src/gpo_lens/events.py                        80      2    98%   121-122
src/gpo_lens/exports.py                      140      6    96%   81, 155-159, 306-307
src/gpo_lens/finding_model.py                168      0   100%
src/gpo_lens/findings.py                     487     33    93%   186, 188, 305, 338, 364-366, 453, 669-671, 912, 934-936, 1014-1015, 1045-1046, 1055, 1070-1071, 1089, 1415, 1452, 1479, 1488, 1556, 1705, 1707, 1900-1907
src/gpo_lens/ingest.py                       880     77    91%   120, 134, 153-157, 190-191, 201-205, 242, 261, 297, 319, 407, 467-470, 472, 531-534, 576, 659-669, 678, 680, 682, 684, 739, 750, 762, 823, 849, 851, 1114, 1117-1121, 1152, 1155-1156, 1178, 1202, 1204, 1249-1250, 1315-1316, 1331, 1335, 1347, 1374, 1378, 1390, 1394, 1398, 1429-1430, 1489-1490, 1508, 1511-1512, 1565-1568, 1696-1697, 1716-1717
src/gpo_lens/merge.py                        570     24    96%   163, 171, 181, 212, 229, 244, 513, 530-532, 572, 586, 677, 687, 693, 710, 772, 790-791, 893, 913, 915, 925, 1096
src/gpo_lens/model.py                        182      1    99%   314
src/gpo_lens/narration.py                    135      9    93%   93, 103, 106, 145, 176-177, 243, 254, 270
src/gpo_lens/normalize.py                     52      3    94%   76, 84-85
src/gpo_lens/paths.py                         22      0   100%
src/gpo_lens/queries/__init__.py              16      0   100%
src/gpo_lens/queries/_admx_coverage.py        76      6    92%   101, 112-115, 150
src/gpo_lens/queries/_baseline.py             76      0   100%
src/gpo_lens/queries/_delegation.py          101      3    97%   108, 162, 190
src/gpo_lens/queries/_doctor.py               72      7    90%   138-139, 165, 255-256, 270-271
src/gpo_lens/queries/_golden.py              101      2    98%   132-134
src/gpo_lens/queries/_search.py               70      3    96%   61, 75, 116
src/gpo_lens/queries/_settings.py            142      1    99%   102
src/gpo_lens/queries/_summary.py              41      0   100%
src/gpo_lens/queries/_topology.py             23      0   100%
src/gpo_lens/queries/_wmi.py                  38      1    97%   60
src/gpo_lens/query_dispatch.py                45      2    96%   225, 239
src/gpo_lens/registry_pol.py                 105      0   100%
src/gpo_lens/report.py                       474     37    92%   190, 280, 380, 405, 460-481, 548, 580, 619, 641, 657-683
src/gpo_lens/safe_output.py                   76      1    99%   149
src/gpo_lens/sinks.py                        133     21    84%   27, 29, 35, 41, 43, 48, 56, 64, 84, 107-109, 124-126, 131, 146, 154, 173-175
src/gpo_lens/snapshot_diff.py                234      2    99%   196, 474
src/gpo_lens/store.py                        215      6    97%   65, 435, 452, 646, 851, 988
src/gpo_lens/topology.py                     483     16    97%   216, 226, 235, 240, 244, 247, 251, 254, 370, 499, 655, 766, 826, 974-989, 993
src/gpo_lens/trend.py                         53      0   100%
src/gpo_lens/web/__init__.py                   2      0   100%
src/gpo_lens/web/_helpers.py                 194     12    94%   149-150, 155-156, 201, 260, 307, 311, 313, 321, 323, 326
src/gpo_lens/web/app.py                      310     32    90%   101-102, 114, 116, 119, 135-136, 187, 236-237, 259-262, 266-269, 279-283, 287, 291-293, 298-299, 331, 422, 476, 506-507
src/gpo_lens/web/auth.py                      71      3    96%   108, 137, 139
src/gpo_lens/web/navigation.py                11      0   100%
src/gpo_lens/web/page_narration.py            87      3    97%   111, 129, 139
src/gpo_lens/web/rate_limit.py                58      0   100%
src/gpo_lens/web/routes/__init__.py            0      0   100%
src/gpo_lens/web/routes/admx_coverage.py      23      0   100%
src/gpo_lens/web/routes/api.py                82      7    91%   152-153, 183-190
src/gpo_lens/web/routes/ask.py                72      5    93%   102-103, 106, 109-110
src/gpo_lens/web/routes/baseline.py           58      4    93%   107-118
src/gpo_lens/web/routes/briefing.py           40      0   100%
src/gpo_lens/web/routes/changelog.py          31      0   100%
src/gpo_lens/web/routes/conflicts.py          47      1    98%   74
src/gpo_lens/web/routes/dashboard.py          53      0   100%
src/gpo_lens/web/routes/delegation.py         21      0   100%
src/gpo_lens/web/routes/explore.py            42      0   100%
src/gpo_lens/web/routes/export.py            123     13    89%   63-64, 89, 93-94, 260-261, 308, 310-321
src/gpo_lens/web/routes/findings.py          111     12    89%   287-288, 300-301, 342-344, 398, 403-406
src/gpo_lens/web/routes/golden.py             60      0   100%
src/gpo_lens/web/routes/gpo.py               123      6    95%   116-117, 171-172, 301-302
src/gpo_lens/web/routes/ingest.py             95      6    94%   107-110, 137-138
src/gpo_lens/web/routes/ou.py                 54      0   100%
src/gpo_lens/web/routes/resultant.py          34      2    94%   73, 89
src/gpo_lens/web/routes/search.py             61      0   100%
src/gpo_lens/web/routes/trends.py             29      1    97%   49
------------------------------------------------------------------------
TOTAL                                      10004    696    93%
Required test coverage of 85% reached. Total coverage: 93.04%
2866 passed, 31 skipped, 1 xfailed, 1 warning, 67 subtests passed in 130.22s (0:02:10)
```

</details>

<details>
<summary>Python 3.13.13 coverage — exit 0</summary>

Command: `COVERAGE_FILE=/tmp/gpo-docs-3.13.coverage /tmp/gpo-docs-py313/bin/pytest -q -o 'addopts=-n auto' -o cache_dir=/tmp/gpo-docs-cache-3.13 --cov=src --cov-report=term-missing --cov-fail-under=85 --junitxml=/tmp/gpo-docs-3.13.xml`

```text
bringing up nodes...
bringing up nodes...

.......s.....ss......................................................... [  2%]
........................................................................ [  4%]
................................................................s.s..s.s [  7%]
s...ss....ss..ss.s.ss.s.ss..sss.s.s.s................................... [  9%]
........................................................................ [ 12%]
........................................................................ [ 14%]
........................................................................ [ 17%]
........................................................................ [ 19%]
............................................................s........... [ 22%]
........................................................................ [ 24%]
........................................................................ [ 27%]
..........................................................u.u....u.....u [ 29%]
...u..uu.u....uu...u.u....u....u..uu.u...u.............................. [ 31%]
..........................u.........................................u... [ 34%]
..................................................................ss..ss [ 36%]
........................................................................ [ 39%]
..........................................u............................. [ 41%]
.........u................u............................................. [ 43%]
..................u............................u........................ [ 46%]
........................................................................ [ 48%]
.....................u.................................................. [ 51%]
................................................u....................... [ 53%]
........................................................................ [ 56%]
....................................................................u... [ 58%]
..................................................................u..... [ 61%]
........................................................................ [ 63%]
.............u........................u................................. [ 66%]
...................u.............u........u.........u................... [ 68%]
........................................................................ [ 70%]
......................u................u............u.........uu........ [ 73%]
u.....................u......uu..................u...........u.......... [ 75%]
........................u................uu..........u.u........u...u.u. [ 77%]
..u.....u..u............................................................ [ 80%]
......u........u........u...u.........u...u.......u.....u............... [ 82%]
...............................u........u..x............................ [ 84%]
........................................................................ [ 87%]
........................................................................ [ 89%]
........................................................................ [ 92%]
........................................................................ [ 94%]
........................................................................ [ 97%]
........................................................................ [ 99%]
.............                                                            [100%]
=============================== warnings summary ===============================
tests/test_events.py::TestDoubleIngestEvents::test_delta_capping_over_100_changes
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/snapshot_diff.py:53: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x7fcc5613bd30>
    result[row[0]].add(tuple(row[1:]))
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_events.py::TestDoubleIngestEvents::test_delta_capping_over_100_changes
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/snapshot_diff.py:53: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x7fcc5613bf10>
    result[row[0]].add(tuple(row[1:]))
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_events.py::TestDoubleIngestEvents::test_delta_capping_over_100_changes
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/snapshot_diff.py:53: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x7fcc54dff100>
    result[row[0]].add(tuple(row[1:]))
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ingest.py::test_parse_report_skips_malformed_guid
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/ingest.py:992: UserWarning: GPO 'Bad GUID GPO' has no valid identifier; skipping
    warnings.warn(

tests/test_explore_tools.py::TestDirectoryPages::test_explore_renders
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/typing.py:1373: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x7fcc54dfd030>
    def __getattr__(self, attr):
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.7.0]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/dataclasses.py:1323: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa06c3e20>
    return tuple(f for f in fields.values() if f._field_type is _FIELD)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.7.0]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/dataclasses.py:1323: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0b473d0>
    return tuple(f for f in fields.values() if f._field_type is _FIELD)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.7.0]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/dataclasses.py:1323: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0b467a0>
    return tuple(f for f in fields.values() if f._field_type is _FIELD)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.7.0]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/dataclasses.py:1323: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0b456c0>
    return tuple(f for f in fields.values() if f._field_type is _FIELD)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v0.7.0]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/dataclasses.py:1323: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a47f10>
    return tuple(f for f in fields.values() if f._field_type is _FIELD)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.0.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a46c50>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.0.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a455d0>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.0.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a472e0>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.0.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a473d0>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.0.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:32: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a453f0>
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/dataclasses.py:1323: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a466b0>
    return tuple(f for f in fields.values() if f._field_type is _FIELD)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/dataclasses.py:1323: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a45d50>
    return tuple(f for f in fields.values() if f._field_type is _FIELD)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/dataclasses.py:1323: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa18588b0>
    return tuple(f for f in fields.values() if f._field_type is _FIELD)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/dataclasses.py:1323: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa185bd30>
    return tuple(f for f in fields.values() if f._field_type is _FIELD)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_released_database_upgrade_preserves_every_entity[v1.2.0]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/dataclasses.py:1323: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa18596c0>
    return tuple(f for f in fields.values() if f._field_type is _FIELD)
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a47e20>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a45e40>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a44e50>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a462f0>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a46e30>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a46f20>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a458a0>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a475b0>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a46110>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a46a70>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a465c0>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a46200>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0d4be20>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0d48130>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_released_db_upgrades.py::test_iis_online_backup_restores_released_database[v1.2.0]
  /projects/.worktrees/gpo-lens-rc/tests/test_released_db_upgrades.py:33: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0d4aa70>
    result[name] = columns, conn.execute(f'SELECT * FROM "{name}"').fetchall()
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_store.py::test_load_estate_tolerates_pre_v3_db_without_principal_tables
  /projects/.worktrees/gpo-lens-rc/src/gpo_lens/store.py:365: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x7d52bbf8f010>
    conn.execute(
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_head_with_title_and_css[/briefing]
  /tmp/gpo-docs-py313/lib/python3.13/site-packages/pydantic/fields.py:257: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x7d52bbf8ed40>
    alias_is_set = any(alias is not None for alias in (self.alias, self.validation_alias, self.serialization_alias))
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_body_with_gp_prefix[/conflicts]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/inspect.py:1823: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a44a90>
    *[make_weakref(entry) for entry in _static_getmro(klass)]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_body_with_gp_prefix[/conflicts]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/inspect.py:1823: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0a464d0>
    *[make_weakref(entry) for entry in _static_getmro(klass)]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_body_with_gp_prefix[/conflicts]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/inspect.py:1823: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0d4b1f0>
    *[make_weakref(entry) for entry in _static_getmro(klass)]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_body_with_gp_prefix[/conflicts]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/inspect.py:1823: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0d4a3e0>
    *[make_weakref(entry) for entry in _static_getmro(klass)]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_body_with_gp_prefix[/conflicts]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/inspect.py:1823: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0d4ac50>
    *[make_weakref(entry) for entry in _static_getmro(klass)]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

tests/test_ui_regression.py::TestNavigationStructure::test_every_page_has_body_with_gp_prefix[/conflicts]
  /home/itadmin/.local/share/uv/python/cpython-3.13.13-linux-x86_64-gnu/lib/python3.13/inspect.py:1823: ResourceWarning: unclosed database in <sqlite3.Connection object at 0x779aa0d48d60>
    *[make_weakref(entry) for entry in _static_getmro(klass)]
  Enable tracemalloc to get traceback where the object was allocated.
  See https://docs.pytest.org/en/stable/how-to/capture-warnings.html#resource-warnings for more info.

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
================================ tests coverage ================================
_______________ coverage: platform linux, python 3.13.13-final-0 _______________

Name                                       Stmts   Miss  Cover   Missing
------------------------------------------------------------------------
src/gpo_lens/__init__.py                       4      0   100%
src/gpo_lens/__main__.py                       5      5     0%   3-10
src/gpo_lens/_legacy_findings.py              75      3    96%   211-213
src/gpo_lens/admx_parser.py                  128     13    90%   100, 109, 141-142, 156-157, 177-178, 182-183, 194-195, 203
src/gpo_lens/authz.py                        228      8    96%   456, 458, 481, 662, 682, 711, 756-760
src/gpo_lens/briefing.py                     158      8    95%   228-229, 378, 380, 387, 403, 416, 422
src/gpo_lens/cli/__init__.py                   2      0   100%
src/gpo_lens/cli/__main__.py                   4      4     0%   1-6
src/gpo_lens/cli/_core.py                     98     11    89%   706-707, 712-719, 723
src/gpo_lens/cli/_danger.py                   15      1    93%   36
src/gpo_lens/cli/_delegation.py               96     21    78%   27-63
src/gpo_lens/cli/_diff.py                    167      6    96%   24, 238-239, 275-276, 283
src/gpo_lens/cli/_estate.py                  119     49    59%   18-56, 159-172, 181-186
src/gpo_lens/cli/_events.py                   35      7    80%   28-31, 53, 63-64
src/gpo_lens/cli/_export.py                  146      8    95%   60, 65, 68, 87, 95, 132, 281, 283
src/gpo_lens/cli/_helpers.py                  46      3    93%   44, 47, 103
src/gpo_lens/cli/_hygiene.py                 120     15    88%   19, 28, 37, 51, 63, 75, 96, 122, 151, 178, 212-213, 252-254
src/gpo_lens/cli/_narration.py                90     15    83%   50-54, 66-67, 85-89, 96-97, 123, 141-143
src/gpo_lens/cli/_repl.py                      9      3    67%   13-15
src/gpo_lens/cli/_report.py                   56      4    93%   62-63, 68-69
src/gpo_lens/cli/_resultant.py                50     11    78%   29-30, 107-109, 111-113, 115-117
src/gpo_lens/cli/_serve.py                    31      3    90%   46-48
src/gpo_lens/cli/_settings.py                159     44    72%   32, 58-62, 73-74, 86-87, 111-118, 147-148, 166-167, 192-196, 240-242, 275, 311-324, 346-349
src/gpo_lens/cli/_topology.py                105     52    50%   30, 55, 78, 105, 121, 132, 144-147, 196-226, 254-266
src/gpo_lens/cli/_trends.py                   18      0   100%
src/gpo_lens/danger.py                       286      9    97%   319, 344, 353, 362, 423, 491, 493, 641, 658
src/gpo_lens/detection/__init__.py            10      0   100%
src/gpo_lens/detection/_acl.py                54      4    93%   51-53, 89
src/gpo_lens/detection/_admx.py               42      2    95%   51, 53
src/gpo_lens/detection/_gpp.py               314     14    96%   158-159, 172, 174, 180, 201, 230, 295, 302, 341, 375, 393, 455, 561
src/gpo_lens/detection/_hygiene.py            77      2    97%   36, 149
src/gpo_lens/display.py                       75      1    99%   64
src/gpo_lens/events.py                        80      2    98%   121-122
src/gpo_lens/exports.py                      140      6    96%   81, 155-159, 306-307
src/gpo_lens/finding_model.py                168      0   100%
src/gpo_lens/findings.py                     487     33    93%   186, 188, 305, 338, 364-366, 453, 669-671, 912, 934-936, 1014-1015, 1045-1046, 1055, 1070-1071, 1089, 1415, 1452, 1479, 1488, 1556, 1705, 1707, 1900-1907
src/gpo_lens/ingest.py                       880     77    91%   120, 134, 153-157, 190-191, 201-205, 242, 261, 297, 319, 407, 467-470, 472, 531-534, 576, 659-669, 678, 680, 682, 684, 739, 750, 762, 823, 849, 851, 1114, 1117-1121, 1152, 1155-1156, 1178, 1202, 1204, 1249-1250, 1315-1316, 1331, 1335, 1347, 1374, 1378, 1390, 1394, 1398, 1429-1430, 1489-1490, 1508, 1511-1512, 1565-1568, 1696-1697, 1716-1717
src/gpo_lens/merge.py                        570     24    96%   163, 171, 181, 212, 229, 244, 513, 530-532, 572, 586, 677, 687, 693, 710, 772, 790-791, 893, 913, 915, 925, 1096
src/gpo_lens/model.py                        182      1    99%   314
src/gpo_lens/narration.py                    135      9    93%   93, 103, 106, 145, 176-177, 243, 254, 270
src/gpo_lens/normalize.py                     52      3    94%   76, 84-85
src/gpo_lens/paths.py                         22      0   100%
src/gpo_lens/queries/__init__.py              16      0   100%
src/gpo_lens/queries/_admx_coverage.py        76      6    92%   101, 112-115, 150
src/gpo_lens/queries/_baseline.py             76      0   100%
src/gpo_lens/queries/_delegation.py          101      3    97%   108, 162, 190
src/gpo_lens/queries/_doctor.py               72      7    90%   138-139, 165, 255-256, 270-271
src/gpo_lens/queries/_golden.py              101      2    98%   132-134
src/gpo_lens/queries/_search.py               70      3    96%   61, 75, 116
src/gpo_lens/queries/_settings.py            142      1    99%   102
src/gpo_lens/queries/_summary.py              41      0   100%
src/gpo_lens/queries/_topology.py             23      0   100%
src/gpo_lens/queries/_wmi.py                  38      1    97%   60
src/gpo_lens/query_dispatch.py                45      2    96%   225, 239
src/gpo_lens/registry_pol.py                 105      0   100%
src/gpo_lens/report.py                       474     37    92%   190, 280, 380, 405, 460-481, 548, 580, 619, 641, 657-683
src/gpo_lens/safe_output.py                   76      1    99%   149
src/gpo_lens/sinks.py                        133     21    84%   27, 29, 35, 41, 43, 48, 56, 64, 84, 107-109, 124-126, 131, 146, 154, 173-175
src/gpo_lens/snapshot_diff.py                234      2    99%   196, 474
src/gpo_lens/store.py                        215      6    97%   65, 435, 452, 646, 851, 988
src/gpo_lens/topology.py                     483     16    97%   216, 226, 235, 240, 244, 247, 251, 254, 370, 499, 655, 766, 826, 974-989, 993
src/gpo_lens/trend.py                         53      0   100%
src/gpo_lens/web/__init__.py                   2      0   100%
src/gpo_lens/web/_helpers.py                 194     12    94%   149-150, 155-156, 201, 260, 307, 311, 313, 321, 323, 326
src/gpo_lens/web/app.py                      310     32    90%   101-102, 114, 116, 119, 135-136, 187, 236-237, 259-262, 266-269, 279-283, 287, 291-293, 298-299, 331, 422, 476, 506-507
src/gpo_lens/web/auth.py                      71      3    96%   108, 137, 139
src/gpo_lens/web/navigation.py                11      0   100%
src/gpo_lens/web/page_narration.py            87      3    97%   111, 129, 139
src/gpo_lens/web/rate_limit.py                58      0   100%
src/gpo_lens/web/routes/__init__.py            0      0   100%
src/gpo_lens/web/routes/admx_coverage.py      23      0   100%
src/gpo_lens/web/routes/api.py                82      7    91%   152-153, 183-190
src/gpo_lens/web/routes/ask.py                72      5    93%   102-103, 106, 109-110
src/gpo_lens/web/routes/baseline.py           58      4    93%   107-118
src/gpo_lens/web/routes/briefing.py           40      0   100%
src/gpo_lens/web/routes/changelog.py          31      0   100%
src/gpo_lens/web/routes/conflicts.py          47      1    98%   74
src/gpo_lens/web/routes/dashboard.py          53      0   100%
src/gpo_lens/web/routes/delegation.py         21      0   100%
src/gpo_lens/web/routes/explore.py            42      0   100%
src/gpo_lens/web/routes/export.py            123     13    89%   63-64, 89, 93-94, 260-261, 308, 310-321
src/gpo_lens/web/routes/findings.py          111     12    89%   287-288, 300-301, 342-344, 398, 403-406
src/gpo_lens/web/routes/golden.py             60      0   100%
src/gpo_lens/web/routes/gpo.py               123      6    95%   116-117, 171-172, 301-302
src/gpo_lens/web/routes/ingest.py             95      6    94%   107-110, 137-138
src/gpo_lens/web/routes/ou.py                 54      0   100%
src/gpo_lens/web/routes/resultant.py          34      2    94%   73, 89
src/gpo_lens/web/routes/search.py             61      0   100%
src/gpo_lens/web/routes/trends.py             29      1    97%   49
------------------------------------------------------------------------
TOTAL                                      10004    696    93%
Required test coverage of 85% reached. Total coverage: 93.04%
2866 passed, 31 skipped, 1 xfailed, 43 warnings, 67 subtests passed in 127.54s (0:02:07)
```

</details>

<details>
<summary>pip-audit — exit 0</summary>

Command: `uvx pip-audit --strict --requirement /tmp/gpo-docs-requirements-audit.txt`

```text
No known vulnerabilities found
```

</details>

<details>
<summary>Identifier gate — exit 0</summary>

Command: `.venv/bin/python scripts/check_committed_identifiers.py`

No stdout or stderr. The denylist was loaded without printing its contents.

</details>

<details>
<summary>Pester 5.7.1 on Linux — exit 0</summary>

Command: `pwsh -NoProfile -Command 'Import-Module Pester -RequiredVersion 5.7.1; $result = Invoke-Pester -Path tests/powershell/*.Tests.ps1 -Output Detailed -CI -PassThru; if ($result.FailedCount -gt 0) { exit 1 }'`

```text
Pester v5.7.1

Starting discovery in 3 files.
Discovery found 72 tests in 565ms.
Running tests.

Running tests from '/projects/.worktrees/gpo-lens-rc/tests/powershell/install-windows.Tests.ps1'
Describing install-windows.ps1
 Describing Parse-BindingInformation
   [+] parses IPv4 wildcard *:8443: 325ms (221ms|104ms)
   [+] parses IPv4 wildcard with a hostname 18ms (14ms|4ms)
   [+] parses an IPv4 literal IP with a hostname 19ms (15ms|4ms)
   [+] parses bracketed IPv6 [::]:8443: 33ms (26ms|6ms)
   [+] parses bracketed IPv6 with a hostname 15ms (12ms|3ms)
   [+] returns empty values for a malformed string 14ms (11ms|3ms)
   [+] returns empty values for an empty string 58ms (55ms|3ms)
 Describing Resolve-EffectiveBinding
   [+] prefer explicit value over existing and default 12ms (8ms|4ms)
   [+] preserves existing value when no explicit value is supplied 8ms (7ms|2ms)
   [+] falls back to default when there is no existing config 7ms (5ms|2ms)
   [+] preserves existing Sni=$true 11ms (9ms|2ms)
   [+] preserves existing Sni=$false over a $true default 17ms (14ms|3ms)
   [+] uses default when the existing value is $null (key absent) 10ms (7ms|3ms)
   [+] explicit false Sni wins over existing true 9ms (6ms|3ms)
   [+] falls to default when existing cert is empty (truthiness semantics) 9ms (6ms|3ms)
   [+] preserves a non-empty existing cert 9ms (6ms|2ms)
 Describing Test-SniConsistency
   [+] throws when Sni is requested without a hostname 69ms (65ms|4ms)
   [+] passes when Sni is requested with a hostname 9ms (6ms|2ms)
   [+] passes when Sni is false and hostname is empty 8ms (5ms|2ms)
   [+] passes when Sni is false and hostname is set 8ms (6ms|2ms)
 Describing Test-BindingChanged
   [+] returns $true when there is no existing binding 9ms (7ms|2ms)
   [+] returns $false when port and host both match 9ms (8ms|1ms)
   [+] returns $true when the port differs 5ms (4ms|2ms)
   [+] returns $true when the host differs 5ms (4ms|1ms)
   [+] returns $false when both existing and effective hosts are empty 5ms (4ms|1ms)
 Describing Compare-CertThumbprint
   [+] returns $true for identical thumbprints 11ms (9ms|2ms)
   [+] ignores whitespace differences in the current thumbprint 6ms (4ms|2ms)
   [+] ignores whitespace differences in the desired thumbprint 5ms (4ms|2ms)
   [+] ignores case differences (PowerShell default equality) 4ms (3ms|1ms)
   [+] returns $false when the current thumbprint is empty 10ms (9ms|1ms)
   [+] returns $false when the desired thumbprint is empty 4ms (3ms|1ms)
 Describing Get-ExistingBindingConfig
   [+] returns $null when there is no https binding 281ms (279ms|2ms)
   [+] detects an IPv4 catch-all binding and reads the ipport cert 112ms (107ms|5ms)
   [+] detects an IPv6 binding with a hostname 49ms (44ms|5ms)
   [+] detects SNI from sslFlags string and reads the hostnameport cert 83ms (81ms|3ms)
   [+] detects SNI from numeric sslFlags bitmask (bit 0 = SNI) 49ms (44ms|4ms)
   [+] detects SNI from sslFlags bitmask with combined flags (3 = SNI + CCS) 63ms (59ms|4ms)
   [+] returns $null when bindingInformation is malformed 32ms (30ms|2ms)
   [+] reads cert from IIS binding certificateHash (no netsh needed) 35ms (33ms|2ms)
   [+] falls back to netsh when IIS binding has no certificateHash 36ms (34ms|2ms)
 Describing Set-SniBinding
  Configuring SNI binding (sslFlags=1, host=gpo-lens.local) on port 8443 ...
    SNI binding installed.
   [+] applies the SNI binding when there is no existing config 285ms (281ms|4ms)
  Configuring SNI binding (sslFlags=1, host=gpo-lens.local) on port 8443 ...
    SNI binding installed.
   [+] re-applies the SNI binding when the current binding is not SNI 119ms (90ms|29ms)
  SNI binding already configured (host=gpo-lens.local, port=8443); preserving.
   [+] preserves the SNI binding when it already matches 34ms (32ms|2ms)
   [+] does nothing when Sni is $false 51ms (48ms|2ms)
 Describing Set-TlsCertBinding
    TLS certificate bound to gpo-lens.local:8443 (SNI, store: MY).
   [+] uses hostnameport for an SNI binding 31ms (28ms|3ms)
    TLS certificate bound to 0.0.0.0:8443 (store: MY).
   [+] uses ipport=0.0.0.0:Port for a non-SNI catch-all binding 17ms (15ms|1ms)
    TLS certificate bound to 0.0.0.0:8443 (store: MY).
   [+] removes stale hostnameport for a non-SNI binding with a hostname 13ms (12ms|2ms)

   [+] throws when netsh add returns a non-zero exit code 32ms (28ms|4ms)
   [+] throws when the show sslcert verification does not contain the thumbprint 10ms (8ms|2ms)
    TLS certificate bound to 0.0.0.0:8443 (store: MY).
   [+] does not throw on a successful binding 13ms (11ms|2ms)

Running tests from '/projects/.worktrees/gpo-lens-rc/tests/powershell/scripts-parse.Tests.ps1'
Describing scripts/*.ps1 integrity
  [+]  parses with no syntax errors 53ms (48ms|5ms)
  [+]  parses with no syntax errors 9ms (6ms|3ms)
  [+]  parses with no syntax errors 12ms (9ms|4ms)
  [+]  parses with no syntax errors 23ms (19ms|3ms)
  [+]  parses with no syntax errors 12ms (8ms|4ms)
  [+]  is ASCII-only (a BOM-less .ps1 is read as ANSI by PS 5.1) 475ms (472ms|3ms)
  [+]  is ASCII-only (a BOM-less .ps1 is read as ANSI by PS 5.1) 48ms (46ms|2ms)
  [+]  is ASCII-only (a BOM-less .ps1 is read as ANSI by PS 5.1) 106ms (104ms|2ms)
  [+]  is ASCII-only (a BOM-less .ps1 is read as ANSI by PS 5.1) 1.06s (1.06s|2ms)
  [+]  is ASCII-only (a BOM-less .ps1 is read as ANSI by PS 5.1) 164ms (163ms|2ms)

Describing Export-GpoEstate.ps1 invariants
  [+] assigns the Get-ADDomain object to $dom exactly once (never clobbered) 38ms (35ms|3ms)

Running tests from '/projects/.worktrees/gpo-lens-rc/tests/powershell/uninstall-windows.Tests.ps1'
Describing uninstall-windows.ps1
 Describing Get-IsSniFlag
   [+] treats numeric sslFlags=1 as SNI 20ms (16ms|4ms)
   [+] treats numeric sslFlags=0 as catch-all 10ms (8ms|2ms)
   [+] treats sslFlags=3 (SNI + Central Cert Store) as SNI 10ms (7ms|3ms)
   [+] treats sslFlags=2 (CCS only, no SNI bit) as catch-all 11ms (7ms|4ms)
   [+] honors the legacy string form 'Sni' 7ms (5ms|2ms)
   [+] honors the legacy string form 'None' 6ms (3ms|3ms)
 Describing Resolve-OwnedSslBinding
   [+] catch-all WITH a host header still resolves to ipport (the LAB-HOST-1 case) 26ms (24ms|2ms)
   [+] catch-all with no host resolves to ipport 12ms (9ms|3ms)
   [+] SNI with a host resolves to hostnameport (and never the catch-all) 14ms (11ms|3ms)
   [+] SNI without a host falls back to catch-all (cannot target a hostnameport) 13ms (11ms|2ms)
   [+] uses the requested port in the target 9ms (7ms|3ms)
Tests completed in 6.4s
Tests Passed: 72, Failed: 0, Skipped: 0, Inconclusive: 0, NotRun: 0
```

</details>

<details>
<summary>Container image build — exit 0</summary>

Command: `docker build -f deploy/container/Dockerfile -t gpo-lens:docs-v1.3.0-smoke .`

```text
#0 building with "default" instance using docker driver

#1 [internal] load build definition from Dockerfile
#1 transferring dockerfile: 1.70kB done
#1 DONE 0.0s

#2 [internal] load metadata for docker.io/library/python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
#2 DONE 0.0s

#3 [internal] load metadata for ghcr.io/astral-sh/uv:0.10.12@sha256:72ab0aeb448090480ccabb99fb5f52b0dc3c71923bffb5e2e26517a1c27b7fec
#3 DONE 0.0s

#4 [uv 1/1] FROM ghcr.io/astral-sh/uv:0.10.12@sha256:72ab0aeb448090480ccabb99fb5f52b0dc3c71923bffb5e2e26517a1c27b7fec
#4 resolve ghcr.io/astral-sh/uv:0.10.12@sha256:72ab0aeb448090480ccabb99fb5f52b0dc3c71923bffb5e2e26517a1c27b7fec 0.0s done
#4 DONE 0.0s

#5 [build 1/6] FROM docker.io/library/python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
#5 resolve docker.io/library/python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 0.0s done
#5 DONE 0.0s

#6 [internal] load build context
#6 transferring context: 19.07kB done
#6 DONE 0.0s

#7 [build 2/6] COPY --from=uv /uv /usr/local/bin/uv
#7 CACHED

#8 [build 3/6] WORKDIR /app
#8 CACHED

#9 [build 4/6] COPY pyproject.toml uv.lock README.md ./
#9 DONE 0.0s

#10 [build 5/6] COPY src ./src
#10 DONE 0.1s

#11 [build 6/6] RUN uv sync --locked --no-dev --extra web --no-editable
#11 0.476 Using CPython 3.12.15 interpreter at: /usr/local/bin/python3
#11 0.476 Creating virtual environment at: .venv
#11 0.485 Resolved 44 packages in 0.96ms
#11 0.495    Building gpo-lens @ file:///app
#11 0.601 Downloading pydantic-core (2.0MiB)
#11 0.611 Downloading uvloop (4.2MiB)
#11 0.818  Downloaded pydantic-core
#11 0.876  Downloaded uvloop
#11 2.087       Built gpo-lens @ file:///app
#11 2.097 Prepared 24 packages in 1.60s
#11 2.175 Installed 24 packages in 77ms
#11 2.175  + annotated-doc==0.0.4
#11 2.175  + annotated-types==0.7.0
#11 2.175  + anyio==4.14.2
#11 2.175  + click==8.4.1
#11 2.175  + defusedxml==0.7.1
#11 2.175  + fastapi==0.136.3
#11 2.175  + gpo-lens==1.2.0 (from file:///app)
#11 2.175  + h11==0.16.0
#11 2.175  + httptools==0.8.0
#11 2.175  + idna==3.18
#11 2.175  + jinja2==3.1.6
#11 2.175  + markupsafe==3.0.3
#11 2.175  + pydantic==2.13.4
#11 2.175  + pydantic-core==2.46.4
#11 2.175  + python-dotenv==1.2.2
#11 2.175  + python-multipart==0.0.32
#11 2.175  + pyyaml==6.0.3
#11 2.175  + starlette==1.3.1
#11 2.175  + typing-extensions==4.15.0
#11 2.175  + typing-inspection==0.4.2
#11 2.175  + uvicorn==0.49.0
#11 2.175  + uvloop==0.22.1
#11 2.175  + watchfiles==1.2.0
#11 2.175  + websockets==16.0
#11 DONE 2.3s

#5 [build 1/6] FROM docker.io/library/python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
#5 CACHED

#12 [stage-2 2/4] COPY --from=build /app/.venv /app/.venv
#12 DONE 0.2s

#13 [stage-2 3/4] RUN groupadd --gid 10001 gpo-lens     && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin gpo-lens     && mkdir /data && chown 10001:10001 /data && chmod 0700 /data
#13 DONE 0.3s

#14 [stage-2 4/4] WORKDIR /data
#14 DONE 0.1s

#15 exporting to image
#15 exporting layers
#15 exporting layers 2.2s done
#15 exporting manifest sha256:e2840edfb5b0d86c01c253c0081ffe36225d1d255f14067981ec1ee86b8e0d33 0.0s done
#15 exporting config sha256:56e330dd6e48b568d8465038e4ac2dd92f0a467eb1e8f9e051519b17a24c92e1 0.0s done
#15 exporting attestation manifest sha256:3eb702fe0de628184520d759ef9e3bb1ce82dec1410bd075ceaf55bb6b30d1f6 0.0s done
#15 exporting manifest list sha256:2913eb0fa0ed8f9ed18ce03869b7303c1deb20be3e4af1a3c6a1023cf67344b3 0.0s done
#15 naming to docker.io/library/gpo-lens:docs-v1.3.0-smoke
#15 naming to docker.io/library/gpo-lens:docs-v1.3.0-smoke done
#15 unpacking to docker.io/library/gpo-lens:docs-v1.3.0-smoke
#15 unpacking to docker.io/library/gpo-lens:docs-v1.3.0-smoke 0.5s done
#15 DONE 2.9s
```

</details>

<details>
<summary>Container acceptance smoke — exit 0</summary>

Command: `python3 deploy/container/smoke.py gpo-lens:docs-v1.3.0-smoke`

Compose's trailing spaces and line endings are preserved losslessly as a JSON
array of output lines. Joining the decoded strings reconstructs the exact log.

```json
[
  " Volume gpo-lens-smoke-6fc0277828ba_estate Creating \n",
  " Volume gpo-lens-smoke-6fc0277828ba_estate Creating \n",
  " Volume gpo-lens-smoke-6fc0277828ba_estate Created \n",
  " Volume gpo-lens-smoke-6fc0277828ba_estate Created \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Creating \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Created \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Creating \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Created \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Starting \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Started \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Waiting \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Healthy \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Starting \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Started \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Waiting \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Waiting \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Healthy \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Healthy \n",
  "PASS: loopback health/index, actual loopback listener, non-root read-only image\n",
  "PASS: verified TLS, basic-auth denial/success, HTTPS links, forwarded client stays loopback\n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Restarting \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Started \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Running \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Running \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Waiting \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Healthy \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Waiting \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Waiting \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Healthy \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Healthy \n",
  "PASS: cross-origin denial, synthetic Ingest upload/HTTPS redirect, persisted snapshot after restart\n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Stopping \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Stopped \n",
  " gpo-lens-smoke-6fc0277828ba-app-1 Copying gpo-lens-smoke-6fc0277828ba-app-1:/data/backup.sqlite3 to /tmp/gpo-lens-smoke-_jiesqw0/restore.sqlite3\n",
  " gpo-lens-smoke-6fc0277828ba-app-1 Copied gpo-lens-smoke-6fc0277828ba-app-1:/data/backup.sqlite3 to /tmp/gpo-lens-smoke-_jiesqw0/restore.sqlite3\n",
  " Container gpo-lens-smoke-6fc0277828ba-app-run-71c2ea6a5840 Creating \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-run-71c2ea6a5840 Created \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Running \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Starting \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Started \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Waiting \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Healthy \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Waiting \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Waiting \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Healthy \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Healthy \n",
  "PASS: online backup includes committed WAL data; stopped restore preserves snapshot\n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Stopping \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Stopped \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Removing \n",
  " Container gpo-lens-smoke-6fc0277828ba-proxy-1 Removed \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Stopping \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Stopped \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Removing \n",
  " Container gpo-lens-smoke-6fc0277828ba-app-1 Removed \n",
  " Volume gpo-lens-smoke-6fc0277828ba_estate Removing \n",
  " Volume gpo-lens-smoke-6fc0277828ba_estate Removed \n"
]
```

</details>

<details>
<summary>README command checks — exit 0</summary>

Command: `Synthetic fixture harness; each subcommand --help; documented CLI examples and local server smoke`

```text
PASS: gpo-lens --help
PASS: gpo-lens summary --help
PASS: gpo-lens ingest --help
PASS: gpo-lens unlinked --help
PASS: gpo-lens empty --help
PASS: gpo-lens disabled-populated --help
PASS: gpo-lens who-sets --help
PASS: gpo-lens conflicts --help
PASS: gpo-lens blocked --help
PASS: gpo-lens version-skew --help
PASS: gpo-lens ms16-072 --help
PASS: gpo-lens cpassword --help
PASS: gpo-lens search --help
PASS: gpo-lens show --help
PASS: gpo-lens perms --help
PASS: gpo-lens delegation --help
PASS: gpo-lens sddl --help
PASS: gpo-lens diff --help
PASS: gpo-lens snapshots --help
PASS: gpo-lens events --help
PASS: gpo-lens events-export --help
PASS: gpo-lens diff-settings --help
PASS: gpo-lens changelog --help
PASS: gpo-lens som --help
PASS: gpo-lens dangling --help
PASS: gpo-lens enforced --help
PASS: gpo-lens loopback --help
PASS: gpo-lens wmi --help
PASS: gpo-lens wmi-filters --help
PASS: gpo-lens sites --help
PASS: gpo-lens topology-check --help
PASS: gpo-lens scope --help
PASS: gpo-lens admx-gaps --help
PASS: gpo-lens admx-coverage --help
PASS: gpo-lens settings-at --help
PASS: gpo-lens som-conflicts --help
PASS: gpo-lens precedence-conflicts --help
PASS: gpo-lens broken-refs --help
PASS: gpo-lens gpp-tasks --help
PASS: gpo-lens gpp-groups --help
PASS: gpo-lens settings-dump --help
PASS: gpo-lens settings-diff --help
PASS: gpo-lens baseline-diff --help
PASS: gpo-lens golden-diff --help
PASS: gpo-lens doctor --help
PASS: gpo-lens report --help
PASS: gpo-lens ask --help
PASS: gpo-lens explain-setting --help
PASS: gpo-lens repl --help
PASS: gpo-lens danger --help
PASS: gpo-lens serve --help
PASS: gpo-lens resultant --help
PASS: gpo-lens trends --help
PASS: gpo-lens export --help
Top-level help and all 53 subcommand help invocations exited 0.
PASS: uv run gpo-lens --db ./gpo-lens.sqlite3 ingest ./GpoExport
PASS: uv run gpo-lens --db ./gpo-lens.sqlite3 doctor
PASS: uv run gpo-lens --db ./gpo-lens.sqlite3 export findings --format csv --lifecycle all --triage all
PASS: uv run gpo-lens --db ./gpo-lens.sqlite3 export briefing --format md --as-of 2026-10-06T00:00:00Z
PASS: uv run gpo-lens --db ./gpo-lens.sqlite3 report --output report.html --format html
PASS: uv run gpo-lens --db ./gpo-lens.sqlite3 --json doctor | jq '.data.findings[] | select(.severity=="critical")'
PASS: uv run gpo-lens --db ./gpo-lens.sqlite3 serve --open (healthz and Briefing HTTP 200; stopped after smoke)
Fixture harness: synthetic tests/fixtures linked as ./GpoExport in a temporary directory; uv --project selected the checkout; BROWSER=true suppressed GUI launch.
Collector command: OutputRoot verified through PowerShell AST and Pester; live execution requires Windows RSAT/AD and was not attempted on this Linux host.
```

</details>

<details>
<summary>Local Markdown links/anchors — exit 0</summary>

Command: `Resolve relative links against each document and match Markdown heading anchors`

```text
Checked 162 local links/anchors across 30 Markdown files.
All local links and anchors resolve.
```

</details>

<details>
<summary>External deployment links — exit 0</summary>

Command: `HTTP GET each external Markdown link; follow redirects`

```text
200 https://caddyserver.com/docs/caddyfile/directives/basic_auth -> https://caddyserver.com/docs/caddyfile/directives/basic_auth
200 https://caddyserver.com/docs/install -> https://caddyserver.com/docs/install
200 https://docs.astral.sh/uv/getting-started/installation/ -> https://docs.astral.sh/uv/getting-started/installation/
200 https://docs.docker.com/engine/network/drivers/host/ -> https://docs.docker.com/engine/network/drivers/host/
200 https://github.com/hraedon/gpo-lens -> https://github.com/hraedon-labs/gpo-lens
200 https://www.iis.net/downloads/microsoft/httpplatformhandler -> https://www.iis.net/downloads/microsoft/httpplatformhandler
```

</details>

## Commit and push boundary

The existing `githooks` configuration is used for pre-commit, commit-message
and pre-push checks. Only documentation is staged. The identifier checker is
also run on staged content before committing; denylist values are never copied
into evidence. The docs commit carries `Co-Authored-By: GPT-6 <noreply@openai.com>`.
Push is restricted to `origin release/v1.3.0-candidate`, with no PR, tag, settings
change or tracker mutation. The final commit/push result is reported in the
session response rather than inventing a self-referential commit hash here.
