"""Tests for the SQLite persistence layer (store.py).

Covers DB-file permission hardening and deterministic load_estate ordering —
both are correctness/reproducibility properties that the snapshot-diff and
--json contract depend on.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from contextlib import closing

import pytest
from _helpers import _make_gpo

from gpo_lens import store
from gpo_lens.model import Estate, Setting

# ---------------------------------------------------------------------------
# DB file permissions
# ---------------------------------------------------------------------------


def test_init_db_restricts_file_permissions_to_owner_only(tmp_path):
    db = tmp_path / "perms.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    conn.close()

    mode = stat.S_IMODE(os.stat(db).st_mode)
    # Owner-only (0o600). On shared hosts the DB holds the full estate — it
    # must not be world/group readable regardless of the process umask.
    assert mode == 0o600


def test_init_db_retightens_permissions_on_existing_db(tmp_path):
    """A pre-existing DB with loose perms is re-tightened by init_db."""
    db = tmp_path / "loose.db"
    db.write_bytes(b"")
    os.chmod(db, 0o644)

    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    conn.close()

    mode = stat.S_IMODE(os.stat(db).st_mode)
    assert mode == 0o600


# ---------------------------------------------------------------------------
# load_estate determinism
# ---------------------------------------------------------------------------


def test_load_estate_returns_gpos_in_stable_order(tmp_path):
    """GPOs loaded from the DB must come back in a stable (id) order,
    independent of insertion order — snapshot diffs depend on this."""
    db = tmp_path / "order.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_b = _make_gpo(id="gpo-b", name="Beta")
    gpo_a = _make_gpo(id="gpo-a", name="Alpha")
    gpo_c = _make_gpo(id="gpo-c", name="Charlie")
    estate_in = Estate(domain="test.local", gpos=[gpo_b, gpo_a, gpo_c])
    sid = store.save_estate(conn, estate_in)

    estate_out = store.load_estate(conn, sid)
    conn.close()

    ids = [g.id for g in estate_out.gpos]
    assert ids == sorted(ids)
    assert ids == ["gpo-a", "gpo-b", "gpo-c"]


def test_load_estate_round_trip_is_stable(tmp_path):
    """Two loads of the same snapshot must produce identical Estates."""
    db = tmp_path / "rt.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo = _make_gpo(
        id="gpo-1",
        name="RoundTrip",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    sid = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo]))

    first = store.load_estate(conn, sid)
    second = store.load_estate(conn, sid)
    conn.close()

    assert [g.id for g in first.gpos] == [g.id for g in second.gpos]
    assert first.gpos[0].settings == second.gpos[0].settings


def test_description_round_trips_through_db(tmp_path):
    db = tmp_path / "desc.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo = _make_gpo(id="gpo-1", name="WithDesc", description="Audit baseline; frozen.")
    sid = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo]))
    loaded = store.load_estate(conn, sid)
    conn.close()

    assert loaded.gpos[0].description == "Audit baseline; frozen."


def test_description_survives_migration_from_old_schema(tmp_path):
    """A DB created before the description column must be migrated (additive
    ALTER TABLE) rather than rejected. init_db adds the column on open."""
    db = tmp_path / "old.db"
    conn = sqlite3.connect(str(db))
    # Hand-build a pre-description schema (no description column).
    conn.execute(
        "CREATE TABLE snapshot (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "domain TEXT NOT NULL, taken_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE gpo ("
        "snapshot_id INTEGER NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, "
        "domain TEXT NOT NULL, computer_enabled INTEGER NOT NULL, "
        "user_enabled INTEGER NOT NULL, filter_data_available INTEGER NOT NULL, "
        "PRIMARY KEY (snapshot_id, id))"
    )
    conn.commit()
    conn.close()

    # init_db on the old DB should add the column without error.
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(gpo)").fetchall()}
    assert "description" in cols
    conn.close()


# ---------------------------------------------------------------------------
# Schema versioning
# ---------------------------------------------------------------------------


def test_init_db_stamps_new_database_with_current_schema_version(tmp_path):
    """A freshly initialized DB must record the current schema version."""
    db = tmp_path / "new-stamp.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == store.CURRENT_SCHEMA_VERSION
    conn.close()


def test_migrate_schema_is_idempotent_for_old_database(tmp_path):
    """An old DB without the description column gets stamped, and a second
    open is a no-op (column not re-added, version unchanged)."""
    db = tmp_path / "old-stamp.db"
    conn = sqlite3.connect(str(db))

    # Hand-build a pre-description schema with no user_version stamp.
    conn.execute(
        "CREATE TABLE snapshot (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "domain TEXT NOT NULL, taken_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE gpo ("
        "snapshot_id INTEGER NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, "
        "domain TEXT NOT NULL, computer_enabled INTEGER NOT NULL, "
        "user_enabled INTEGER NOT NULL, filter_data_available INTEGER NOT NULL, "
        "PRIMARY KEY (snapshot_id, id))"
    )
    conn.commit()
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
    conn.close()

    # First migration adds the column and stamps the version.
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(gpo)").fetchall()}
    assert "description" in cols
    assert conn.execute("PRAGMA user_version").fetchone()[0] == store.CURRENT_SCHEMA_VERSION
    conn.close()

    # Second migration leaves the DB unchanged and does not bump anything.
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(gpo)").fetchall()}
    assert "description" in cols
    assert conn.execute("PRAGMA user_version").fetchone()[0] == store.CURRENT_SCHEMA_VERSION
    conn.close()


def test_init_db_rejects_future_schema_version(tmp_path):
    """A DB written by a newer gpo-lens must raise a clear error, not truncate
    or silently ignore the future version."""
    db = tmp_path / "future.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    conn.execute("PRAGMA user_version = 99")
    conn.execute("ALTER TABLE gpo ADD COLUMN future_col TEXT")
    conn.commit()
    conn.close()

    conn = sqlite3.connect(str(db))
    with pytest.raises(
        RuntimeError,
        match=(
            "schema version 99 is newer than this gpo-lens release supports "
            rf"\(version {store.CURRENT_SCHEMA_VERSION}\)"
        ),
    ):
        store.init_db(conn)
    conn.close()


# ---------------------------------------------------------------------------
# snapshot_changelog batching
# ---------------------------------------------------------------------------


def test_snapshot_changelog_batched_query_shape(tmp_path):
    """snapshot_changelog must return the same shape/content after batching
    the per-GPO version queries. This is the behavior-preservation check for
    the N+1 → batched query refactor in queries.py.
    """
    from gpo_lens import queries
    from gpo_lens.model import Setting

    db = tmp_path / "changelog_batched.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo_alpha_a = _make_gpo(
        id="gpo-alpha",
        name="Alpha",
        computer_ver_ds=1,
        computer_ver_sysvol=1,
        user_ver_ds=1,
        user_ver_sysvol=1,
        settings=[
            Setting(
                gpo_id="gpo-alpha",
                side="Computer",
                cse="Registry",
                identity="HKLM\\Software\\Foo",
                display_name="Foo",
                display_value="old",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_beta_a = _make_gpo(
        id="gpo-beta",
        name="Beta",
        computer_ver_ds=1,
        computer_ver_sysvol=1,
        user_ver_ds=1,
        user_ver_sysvol=1,
    )
    sid_a = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo_alpha_a, gpo_beta_a]))

    gpo_alpha_b = _make_gpo(
        id="gpo-alpha",
        name="Alpha",
        computer_ver_ds=2,
        computer_ver_sysvol=3,
        user_ver_ds=1,
        user_ver_sysvol=1,
        settings=[
            Setting(
                gpo_id="gpo-alpha",
                side="Computer",
                cse="Registry",
                identity="HKLM\\Software\\Foo",
                display_name="Foo",
                display_value="new",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    gpo_beta_b = _make_gpo(
        id="gpo-beta",
        name="Beta",
        computer_ver_ds=1,
        computer_ver_sysvol=1,
        user_ver_ds=2,
        user_ver_sysvol=2,
    )
    gpo_gamma_b = _make_gpo(
        id="gpo-gamma",
        name="Gamma",
        computer_ver_ds=1,
        computer_ver_sysvol=1,
        user_ver_ds=1,
        user_ver_sysvol=1,
    )
    sid_b = store.save_estate(
        conn, Estate(domain="test.local", gpos=[gpo_alpha_b, gpo_beta_b, gpo_gamma_b])
    )

    entries = queries.snapshot_changelog(conn, sid_a, sid_b)
    conn.close()

    # We expect three changelog lines: gpo-gamma added, plus one per changed
    # side for the common GPOs, in sorted GPO id order (alpha, beta, gamma).
    assert len(entries) == 3

    e_alpha = entries[0]
    assert e_alpha.gpo_id == "gpo-alpha"
    assert e_alpha.gpo_name == "Alpha"
    assert e_alpha.side == "Computer"
    assert e_alpha.kind == "settings_detail"
    assert e_alpha.version_change is not None
    assert e_alpha.version_change.old_ds == 1
    assert e_alpha.version_change.old_sysvol == 1
    assert e_alpha.version_change.new_ds == 2
    assert e_alpha.version_change.new_sysvol == 3
    assert e_alpha.version_change.edit_count == 2
    assert len(e_alpha.setting_changes) == 1
    sc = e_alpha.setting_changes[0]
    assert sc.change_type == "modified"
    assert sc.old_value == "old"
    assert sc.new_value == "new"

    e_beta = entries[1]
    assert e_beta.gpo_id == "gpo-beta"
    assert e_beta.gpo_name == "Beta"
    assert e_beta.side == "User"
    assert e_beta.kind == "metadata_only"
    assert e_beta.version_change is not None
    assert e_beta.version_change.old_ds == 1
    assert e_beta.version_change.old_sysvol == 1
    assert e_beta.version_change.new_ds == 2
    assert e_beta.version_change.new_sysvol == 2
    assert e_beta.version_change.edit_count == 1
    assert e_beta.setting_changes == []

    e_gamma = entries[2]
    assert e_gamma.gpo_id == "gpo-gamma"
    assert e_gamma.gpo_name == "Gamma"
    assert e_gamma.kind == "gpo_added"


# ---------------------------------------------------------------------------
# principal / group_member persistence (schema v3) — Plan 020/021 inputs must
# survive the snapshot round-trip, or the default --db path silently degrades
# principal resolution to raw SIDs.
# ---------------------------------------------------------------------------


def test_principals_and_group_members_round_trip(tmp_path):
    from gpo_lens.model import GroupMembership, ResolvedPrincipal

    db = tmp_path / "principals.db"
    with closing(sqlite3.connect(str(db))) as conn:
        store.init_db(conn)

        principals = {
            "s-1-5-21-1-2-3-1000": ResolvedPrincipal(
                sid="s-1-5-21-1-2-3-1000",
                name="TEST\\GPO-Admins",
                sam="GPO-Admins",
                principal_type="Group",
                domain="TEST",
                resolved=True,
            ),
            "s-1-5-21-1-2-3-9999": ResolvedPrincipal(
                sid="s-1-5-21-1-2-3-9999",
                name="s-1-5-21-1-2-3-9999",
                sam="",
                principal_type="Unresolved",
                domain="",
                resolved=False,
            ),
        }
        group_members = {
            "s-1-5-21-1-2-3-1000": GroupMembership(
                sid="s-1-5-21-1-2-3-1000",
                name="TEST\\GPO-Admins",
                members=("s-1-5-21-1-2-3-1001", "s-1-5-21-1-2-3-1002"),
                member_count=2,
                implicit="",
            ),
        }
        estate_in = Estate(
            domain="test.local",
            gpos=[_make_gpo()],
            principals=principals,
            group_members=group_members,
        )
        sid = store.save_estate(conn, estate_in)
        out = store.load_estate(conn, sid)

        assert out.principals == principals
        assert out.group_members == group_members
        # the resolved name is what the danger/resultant surfaces depend on
        assert out.principals["s-1-5-21-1-2-3-1000"].name == "TEST\\GPO-Admins"
        assert out.group_members["s-1-5-21-1-2-3-1000"].members == (
            "s-1-5-21-1-2-3-1001",
            "s-1-5-21-1-2-3-1002",
        )


def test_load_estate_tolerates_pre_v3_db_without_principal_tables(tmp_path):
    """A DB written before schema v3 has no principal/group_member tables; the
    read path must return empty maps, not raise."""
    db = tmp_path / "legacy.db"
    with closing(sqlite3.connect(str(db))) as conn:
        store.init_db(conn)
        sid = store.save_estate(conn, Estate(domain="test.local", gpos=[_make_gpo()]))
        # Simulate a pre-v3 DB by dropping the new tables.
        conn.execute("DROP TABLE principal")
        conn.execute("DROP TABLE group_member")
        conn.commit()

        out = store.load_estate(conn, sid)
        assert out.principals == {}
        assert out.group_members == {}


def test_load_estate_corrupted_setting_raw_raises(tmp_path):
    """Corrupt JSON in the setting.raw column must raise, not silently
    return a default (WI-049 — coverage honesty charter)."""
    db = tmp_path / "corrupt.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo = _make_gpo(
        id="gpo-1",
        name="Corrupt",
        settings=[
            Setting(
                gpo_id="gpo-1",
                side="Computer",
                cse="Registry",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    sid = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo]))

    conn.execute(
        "UPDATE setting SET raw = 'not-valid-json' WHERE snapshot_id = ? AND gpo_id = ?",
        (sid, "gpo-1"),
    )
    conn.commit()

    with pytest.raises(json.JSONDecodeError):
        store.load_estate(conn, sid)
    conn.close()


def test_load_estate_corrupted_group_members_raises(tmp_path):
    """Corrupt JSON in the group_member.members column must raise (WI-049)."""
    from gpo_lens.model import GroupMembership

    db = tmp_path / "corrupt-gm.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gm = GroupMembership(
        sid="s-1-5-21-1-2-3-1000",
        name="Test",
        members=("s-1-5-21-1-2-3-1001",),
        member_count=1,
        implicit="",
    )
    sid = store.save_estate(
        conn,
        Estate(
            domain="test.local",
            gpos=[_make_gpo()],
            group_members={"s-1-5-21-1-2-3-1000": gm},
        ),
    )

    conn.execute(
        "UPDATE group_member SET members = 'not-valid-json' WHERE snapshot_id = ? AND sid = ?",
        (sid, "s-1-5-21-1-2-3-1000"),
    )
    conn.commit()

    with pytest.raises(json.JSONDecodeError):
        store.load_estate(conn, sid)
    conn.close()


def test_restrict_db_permissions_warns_on_failure(tmp_path, monkeypatch):
    db = tmp_path / "warn.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    def fail_chmod(path, mode):
        raise OSError("permission denied")

    monkeypatch.setattr(os, "chmod", fail_chmod)

    with pytest.warns(UserWarning, match="Could not restrict DB permissions"):
        store.restrict_db_permissions(conn)
    conn.close()


def test_delete_snapshot_cascades_and_reports(tmp_path):
    """delete_snapshot removes the estate wholesale and reports existence."""
    db = tmp_path / "del.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)
    s1 = store.save_estate(
        conn,
        Estate(
            domain="a.local",
            gpos=[
                _make_gpo(
                    id="gpo-a",
                    settings=[
                        Setting(
                            gpo_id="gpo-a",
                            side="Computer",
                            cse="Registry",
                            identity="HKLM\\X:V",
                            display_name="V",
                            display_value="1",
                            raw={},
                            from_disabled_side=False,
                        )
                    ],
                )
            ],
        ),
    )
    s2 = store.save_estate(conn, Estate(domain="b.local", gpos=[_make_gpo(id="gpo-b")]))

    assert store.delete_snapshot(conn, s2) is True
    assert [s[0] for s in store.list_snapshots(conn)] == [s1]
    # cascade: no child rows survive for the deleted snapshot
    for table in ("gpo", "setting", "gpo_link", "delegation", "som", "som_link"):
        n = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE snapshot_id=?",
            (s2,),  # noqa: S608
        ).fetchone()[0]
        assert n == 0, table
    # deleting a non-existent snapshot is a no-op that reports False
    assert store.delete_snapshot(conn, 9999) is False
    conn.close()


def test_restrict_db_permissions_also_restricts_wal_shm(tmp_path):
    """restrict_db_permissions must chmod WAL and SHM sidecar files, not
    just the main DB file. These files contain the same sensitive estate data.
    """
    db = tmp_path / "waltest.db"
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t (x)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    store.restrict_db_permissions(conn)
    conn.close()

    for suffix in ("", "-wal", "-shm"):
        path = str(db) + suffix
        if os.path.exists(path):
            mode = stat.S_IMODE(os.stat(path).st_mode)
            assert mode == 0o600, f"{path} has mode {oct(mode)}, expected 0o600"


# ---------------------------------------------------------------------------
# Hyphenated GPO ID backward compatibility (cb21237 regression)
# ---------------------------------------------------------------------------

_HYPHEN_ID = "31b2f340-016d-11d2-945f-00c04fb984f9"
_CANON_ID = "31b2f340016d11d2945f00c04fb984f9"


def test_gpo_by_id_finds_hyphenated_via_canonical_lookup(tmp_path):
    """A GPO stored with a hyphenated ID (pre-cb21237 DB) must be found
    when the lookup uses the current canonical (hyphen-stripped) form.

    This is the root cause of the /gpo/{id} 404: the web route canonicalizes
    the URL param (strips hyphens) but the gpo_index was keyed by the
    stored ID (with hyphens).
    """
    gpo = _make_gpo(id=_HYPHEN_ID, name="Default Domain Policy")
    estate = Estate(domain="test.local", gpos=[gpo])

    assert estate.gpo_by_id(_HYPHEN_ID) is not None
    assert estate.gpo_by_id(_CANON_ID) is not None
    assert estate.gpo_by_id(_CANON_ID.upper()) is not None
    assert estate.gpo_by_id("{" + _HYPHEN_ID.upper() + "}") is not None


def test_gpo_names_contains_stored_and_canonical_ids():
    gpo = _make_gpo(id=_HYPHEN_ID, name="Default Domain Policy")
    estate = Estate(domain="test.local", gpos=[gpo])

    assert estate.gpo_names[_HYPHEN_ID] == "Default Domain Policy"
    assert estate.gpo_names[_CANON_ID] == "Default Domain Policy"


def test_gpo_by_id_finds_canonical_via_hyphenated_lookup(tmp_path):
    """A GPO stored with a canonical (no-hyphens) ID must also be found
    when the lookup uses a hyphenated form."""
    gpo = _make_gpo(id=_CANON_ID, name="Default Domain Policy")
    estate = Estate(domain="test.local", gpos=[gpo])

    assert estate.gpo_by_id(_CANON_ID) is not None
    assert estate.gpo_by_id(_HYPHEN_ID) is not None


def test_hyphenated_gpo_id_round_trips_through_db(tmp_path):
    """An estate saved with hyphenated GPO IDs (simulating an old DB) must
    load back and be findable via the canonical (hyphen-stripped) form."""
    db = tmp_path / "hyphen.db"
    conn = sqlite3.connect(str(db))
    store.init_db(conn)

    gpo = _make_gpo(
        id=_HYPHEN_ID,
        name="Old Estate GPO",
        settings=[
            Setting(
                gpo_id=_HYPHEN_ID,
                side="Computer",
                cse="Security",
                identity="X",
                display_name="X",
                display_value="1",
                raw={},
                from_disabled_side=False,
            ),
        ],
    )
    sid = store.save_estate(conn, Estate(domain="test.local", gpos=[gpo]))
    loaded = store.load_estate(conn, sid)
    conn.close()

    assert loaded.gpo_by_id(_CANON_ID) is not None
    assert loaded.gpo_by_id(_HYPHEN_ID) is not None
    found = loaded.gpo_by_id(_CANON_ID)
    assert found is not None
    assert found.name == "Old Estate GPO"
    assert len(found.settings) == 1


def test_gpo_index_warns_on_dual_key_collision():
    """When two GPOs produce the same stripped ID, a warning is emitted and
    the first GPO shadows the second."""
    gpo_a = _make_gpo(id="31b2f340-016d-11d2-945f-00c04fb984f9", name="Alpha")
    gpo_b = _make_gpo(id="{31B2F340-016D-11D2-945F-00C04FB984F9}", name="Beta")
    estate = Estate(domain="test.local", gpos=[gpo_a, gpo_b])

    with pytest.warns(UserWarning, match="GPO id collision in dual-key index"):
        _ = estate.gpo_index

    assert estate.gpo_by_id("31b2f340016d11d2945f00c04fb984f9").name == "Alpha"
