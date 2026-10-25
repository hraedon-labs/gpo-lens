"""Inventory modification sorting preserves date range, precision and UTC order."""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path

import pytest
from _helpers import _make_gpo
from fastapi.testclient import TestClient

from gpo_lens.model import Estate, Gpo
from gpo_lens.store import init_db, save_estate
from gpo_lens.web._helpers import filter_gpos
from gpo_lens.web.app import create_app


def _policy(index: int, name: str, modified: str | None) -> Gpo:
    return _make_gpo(
        id=f"{index:032x}",
        name=name,
        domain="example.test",
        modified=datetime.fromisoformat(modified) if modified is not None else None,
    )


@pytest.mark.parametrize(
    "value",
    [
        "0001-01-01T00:00:00",
        "0001-01-01T00:00:00+14:00",
        "1601-01-01T00:00:00",
        "1969-12-31T23:59:59",
        "2026-01-01T00:00:00",
        "9999-12-31T23:59:59.999999",
        "9999-12-31T23:59:59.999999-14:00",
    ],
)
def test_every_representable_timestamp_sorts_before_missing(value: str) -> None:
    dated = _policy(1, "Dated", value)
    unknown = _policy(2, "Unknown", None)

    assert filter_gpos([unknown, dated], "", "", "modified") == [dated, unknown]


@pytest.mark.parametrize("year", [2026, 2400, 9999])
def test_sort_keeps_microsecond_precision(year: int) -> None:
    older = _policy(1, "Older", f"{year}-01-01T00:00:00.000001+00:00")
    newer = _policy(2, "Newer", f"{year}-01-01T00:00:00.000002+00:00")

    assert filter_gpos([older, newer], "", "", "modified") == [newer, older]


def test_mixed_offsets_sort_by_instant_and_preserve_ties() -> None:
    local_later = _policy(1, "Earlier instant", "2026-01-01T02:00:00+03:00")
    utc_later = _policy(2, "Later instant", "2026-01-01T00:00:00+00:00")
    same_instant = _policy(3, "Same instant", "2025-12-31T19:00:00-05:00")
    unknown = _policy(4, "Unknown", None)
    policies = [unknown, local_later, utc_later, same_instant]

    assert filter_gpos(policies, "", "", "modified") == [
        utc_later,
        same_instant,
        local_later,
        unknown,
    ]
    assert policies == [unknown, local_later, utc_later, same_instant]


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="POSIX timezone switching unavailable")
@pytest.mark.parametrize(
    ("zone", "aware", "expected"),
    [
        ("UTC-03", "2026-01-01T01:00:00+00:00", ["Naive", "Aware"]),
        ("UTC+07", "2026-01-01T03:00:00+00:00", ["Aware", "Naive"]),
    ],
)
def test_naive_dates_use_utc_independently_of_server_timezone(
    monkeypatch: pytest.MonkeyPatch, zone: str, aware: str, expected: list[str]
) -> None:
    policies = [
        _policy(1, "Naive", "2026-01-01T02:00:00"),
        _policy(2, "Aware", aware),
    ]
    try:
        with monkeypatch.context() as timezone:
            timezone.setenv("TZ", zone)
            time.tzset()
            names = [g.name for g in filter_gpos(policies, "", "", "modified")]
    finally:
        time.tzset()
    assert names == expected


@pytest.mark.parametrize(
    "value",
    [
        "0001-01-01T00:00:00",
        "0001-01-01T00:00:00+14:00",
        "1601-01-01T00:00:00",
        "2026-01-01T00:00:00",
        "9999-12-31T23:59:59.999999-14:00",
    ],
)
def test_inventory_page_sorts_persisted_dates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    db = tmp_path / "inventory.sqlite3"
    policies = [_policy(2, "Unknown policy", None), _policy(1, "Dated policy", value)]
    with closing(sqlite3.connect(db)) as conn:
        init_db(conn)
        save_estate(conn, Estate(domain="example.test", gpos=policies))
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "synthetic-inventory-token")
    app = create_app(str(db))
    with TestClient(
        app,
        headers={"Authorization": "Bearer synthetic-inventory-token"},
        raise_server_exceptions=False,
    ) as client:
        response = client.get("/inventory", params={"sort": "modified", "per_page": "1"})
        second = client.get("/inventory", params={"sort": "modified", "per_page": "1", "page": "2"})
        empty = client.get("/inventory", params={"sort": "modified", "q": "no-match"})
    assert response.status_code == 200
    assert "Dated policy" in response.text and "Unknown policy" not in response.text
    assert second.status_code == 200
    assert "Unknown policy" in second.text and "Dated policy" not in second.text
    assert empty.status_code == 200
    assert "No GPOs match" in empty.text
