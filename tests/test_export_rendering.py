"""Plan 025 WI-6: deterministic, bounded, safe evidence exports."""

from __future__ import annotations

import csv
import io

import pytest

from gpo_lens.exports import ExportDocument, ExportSection, render_export


def document():
    return ExportDocument(
        "Ledger",
        {"snapshot_id": 7, "evaluation_ids": [3], "filters": {"side": "Computer"}},
        (ExportSection("settings", ({"identity": "Test", "display_value": "1"},)),),
    )


@pytest.mark.parametrize("format", ["md", "csv"])
def test_golden(format):
    from pathlib import Path

    actual = "".join(render_export(document(), format))
    assert actual == (Path(__file__).parent / "exports" / f"ledger.{format}").read_text()
    assert actual == "".join(render_export(document(), format))
    assert "generated_at" not in actual


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_csv_formula_neutralized(prefix):
    doc = ExportDocument("Test", {}, (ExportSection("rows", ({"value": prefix + "SUM(1,1)"},)),))
    rows = list(csv.reader(io.StringIO("".join(render_export(doc, "csv")))))
    assert rows[-1][-1] == "'" + prefix + "SUM(1,1)"


def test_export_iterator_does_not_materialize_rows():
    consumed = []

    def rows():
        for i in range(100_000):
            consumed.append(i)
            yield {"id": i}

    stream = iter(
        render_export(ExportDocument("Large", {}, (ExportSection("rows", rows()),)), "csv")
    )
    next(stream)
    assert not consumed
    next(stream)
    assert consumed == [0]
