"""Plan 025 WI-6: deterministic Markdown/CSV over typed query results.

The caller owns query selection, filtering and authorization. Rendering is
lazy (one record at a time), with a fixed CSV schema suitable for heterogeneous
views: section, record, field, value. Metadata uses the same schema. Neither
format calls a model, reads source files, or consults the clock.
"""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from gpo_lens.display import serialize_result

if TYPE_CHECKING:
    from gpo_lens.model import AdmxResolver, Estate
    from gpo_lens.queries import LedgerRow

from gpo_lens import __version__
from gpo_lens.safe_output import safe_data, secret_values

SCOPE_CAVEAT = (
    "Read-only analysis of collected copies; collection coverage is bounded by collector access. "
    "OU-level scope only: security/WMI/loopback/item targeting and site membership are flagged, "
    "not simulated. No object-level RSoP claim."
)


@dataclass(frozen=True)
class ExportSection:
    name: str
    rows: Iterable[object]


@dataclass(frozen=True)
class ExportDocument:
    title: str
    metadata: Mapping[str, object]
    sections: tuple[ExportSection, ...]
    include_audit: bool = False
    secrets: tuple[str, ...] = ()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def csv_cell(value: str) -> str:
    return "'" + value if value.startswith(("=", "+", "-", "@", "\t", "\r")) else value


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    return canonical_json(value)


def _markdown(value: str) -> str:
    value = html.escape(value, quote=False)
    for char in ("\\", "`", "*", "_", "[", "]", "|"):
        value = value.replace(char, "\\" + char)
    return value.replace("\r", "&#13;").replace("\n", "<br>").replace("\t", "&#9;")


def render_export(document: ExportDocument, format: str) -> Iterator[str]:
    """Stream safe UTF-8 text in stable field and record order.

    Typed queries define record order. Mapping keys are sorted, nested values
    use canonical JSON, persisted timestamps remain evidence; no generated-at
    timestamp is added. Only one projected record and output line are buffered.
    """
    if format not in {"md", "csv"}:
        raise ValueError("format must be md or csv")
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")

    def line(cells: list[str]) -> str:
        if format == "md":
            return "| " + " | ".join(_markdown(c) for c in cells) + " |\n"
        writer.writerow([csv_cell(c) for c in cells])
        result = buffer.getvalue()
        buffer.seek(0)
        buffer.truncate()
        return result

    if format == "md":
        yield "# " + _markdown(document.title) + "\n\n"
    yield line(["section", "record", "field", "value"])
    if format == "md":
        yield "| --- | --- | --- | --- |\n"
    sections = (ExportSection("metadata", (document.metadata,)), *document.sections)
    for section in sections:
        for index, row in enumerate(section.rows, 1):
            projected = safe_data(
                row, include_audit=document.include_audit, secrets=document.secrets
            )
            fields = projected if isinstance(projected, dict) else {"value": projected}
            for key in sorted(fields):
                yield line([section.name, str(index), key, _text(fields[key])])


def export_metadata(
    conn: sqlite3.Connection,
    *,
    snapshot_ids: Iterable[int] | None = None,
    run_ids: Iterable[int] | None = None,
    filters: Mapping[str, object] | None = None,
    admx: object = None,
    comparator: object = None,
) -> dict[str, object]:
    """Pin snapshot/run/input provenance without raw input metadata or a clock."""
    if snapshot_ids is None:
        latest = conn.execute("SELECT MAX(id) FROM snapshot").fetchone()[0]
        snapshot_ids = [latest] if latest is not None else []
    snapshots = sorted(set(snapshot_ids))
    if run_ids is None:
        run_ids = [
            r[0]
            for sid in snapshots
            for r in conn.execute(
                "SELECT id FROM evaluation_run WHERE snapshot_id=? ORDER BY id", (sid,)
            )
        ]
    runs: list[dict[str, Any]] = []
    for run_id in sorted(set(run_ids)):
        row = conn.execute(
            "SELECT id,snapshot_id,evaluation_kind,detector_set_digest,comparator_input_id,"
            "application_version,status FROM evaluation_run WHERE id=?",
            (run_id,),
        ).fetchone()
        if row is not None:
            keys = (
                "id",
                "snapshot_id",
                "evaluation_kind",
                "detector_set_digest",
                "comparator_input_id",
                "application_version",
                "status",
            )
            runs.append(dict(zip(keys, row, strict=True)))
    snapshots = sorted(set(snapshots) | {r["snapshot_id"] for r in runs})
    inputs = []
    for input_id in sorted(
        {r["comparator_input_id"] for r in runs if r["comparator_input_id"] is not None}
    ):
        row = conn.execute(
            "SELECT id,kind,canonical_digest,version FROM analysis_input WHERE id=?", (input_id,)
        ).fetchone()
        if row:
            inputs.append(
                dict(zip(("id", "kind", "canonical_digest", "version"), row, strict=True))
            )

    def digest(value: object) -> str:
        if hasattr(value, "gpos"):
            value = [
                {
                    "name": g.name,
                    "settings": sorted(
                        [
                            {
                                "side": s.side,
                                "cse": s.cse,
                                "identity": s.identity,
                                "value": s.display_value,
                            }
                            for s in g.settings
                        ],
                        key=canonical_json,
                    ),
                }
                for g in sorted(value.gpos, key=lambda g: (g.name, g.id))
            ]
        elif hasattr(value, "policies"):
            value = sorted(cast(list[object], serialize_result(value.policies)), key=canonical_json)
        else:
            value = serialize_result(value)
        return hashlib.sha256(canonical_json(value).encode()).hexdigest()

    return {
        "application_version": __version__,
        "snapshot_ids": snapshots,
        "evaluation_ids": [r["id"] for r in runs],
        "evaluations": runs,
        "analysis_inputs": inputs,
        "admx_digest": digest(admx) if admx is not None else "unavailable",
        "comparator_digest": digest(comparator) if comparator is not None else "not supplied",
        "filters": dict(filters or {}),
        "scope_caveats": SCOPE_CAVEAT,
        "evidence_policy": "Safe references only; raw source and credential values are [REDACTED].",
        "evaluation_caveat": "No evaluation provenance recorded."
        if not runs
        else "Only completed evaluations can support resolution claims.",
    }


def filter_ledger(
    rows: list[dict[str, Any]], *, q: str = "", side: str = "", cse: str = ""
) -> list[dict[str, Any]]:
    """The server/browser ledger's shared search fields, after redaction."""
    q = q.strip()[:200].lower()
    fields = ("identity", "display_name", "display_value", "reg_key", "reg_value_name", "admx_name")
    return [
        r
        for r in rows
        if (not side or r["side"] == side)
        and (not cse or r["cse"] == cse)
        and (not q or q in " ".join(str(r[k]) for k in fields).lower())
    ]


def ledger_payload(
    estate: Estate, gpo_id: str, admx: AdmxResolver | None = None
) -> list[dict[str, Any]]:
    """Project the typed ledger with its source setting's credential context."""
    from gpo_lens.queries import settings_ledger

    gpo = estate.gpo_by_id(gpo_id)
    return cast(
        list[dict[str, Any]],
        safe_data({"ledger": settings_ledger(estate, gpo_id, admx=admx), "source": gpo})["ledger"],
    )


def setting_payload(
    estate: Estate,
    identity: str,
    *,
    cse: str = "",
    side: str = "",
    admx: AdmxResolver | None = None,
) -> list[dict[str, Any]]:
    """Exact setting identity, across GPOs; no per-principal applicability claim."""
    return [
        r
        for g in sorted(estate.gpos, key=lambda g: (g.name.lower(), g.id))
        for r in ledger_payload(estate, g.id, admx)
        if r["identity"] == identity
        and (not cse or r["cse"] == cse)
        and (not side or r["side"] == side)
    ]


def compare_ledgers(a: Iterable[LedgerRow], b: Iterable[LedgerRow]) -> list[dict[str, str]]:
    """GPO-vs-GPO diff over the exact typed ledgers shown by the dossiers."""
    idx_a = {(r.side, r.cse, r.identity): r for r in a}
    idx_b = {(r.side, r.cse, r.identity): r for r in b}
    result = []
    for key in sorted(set(idx_a) | set(idx_b)):
        left, right = idx_a.get(key), idx_b.get(key)
        row = left or right
        assert row is not None
        if left and right and left.display_value == right.display_value:
            continue
        result.append(
            {
                "side": row.side,
                "cse": row.cse,
                "identity": row.identity,
                "display_name": row.admx_name or row.display_name,
                "change": "modified" if left and right else "only_in_a" if left else "only_in_b",
                "val_a": left.display_value if left else "",
                "val_b": right.display_value if right else "",
            }
        )
    return result


def snapshot_secrets(conn: sqlite3.Connection, snapshot_ids: Iterable[int]) -> tuple[str, ...]:
    """Read credential context a setting at a time; never include raw fragments."""
    values: set[str] = set()
    for snapshot_id in sorted(set(snapshot_ids)):
        for identity, display_value, raw in conn.execute(
            "SELECT identity,display_value,raw FROM setting WHERE snapshot_id=?", (snapshot_id,)
        ):
            try:
                source = json.loads(raw)
            except (ValueError, TypeError):
                source = None
            values.update(
                secret_values({"identity": identity, "display_value": display_value, "raw": source})
            )
    return tuple(sorted(values, key=lambda s: (-len(s), s)))


@dataclass(frozen=True)
class ExportContext:
    """Detached provenance/redaction context captured with the view's read transaction."""

    metadata: dict[str, object]
    secrets: tuple[str, ...]


def export_context(
    conn: sqlite3.Connection,
    *,
    snapshot_ids: Iterable[int] | None = None,
    run_ids: Iterable[int] | None = None,
    admx: object = None,
    comparator: object = None,
    secret_sources: object = None,
) -> ExportContext:
    metadata = export_metadata(
        conn, snapshot_ids=snapshot_ids, run_ids=run_ids, admx=admx, comparator=comparator
    )
    secrets = set(snapshot_secrets(conn, cast(list[int], metadata["snapshot_ids"])))
    secrets.update(secret_values(comparator))
    secrets.update(secret_values(secret_sources))
    return ExportContext(metadata, tuple(sorted(secrets, key=lambda s: (-len(s), s))))
