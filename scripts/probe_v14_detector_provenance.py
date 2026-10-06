"""Reviewer continuity probe using stored pipeline digests, not ID-only hashes.

Run with the project's Python. Only synthetic candidates and an in-memory DB
are used; no estate files or external services are accessed.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from unittest.mock import patch

from gpo_lens import findings, store
from gpo_lens.finding_model import FindingCandidate
from gpo_lens.model import Estate


def probe() -> dict[str, object]:
    version = "1"

    def candidates(*_args: object, **_kwargs: object) -> list[FindingCandidate]:
        return [
            FindingCandidate(
                detector_id="broken_ref:missing_script",
                detector_version=version,
                category="broken_ref:missing_script",
                severity="low",
                subject_type="gpo",
                subject_key=("a" * 32,),
                dimensions=(("ref_value", "missing.cmd"),),
                summary=f"Missing script under detector v{version}",
            )
        ]

    with (
        closing(sqlite3.connect(":memory:")) as conn,
        patch.object(findings, "candidates_from_estate", candidates),
        patch.dict(findings.INTRINSIC_DETECTOR_VERSIONS, {"broken_ref:*": "1"}),
    ):
        store.init_db(conn)
        estate = Estate(domain="lab.example.com")
        store.save_evaluated_estate(conn, estate)
        occurrence = findings.finding_inbox(conn)[0].occurrence_id
        findings.append_triage_event(
            conn, occurrence, "accepted_risk", "lab-reviewer", rationale="Lab control"
        )
        version = "2"
        findings.INTRINSIC_DETECTOR_VERSIONS["broken_ref:*"] = version
        store.save_evaluated_estate(conn, estate)
        view = findings.finding_inbox(conn)[0]
        stored = conn.execute(
            "SELECT detector_version, first_seen_run_id, last_seen_run_id FROM finding WHERE id=?",
            (occurrence,),
        ).fetchone()
        digests = [r[0] for r in conn.execute("SELECT detector_set_digest FROM evaluation_run")]
        observation_versions = [
            r[0]
            for r in conn.execute("SELECT detector_version FROM finding_observation ORDER BY id")
        ]
        result = {
            "same_occurrence": view.occurrence_id == occurrence,
            "triage_status": view.triage_status,
            "stored_detector_version_after_v2": stored[0],
            "observation_versions": observation_versions,
            "application_versions": [
                r[0] for r in conn.execute("SELECT application_version FROM evaluation_run")
            ],
            "first_seen_run_id": stored[1],
            "last_seen_run_id": stored[2],
            "pipeline_digest_v1": digests[0],
            "pipeline_digest_v2": digests[1],
            "digests_equal": digests[0] == digests[1],
        }
        assert result["same_occurrence"]
        assert result["triage_status"] == "accepted_risk"
        assert not result["digests_equal"]
        assert observation_versions == ["1", "2"]
        return result


if __name__ == "__main__":
    print(json.dumps(probe(), sort_keys=True))
