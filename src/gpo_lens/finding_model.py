"""Durable finding identity, lifecycle, and triage data model (Plan 024).

This module defines the typed protocol that every lifecycle-aware detector
emits, along with the persistence-model entities (evaluation run, occurrence,
observation, triage event). The deterministic core uses these types to track
findings across snapshots with provenance — *which* detector, rules,
catalogue, comparator, snapshot, and software version produced each claim.

Key distinctions (Plan 024 §2):

- **Finding definition:** the typed rule/check and its version.
- **Evaluation run:** one execution against a snapshot and optional comparator.
- **Finding fingerprint:** detector-specific canonical identity of the issue.
- **Occurrence:** one continuous interval from first observed until resolved.
- **Observation:** presence or absence in one evaluation run.
- **Triage event:** append-only local operator action about an occurrence.
- **Estate fact:** immutable snapshot input from which an evaluation was derived.

This module is a core module — no ``narration`` or ``web`` imports.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

ClaimLevel = Literal["confirmed", "probable", "possible"]
"""How confidently the detector asserts the finding.

- ``confirmed``: directly observed in estate data (e.g. cpassword in XML).
- ``probable``: inferred from a strong structural signal (e.g. GPO writable
  by non-admin via SDDL parse).
- ``possible``: heuristic or pattern-based (e.g. a pattern without enough evidence to confirm
  its effect).
"""

OccurrenceState = Literal[
    "new",
    "persisting",
    "resolved",
    "regressed",
    "unobserved_due_to_coverage",
    "snapshot_scoped",
]
"""Lifecycle state of a finding occurrence.

``snapshot_scoped`` marks findings whose subjects cannot be stably identified
across snapshots — they cannot be acknowledged or tracked across runs.
"""

TriageAction = Literal[
    "commented",
    "acknowledged",
    "reopened",
    "accepted_risk",
    "risk_acceptance_expired",
    "risk_acceptance_revoked",
]
"""Append-only triage event types.

Current triage status is a deterministic fold over these events. The fold
rules are:

- ``acknowledged`` supersedes ``open`` (the default).
- ``accepted_risk`` supersedes ``acknowledged``.
- ``reopened`` supersedes ``acknowledged`` and ``accepted_risk`` (but not
  expired/revoked risk acceptance — those are terminal for that acceptance).
- ``risk_acceptance_expired`` and ``risk_acceptance_revoked`` return the
  occurrence to ``open`` if the most recent non-expiry action was
  ``accepted_risk``. A subsequent ``acknowledged`` can re-acknowledge.
"""

EvaluationKind = Literal["intrinsic", "contextual"]
"""Whether the evaluation requires an external comparator.

Intrinsic findings are evaluated from one estate snapshot plus pinned analysis
inputs (danger rules, detectors). Contextual findings require an external
comparison context (baseline, golden GPO, ADMX catalogue).
"""

RunStatus = Literal["completed", "failed", "partial"]
"""Completion state of an evaluation run.

Only ``completed`` runs resolve absent findings. ``failed`` and ``partial``
runs never imply resolution.
"""

# ---------------------------------------------------------------------------
# Evidence reference
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceRef:
    """A bounded, safe projection of evidence for a finding.

    Stores a *reference* to where the evidence lives (snapshot_id, gpo_id,
    file path, field path) plus a *safe projection* — a short string
    fragment that is safe to display without exposing secrets.

    Never stores raw credentials, cpassword values, or full SDDL strings.
    """

    snapshot_id: int
    gpo_id: str
    source: str  # e.g. "gpp_xml", "registry_pol", "delegation", "sddl"
    field_path: str  # dotted path to the evidence field
    safe_projection: str  # truncated, masked, or summarized evidence text


# ---------------------------------------------------------------------------
# Finding candidate — emitted by detectors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingCandidate:
    """One finding emitted by a lifecycle-aware detector.

    The stable fingerprint is a versioned digest over canonical fields
    (Plan 024 §4):

    - ``fingerprint_version``
    - ``detector_id``
    - ``subject_type`` + complete ``subject_key``
    - sorted identity-bearing ``dimensions``
    - comparator series identity, when contextual

    Severity, prose, remediation, and evidence location are **not**
    fingerprint fields — they can change between observations without
    breaking identity.
    """

    detector_id: str
    detector_version: str
    category: str
    severity: str
    subject_type: str
    subject_key: tuple[str, ...]
    dimensions: tuple[tuple[str, str], ...] = ()
    summary: str = ""
    detail: str = ""
    evidence_refs: tuple[EvidenceRef, ...] = ()
    claim: ClaimLevel = "confirmed"
    remediation: str = ""
    compliance: tuple[tuple[str, str], ...] = ()
    gpo_name: str = ""
    comparator_series: str = ""
    """Non-empty for contextual findings; identifies the comparator series
    (e.g. baseline digest + version). Different comparator = different series.
    """

    subject_stable: bool = True
    """False when the candidate has no stable subject to key identity on.

    The adapter sets this when a finding carries neither a ``gpo_id`` nor a
    declared ``subject_key``, leaving the prose summary as the only available
    subject. Such a finding's fingerprint changes whenever the wording does,
    so it cannot be tracked — or acknowledged — across snapshots. Plan 024 §4
    calls this ``snapshot_scoped``; the queries surface that state rather than
    presenting a churning identity as a genuine new/persisting finding.

    Defaults True: a detector that declares a subject is the normal case.
    """


# ---------------------------------------------------------------------------
# Fingerprint computation
# ---------------------------------------------------------------------------

FINGERPRINT_VERSION: int = 1


def compute_fingerprint(candidate: FindingCandidate) -> str:
    """Compute a stable, deterministic fingerprint for a finding candidate.

    The fingerprint is a SHA-256 hex digest over the canonical identity
    fields defined in Plan 024 §4. It is invariant under:

    - Ordering of dimensions (sorted before hashing).
    - Changes to severity, summary, remediation, or evidence (these are
      observation-level, not identity-level).
    - Export ordering (the same finding data always produces the same key).

    The ``fingerprint_version`` is included so a future change to the
    fingerprinting algorithm starts a new lifecycle series rather than
    silently corrupting existing occurrences.
    """
    # Sort identity-bearing dimensions for ordering invariance,
    # and normalize values (strip + lowercase) for consistency.
    sorted_dims = tuple(
        sorted((k.strip().lower(), v.strip().lower()) for k, v in candidate.dimensions)
    )

    raw = json.dumps(
        {
            "v": FINGERPRINT_VERSION,
            "detector_id": candidate.detector_id.strip().lower(),
            "subject_type": candidate.subject_type.strip().lower(),
            "subject_key": tuple(s.strip().lower() for s in candidate.subject_key),
            "dimensions": sorted_dims,
            "comparator_series": candidate.comparator_series.strip().lower(),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def series_key(
    detector_id: str,
    comparator_series: str = "",
) -> str:
    """Compute the series key for a finding.

    The series key groups occurrences that belong to the same detector +
    comparator combination. Intrinsic findings share one series per
    detector; contextual findings get a separate series per comparator.
    """
    parts = [detector_id.strip().lower()]
    if comparator_series:
        parts.append(comparator_series.strip())
    return "\x00".join(parts)


# ---------------------------------------------------------------------------
# Persistence-model entities (in-memory representations of DB rows)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnalysisInput:
    """One pinned analysis input (danger rules, ADMX catalogue, etc.)."""

    id: int
    kind: str  # "danger_rules" | "admx_catalogue" | "comparator"
    canonical_digest: str  # SHA-256 of the input content
    version: str  # semantic version or "unknown"
    metadata_json: str  # bounded JSON metadata


@dataclass(frozen=True)
class EvaluationRun:
    """One evaluation execution against a snapshot."""

    id: int
    snapshot_id: int
    evaluation_kind: EvaluationKind
    detector_set_digest: str
    comparator_input_id: int | None
    application_version: str
    started_at: datetime
    completed_at: datetime | None
    status: RunStatus
    error_summary: str


@dataclass(frozen=True)
class FindingOccurrence:
    """One continuous interval of a finding from first seen until resolved."""

    id: int
    fingerprint: str
    fingerprint_version: int
    series_key: str
    detector_id: str
    detector_version: str
    category: str
    subject_type: str
    subject_key: tuple[str, ...]
    first_seen_run_id: int
    last_seen_run_id: int
    resolved_run_id: int | None
    predecessor_id: int | None


@dataclass(frozen=True)
class FindingObservation:
    """Presence or absence of a finding in one evaluation run."""

    run_id: int
    occurrence_id: int
    severity: str
    summary: str
    evidence_json: str
    claim_level: ClaimLevel
    remediation: str
    compliance_json: str


@dataclass(frozen=True)
class TriageEvent:
    """One append-only triage event about an occurrence."""

    id: int
    occurrence_id: int
    action: TriageAction
    actor: str
    occurred_at: datetime
    note: str
    rationale: str
    expires_at: datetime | None
    supersedes_event_id: int | None


@dataclass(frozen=True)
class TriageStatus:
    """Current triage state, deterministically folded from events.

    The fold rules (Plan 024 §8):

    - Start: ``open``
    - ``acknowledged`` → ``acknowledged``
    - ``accepted_risk`` → ``accepted_risk``
    - ``reopened`` → ``open``
    - ``risk_acceptance_expired`` → ``open`` (if current was ``accepted_risk``)
    - ``risk_acceptance_revoked`` → ``open`` (if current was ``accepted_risk``)
    - ``commented`` never changes status (it's a note-only event)
    """

    status: str  # "open" | "acknowledged" | "accepted_risk"
    actor: str
    note: str
    updated_at: datetime
    expires_at: datetime | None
    rationale: str


# ---------------------------------------------------------------------------
# Query result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingView:
    """One row in the finding inbox."""

    occurrence_id: int
    fingerprint: str
    detector_id: str
    category: str
    severity: str
    summary: str
    detail: str
    remediation: str
    gpo_id: str
    gpo_name: str
    subject_type: str
    subject_key: tuple[str, ...]
    claim_level: ClaimLevel
    lifecycle_state: OccurrenceState
    triage_status: str
    triage_actor: str
    triage_note: str
    triage_expires_at: datetime | None
    first_seen_run_id: int
    last_seen_run_id: int
    resolved_run_id: int | None
    predecessor_id: int | None
    compliance: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class FindingHistory:
    """Full history of a finding occurrence across evaluation runs."""

    occurrence: FindingOccurrence
    observations: tuple[FindingObservation, ...]
    triage_events: tuple[TriageEvent, ...]


@dataclass(frozen=True)
class FindingDelta:
    """Difference between two evaluation runs."""

    new_fingerprints: tuple[str, ...]
    resolved_fingerprints: tuple[str, ...]
    persisting_fingerprints: tuple[str, ...]
    regressed_fingerprints: tuple[str, ...]


@dataclass(frozen=True)
class RiskAcceptance:
    """One active or expired risk acceptance."""

    occurrence_id: int
    fingerprint: str
    category: str
    summary: str
    severity: str
    actor: str
    rationale: str
    accepted_at: datetime
    expires_at: datetime | None
    is_expired: bool
    revoked_at: datetime | None
    revoked_by: str


# ---------------------------------------------------------------------------
# Detector adapter protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class FindingEmitter(Protocol):
    """Protocol for detectors that emit FindingCandidate records.

    A detector adapter wraps an existing detector function and converts
    its output to ``FindingCandidate`` records with declared identity
    dimensions. The adapter documents:

    - subject_key: which normalized identities distinguish findings
    - dimensions: which fields are identity-bearing vs. presentation
    - rule versioning: how detector_version changes map to lifecycle
    - evidence projection: what safe fragment to store
    - coverage requirements: when absence is meaningful
    """

    def emit(
        self,
        estate: object,
        *,
        snapshot_id: int = 0,
        admx: object | None = None,
    ) -> list[FindingCandidate]: ...
