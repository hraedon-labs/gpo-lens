"""Estate doctor: run all hygiene checks and return prioritized findings."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from gpo_lens.danger import ComplianceMapping, DangerFinding, danger_findings
from gpo_lens.detection import (
    admx_gaps,
    broken_refs,
    cpassword_scan,
    dangling_links,
    deny_aces,
    disabled_but_populated,
    empty_gpos,
    enforced_links,
    excessive_writers,
    mask_cpassword,
    ms16_072_vulnerable,
    scan_ilt,
    unlinked_gpos,
    version_skew,
)
from gpo_lens.model import SEVERITY_ORDER
from gpo_lens.queries._topology import topology_crosscheck
from gpo_lens.queries._wmi import (
    broken_wmi_refs,
    orphaned_wmi_filters,
    stale_gpos,
)

if TYPE_CHECKING:
    from gpo_lens.model import AdmxResolver, Estate


@dataclass(frozen=True)
class DoctorFinding:
    """One prioritized finding from the estate doctor."""

    severity: str  # "critical", "high", "medium", "low", "info"
    category: str  # "cpassword", "ms16_072", "version_skew", etc.
    gpo_id: str
    gpo_name: str
    summary: str
    detail: str
    compliance: tuple[ComplianceMapping, ...] = ()
    remediation: str = ""
    # Declared identity dimensions for lifecycle fingerprinting (WI-089,
    # Plan 024 §4). When non-empty, these — not the prose summary/detail —
    # define the finding's identity across snapshots. Required for GPO-less
    # findings (topology, excessive writers, orphaned WMI filters, coverage
    # gaps), whose identity would otherwise key on wording and evidence
    # counts and churn on every re-scan.
    subject_key: tuple[str, ...] = ()
    # Identity-bearing dimensions for lifecycle fingerprinting (WI-1.1,
    # Plan 024 §4). Typed key/value pairs the adapter reads directly instead
    # of parsing the prose summary/detail, so rewording a finding never churns
    # its identity. Distinguishes multiple findings that share one subject
    # (e.g. a coverage gap's kind on a GPO, a deny-ACE's trustee).
    dimensions: tuple[tuple[str, str], ...] = ()


_SEVERITY_ORDER = SEVERITY_ORDER


def estate_doctor(
    estate: Estate,
    *,
    now: datetime | None = None,
    admx: AdmxResolver | None = None,
    danger: list[DangerFinding] | None = None,
) -> list[DoctorFinding]:
    """Run all hygiene checks and return prioritized findings.

    *now* is forwarded to the staleness check; tests pin it so the stale-GPO
    finding stays deterministic as wall-clock time advances.

    *danger* lets a caller that already computed ``danger_findings()`` pass
    the list in, avoiding a redundant re-evaluation (WI-031).
    """
    findings: list[DoctorFinding] = []

    for gpo in estate.gpos:
        legacy_reported = False
        for setting in gpo.settings:
            note = str(setting.raw.get("source_note") or "")
            category = ""
            if setting.raw.get("cse_parser") == "legacy_deprecated" and not legacy_reported:
                category = "legacy_extension"
                legacy_reported = True
            elif setting.raw.get("audit_disagreement"):
                category = "audit_source_disagreement"
            elif setting.cse == "Advanced Audit Configuration" and note:
                category = "audit_parse_warning"
            elif setting.cse == "Public Key" and note:
                category = "pki_parse_warning"
            if category:
                evidence_kind = (
                    "Public Key" if category == "pki_parse_warning" else "Advanced audit"
                )
                findings.append(
                    DoctorFinding(
                        severity="info" if category == "legacy_extension" else "low",
                        category=category,
                        gpo_id=gpo.id,
                        gpo_name=gpo.name,
                        summary="Legacy, deprecated Internet Explorer Maintenance extension"
                        if category == "legacy_extension"
                        else f"{evidence_kind} evidence: {setting.display_name}",
                        detail=note,
                        dimensions=()
                        if category == "legacy_extension"
                        else (("side", setting.side), ("identity", setting.identity)),
                    )
                )

    _COVERAGE_SUMMARY = {
        "inaccessible": "GPO could not be collected — estate analysis is incomplete",
        "missing_sysvol": ("No SYSVOL collected — GPP/cPassword detectors are BLIND, not clean"),
        "unreadable_sysvol": "GPP content unreadable — estate view is partial",
    }
    for cov in estate.coverage_gaps:
        findings.append(
            DoctorFinding(
                # A missing SYSVOL silently zeroes a critical detector (cPassword),
                # so it outranks an ordinary per-GPO collection gap.
                severity="critical" if cov.kind == "missing_sysvol" else "high",
                category="coverage_gap",
                gpo_id=cov.gpo_id,
                gpo_name=cov.display_name or "(estate)",
                summary=_COVERAGE_SUMMARY.get(
                    cov.kind,
                    "GPO collection failed — estate analysis may be incomplete",
                ),
                detail=cov.detail,
                subject_key=(cov.kind, cov.gpo_id),
                dimensions=(("kind", cov.kind),),
            )
        )

    for hit in cpassword_scan(estate):
        findings.append(
            DoctorFinding(
                severity="critical",
                category="cpassword",
                gpo_id=hit.gpo_id,
                gpo_name=hit.gpo_name,
                summary=f"cpassword in {hit.file} <{hit.tag}> (MS14-025)",
                detail=f"Encrypted password found: {mask_cpassword(hit.cpassword)}",
            )
        )

    for g in ms16_072_vulnerable(estate):
        findings.append(
            DoctorFinding(
                severity="high",
                category="ms16_072",
                gpo_id=g.id,
                gpo_name=g.name,
                summary="Missing Authenticated Users / Domain Computers Read (MS16-072)",
                detail="GPO may silently stop applying after MS16-072 patch",
            )
        )

    for g, side in version_skew(estate):
        if side == "Computer":
            ds_ver = g.computer_ver_ds
            sysvol_ver = g.computer_ver_sysvol
        else:
            ds_ver = g.user_ver_ds
            sysvol_ver = g.user_ver_sysvol
        findings.append(
            DoctorFinding(
                severity="medium",
                category="version_skew",
                gpo_id=g.id,
                gpo_name=g.name,
                summary=f"{side} version skew (GPC != GPT)",
                detail=f"DS={ds_ver}, SYSVOL={sysvol_ver}",
                dimensions=(("side", side),),
            )
        )

    for som, link in dangling_links(estate):
        findings.append(
            DoctorFinding(
                severity="medium",
                category="dangling_link",
                gpo_id=link.gpo_id,
                gpo_name="<missing>",
                summary=f"Dangling link at {som.name}",
                detail=f"SOM {som.path} links to missing GPO {link.gpo_id}",
            )
        )

    for d in topology_crosscheck(estate):
        findings.append(
            DoctorFinding(
                severity="medium",
                category="topology_discrepancy",
                gpo_id="",
                gpo_name="",
                summary=f"{d.kind}: {d.ou_dn}",
                detail=d.detail,
                subject_key=(d.kind, d.ou_dn),
            )
        )

    for g, side in disabled_but_populated(estate):
        findings.append(
            DoctorFinding(
                severity="low",
                category="disabled_but_populated",
                gpo_id=g.id,
                gpo_name=g.name,
                summary=f"{side} side disabled but has settings",
                detail=(
                    f"{sum(1 for s in g.settings if s.side == side)}"
                    f" settings on disabled {side} side"
                ),
                dimensions=(("side", side),),
            )
        )

    for ref in broken_refs(estate):
        findings.append(
            DoctorFinding(
                severity="low",
                category=f"broken_ref:{ref.ref_type}",
                gpo_id=ref.gpo_id,
                gpo_name=ref.gpo_name,
                summary=ref.detail,
                detail=ref.ref_value,
                dimensions=(("ref_value", ref.ref_value),),
            )
        )

    gaps_by_gpo: dict[str, list[str]] = {}
    for gap in admx_gaps(estate, admx):
        gaps_by_gpo.setdefault(gap.gpo_id, []).append(f"{gap.side}/{gap.identity}")
    for gpo_id, settings in sorted(gaps_by_gpo.items()):
        gpo = estate.gpo_by_id(gpo_id)
        findings.append(
            DoctorFinding(
                severity="low",
                category="admx_gap",
                gpo_id=gpo_id,
                gpo_name=gpo.name if gpo else "",
                summary=f"{len(settings)} registry settings without a loaded ADMX template",
                detail="\n".join(sorted(settings)),
                dimensions=(("aggregation", "gpo"),),
            )
        )

    for g in unlinked_gpos(estate):
        findings.append(
            DoctorFinding(
                severity="info",
                category="unlinked",
                gpo_id=g.id,
                gpo_name=g.name,
                summary="GPO has no links (applies nowhere)",
                detail="",
            )
        )

    for g in empty_gpos(estate):
        findings.append(
            DoctorFinding(
                severity="info",
                category="empty",
                gpo_id=g.id,
                gpo_name=g.name,
                summary="GPO has no settings on either side",
                detail="",
            )
        )

    for som, link in enforced_links(estate):
        findings.append(
            DoctorFinding(
                severity="info",
                category="enforced_link",
                gpo_id=link.gpo_id,
                gpo_name="",
                summary=f"Enforced link at {som.name} (order {link.order})",
                detail=f"Target: {link.target}",
                dimensions=(
                    ("som_path", som.path),
                    ("order", str(link.order)),
                    ("target", link.target),
                ),
            )
        )

    for da in deny_aces(estate):
        trustee_display = da.trustee_name or da.trustee_sid
        findings.append(
            DoctorFinding(
                severity="medium",
                category="deny_ace",
                gpo_id=da.gpo_id,
                gpo_name=da.gpo_name,
                summary=f"Deny ACE: {trustee_display} ({da.rights})",
                detail=f"Trustee SID: {da.trustee_sid}"
                + (f"; Flags: {da.flags}" if da.flags else ""),
                dimensions=(("trustee_sid", da.trustee_sid),),
            )
        )

    for w in excessive_writers(estate):
        trustee_display = w.trustee_name or w.trustee_sid
        findings.append(
            DoctorFinding(
                severity="medium",
                category="excessive_writer",
                gpo_id="",
                gpo_name="",
                summary=f"{trustee_display} has write access to {w.gpo_count} GPOs",
                detail=f"Trustee SID: {w.trustee_sid}; Rights: {', '.join(w.rights)}; "
                f"GPOs: {', '.join(w.gpo_names[:10])}",
                subject_key=(w.trustee_sid,),
            )
        )

    for wref in broken_wmi_refs(estate):
        findings.append(
            DoctorFinding(
                severity="medium",
                category="broken_wmi_ref",
                gpo_id=wref.gpo_id,
                gpo_name=wref.gpo_name,
                summary=f"WMI filter '{wref.filter_name}' not found in estate",
                detail="GPO references a WMI filter absent from wmi-filters.json",
            )
        )

    for wf in orphaned_wmi_filters(estate):
        findings.append(
            DoctorFinding(
                severity="low",
                category="orphaned_wmi_filter",
                gpo_id="",
                gpo_name="",
                summary=f"Orphaned WMI filter: {wf.name}",
                detail=f"Defined but referenced by zero GPOs. Query: {wf.query}",
                subject_key=(wf.name,),
            )
        )

    for ilt in scan_ilt(estate):
        findings.append(
            DoctorFinding(
                severity="low",
                category="ilt_gpo",
                gpo_id=ilt.gpo_id,
                gpo_name=ilt.gpo_name,
                summary=f"Item-level targeting in {', '.join(ilt.files)}",
                detail=f"Filter types: {', '.join(ilt.filter_types)}",
            )
        )

    for sg, years in stale_gpos(estate, now=now):
        findings.append(
            DoctorFinding(
                severity="info",
                category="stale_gpo",
                gpo_id=sg.id,
                gpo_name=sg.name,
                summary=f"Stale: modified {years}+ years ago and still linked",
                detail=f"Last modified: {sg.modified.isoformat() if sg.modified else 'unknown'}",
            )
        )

    for df in danger if danger is not None else danger_findings(estate, admx=admx):
        findings.append(
            DoctorFinding(
                severity=df.severity,
                category=f"danger:{df.check_id}",
                gpo_id=df.gpo_id,
                gpo_name=df.gpo_name,
                summary=df.title,
                detail=f"{df.detail} [ref: {df.reference}]",
                compliance=df.compliance,
                remediation=df.remediation,
            )
        )

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.category, f.gpo_id))
    return findings
