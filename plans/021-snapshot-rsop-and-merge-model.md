# Plan 021 — Snapshot RSoP for a principal (with an explicit merge-resolution model)

**Status:** Shipped in v0.6.3; verified 2026-10-06. Evidence: [src/gpo_lens/merge.py](../src/gpo_lens/merge.py), [tests/test_principal_resultant_boundary.py](../tests/test_principal_resultant_boundary.py).

The supported snapshot principal/token/security-gate/CSE merge model shipped; `docs/spec/wi_merge.md` and `tests/test_merge.py` define the exact contract. WMI, ILT, loopback and unsupported CSE behavior retain explicit limits; this is not live Windows RSoP.

The design below is the historical specification; this status records the verified release scope.
**Author:** Claude (Opus 4.8), from the "snapshot RSoP / merge-semantics" thread
**Strategic role:** The end state people actually want: **take a principal and
see its Resultant Set of Policy** — computed offline from a snapshot, at scale,
diffable, with *honest, bounded* caveats. This becomes feasible (not a live-bind
subsystem) once Plan 020 collects group membership: the one gate Plan 019 left
*shown but unevaluated* — security filtering — flips to *evaluated* via set
intersection over collected tokens. The remaining gates (WMI, ILT, loopback,
merge-runtime) are a small, nameable set we handle by **explicit exclusion +
listing**, never silent guessing. The killer application is the fusion with the
danger detectors (Plan 018 / `danger.py`): not "this GPO *contains* a dangerous
config" but "this dangerous config is *in force for this principal / these N
objects*." That is the jump from a finding to a prioritized one.

This plan is an **increment on 019**, not a parallel engine: same resultant
machinery, one gate evaluated, plus a per-CSE merge-resolution model.

## Hard dependencies

- **020-B (group membership)** — `group-members.json`; required to build a
  principal's token. Without it, security filtering stays *shown, not evaluated*
  (i.e. 019, not 021).
- **020-A (principal resolution)** — and `principals.json` must carry each
  principal's **`distinguishedName`**, so a principal's OU chain (hence its
  precedence chain) is derivable by walking its DN up the ingested `ou-tree`.
  This is a small addition to 020-A; record it there.
- **WI-028 (loopback mode)** — loopback changes the *user-side* resultant on the
  target computer; until the mode parser is fixed, loopback'd computers are wrong.
  Until then, loopback is treated as an explicit caveat, never silently applied.

## Charter addendum (decisions this plan records)

1. **Evaluating security filtering from collected membership is *reading*, not
   *simulating*.** It is set intersection between a principal's token SIDs and a
   GPO's Apply-Group-Policy trustees — both static, collected facts. This is the
   one place 021 crosses 019's "shown, not evaluated" line, and it is a
   deliberate, recorded decision. The MS16-072 Read+Apply predicate
   (`authz.broad_trustee_key`, fixed in WI-029) is the core of it.
2. **WMI and ILT are blanket-unevaluated by design.** We do **not** partial-eval
   them. A WMI-gated GPO (or an ILT-gated GPP item) is excluded from the
   deterministic resultant and **listed** as a conditional. Rationale: WMI/ILT
   conditions depend on runtime machine state we don't collect, *and* heavy WMI
   filtering is a discouraged anti-pattern, so the excluded set is small and
   human-reasonable. A short explicit list beats a clever, fragile estimate.
3. **Exclusion must never hide a danger.** For the resultant *value*, excluding a
   WMI/ILT-gated contributor is conservative and fine. For **danger** findings it
   is not — a dropped dangerous-but-gated GPO is a false negative. So gated
   dangerous contributors go into a **"conditional dangers — verify gate"** bucket,
   surfaced, never silently dropped (decision 2's listing requirement, applied to
   danger).
4. **Output is "resultant given collected inputs," never unqualified
   "effective."** Every result carries its caveat set (excluded WMI/ILT GPOs,
   loopback state, approximate-merge CSEs). The "evaluated" label ships only after
   lab calibration (see Validation) — the over-claim discipline from the sf2 work.
5. **A principal RSoP is per (user, computer).** A user's full resultant depends
   on the computer it logs into (computer-side policy, loopback, and post-MS16-072
   computer-context retrieval of user policy). We support: computer principal
   (self), user principal with an *optional* computer argument, and — when no
   computer is given — a clearly-labeled "user in own OU, no loopback" default.

## Phase A — Principal → token → evaluated resultant

### A.1 Build the token

From 020-B: expand the principal's transitive group membership (nested groups,
primary group, well-known groups like Authenticated Users / Domain Computers /
Users) into a set of token SIDs. Computers carry their machine SID + Domain
Computers + Authenticated Users. Record what could not be expanded (foreign
security principals, unresolved SIDs) as a token caveat.

### A.2 Resolve the precedence chain for the principal

Walk the principal's `distinguishedName` up the ingested `ou-tree` to get its
SOM chain (site + domain + OU path), then reuse `som_effective_gpos` /
`gp-inheritance` for the DC-computed, block-inheritance/enforced-resolved
candidate list. No new precedence logic.

### A.3 Evaluate the security-filter gate (the new bit)

For each candidate GPO, compute "does this principal's token intersect the GPO's
Read+Apply trustees?" reusing `security_filtering_detail` + `broad_trustee_key`,
now resolved against the *token* instead of just broad-trustee names. A GPO the
token cannot Read+Apply is dropped from the resultant (with reason). Honor the
post-MS16-072 rule: user policy is retrieved in the *computer's* context, so the
computer token must also have Read.

### A.4 Apply the merge-resolution model (Phase B) and produce the resultant

Fold the surviving candidates into the effective settings via the per-CSE model
(Phase B), not bare last-writer-wins. Output per setting: winning value, winning
GPO (provenance), what it overrode, the CSE's resolution mode, and any
approximate/conditional flag.

### A.5 Output

A principal resultant view (web + CLI `--json`): effective settings with
provenance, plus three explicit lists — **excluded (WMI/ILT-gated)**,
**approximate (merge-CSE)**, and **token caveats**. Every number is attributable
to a GPO and a rule.

### A.6 Acceptance criteria

- `AC-1` A GPO the principal's token cannot Read+Apply is absent from the
  resultant, with the exclusion reason recorded.
- `AC-2` A GPO the token *can* Apply, that is not otherwise gated, contributes
  per its CSE resolution mode.
- `AC-3` A WMI-gated GPO is excluded from the resultant **and** listed as
  conditional (decision 2); if it carries a danger, it also appears in the
  conditional-dangers bucket (decision 3).
- `AC-4` User-principal resultant with a computer argument applies computer-side
  policy + loopback (loopback gated on WI-028); without one, the default is
  labeled.
- `AC-5` Every effective value is traceable to its winning GPO and CSE rule.
- `AC-6` Output is labeled "resultant given collected inputs" with its caveat
  lists; the word "effective" appears only behind the lab-calibration gate.

## Phase B — The merge-resolution model

"Merge" is not one behavior; it is a small per-CSE table, most of it
deterministic from the snapshot. This phase encodes it.

### B.1 Per-CSE resolution mode (a table, not ad-hoc logic)

| CSE class | Resolution | Deterministic from snapshot |
| --- | --- | --- |
| Admin Templates / registry policy | last-writer-wins per value | yes (today's `settings_at_som`) |
| Scripts (startup/logon/…) | union, all run, precedence→order | yes (ordering known) |
| Restricted Groups "Members" | authoritative replace, last-writer | yes |
| Restricted Groups "Member Of" | additive | yes |
| Software Installation | accumulate | yes |
| GPP (drives/registry/files/local groups/…) | accumulate, per-item action + ILT | action: yes; ILT: blanket-excluded (decision 2) |
| IPsec / Wireless / Wired | single highest-precedence wins | yes |
| Folder Redirection | merge/replace flag, loopback-sensitive | yes if WI-028 |

The mode is keyed off the CSE (and, where relevant, a setting flag like
Restricted Groups Members-vs-MemberOf or FR merge/replace). Unknown CSEs default
to last-writer-wins **and are flagged approximate**, never silently assumed.

### B.2 GPP item action state machine

For accumulate CSEs, resolve items in precedence→order through the
Create / Replace / Update / Delete action semantics (a later Delete removes; a
later Replace supersedes; Update merges fields). Deterministic *given the items*.
This reuses the existing GPP parsing in `detection.py` (`_walk_gpp_xml`,
`scan_local_groups`, `scan_scheduled_tasks`).

### B.3 ILT as WMI (uniform handling)

Item-Level Targeting is the GPP analog of WMI: conditions on group/OS/OU are in
principle knowable, conditions on runtime state (file/registry/RAM/IP/time) are
not. Per decision 2 we do **not** partial-eval — an ILT-gated item is excluded
from the deterministic resultant and listed (and routed to conditional-dangers if
dangerous). One mechanism, shared with WMI.

### B.4 Explicitly NOT modeled (the irreducible remainder — flag, don't fake)

A short, named list, surfaced as caveats:

- **"Stop processing on error"** — a runtime failure can halt an extension; we
  model the no-error path and flag that error-stop is possible.
- **Tattooing / persistence** — GPP can leave state behind after a GPO stops
  applying. This affects *a machine's current state* (gpresult-logging
  territory), **not** "what this config applies"; out of scope, noted.
- **Slow-link / async / timing** edge cases.

These are the entire non-deterministic surface, and none of them makes the
normal-path resultant non-deterministic — they make specific items conditional.

## Phase C — Effective-danger (the killer app)

Cross the resultant (A) with the danger detectors (`danger.py`): for each danger,
report the principals / object population for which it is *in force*, not merely
present. Plus the **conditional-dangers** bucket (gated-but-not-excluded, decision
3). With 020-C population counts, this yields blast-radius-sized, prioritized
danger findings — the difference between a backlog and a worklist. Gated on A+B
and on real demand.

## Validation — the lab is the shipping gate

The over-claim risk (a wrong "does not apply" is a security blind spot) is real
and high-stakes. the homelab (`LABDOMAIN`) is the oracle that converts this from plausible
to defensible:

- Build known scenarios (controlled membership, security filtering, GPP with
  actions/ILT, scripts, Restricted Groups, loopback) in the lab.
- Run real `gpresult /h` on real machines for chosen (user, computer) pairs.
- Assert the snapshot resultant **matches** for the deterministic cases, and that
  **every divergence is exactly an item we already flag** (WMI/ILT/error-stop/
  tattooing) — proving the remainder is what we claim, not a hidden long tail.
- This calibration suite (alongside the now-live `test_calibration.py`) is the
  gate for using the "effective" label (decision 4), cross-checked against
  `gpresult`/`Get-ADObject`, never the tool's own output (WI-029 lesson).

## Non-goals

- **Live AD bind / continuous monitoring / interactive what-if.** Still a
  separate, larger initiative (Plan 019 boundary). 021 is snapshot-only.
- **WMI/ILT partial evaluation.** Blanket-excluded by decision 2.
- **Modeling error-stop / tattooing / timing.** Flagged, not faked (B.4).
- **A machine's *current* state.** That is gpresult-logging; 021 computes what the
  *config* resolves to for a principal, from a snapshot.

## Sequencing & risk

- **Strictly after 020-B** (membership) and the 020-A DN addition; **WI-028**
  before loopback is trusted.
- **Phase A is the increment** — token + security-gate eval over 019's existing
  resultant. **Phase B** (merge model) makes the resultant correct rather than
  last-writer-approximate; do A and B together (A's output is only honest with
  B's CSE modes). **Phase C** (effective-danger) is the payoff, gated.
- **Top risk is over-claim**; the mitigations are structural: never print
  "effective" un-gated, always ship the three caveat lists, and gate the label on
  lab calibration. RSoP that is quietly wrong is worse than none — the lab is what
  prevents that.
- **Anti-drift:** the principal resultant, the OU resultant (019), and `gpresult`
  must agree on shared cases; a calibration test asserts it (WI-029).
