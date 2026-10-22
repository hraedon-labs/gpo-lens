# Design — Per-user RSoP: principal-group effective policy (the honest middle tier)

**Status:** design draft  
**Author:** coding agent, from the "flag, don't simulate" RSoP boundary review  
**Scope:** deterministic core (`merge`, `topology`, `queries`, CLI/web presentation)  
**Related work items:** WI-028 (loopback mode parser), WI-051 (user+computer chain deduplication)  

## Strategic role

The project charter says *flag, don't simulate*: topology resolution is
OU-level, never object-level. Plan 019 extended that honesty to per-candidate
gate attribution. Plan 021 then built a real, bounded resultant for a principal
from a snapshot by evaluating **security filtering** against collected AD group
membership. That code already ships in `merge.principal_resultant`, but the
*design* was never written down as a boundary statement. This document does
that. It defines the middle tier the project occupies: "principal-group
effective policy", which is more than "gates shown but not evaluated" and less
than "true per-object RSoP". Naming the tier makes the tool's claims auditable
and its caveats legible.

## Ground truth at time of writing

The deterministic core already implements the building blocks:

- **`merge.build_token(estate, principal_sid)`** expands a principal's
  transitive group membership (`estate.group_members`) into a `PrincipalToken`,
  adding well-known SIDs and domain-relative groups (Domain Users / Domain
  Computers). Unresolved foreign SIDs become `token_caveats`.
- **`merge.principal_resultant(...)`** composes the full resultant: token
  expansion, OU-chain resolution from a DN, security-filter gate evaluation
  against the token, per-CSE merge-resolution, and explicit exclusion of
  WMI/ILT-gated contributors. It returns `PrincipalResultant` with `settings`,
  `excluded`, `excluded_settings`, `conditional_dangers`, `token_caveats` and a
  `caveat_summary`.
- **`topology.scope_caveats(estate, som_path)`** emits the aggregated caveats
  for security filtering, WMI, ILT, loopback, site links and disabled sides.
- **`topology.effective_scope(...)`** gives a per-GPO scoping view: explicit
  Apply trustees, WMI filters, loopback mode and ILT presence.
- The collector already produces `principals.json` (SID → name/type) and
  `group-members.json` (group SID → member SIDs), because Plan 020 collected
  group membership for delegation resolution and dead-group detection.

What was **missing** is the design-level contract: *what exactly is simulated,
what is not, and why this is an honest middle tier and not a charter
violation.* The code and UI say "resultant given collected inputs"; this
document says what that sentence means.

## Charter addendum (decisions this design records)

1. **Principal-group effective policy is in charter.** Evaluating
   security-filter SIDs against collected AD group membership *reads collected
   facts*; it does not simulate Windows client behavior. Both sides of the
   intersection (token SIDs and Apply-Group-Policy trustee SIDs) come from the
   static export. This is the one gate that moves from "shown" to "evaluated".
2. **It is still not object-level RSoP.** The tool does not resolve per-machine
   WMI state, per-item ILT conditions, primary-group nuances or deny-ACE
   interactions with the full token, and loopback is best-effort only. Those
   remain caveats.
3. **Output stays labeled.** Result objects and UI never use the word
   "effective" without the "given collected inputs" qualifier. The label
   changes only after lab calibration (see Plan 021 validation).
4. **Exclusion must never hide a danger.** GPOs or settings excluded because of
   an unevaluated gate flow into `conditional_dangers` when they carry
   dangerous configurations (Plan 018). A gated dangerous setting is still
   surfaced.
5. **User+computer pairs are first-class.** A user's full resultant needs the
   computer token (post-MS16-072 Read behavior). The API already accepts an
   optional `computer_sid` and `computer_dn`; this design endorses that shape.

## What IS simulated

These mechanisms produce deterministic output from the snapshot:

- **Security-filter SID resolution.** A principal's expanded token (SID + nested
and well-known group SIDs) is intersected with the GPO's Read+Apply/Apply Group
Policy trustees. If the token matches, the GPO enters the candidate set.
- **GPO apply/deny from security filtering.** GPOs whose Apply list does not
intersect the token are excluded from the deterministic resultant with a reason.
- **OU-chain precedence merge.** Applicable GPOs are merged according to the
DC-computed `gp-inheritance` order, with block-inheritance and enforced already
resolved by the collector.
- **Per-CSE merge semantics.** The merge-resolution model in `merge.py`
(LAST_WRITER_WINS, UNION, AUTHORITATIVE_REPLACE, ACCUMULATE for GPP actions,
SINGLE_WINNER, etc.) determines surviving values.
- **Disabled-side exclusion.** Settings from a disabled Computer/User side are
not merged (they are surfaced separately as disabled-but-populated findings).

## What is NOT simulated (the caveat banner)

These are surfaced explicitly in every result, never silently assumed:

- **Loopback processing (partly).** The merge/replace mode changes which
  user-side settings apply on affected computers. `principal_resultant` applies
  it best-effort (WI-028): in replace mode the computer chain is the sole source
  of User-side settings, and in merge mode both chains contribute with the
  computer chain winning conflicts. `mixed` and `unknown` modes, and WMI/ILT on
  computer-chain user-side GPOs, are not simulated; they fall back to the
  non-loopback path with a caveat.
- **WMI filter evaluation.** A WMI filter name and query are collected and
attached, but the query is not evaluated against any actual machine state. A
WMI-filtered GPO is excluded and listed as conditional.
- **Item-level targeting (ILT).** GPP per-item conditions (group, OS, OU,
registry/file/RAM/IP/time) are not evaluated. ILT-gated GPP items are excluded
and listed as `excluded_settings`.
- **AD-site membership.** Site SOMs exist as a parallel scoping axis, but the
per-machine AD site is not resolved. Site-linked GPOs are flagged, not folded
into the deterministic chain.
- **Deny-ACE interaction with the full token.** Deny ACEs within a GPO's own
security descriptor are honored for that GPO's Apply set (the existing
security-gate already does this). Broader deny ACE interactions across the token
cannot be fully evaluated against partial collection.
- **Primary-group and foreign-security-principal edge cases.** Token expansion
uses collected membership; any unresolvable SIDs are recorded as caveats.

## Data flow

```text
principal SID
   ↓
build_token(estate, principal_sid) → PrincipalToken
   ↓
for each GPO in the principal's OU-chain precedence:
   ├─ evaluate_security_gate(GPO, token_sids) → applies / excluded + reason
   ├─ if computer_sid given: include computer token in gate evaluation
   └─ if WMI/ILT gated: exclude and record as conditional
   ↓
applicable GPOs → merge_settings_with_exclusions(chain_entries)
   ↓
PrincipalResultant {
   settings, excluded, excluded_settings,
   conditional_dangers, token_caveats, caveat_summary
}
```

The flow reuses existing functions: `build_token`, `_evaluate_security_gate`,
`som_effective_gpos` (chain resolution), `merge_settings_with_exclusions`, and
`scope_caveats` for presentation. New work is largely documentation, tests, and
thin presentation glue.

## What already exists vs. what is new

Already exists:

- Token construction and transitive group expansion (`merge.build_token`).
- Security-filter evaluation (`merge._evaluate_security_gate`).
- Per-CSE merge-resolution (`merge.cse_merge_mode`, `merge.merge_settings_with_exclusions`).
- Conditional-danger surfacing (`merge._build_conditional_dangers`).
- OU-chain resolution (`topology.som_effective_gpos`).
- Scoping caveats (`topology.scope_caveats`, `topology.effective_scope`).

What this design adds:

- A formal contract document that names the middle tier.
- Acceptance criteria that lock the boundary:
  simulated mechanisms + non-simulated mechanisms + caveat coverage.
- UI/CLI affordance: a persistent caveat banner on every principal resultant
  view listing the non-simulated mechanisms.
- Test fixtures and calibration cases that prove the simulated part matches
  `gpresult` on simple cases and that every divergence is a listed caveat.

## Acceptance criteria

- **AC-1** A test fixture with a user in a group that is security-filtered on a
GPO produces that GPO's settings in the principal's `PrincipalResultant.settings`.
- **AC-2** A test fixture with a user whose token does **not** intersect a GPO's
Apply trustees excludes that GPO with reason `"security filter: token does not
intersect Apply trustees"`.
- **AC-3** A GPO with an attached but unevaluated WMI filter is excluded from the
deterministic `settings` list and appears in `excluded` with kind `wmi_filter`.
- **AC-4** An ILT-gated GPP item is excluded from `settings` and appears in
`excluded_settings` with kind `ilt`.
- **AC-5** Every `PrincipalResultant` carries a non-empty `caveat_summary`
containing the "given collected inputs" qualifier and counts of excluded /
conditional / approximate items.
- **AC-6** When a computer SID is supplied for a user principal, the computer
side of the computer's OU chain is merged and loopback state is surfaced in the
caveat summary (not silently applied). The original draft required that
loopback never be applied; the code now applies it best-effort (see "What is
NOT simulated").
- **AC-7** A dangerous configuration inside a gated (WMI/ILT/security-filter)
GPO appears in `conditional_dangers`, never in `settings`.
- **AC-8** The UI and CLI never render the word "effective" without the adjacent
"given collected inputs" label.
- **AC-9** A principal whose token cannot be fully expanded (foreign / unresolved
SIDs) carries those unresolved SIDs in `token_caveats`.
- **AC-10** Lab calibration: for at least two known (user, computer) pairs in
LABDOMAIN, the snapshot resultant matches `gpresult /h` on all deterministic
settings, and every divergence is exactly one of the listed non-simulated
caveats.

## Tests & validation

- Unit tests in `tests/test_merge.py` for token/gate/merge behavior using
synthetic fixtures (no real domain identifiers).
- A new `tests/test_principal_resultant_boundary.py` that asserts each AC above,
especially the caveat banner contents.
- Calibration additions in `test_calibration.py` against LABDOMAIN `gpresult`
exports, following the WI-029 cross-check discipline (external oracle, never the
tool's own output).

## Non-goals

- True object-level RSoP (per-user security/WMI/loopback simulation). The
charter still forbids that. This design stops at principal-group effective
policy.
- Live AD bind or continuous monitoring. Inputs remain static export files.
- Partial WMI/ILT evaluation. Blanket exclusion keeps the result conservative.
- Modeling deny-ACE interactions across the entire token. Only per-GPO
Apply-trustee deny precedence is evaluated.
- Changing the output label to unqualified "effective" before lab calibration.

## Sequencing & risk

- **Effort:** small. Principal work is documentation, tests, and presentation;
the core computation already exists in `merge.py`.
- **Risk:** low. No new AD bind, no import-boundary crossing, no data-model
changes. The main risk is over-claim in documentation or UI; AC-8 and the
caveat banner mitigate it.
- **Suggested sequencing:** ship this document alongside a test + UI caveat pass,
not as a code refactor. It can land in any v1.x release once the tests are
passing.
- **Dependencies before trusting the user+computer path:** WI-028 (loopback mode
  parser) and confirmation that the WI-051 deduplication logic handles
  double-chain collection correctly.
