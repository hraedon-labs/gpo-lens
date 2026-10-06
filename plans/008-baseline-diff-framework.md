# Plan 008 — Baseline Diff Framework (Tier 2)

**Status:** Superseded by GPO-backup baseline comparison (shipped by v0.1.0); verified 2026-10-06. Evidence: [src/gpo_lens/queries/_baseline.py](../src/gpo_lens/queries/_baseline.py), [tests/test_cli_diff.py](../tests/test_cli_diff.py).

The custom JSON/YAML rule-file design and `baseline` command were not implemented. The product loads Microsoft baseline backup ZIPs through `ingest.load_baseline_from_zip` and exposes `baseline-diff` instead.

The design below is the historical specification; this status records the verified release scope.

## Context

Tier 1 hygiene queries (unlinked, empty, conflicts, version skew, MS16-072,
cpassword, disabled-but-populated, blocked extensions) are complete.

The next tier in the charter is **baseline diff**: comparing the estate against
a known-good reference state, starting with the Microsoft Security Baseline.

This plan defines the *framework* — not a complete mapping. A framework that can
carry one baseline can carry any baseline; the mapping is the per-baseline
artifact.

## Requirements

### R1. Baseline artifact format

A JSON or YAML file consumed at *run time* (not compiled in). Each baseline
record maps a setting identity to an expected value:

```json
{
  "baseline": "Microsoft Security Baseline – Windows Server 2022",
  "source_url": "https://...",
  "rules": [
    {
      "id": "MSFT-2022-001",
      "title": "Account lockout threshold",
      "cse": "Security",
      "identity": "Account Lockout:LockoutBadCount",
      "expected_value": "5",
      "severity": "high"
    }
  ]
}
```

The `identity` matches exactly against `Setting.identity` as produced by the
Tier-1 ingest (Security CSE: `Type:Name`).

### R2. `baseline_diff(estate, baseline_path) -> list[BaselineDeviation]`

Dataclass:
- `rule_id`, `title`, `cse`, `identity`, `expected_value`, `actual_value`,
  `gpo_name`, `severity`, `status` ("missing", "wrong_value", "extra")

Three outcomes per rule:
1. **missing** — no setting with that identity exists anywhere in the estate
2. **wrong_value** — exists, but `display_value != expected_value`
3. **extra** — a GPO sets it, but the rule says it shouldn't be configured at all
   (optional; depends on baseline schema version)

### R3. CLI wiring

`gpo-lens baseline <baseline.json> [src]`

Respects `--json`. If run without a baseline file, prints the baseline spec
(where to get one, how to build your own).

### R4. Baseline mapping as external data

Do NOT ship a full Microsoft baseline in the repo (copyrighted content). Instead:
- Document the expected format
- Provide a script/link showing how to generate one from a GPO backup using the
  existing ingest path
- Ship a `samples/baseline-example.json` with 5 synthetic rules so the feature
  is testable without a real baseline

## Why this is gated

The **hard part** is the crosswalk: ADMX policy name ↔ registry key ↔ CIS
recommendation ↔ Microsoft baseline rule. That is research, not code. The code
is trivial once the mapping exists. This plan defines the contract so the
research can happen in parallel.

## Out of scope

- ADMX resolution (Extra Registry Settings → friendly policy names)
- CIS Controls cross-mapping
- Auto-generation of baselines from GPO backups
- Commercial baseline ingestion

## Files to touch

- `src/gpo_lens/baseline.py` (new module)
- `src/gpo_lens/cli.py` (subcommand)
- `tests/test_baseline.py` (unit tests with synthetic baseline)
- `docs/baseline-format.md` (contract for mapping authors)

## Acceptance

Synthetic baseline produces deterministic deviations against the lab domain.
All tests pass. `ruff` and `mypy` clean.
