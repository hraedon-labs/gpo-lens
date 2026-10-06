# Deterministic view exports (Plan 025 WI-6)

A view's Markdown/CSV control uses the same handler, typed query results,
normalized filters and page window as its HTML response. It does not scrape
HTML or call narration. Controls preserve query parameters, including snapshot,
comparison, search and pagination. The dossier also has ledger-only downloads;
its browser filter updates both dossier and ledger download links.

Supported web views: GPO dossier (including GPO comparison), settings ledger,
findings inbox, occurrence observations and triage history, accepted-risk
register, briefing, exact setting identity, settings search and snapshot
changelog/settings diff. Baseline/golden comparison uploads offer an output
selector before uploading: view, Markdown or CSV. All three choices consume
one computation over that upload. Comparison provenance includes a semantic
comparator digest and explicitly labels the comparison as ad hoc, because
these upload workbenches do not persist comparison evaluation runs.

Downloads require VIEW. Workflow state is visible to viewers; actor, note,
rationale and audit events require TRIAGE, consistently in HTML and exports.
This uses existing permissions and changes no IIS or loopback/token boundary.
CLI exports are authorized by the local operator's access to the database.

```bash
gpo-lens --db estate.sqlite3 export ledger --gpo-id <canonical-guid> --format csv
gpo-lens --db estate.sqlite3 export dossier --gpo-id <guid> --compare <other-guid> --format md
gpo-lens --db estate.sqlite3 export findings --lifecycle all --triage all --format md
gpo-lens --db estate.sqlite3 export occurrence --occurrence-id 1 --format csv
gpo-lens --db estate.sqlite3 export accepted-risks --as-of 2026-08-01T00:00:00Z
gpo-lens --db estate.sqlite3 export briefing --snapshot 1 --as-of 2026-08-01T00:00:00Z
gpo-lens --db estate.sqlite3 export setting --identity 'Synthetic:Value' --format md
gpo-lens --db estate.sqlite3 export diff-settings --snapshot-a 1 --snapshot-b 2 --format csv
gpo-lens --db estate.sqlite3 export baseline-diff --comparator baseline.zip --format md
```

`export --help` lists the remaining equivalents: snapshot diff, changelog,
golden diff, settings dump, two-file settings diff and who-sets. Existing
commands and their frozen `--json` envelopes are unchanged. Legacy web JSON
attachment shapes remain available; source subtrees/credentials are redacted.
The old findings/GPO CSV URLs redirect to the filtered view download.

Both formats use a common four-column schema: `section,record,field,value`.
A record number groups fields belonging to the same typed result. Nested
values use canonical JSON. Metadata is a section in the same schema, so even
an empty result includes snapshot and evaluation IDs, application/rule/ADMX/
comparator provenance, filters, coverage/scope/claim caveats and the evidence
redaction policy. Missing evaluation/ADMX provenance is explicit. Observation
history carries each run's own provenance and safe evidence references.

Fields are sorted; query record order is preserved; line endings are LF;
output is UTF-8. No generated-at timestamp is added. Persisted snapshot,
observation and triage timestamps are evidence and remain present. Time-sensitive
briefing/risk classification accepts explicit `as_of` (web) / `--as-of` (CLI)
for repeatable output; omitting it means current workflow state. New triage or
analysis changes the input and can therefore change the artifact.

Credential fields, raw Setting subtrees, source XML and full SDDL are omitted
with `[REDACTED]` markers. Credential context from the selected snapshots also
masks copied values in diffs and active filters. Workflow exports retain the
source evaluations even after a newer snapshot replaces that estate. Two-file
CLI diffs use credential context and a digest of both input files, explicitly
without claiming a persisted snapshot or evaluation run. Non-secret password policy
values (for example MinimumPasswordLength) remain visible. Markdown text is
escaped; every CSV cell beginning with `=`, `+`, `-`, `@`, tab or CR receives
a leading apostrophe for spreadsheet safety.

Rendering streams one record/line at a time; it never builds the complete
artifact or copies the full result into another output list. Query memory is
the existing typed view result plus provenance and the distinct credential
masking context. Findings pagination uses SQL and is bounded by the view's
existing limits (50 by default, up to 200 per page; `per_page=all` displays at
most 10,000 occurrences). Exports mirror that window rather than silently
claiming to contain every occurrence. Other views use their existing typed
query lists. Connections close before HTTP streaming; detached provenance is
captured in the same SQLite read transaction as the facts, so concurrent ingest
cannot relabel them with a different snapshot. CLI holds one read transaction
while streaming and opens the database with `mode=ro`.

The secret fixture corpus is defined once in `tests/conftest.py`, from the
existing synthetic cpassword carriers in `tests/fixtures` and
`tests/golden_estate`, plus a synthetic plaintext credential. HTML, API,
narration, Markdown and CSV tests consume this corpus.
