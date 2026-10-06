# Calibration harness

Run `scripts/calibrate.py` with the project's dev and web extras installed.
Pass only the ZIP exports you intend to inspect; the harness never discovers
sample exports. Multiple archives create snapshots in the supplied order.
Resolved and unresolved principal counts come from the corresponding persisted
snapshot's `principal` rows, including when the in-memory projection omits them.

```sh
.venv/bin/python scripts/calibrate.py --out /tmp/calibration.json export.zip
```

The default JSON and stdout contain aggregate measurements and fixed source
vocabulary. Input identifiers, messages, and HTTP bodies stay private. The
self-check scans non-vocabulary string values against strings from the input
and databases. Keys, numbers, and booleans are exempt. Exact allowed string
values come mechanically from source-defined finding/rule codes, severities,
CLI commands, route declarations, `Literal`/`Enum` declarations, source warning
templates, trusted schema and exception locations, and the harness's fixed
constants (including its Microsoft CSE GUID allow-list). An allowed word within
a longer string does not exempt that string. Refusal prints a numeric field
position and writes no new report.

Use `--keep-db /tmp/calibration.sqlite3` to preserve the measured database; its
destination must not exist. The database contains estate data and survives a
self-check refusal when explicitly requested. Extracted inputs and temporary
databases are cleaned up.

For examples to guide parser and feature work, opt into a separate detail file:

```sh
.venv/bin/python scripts/calibrate.py --out /tmp/calibration.json \
  --detail --detail-out /tmp/calibration-detail.json export.zip
```

**The detail file contains estate data. Never commit or publish it.** It is
labelled accordingly, written with private temporary-file permissions, and
refused inside Git worktrees, including symlink destinations and other Git
repositories. Both detail flags are required together. All output destinations
must differ from inputs and each other. Detail content never enters the default
JSON or stdout and is written only after the sanitized self-check passes.

Each category contains at most ten examples:

- Original source warning templates with up to three observed messages each;
  unmatched warnings retain a null template.
- Interpreter resource, deprecation, pending-deprecation and import warnings
  have their own category. Sanitized warning records expose only counts under
  `interpreter_warnings`, folded to these fixed built-in classes (including
  third-party subclasses). Messages stay in private detail; these warnings
  never increment product templates or `other_warnings`.
- Extension GUIDs outside the harness allow-list and generic parser fallbacks,
  with element names and registry paths where available. An unallowlisted GUID
  alone does not prove that an extension is unsupported.
- Blocked or generically parsed settings, attributed to their extension.
- ADMX gaps and example key paths.
- Routes returning 5xx, with exception messages and structured traceback frames
  limited to `gpo_lens` source files.
- Slowest routes, with method, concrete requested URL, and elapsed time.
- Redaction leak routes and field locations, without the matched secret values.
  Non-tabular text/HTML leaks identify `response.body`.
- Empty or skipped report content, unclassified settings preserved by the
  generic parser, partially omitted GPP items, skipped-input warnings, and
  exceptions stopping an operation. Operation failures take priority within
  this category's cap.

Categories may be empty when no examples were observed or when an earlier
failure prevented a measurement. Failures remain visible in sanitized operation
statuses and exception locations. A successful harness exit means the report
passed sanitization; inspect operation statuses before treating calibration as
complete. Timings vary between runs and detail collection adds overhead.
