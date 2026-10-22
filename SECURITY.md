# Security policy

## About this tool

gpo-lens is a **defensive, local-first, read-only** Group Policy analyzer. It
ingests *copies* of a GPO estate (collector exports or ZIPs) and reports
hygiene findings, dangerous configurations and estate structure. The Python
application never connects to or writes to Active Directory, Group Policy or
SYSVOL. The PowerShell collector that produces its inputs runs on a domain
controller or RSAT host and is read-only by design. The deterministic core has
no AI in the truth path; the optional narration layer only explains facts the
core computed.

## Reporting a vulnerability

Report security issues **privately**, not as a public issue:

- Email: **plm@hraedon.com**
- Or open a private vulnerability report via GitHub's
  [Security Advisories](https://github.com/hraedon-labs/gpo-lens/security/advisories/new).

Include the affected version (`gpo-lens --version` or the release tag), the
Python version, a reproduction, and the expected and actual behavior. Attach
any proof of concept or sample export as a file, and **sanitize real estate
data first** (domain names, GPO names, OU paths, SIDs, account names). Never
send a real `cpassword` value or an unsanitized SYSVOL copy.

The target is to acknowledge within 72 hours. Disclosure is coordinated: it
follows the release of a fix.

## Supported versions

Security fixes land on `main` and ship in the next release. Only the latest
release is supported. Upgrade before reporting where you can.

| Version | Supported |
|---------|-----------|
| Latest release (currently v1.5.0) | Yes |
| Any older release | No — upgrade to the latest release |
| Unreleased `main` / release candidates | Report findings against them; run a release in production |

## What counts as a vulnerability

In scope — vulnerabilities in gpo-lens itself, including:

- **A false all-clear**: gpo-lens reports an estate, GPO or setting as clean
  (or omits a finding, coverage gap or caveat it documents that it raises) when
  the export contains the condition. A silent under-report of a cpassword,
  MS16-072 exposure, dangerous configuration or coverage gap is a security bug.
- **Presenting a partial estate as complete**, or claiming object-level RSoP
  the tool does not compute (see the "Flag, don't simulate" rules in
  `AGENTS.md`).
- Path traversal, symlink, decompression-bomb or resource-exhaustion issues in
  directory or ZIP ingest; XML parser abuse (entity expansion, external
  entities) on a malformed or hostile export.
- Injection in rendered output: HTML/script injection in the web UI, formula
  injection in CSV exports, Markdown/HTML injection in reports.
- Leakage of estate data: credentials or secrets (including `cpassword`
  values) appearing unredacted in web pages, exports, logs, narration payloads
  or error messages; database or audit files readable by other local users.
  Since schema v11 every `cpassword` value is redacted at ingest (no hash is
  kept), so any `cpassword` value or copy found in a database, `-wal`/`-journal`
  file, event payload or finding is a vulnerability, not a known limitation.
  Operator-supplied text (triage notes, Ask questions, forwarded user names)
  is refused rather than redacted (see
  [Credentials in analyst-typed text](#credentials-in-analyst-typed-text)); a
  path that stores or sends such text without the guard, or a miss outside the
  limits documented there, is in scope.
- Web access-control bypass: Host allow-list, CSRF, loopback-trust, bearer
  token or permission checks that can be evaded.
- Narration egress beyond what is documented (estate strings reaching the LLM
  endpoint on a path that promises only signed numeric facts).
- **The PowerShell collector mutating anything** in Active Directory, Group
  Policy or SYSVOL. It is read-only by design; a write is a critical bug.
  Report it the same way.

Out of scope (welcome as regular issues):

- The Group Policy misconfigurations gpo-lens *detects*. Those are findings in
  your estate, not gpo-lens bugs.
- Deployments that ignore the documented access boundary, for example a
  non-loopback listener without the documented reverse proxy, authentication
  and `GPO_LENS_ALLOWED_HOSTS` configuration (see
  [`deploy/README.md`](deploy/README.md#access-boundary)).
- Behavior of a custom collector script supplied with `-CollectorPath`, or of
  the configured third-party LLM endpoint.
- Findings that require an attacker who already controls the analysis host
  account that owns the database.

## Credentials in analyst-typed text

Ingest redacts every `cpassword` value and keeps no hash or fingerprint of one,
so nothing at rest can recognise a value an operator types or pastes later. The
paths below that store or send operator-supplied text pass one guard,
`gpo_lens.analyst_text.check_analyst_text`. It **refuses** the text and never
rewrites it:

| Path | Stored or sent | On refusal |
|------|----------------|------------|
| Web triage form (`POST /findings/{id}/triage`) and `findings.triage_finding` / `append_triage_event` | `finding_triage_event.note`, `.rationale`, `.actor` (append-only) | `400` with the reason; nothing written; `audit.log` records `triage` / `refused` with the field name. The form keeps the draft in place (a script submits it without leaving the page; without JavaScript the browser shows the 400 page). |
| Web Ask (`POST /ask`) | the `audit.narrate` event, and the model provider | `400` page with the reason and an empty question box; the model is not called; the event records `"question": ""`, outcome `refused` |
| CLI `ask` | the model provider | exit 1, reason on stderr, model not called |
| CLI `explain-setting` (model fallback) | the model provider | exit 1, reason on stderr, model not called |
| Forwarded-user header (`GPO_LENS_FORWARDED_USER_HEADER`) | becomes the principal name: triage `actor`, the `principal` of audit events, `audit.log` | the name must be an account name (`user`, `user@domain` or `DOMAIN\user`; the domain may contain inner spaces such as `NT AUTHORITY`, and the user part `@` as a SAM account name can; at most 256 characters; each part non-empty with no leading or trailing space; none of the characters AD forbids in an account name, `"/\[]:;|=,+*?<>`; no whitespace but the plain space; no control, format, line- or paragraph-separator character, Unicode categories Cc/Cf/Zl/Zp/Cs/Co) with no cpassword material, or the request is refused with `401`. Only outer spaces and tabs are trimmed; nothing else is stripped. The value is never echoed |
| Event log (`events.append_event` / `append_events`) | `payload.question` of `audit.narrate`, `payload.principal` of every event | `CpasswordInAnalystTextError`; nothing written (defence in depth behind the rows above) |
| `audit.log` | the principal name | a name carrying cpassword material is written as `[refused principal name]` (defence in depth) |

The refusal names the field and the reason ("looks like it contains a Group
Policy Preferences cpassword; remove it — the value is a recoverable
credential…"), never the value or any part of it. Callers check what they
store or send plus 1,024 characters past a truncation point
(`analyst_text.checked_slice`). A value cut by the 2,000-character note limit
is therefore still refused, and the work per request stays bounded. Text beyond
that is discarded, never stored.

`tests/test_analyst_text_guard.py` keeps a static inventory of write paths and
request sources: SQL writes to the triage tables and the event log, dynamic SQL,
`append_event` call sites and their payload keys, model calls, declared web
inputs (`Form`/`File`/`Body`/`Header`/`Query`/`Cookie`), POST-route parameters,
raw `headers`/`cookies`/`query_params` reads and request body reads. Each must
be guarded field by field before its sink, or classified with a reason, or the
test fails. A writer that truncates must guard each field both before and after
the truncation. Removing the only guard for a field, or either stage of a
truncating writer, fails the test; other redundant guards are not individually
required. The test is a heuristic, not dataflow analysis. Its blind spots (SQL
assembled outside string literals, values renamed before a sink, sinks reached
through helpers, new tables nobody listed, writes outside SQLite/events/
`audit.log`/model calls) are listed in the test. gpo-lens does not store search
terms and filters, but they appear in URLs, so a reverse proxy's access log may
record them. The app cannot refuse them.

**What is refused.** (a) A labelled cpassword in any form the ingest redactor
recognises: `cpassword="…"`, `cpassword: …`, escaped quotes (`\"`, `&quot;`),
any casing, JSON keys (including `\u` escapes), `<cpassword>` elements, the
word split across XML nodes, character references. `cpassword=""` and the
redaction marker carry no value and pass. (b) An unlabelled token with the
shape the ingest copy chaser uses (`redaction.ciphertext_shaped`: base64 of
whole 16-byte AES blocks, at least 22 characters, after removing whitespace,
mapping URL-safe base64 to standard and stripping `=` padding). Tokens are also
tried wrapped across lines — a token ending a line, joined with following
one-token lines and with the token that starts the next line, so prose may come
before and after the value — and between `-`, `_` and `/` inside a token
(`pw-<value>`, `/var/<value>/x`). A candidate is let through when it has a shape
Windows-written ciphertext cannot have: pure hex; one letter case only;
non-canonical base64 (unused bits of the last character set); base64 that
decodes to printable ASCII or to at least a quarter NUL bytes (UTF-16 text,
e.g. a PowerShell `-EncodedCommand`); or an identifier or path built from words
(CamelCase, kebab, snake or `/`-separated, word segments averaging at least four
letters). (c) Text the guard cannot inspect fully is refused as
*uninspectable*: structure nested beyond the redactor's recursion limit, or XML
the safe parser rejects for another reason than not being XML (a declared
entity, internal or external; a bare external DTD reference parses and is
inspected, and nothing is fetched). The guard is total: it returns or raises
`CpasswordInAnalystTextError`, so a crafted input cannot turn a refusal into an
HTTP 500.

**Measured behaviour** (2026-10-13). Miss rates are reproducible with
`python scripts/measure_analyst_text_guard.py` (fixed seeds, 200,000 samples per
size; the tests run the same function with fewer samples and pin upper bounds).
The false-positive corpora are local files, not in this repository.

| Input | Refused |
|-------|---------|
| Random GPP-shaped ciphertext, 1 AES block (passwords up to 7 characters) | 99.88 % (241 of 200,000 missed: random strings that happen to look word-built) |
| 2 blocks (8–15 characters) | 99.9995 % (1 missed) |
| 3 and 4 blocks | 100 % |
| GPO/AD/PKI project prose (23,666 unique paragraphs from this and sibling repositories) | 7 paragraphs (0.03 %) |
| Technical Markdown (146,460 paragraphs, dense with file paths and random ids) | 137 (0.09 %), mostly `/`-separated paths with random-looking segments |
| CPython 3.14 standard-library source (131,688 lines) | 2 |

Hex digests (SHA-1/SHA-256/MD5/SHA-512, either case), certificate thumbprints
and serials, GUIDs with or without braces, SIDs, URLs, UNC and file paths,
registry paths, distinguished names, event XML, setting names and cmdlets of
exactly one block's length (`DisableIPSourceRouting`, `ConvertTo-SecureString`),
hard-wrapped prose and ordinary prose pass; the tests pin each case.

**Known false positives.**

- Base64 of any whole number of AES blocks — 16, 32, 48, 64, 80, … bytes — is
  indistinguishable from GPP ciphertext: a base64 MD5, SHA-256, SHA-384 or
  SHA-512 digest, a base64 GUID, a random key or session token, and **any
  64-character line of a PEM certificate** (48 bytes). Refer to a certificate
  by its thumbprint or serial (hex) and write digests in hex.
- Longer base64 blobs of other sizes can hold a block-length run between two
  `/` (or `-`, `_`), which the window search refuses: measured about 0.1–0.5 %
  of 20–24-byte values, 3–6 % at 40–56 bytes, 15 % at 100 bytes and 29 % at
  200 bytes.
- Prose that puts a word straight after `cpassword:` or `cpassword=`
  (`cpassword: removed`) is an assignment to the ingest redactor too.
- Deeply nested JSON or XML that mentions `cpassword`, and XML that declares
  an entity (even a harmless one), are refused as uninspectable: an entity can
  spell the `cpassword` label, and expanding it is what the safe parser
  forbids. The message says to paste the plain text or drop the `<!DOCTYPE …>`
  declarations.

The refusal message explains each case.

**Known limits.** The guard catches accidents, not a determined insider. These
pass: a value deliberately broken up (spaces or zero-width characters inside
it), re-encoded (percent- or entity-encoding, a Unicode look-alike in the
label) or glued to other letters, and the measured fraction of one-block values
above.

**Rows written before this guard** are not rewritten: the triage log is
append-only history. `gpo-lens analyst-text-check` (read-only) lists the table,
column and id of every stored note, rationale, triage actor, Ask question and
event principal the guard would now refuse, never the value. It exits 1 when it
lists any. The operator decides what to do; back up the database before editing
it.

**Upgrading a schema v7 database.** The v7→v8 step copies the legacy
`finding_triage` rows into `finding_triage_event`. Each copied actor, note and
rationale passes the guard: a value it would refuse is copied as a marker
(`[refused principal name]` for the actor, `[refused analyst text]` for a note
or rationale) instead of the value; the legacy row is left exactly as it was,
so `analyst-text-check` (which covers the legacy note, rationale and actor
columns) still lists it; and the substitutions are recorded by legacy row id
and field only, in a `maintenance.analyst_text_substituted` event and a warning.
Every SQLite storage class is handled: TEXT is checked; INTEGER, REAL and NULL
are copied, since their text cannot hold a label or a mixed-case base64 token;
a BLOB is never copied — gpo-lens never writes one into these columns, and a
BLOB has no declared encoding, so no set of readings (UTF-8, UTF-16, UTF-32,
EBCDIC, misaligned…) could show it is clean — it is always copied as the marker
and counted as *uninspectable*. `analyst-text-check` likewise reports every
BLOB in an operator-text column, and every BLOB event payload, as
uninspectable.

The copy re-runs on every open while the schema is below the current version:
when upgrading from any older release (v8–v10 databases included, whose
release already copied the legacy rows verbatim), and on every open while the
v11 scrub has not been stamped (the additive migrations commit first). Which
event each legacy row became is recorded in `finding_triage_legacy_copy`
(legacy row id → event id, ids only; created, filled and committed in the copy's
own transaction), so a re-run copies exactly the rows not yet recorded. A legacy
row with no record can only have been copied by a release before this table
existed; those releases copied verbatim, so such a row is recognised by exact
equality of every column a copy writes (by SQLite's own comparison: storage
class, INTEGER and REAL as exact numbers, `IS` for the expiry) and by the column
a copy always leaves NULL (`supersedes_event_id`), one event per row (a maximum
one-to-one matching), recorded, and left as it is — the triage log is not
rewritten, and `analyst-text-check` lists it when its value would be refused. A
marker event without provenance is never taken for a copy: older releases never
wrote markers, and this release writes the marker and its provenance in one
transaction.

The legacy structural columns are validated too, because the copy carries them
into the event log: a status must be one v1 wrote (`open`, `acknowledged`,
`accepted_risk`) — any other value is copied as a `commented` event, which
changes no status — and a timestamp or expiry must be one the triage fold can
read, checked with the fold's own parser (`normalize.parse_triage_dt`), so an
impossible date such as 30 February, a non-leap 29 February or an expiry whose
UTC conversion overflows is rejected rather than read as "no expiry" (NULL is
allowed for the expiry). A row whose timestamp or expiry is anything else is
not copied, because neither has a neutral replacement (an invented time would
misorder the history; a dropped expiry would make a risk acceptance permanent);
it is recorded as withheld so a re-run does not report it again. Both cases are
reported by row id and field, and `analyst-text-check` lists such legacy rows.

The triage readers are strict too, for every event however it was written —
an app write, a migration copy, or a copy an earlier release already made
(which the migration recognises and leaves as it is). Each stored event is read
by one function with the shared parser. An `accepted_risk` event whose stored
expiry is not NULL but cannot be read is never taken as a permanent
acceptance: the triage fold treats the acceptance as expired (the finding is
`open`), the accepted-risk register reports it as expired, and both carry an
integrity note naming the occurrence and event id, never the value. If any
event in a finding's history has a time that cannot be read, the history
cannot be ordered, so it fails closed: `open`, no active acceptance, an
integrity note — instead of ordering the event by a placeholder time.
`analyst-text-check` lists such events (`finding_triage_event.occurred_at` /
`.expires_at`, uninspectable).

The provenance table is internal migration state and the trust boundary for
re-runs: it is only ever written by the copy. Editing it by hand — deleting a
row, or pointing a legacy row at an unrelated event — makes a later re-run copy
a row twice or skip it, and foreign-key checks cannot tell. Repair a database
by restoring a backup, not by editing this table on its own.

This does not break "refuse, never rewrite". That contract
covers what an analyst submits: refusing lets the analyst remove the value and
resubmit. A migration has no submitter to refuse to, and copying
the value verbatim would put it into the active, append-only history. Refusing
the upgrade instead was rejected: nothing in the app can edit the legacy table,
and a database stuck below v8 would never reach the v11 cpassword scrub, which
removes estate credentials. A labelled value in a legacy note or rationale is
also redacted in place by that v11 scrub, as every labelled value in a
descriptive column is.

The CLI `ask` command checks the whole question, not a slice, because it sends
the whole question. The argument is local and bounded by the operating system.

## Threat model

[`docs/threat-model.md`](docs/threat-model.md) covers the assets, trust
boundaries (collector host, transport, ingest, database at rest, web server,
browser, narration and Splunk egress, deployments), the mitigations with code
and test citations, and the residual risks that code does not mitigate.
