# Security policy

## About this tool

gpo-lens is a **defensive, local-first, read-only** Group Policy analyzer. It
ingests *copies* of a GPO estate (collector exports or ZIPs) and reports
hygiene findings, dangerous configurations and estate structure. The Python
application never connects to or writes to Active Directory, Group Policy or
SYSVOL; the PowerShell collector that produces its inputs runs on a domain
controller or RSAT host and is read-only by design. The deterministic core has
no AI in the truth path; the optional narration layer only explains facts the
core computed.

## Reporting a vulnerability

Please report security issues **privately**, not as a public issue:

- Email: **plm@hraedon.com**
- Or open a private vulnerability report via GitHub's
  [Security Advisories](https://github.com/hraedon-labs/gpo-lens/security/advisories/new).

Include the affected version (`gpo-lens --version` or the release tag), the
Python version, a reproduction, and the expected vs. actual behavior. Attach
any proof of concept or sample export as a file, and **sanitize real estate
data first** (domain names, GPO names, OU paths, SIDs, account names). Never
send a real `cpassword` value or an unsanitized SYSVOL copy.

Acknowledgement within 72 hours is the target. Coordinated disclosure follows
once a fix is released.

## Supported versions

Security fixes land on `main` and ship in the next release. Only the latest
release is supported; upgrade before reporting where you can.

| Version | Supported |
|---------|-----------|
| Latest release (currently v1.4.0) | Yes |
| Any older release | No — upgrade to the latest release |
| Unreleased `main` / release candidates | Report findings against them; run a release in production |

## What counts as a vulnerability

In scope — vulnerabilities in gpo-lens itself, including:

- **A false all-clear**: gpo-lens reports an estate, GPO or setting as clean
  (or omits a finding, coverage gap or caveat it documents that it raises) when
  the export contains the condition. A silent under-report of a cpassword,
  MS16-072 exposure, dangerous configuration or coverage gap is a security bug,
  not a cosmetic one.
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
  Analyst-typed text is refused rather than redacted (see
  [Credentials in analyst-typed text](#credentials-in-analyst-typed-text)); a
  path that stores or sends such text without the guard, or a GPP cpassword in
  a common form that the guard misses, is in scope.
- Web access-control bypass: Host allow-list, CSRF, loopback-trust, bearer
  token or permission checks that can be evaded.
- Narration egress beyond what is documented (estate strings reaching the LLM
  endpoint on a path that promises only signed numeric facts).
- **The PowerShell collector mutating anything** in Active Directory, Group
  Policy or SYSVOL. It is read-only by design; if it ever writes, that is a
  critical bug — report it the same way.

Out of scope (welcome as regular issues):

- The Group Policy misconfigurations gpo-lens *detects*. Those are findings in
  your estate, not gpo-lens bugs.
- Deployments that ignore the documented access boundary — for example a
  non-loopback listener without the documented reverse proxy, authentication
  and `GPO_LENS_ALLOWED_HOSTS` configuration (see
  [`deploy/README.md`](deploy/README.md#access-boundary)).
- Behavior of a custom collector script supplied with `-CollectorPath`, or of
  the configured third-party LLM endpoint.
- Findings that require an attacker who already controls the analysis host
  account that owns the database.

## Credentials in analyst-typed text

Ingest redacts every `cpassword` value and keeps no hash or fingerprint of one,
so nothing at rest can recognise a value an analyst types or pastes later. Every
path that stores or sends analyst-typed text therefore passes one guard,
`gpo_lens.analyst_text.check_analyst_text`, which **refuses** (never rewrites)
the text:

| Path | Stored or sent | On refusal |
|------|----------------|------------|
| Web triage form (`POST /findings/{id}/triage`) and `findings.triage_finding` / `append_triage_event` | `finding_triage_event.note`, `.rationale` (append-only) | `400` with the reason; nothing written; `audit.log` records `triage` / `refused` with the field name. The form keeps the draft in place (a script submits it without leaving the page; without JavaScript the browser shows the 400 page). |
| Web Ask (`POST /ask`) | the `audit.narrate` event, and the model provider | `400` page with the reason and an empty question box; the model is not called; the event records `"question": ""`, outcome `refused` |
| CLI `ask` | the model provider | exit 1, reason on stderr, model not called |
| CLI `explain-setting` (model fallback) | the model provider | exit 1, reason on stderr, model not called |

The refusal names the field and the reason ("looks like it contains a Group
Policy Preferences cpassword; remove it — the value is a recoverable
credential…"), never the value or any part of it. `tests/test_analyst_text_guard.py`
enumerates every write path from the source (SQL writes to the triage tables,
`append_event` call sites, web `Form`/`File` fields, model calls): a new one fails
the test until it is guarded or classified. Search terms and filters are not
stored by gpo-lens; they appear in URLs, so a reverse proxy's access log may
record them, which the app cannot refuse.

**What is refused.** (a) A labelled cpassword in any form the ingest redactor
recognises: `cpassword="…"`, `cpassword: …`, escaped quotes (`\"`, `&quot;`),
any casing, JSON keys (including `\u` escapes), `<cpassword>` elements, the
word split across XML nodes, character references. `cpassword=""` and the
redaction marker carry no value and pass. (b) An unlabelled token with the
shape the ingest copy chaser uses (`redaction.ciphertext_shaped`: base64 of
whole 16-byte AES blocks, at least 22 characters, after removing whitespace,
mapping URL-safe base64 to standard and stripping `=` padding), also when it is
wrapped across lines or follows `pw-` or a path separator — unless it has a
shape Windows-written ciphertext cannot have: pure hex; one letter case only;
non-canonical base64 (unused bits of the last character set); base64 that
decodes to printable ASCII or to at least a quarter NUL bytes (UTF-16 text,
e.g. a PowerShell `-EncodedCommand`); or an identifier or path built from words
(CamelCase, kebab, snake or `/`-separated, word segments averaging at least four
letters).

**Measured behaviour** (2026-10-13, `cpassword_material` at this commit):

| Input | Refused |
|-------|---------|
| Random GPP-shaped ciphertext, 1 AES block (passwords up to 7 characters), 200,000 samples | 99.868 % (264 missed: random strings that happen to look word-built) |
| 2 blocks (8–15 characters), 200,000 samples | 99.9985 % (3 missed) |
| 3 and 4 blocks, 200,000 samples each | 100 % |
| GPO/AD/PKI project prose (23,666 unique paragraphs from this and sibling repositories) | 7 paragraphs (0.03 %) |
| Technical Markdown (137,718 paragraphs, dense with file paths and random ids) | 126 (0.09 %), mostly `/`-separated paths with random-looking segments |
| CPython 3.14 standard-library source (131,688 lines) | 2 |
| Repository docs paragraphs that discuss cpassword (65) | 2, both quoting `cpassword="…"` |

Hex digests (SHA-1/SHA-256/MD5/SHA-512, either case), certificate thumbprints,
GUIDs with or without braces, SIDs, URLs, UNC and file paths, registry paths,
distinguished names, setting names and cmdlets of exactly one block's length
(`DisableIPSourceRouting`, `ConvertTo-SecureString`) and ordinary prose pass;
the tests pin each case.

**Known false positives.** Base64 of any 16-, 32- or 48-byte value is
indistinguishable from GPP ciphertext: a base64 MD5 or SHA-256 digest, a base64
GUID, a random key or session token. Write digests in hex. Prose that puts a
word straight after `cpassword:` or `cpassword=` (`cpassword: removed`) is an
assignment to the ingest redactor too. The refusal message explains both.

**Known limits.** The guard is for accidents, not a determined insider: a value
deliberately broken up (spaces inside it, homoglyphs, re-encoding) or glued to
other letters passes, as does the measured fraction of one-block values above.

**Rows written before this guard** are not rewritten: the triage log is
append-only history. `gpo-lens analyst-text-check` (read-only) lists the table,
column and id of every stored note, rationale or Ask question the guard would
now refuse, never the value, and exits 1 when it lists any; the operator
decides what to do (back up the database before editing it).

## Threat model

[`docs/threat-model.md`](docs/threat-model.md) describes the assets, trust
boundaries (collector host, transport, ingest, database at rest, web server,
browser, narration and Splunk egress, deployments), the mitigations with code
and test citations, and the residual risks that are not mitigated by code.
