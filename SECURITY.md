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

## Threat model

[`docs/threat-model.md`](docs/threat-model.md) describes the assets, trust
boundaries (collector host, transport, ingest, database at rest, web server,
browser, narration and Splunk egress, deployments), the mitigations with code
and test citations, and the residual risks that are not mitigated by code.
