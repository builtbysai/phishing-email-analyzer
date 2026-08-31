# Phishing Email Analyzer

A dependency-light command-line tool that statically analyzes raw `.eml` files for phishing indicators. It produces a weighted, plain-language assessment for each message, a self-contained dark HTML report, and a machine-readable JSON export.

The analyzer is fully offline at runtime and uses only the Python standard library. It never visits extracted links, executes attachments, performs DNS requests, or sends message data elsewhere.

## What it checks

### Headers

- SPF, DKIM, and DMARC pass/fail outcomes when `Authentication-Results` or `Received-SPF` headers are present
- `Reply-To` and `From` organizational-domain mismatch
- Display-name impersonation, including common service names and embedded email addresses
- Suspicious sender-domain suffixes and IP-only originating mail hops

### URLs

- Visible link text that names a different destination than the actual `href`
- Common URL-shortening services
- Lookalike domains, simple typos, leetspeak, Unicode homoglyphs, and Punycode labels
- IPv4 and IPv6 literal destinations

### Content and attachments

- Pressure and urgency phrases
- Sign-in, password, identity-verification, and security-code language
- Executables, scripts, macro-enabled documents, archives, disk images, and active web-content attachments
- Double-extension executable filenames such as `document.pdf.exe`

## Requirements

- Python 3.10 or newer
- No runtime packages and no network access
- `pytest` is needed only to run the development test suite

## Run it

From the project directory, analyze the included synthetic dataset:

```bash
python -m phishing_email_analyzer sample_emails
```

This creates `phishing-report.html` and `phishing-report.json` in the current directory. Open the HTML file in any modern browser.

Choose output paths or scan nested directories:

```bash
python analyze.py path/to/messages --html output/report.html --json output/report.json --recursive
```

Analyze a single message:

```bash
python -m phishing_email_analyzer message.eml --html one-message.html --json one-message.json
```

The command prints the number of analyzed emails, the high/critical count, and the resolved report paths. Inputs are never modified.

## Score interpretation

Every matched rule contributes a documented weight. The total is capped at 100:

| Score | Level | Suggested interpretation |
| ---: | --- | --- |
| 0–19 | Low | No or few configured structural indicators |
| 20–49 | Moderate | Review the message and independently verify unusual requests |
| 50–74 | High | Multiple strong indicators; avoid interacting until verified |
| 75–100 | Critical | Strongly consistent with phishing behavior |

A low score is not proof that a message is safe, and a high score is not a legal or forensic verdict. Authentication results are read from the message as supplied; this tool does not independently validate cryptographic signatures.

## Tests

The test suite uses pytest-style plain functions and assertions:

```bash
python -m pytest
```

It covers each rules module independently, parsing and scoring behavior, report escaping, the CLI, and a full run across the sample batch.

If pytest is not already available, the repository includes a standard-library fallback that runs the same test functions (including their temporary-directory fixture) without installing anything:

```bash
python run_tests.py
```

## Project layout

```text
phishing_email_analyzer/
  analyzer.py       # orchestration and scoring
  header_rules.py   # sender and authentication rules
  url_rules.py      # link extraction and URL rules
  content_rules.py  # language and attachment rules
  reporting.py      # JSON and standalone HTML output
sample_emails/      # seven fictional safe-to-inspect fixtures
tests/              # focused unit and end-to-end tests
analyze.py          # source-checkout convenience entry point
```

## Design notes

Rules are deliberately small pure functions. Each returns zero or more immutable `Finding` objects containing a stable rule ID, category, score weight, evidence, and plain-language explanation. The orchestrator has no rule-specific logic: it parses one message, runs the rule groups, caps the score, and assigns a risk band. This keeps individual behaviors straightforward to test or extend.

Domain comparison is intentionally conservative and offline. A compact set of common multi-label public suffixes stands in for the full Public Suffix List, and lookalike detection uses Unicode normalization, a small homoglyph map, and edit distance against a short protected-domain set. Production deployments may want a maintained suffix list and a carefully governed organization-specific brand list.

The report renderer escapes every message-derived value and emits only local HTML and CSS. URLs are shown as code rather than clickable anchors so reviewing a report cannot accidentally navigate to a suspicious destination.

## Synthetic data

All sample messages, people, identifiers, addresses, and message bodies are fictional. Reserved `.example` domains and documentation IP ranges are used where practical. One inert URL-shortener string is included solely to exercise that rule; the analyzer never opens it.

## License

MIT. See [LICENSE](LICENSE).
