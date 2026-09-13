# Independent external holdout

## Why this directory exists

`SARD_AGENTIC_SECURITY_PRD.md`'s external-holdout requirement (§43-44) exists
to catch a benchmark-driven engine change that improves a tuning corpus'
score without genuinely generalizing. `bench-realworld.js`'s pre-existing
curated apps (`dvwa`, `juice-shop`, `nodegoat`, `pygoat`, `railsgoat`) look
like they satisfy this — real, non-Juliet, non-SARD applications with
hand-curated `expected.json` ground truth — but every one of them carries
`provenance: "bootstrap-from-engine-output-*"` in its own `expected.json`:
the ground truth was seeded from what a past scanner run reported, then
filtered, not built independently from the code. Scoring the scanner
against a ground truth the scanner itself produced is circular — it can
prove the fixture wasn't corrupted by that seeding run, but it cannot prove
genuine generalization, and it's exactly why every one of those apps
carries `requiresReAudit: true` and their entry in the holdout gate
(`bench/sard/scripts/holdout-check.mjs`) is informational-only, never
gating anything.

`tinymart/` is the fix: a small, hand-written application whose
`expected.json` (`scanner/test/benchmark/realworld/expected/tinymart.json`)
was authored by reading `tinymart/`'s own source — deciding what's
vulnerable and why — **before the scanner was ever run against it once**.
It carries `requiresReAudit: false` and `provenance:
"authored-independently-..."`, and it is the first (and, as of this
writing, only) holdout app whose entry in `holdout-check.mjs` actually
gates a build.

## What's in `tinymart/`

A small Express app, six files, with five deliberately injected
vulnerabilities and a hand-written safe variant of each right next to it in
the same file (so the same run also tests for false positives on the fixed
code, not just true positives on the vulnerable code):

| File | Vulnerable route | Safe route | Class |
|---|---|---|---|
| `routes/products.js` | `GET /search` | `GET /search-safe` | SQL injection (string concat vs. parameterized query) |
| `routes/products.js` | `GET /by-vendor/:vendorId` | — | SQL injection (second, independent instance) |
| `routes/admin.js` | `GET /ping` | `GET /ping-safe` | Command injection (`exec` + shell string vs. `execFile` + argv array) |
| `routes/files.js` | `GET /invoice` | `GET /invoice-safe` | Path traversal (unchecked `path.join` vs. a resolved-path containment check) |
| `routes/comments.js` | `GET /list` (fed by `POST /add`) | `GET /list-safe` | Stored XSS (unescaped concatenation vs. HTML-escaped output) |
| `config.js` | — | — | Hardcoded secret (a Stripe-key-shaped literal) |

This is **not** a real, installable application — it has never been `npm
install`ed or run. It exists purely as scan input. See each route's own
comment for the exact reasoning behind why it is or isn't vulnerable.

## How independence is maintained going forward

1. **Never run the scanner against a change to this fixture before deciding
   what the change should score.** Decide the intended vulnerable/safe
   status first, write it into `expected.json`, then run the scanner. If a
   result doesn't match, that is real information about the scanner — it is
   never a reason to adjust `expected.json` to match what the scanner
   reported.
2. **Advisory/best-practice findings are out of scope by design, not
   suppressed.** A real scan of `tinymart` reports plenty of true findings
   this fixture's `expected.json` does not enumerate — missing CSRF
   protection, missing rate limiting, missing `helmet()`, the Express
   security checklist, a second hardcoded value (`dbPassword` in
   `config.js`) that duplicates the enumerated Stripe-key finding at a
   different line. These are not false positives; `expected.json` is
   deliberately scoped to the five "classic" exploitable vulnerability
   classes PRD §6.1 names (SQL injection, command injection, path
   traversal, XSS, hardcoded secret) plus the safe/fixed counterpart of
   each, matching how Juliet/OWASP-Benchmark-style corpora scope
   themselves. Precision numbers from this fixture measure precision
   against that scope, not absolute precision — the same convention every
   other curated app in this directory already uses.
3. **A real miss is a real, disclosed result, not something to fix by
   loosening the fixture.** The first real run of this fixture correctly
   detected 4 of 5 injected core vulnerabilities but missed the stored XSS
   in `routes/comments.js` — the taint has to survive being written into a
   module-level array in one request handler (`POST /add`) and read back out
   in a completely different one (`GET /list`), a genuinely hard
   cross-function, heap-modeling problem. This is left as an honest,
   informative result about current capability, not "fixed" by simplifying
   the fixture to something easier to detect.

## Adding to this fixture

Adding a new vulnerable route (or a new file) is welcome, but keep the
discipline above: write the code, decide its vulnerable/safe status from
reading it, add the `expected.json` entry, THEN run the scanner to see if it
agrees — never the other order.
