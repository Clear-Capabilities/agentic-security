# Examples gallery

**Goal:** thirteen real findings, one screen each, so you can recognize a
shape before you read the full walkthrough for it. Every entry below is
either a finding this tool actually produced (captured from a real scan of
this repo's own fixtures) or a real captured run of a non-scan feature
(fix verification, egress policy). None of it is invented output — where a
number, id, or log line appears below, it's copied from a run, not written
to look plausible.

Most entries scan [`examples/demo-app/`](../../examples/demo-app/) — the
same deliberately-vulnerable fixture the [quickstart](../guides/quickstart.md)
uses, so you can reproduce every one of them yourself:

```bash
npx @clear-capabilities/agentic-security-scanner scan examples/demo-app --format json
```

Each entry answers four questions — what happened, what the tool found,
what evidence proves it, and what to do about it — then links to the fuller
walkthrough or guide for the mechanics. This page doesn't repeat those; it's
the index.

---

## Index

1. [SQL injection](#1-sql-injection)
2. [Authz vulnerability](#2-authz-vulnerability)
3. [Secret exposure](#3-secret-exposure)
4. [Vulnerable dependency](#4-vulnerable-dependency)
5. [IaC misconfiguration](#5-iac-misconfiguration)
6. [PII → logs](#6-pii--logs)
7. [PII → external API](#7-pii--external-api)
8. [Cross-file taint path](#8-cross-file-taint-path)
9. [Incomplete scan](#9-incomplete-scan)
10. [Verified fix](#10-verified-fix)
11. [Rejected fix](#11-rejected-fix)
12. [Compliance evidence](#12-compliance-evidence)
13. [Model egress denial](#13-model-egress-denial)

---

## 1. SQL injection

**What happened?** The demo app's nightly revenue report builds a SQL query
by dropping a request parameter straight into an f-string:
[`report.py:16`](../../examples/demo-app/report.py) —
`cur.execute(f"SELECT SUM(total) FROM orders WHERE region = '{region}'")`.

**What did the tool find?** `ir-taint:report.py:16:py-cursor-execute` —
`SQL Injection (cursor.execute)`, severity `high`, CWE-89.

**What evidence proves it?** A one-hop `chain[]`: `region = request.args.get(...)`
at line 13 (provenance `url-param`) reaches the `cursor.execute` sink at
line 16. Two independent signals corroborate it (`IR-TAINT` and `PYTHON`);
the falsification pass found no parameterized-query control on this
particular path, so nothing demoted it.

**What should the developer do?** Parameterize the query
(`cur.execute("... WHERE region = ?", (region,))`) instead of interpolating
the value.

**See:** [Finding evidence](../walkthroughs/finding-evidence.md) — this
exact finding, read field by field, including `confidence`, `proof`,
`falsification`, and `riskDollars`.

---

## 2. Authz vulnerability

**What happened?** [`server.js`](../../examples/demo-app/server.js) has four
order routes; three call `requireAuth` and check ownership or scope the
query to `req.user.id`. The fourth, `DELETE /orders/:id` (line 30), checks
neither — anyone who can reach the API can delete any order by id.

**What did the tool find?** Three independent detectors converge on the
same line: `authz-matrix-idor:server.js:30:DELETE-/orders/:id`
("Potential IDOR (AuthZ matrix): DELETE /orders/:id mutates by id without
ownership/role check in the same handler," CWE-639, `high`),
`api-authz:BOLA:server.js:30` (Broken Object Level Authorization / API1),
and `ownership-authz:ownership-missing:server.js:31`.

**What evidence proves it?** The AuthZ-matrix detector compares this route
against its siblings in the same file — the other three all gate the
mutation on `req.user`, this one doesn't, which is exactly the asymmetry
the detector is built to catch rather than a guess from the route shape
alone.

**What should the developer do?** Verify the authenticated user owns the
resource before mutating it, e.g. `Item.findOne({ _id: req.params.id, owner:
req.user.id })`, and reject with 403 when the check fails — the same
`requireAuth` + ownership pattern the other three routes already use.

**See:** [`examples/demo-app/README.md`](../../examples/demo-app/README.md)
— the full list of vulnerability classes this fixture demonstrates.

---

## 3. Secret exposure

**What happened?** [`auth.js:7`](../../examples/demo-app/auth.js) hardcodes
a payment API key, split across a string concatenation
(`'sk_live' + '_' + 'demo4pp51mulatedKey890AB'`) specifically to see whether
the detector can be evaded that way.

**What did the tool find?** `secret-concat:auth.js:7` — "Hardcoded
credential — secret split across concatenated literals to evade detection,"
CWE-798. It isn't evaded: the detector reconstructs the concatenated
literal before matching it.

**What evidence proves it?** The finding's `snippet` shows the
reconstructed value redacted (`const PAYMENT_API_KEY = sk_l…90AB;`), proving
the match happened on the joined string, not on either half alone.

**What should the developer do?** Treat the value as compromised the moment
it's found — splitting a literal across a concatenation doesn't protect it.
Load it from an environment variable or secrets manager instead, and rotate
it at the provider.

**See:** [Responding to a leaked secret](../guides/leaked-secrets.md) — the
full rotation playbook (assess blast radius, revoke, rotate, scrub history)
for exactly this finding class.

---

## 4. Vulnerable dependency

**What happened?** [`package.json`](../../examples/demo-app/package.json)
pins `lodash` at `4.17.15`, a version with several published advisories.

**What did the tool find?** One SCA finding per advisory against that
version; the sharpest is `GHSA-35jh-r3h4-6jhm` (`CVE-2021-23337`), Command
Injection in lodash, fixed in `4.17.21`.

**What evidence proves it?** The advisory's own severity is `low`, but this
finding carries `exploitedNow: true` and `tags: ["exploited-now"]` — CISA
KEV / EPSS data (`epssPercentile: 0.97`) says this specific CVE is being
exploited in the wild right now, which is a real signal the base advisory
severity alone wouldn't tell you.

**What should the developer do?** Upgrade `lodash` to `>= 4.17.21`.

**See:** [`examples/demo-app/README.md`](../../examples/demo-app/README.md)
— SCA/SBOM/CVE-alert demos this fixture is built for.

---

## 5. IaC misconfiguration

**What happened?** [`Dockerfile`](../../examples/demo-app/Dockerfile) has no
`USER` directive, so the container runs as root; it also pulls an unpinned
`node:latest` base and `ADD`s a remote URL with no checksum.

**What did the tool find?** `container-runtime:Dockerfile:1:...` — "Dockerfile
has no USER directive (defaults to root)," CWE-250, `medium` — alongside
sibling findings for the unpinned base image and the checksum-less `ADD`.

**What evidence proves it?** A structural directive scan of the Dockerfile:
no line matching `USER` exists anywhere in the file, which is a presence
check, not a taint trace — this class of finding doesn't need one.

**What should the developer do?** Add a non-root `USER` directive, pin the
base image to a digest instead of a floating tag, and replace the `ADD` of
a remote URL with a `COPY` of a locally verified artifact.

**See:** [`examples/demo-app/README.md`](../../examples/demo-app/README.md)
— container hygiene is one of six vulnerability classes this fixture covers.

---

## 6. PII → logs

**What happened?** Two checkout handlers read the same `card_number` field;
one masks it before logging (`maskCard()`), the other logs it raw — same
field, same sink category (`Application Logs`), two different outcomes.

**What did the tool find?** The Data Flow Explorer's graph, not a line-scoped
finding: one edge into `Application Logs` marked `✅ maskCard() → masked`,
a second edge into the same sink marked `❌ logged raw, no transform`.

**What evidence proves it?** The masked edge carries the specific
`maskCard()` call as its evidence; the raw edge carries the absence of any
recognized masking transform on its path. Neither verdict is guessed from
the other, which is the entire reason a per-edge graph exists instead of a
single per-call-site finding.

**What should the developer do?** Route every log call that can see this
field through the same masking transform the safe handler already uses.

**See:** [Watch one field's journey](../walkthroughs/privacy-data-flow.md)
— the full hop-by-hop read of this exact example, plus
[Data Flow Explorer](../guides/data-flow-explorer.md) for how to build and
browse the graph that produced it.

---

## 7. PII → external API

**What happened?** [`ai-assistant.js`](../../examples/demo-app/ai-assistant.js)
takes the customer's raw request body and hands it straight to Anthropic's
`messages.create` — a third-party model provider — with no check for what's
in it.

**What did the tool find?** `ir-taint:ai-assistant.js:13:js-anthropic-messages-create`
— "Regulated Data to AI Model Provider (Anthropic messages.create)," CWE-201.

**What evidence proves it?** A one-hop `chain[]`: `req.body` at line 12
(provenance `http-body`) reaches the `messages.create` call at line 13 —
the same taint-tracing evidence style as the SQL injection above, applied
to an external-API sink instead of a database sink.

**What should the developer do?** Confirm the payload carries no PCI/PHI/PII
before it leaves the process, or route it through an approved DPA /
redaction layer first.

**See:** [Data Flow Explorer](../guides/data-flow-explorer.md) — the
shipped reference topology's own AI-provider edge (`❓ manual review
required`) shows the graph-level view of this same class of flow, one level
up from a single line-scoped finding.

---

## 8. Cross-file taint path

**What happened?** `app.js` calls `getSSN(count)`, imported from a sibling
`helper.js`, and logs the return value. `getSSN` does nothing but hand the
argument straight back — the taint has to be resolved through a function
defined in a different file to catch this.

**What did the tool find?** `ir-privacy-taint:app.js:5:privacy-js-console-log`
— "Privacy Leak (console.log)," CWE-359, `medium` — fired against
[`scanner/test/fixtures/privacy-deep/cross-file/app.js`](../../scanner/test/fixtures/privacy-deep/cross-file/app.js)
and [`helper.js`](../../scanner/test/fixtures/privacy-deep/cross-file/helper.js),
with `AGENTIC_SECURITY_DEEP=1 AGENTIC_SECURITY_PRIVACY_DEEP=1` set (this
class of tracing runs in deep mode, not a plain scan).

**What evidence proves it?** The finding resolves through the real,
whole-scan call graph (`buildCallGraph` in `scanner/src/ir/callgraph.js`) —
not a per-file heuristic — so a neutral, non-sensitive sibling function
(`getCount`, same file, same shape) correctly does *not* fire, proving the
detector is reading what `getSSN`'s body actually does, not just its name
or its caller's file.

**What should the developer do?** Don't log the return value of a function
that passes sensitive input straight through; redact or hash it first,
same as any single-file privacy finding.

**See:** [`scanner/test/privacy-deep-e2e.test.js`](../../scanner/test/privacy-deep-e2e.test.js)
— the regression test this fixture backs; [Data Flow Explorer](../guides/data-flow-explorer.md)
for the broader graph this same tracing feeds.

---

## 9. Incomplete scan

**What happened?** A scan of 6 files ran all 120 analyzers to completion —
zero failures, zero timeouts — but the local EPSS exploit-probability cache
was 20,699 days stale.

**What did the tool find?** `scanHealth.status: "partial"`, even though
`files` and `analyzers` are both fully clean (`6/6` scanned, `120/120`
completed, `failed: 0`). The one thing wrong is
`freshness.epss: { stale: true, ageDays: 20699 }`.

**What evidence proves it?** `scanHealth.conditions` names the reason in
plain language: `"EPSS exploit-probability data is stale (20699 day(s)
old)"` — the same text a `ci --assurance strict` gate and the one-screen
verdict both quote directly.

**What should the developer do?** Refresh the EPSS cache before trusting a
"nothing found" result as "safe to deploy" — a scan can be structurally
perfect and still `partial` because the data it reasoned with was stale, a
different problem with a different fix than a crashing analyzer.

**See:** [Scan health](../walkthroughs/scan-health.md) — this exact capture,
plus the fault-isolation guarantee (one analyzer failing never silently
drops another's findings) and the 3-state ship verdict this field drives.

---

## 10. Verified fix

**What happened?** `agentic-security fix --finding <id> --apply` composed a
patch, then ran it through re-scan, lint, and test legs before writing
anything to disk.

**What did the tool find?** Every leg passed:

```
re-scan: PASS
linter:  eslint PASS
tests:   PASS
honesty: PASS (FULL)
poc:     PASS (ran against the patch and no longer demonstrates the vulnerability)
```

**What evidence proves it?** The PoC leg is the strongest signal here — it's
the only leg that re-executes the actual exploit against the patched code,
not just checks that the detector stopped firing.

**What should the developer do?** Trust the CLI's condensed line —
`verified: yes — fully verified` — and ship it; `agentic-security undo`
reverts it if you change your mind.

**See:** [Verified remediation](../walkthroughs/verified-remediation.md) —
the three separate vocabularies ("did it verify" / the mechanical detail
behind that / how *complete* the fix is) this line collapses into one
sentence.

---

## 11. Rejected fix

**What happened?** A candidate patch for a Node command-injection finding
added a comment claiming the input was sanitized, but left the vulnerable
`exec()` call's string interpolation untouched.

**What did the tool find?** `verifyFixWithTests` returned
`verdict: "verification-failed"` — the re-scan leg failed with reason
`"introduced-new-findings"`, lint and tests were both skipped (no linter or
test runner configured in that scratch fixture).

**What evidence proves it?** The re-scan is scoped to just the patched file
content, which in this case surfaced a *second*, pre-existing finding the
original whole-project scan hadn't isolated to that file — proof the
verifier caught the fake fix even though the specific reason wasn't "same
bug still there."

**What should the developer do?** Never trust a self-reported "fixed" claim
over a failed verification leg — a comment claiming sanitization is not
evidence of it.

**See:** [Verified remediation](../walkthroughs/verified-remediation.md) —
this exact captured rejection, plus the honesty gate's real violation
messages for a self-reported `FULL` tier contradicted by mechanical
evidence.

---

## 12. Compliance evidence

**What happened?** A privacy-framework assessment ran against the demo app
for NIST Privacy Framework 1.1 (104 controls total).

**What did the tool find?** `13 of 29 assessed controls satisfied. 27
controls NIST rates code-testable were NOT assessed by this engine, and 48
are governance controls outside any scanner's reach. Neither group is
evidence of compliance.` — the assessment's own real interpretation string.

**What evidence proves it?** The four-bucket split behind that sentence:
`satisfied: 13`, `gap: 16`, `engine-gap: 27`, `manual: 48` — only 23 of 104
controls (`satisfied + gap`, where `codeTestable: "yes"`) are fully
code-testable at all; the satisfied rate is reported over that 29, never
over the full 104, so a report can't quietly count an unassessed control as
passed.

**What should the developer do?** Work the `gap` bucket first (it's the
only one that emits a fixable finding), treat `engine-gap` as "not
assessed, not proof of anything," and route `manual` to policy/governance
review.

**See:** [Compliance](../guides/compliance.md) — the honesty model this
example is built from, the three other real compliance-state vocabularies
in this codebase, and how to run this exact assessment yourself.

---

## 13. Model egress denial

**What happened?** An operator policy set `mode: local-only` and
`allowedProviders: [anthropic]`; a scan was pointed at a remote,
non-`anthropic` LLM endpoint for validation.

**What did the tool find?** The call was denied before a prompt was ever
built. One hash-chained line in `.agentic-security/egress-audit.log`:

```json
{"outcome":"deny","reason":"egress mode is 'local-only' and the endpoint is not a loopback address","byteCount":null,"tokenCount":null,"contentHash":null,"prev":"GENESIS"}
```

**What evidence proves it?** `byteCount`/`tokenCount`/`contentHash` are all
`null` — a denied call never got far enough to build a payload to measure,
so there's nothing to hide and nothing was logged that shouldn't be. Each
entry's `prev` is the SHA-256 of the line before it, so the log is
tamper-evident from that point forward.

**What should the developer do?** Nothing — this is the control working.
The finding this call would have validated is tagged
`llmValidationStatus: "policy-blocked"` instead of silently dropped, so
it's still visible in the scan output as unvalidated, not missing.

**See:** [Model egress policy](../walkthroughs/model-egress.md) — this
exact captured audit log, the redaction pipeline that runs on anything that
*is* allowed through, and the real call site that enforces this before
`renderPrompt` ever runs.
