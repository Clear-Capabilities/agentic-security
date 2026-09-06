# NIST SP 800-171 Rev. 3 coverage

**Framework id:** `nist-800-171-r3` · **aliases:** `800-171`, `cui`
**Source:** [NIST SP 800-171r3](https://csrc.nist.gov/pubs/sp/800/171/r3/final), public domain (US Federal publication)
**Catalogue:** all **97** requirements across **17** families

```bash
agentic-security compliance --walkthrough nist-800-171-r3     # auditor narrative
/compliance --report 800-171                                  # evidence report
/compliance --report 800-171 --format json                    # structured
/compliance --report 800-171 --format oscal                   # OSCAL 1.1.2
/compliance --gap nist-800-171-r3                             # what isn't clearing
```

## This page quotes no coverage figures on purpose

Earlier coverage maps in this directory hand-transcribed control counts and coverage
percentages, and they drifted, one disagreed with both the generated catalogue and the engine
mapping, another had the framework *version* wrong. A page that restates what the engine
computes is a second source of truth that nothing keeps honest.

So this page states **no coverage figure for the framework**. Run the commands above; the engine
is the only place that number lives.

The worked example further down does contain numbers, and they are a different kind of claim:
they are the output of the commands printed directly above them, taken against one specific
demo application. They describe that run, not this framework's coverage, if they ever drift,
re-running the example is what corrects them.

## Why 800-171

SP 800-171 Rev. 3 defines the requirements for protecting **Controlled Unclassified
Information (CUI)** in nonfederal systems. It is the control basis for **CMMC Level 2** and for
contracts carrying DFARS 252.204-7012. Its technical families map onto real detector output
better than most bundled frameworks do, access enforcement, cryptographic protection,
configuration settings, flaw remediation and supply-chain integrity are all things this engine
decides directly.

## The honesty model, applied here

800-171 is a *system* standard, not an application-security standard. Much of it is about
locked doors, cleared people and signed procedures. The catalogue therefore splits three ways,
and the split is visible in every report:

| Rating | Meaning |
|---|---|
| `yes` | A detector's findings bear directly on the requirement. An empty finding bucket is real evidence. |
| `partial` | Some code-observable component, but the requirement is materially broader than anything a scanner sees. |
| `no` | Organisational, physical or personnel. Nothing a code scanner observes can evidence it. |

**All 97 requirements are carried, including the ones this tool cannot assess.** Shipping only
the subset with automated signal would have been a smaller, better-looking artifact and a
dishonest one, omission reads as coverage. Whole families (Awareness and Training, Personnel
Security, Physical Protection) and most of Incident Response, Maintenance and Media Protection
carry **no automated signal at all** and report as requiring manual evidence collection.

Two structural guarantees back that up, both enforced in code rather than promised in prose:

- **A control rated `no` can never read as evidenced.** The evaluator forces it away from
  `present` and states why in the observations.
- **A scan that examined nothing satisfies nothing.** An empty finding bucket from a run that
  read zero files is not evidence, and is reported as *not assessed* rather than as a pass.
  (This guard was added to the shared evaluator while building this framework; it previously
  existed only inside the privacy-framework module, so every framework reachable from
  `--report` had the hazard.)

### The testability rating is ours, not NIST's

Unlike the AI 600-1 workbook, the 800-171 export carries **no** code-testability column. Every
`yes`/`partial`/`no` in this framework is a judgment made by this engine's authors, recorded
with a one-line rationale per requirement in
[`scripts/nist-800-171/code-testability.json`](../../scripts/nist-800-171/code-testability.json).
Disagree with a rating and you are disagreeing with us, not with NIST. That file is the place
to argue.

## What this is not

- **Not a CMMC assessment.** CMMC is a certification program built on 800-171 with its own
  assessors and procedures. This tool produces neither an assessment nor a certification.
- **Not an SPRS score.** The DoD self-assessment score is a weighted formula over the full
  control set, most of which is organisational. Computing one from partial automated evidence
  would assert a posture this tool cannot observe.
- **Not a substitute for a System Security Plan.** 03.15.02 requires one; nothing here writes it.
- **Not Rev. 2.** Rev. 2's 110 controls are a different catalogue. This is Rev. 3's 97.

## Worked example: assess, remediate, re-assess

![NIST SP 800-171 Rev. 3: assess, remediate, re-assess](../brand/nist-800-171-demo.gif)

*Recorded from the commands below. Regenerate with `vhs docs/brand/nist-800-171-demo.tape`.*

Every number below was produced by running these commands against the demo app this repo
ships at [`examples/demo-app/`](../../examples/demo-app/). Copy it somewhere writable and
follow along; a deliberately vulnerable app means the first run always finds something.

```bash
cp -R examples/demo-app /tmp/cui-app && cd /tmp/cui-app
```

### 1. Assess

```bash
agentic-security scan .
agentic-security compliance --report nist-800-171-r3 --format oscal > oscal-before.json
```

The OSCAL document is an `assessment-results` model. Count what it decided:

```bash
jq '[.results[0].findings[] | .target.status.state] | group_by(.) | map({(.[0]): length}) | add' oscal-before.json
```

```json
{
  "not-satisfied": 20,
  "satisfied": 26
}
```

**46 decided, 51 not.** The 51 organisational requirements are deliberately absent from
`findings` and present as `observations` instead, OSCAL's `status.state` is binary
(`satisfied` / `not-satisfied`) with no "we did not look", so recording a control nobody
assessed as a finding would fabricate a verdict. See [OSCAL output](../OSCAL.md).

### 2. Find out which code is responsible

A failing control names the findings that caused it, with file and line:

```bash
agentic-security compliance --report nist-800-171-r3 --format json \
  | jq -r '.[] | select(.controlRefs | length > 0)
           | "\(.control.id)  \(.control.summary | split(": ")[0])  <- \(.controlRefs | join(", "))"'
```

```
03.01.02  Access Enforcement  <- ownership-authz:ownership-missing:server.js:11, …
03.01.07  Least Privilege - Privileged Functions  <- ownership-authz:ownership-missing:server.js:11, …
03.04.06  Least Functionality  <- container-runtime:Dockerfile:7:Dockerfile ADD with remote URL, …
03.05.01  User Identification and Authentication  <- ownership-authz:ownership-missing:server.js:11, …
03.05.07  Password Management  <- weak-pw-hash:auth.js:11
03.13.11  Cryptographic Protection  <- struct:auth.js:11:MD5/SHA1_Password_Hashing
03.14.01  Flaw Remediation  <- py-struct-cursor-sqli:report.py:16, ir-taint:server.js:11:js-sql-query, …
```

(Long reference lists are elided at `…`; every id shown is real output.)

This is the step that makes the report actionable rather than merely damning: **03.13.11
"Cryptographic Protection" is not an abstract gap, it is `auth.js:11`.**

### 3. Remediate

`auth.js:11` hashes passwords with unsalted MD5, and the file also carries a hardcoded
payment key. Fix both, by hand, or with `/fix --all` to let the verified fix loop do it:

```js
// before
const PAYMENT_API_KEY = 'sk_live' + '_' + 'demo4pp51mulatedKey890AB';
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// after
const PAYMENT_API_KEY = process.env.PAYMENT_API_KEY;
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
```

### 4. Re-assess

```bash
agentic-security scan .
agentic-security compliance --report nist-800-171-r3 --format oscal > oscal-after.json
```

```json
{
  "not-satisfied": 18,
  "satisfied": 28
}
```

Two controls flipped, and the OSCAL finding for `03.13.11` changed state, this is the
artifact an assessor reads, before and after:

```diff
   "props": [
     { "name": "source-control-id", "value": "03.13.11" },
-    { "name": "assessment-status", "value": "partial" }
+    { "name": "assessment-status", "value": "present" }
   ],
   "target": {
     "target-id": "_03.13.11",
-    "status": { "state": "not-satisfied", "reason": "fail" }
+    "status": { "state": "satisfied",     "reason": "pass" }
   }
```

Join the two documents to see exactly what moved, and, just as importantly, that nothing
moved backwards:

```bash
jq -sr '([.[0].results[0].findings[]
          | {key:(.props[]|select(.name=="source-control-id")|.value), value:.target.status.state}]
         | from_entries) as $before
  | .[1].results[0].findings[]
  | {id:(.props[]|select(.name=="source-control-id")|.value), state:.target.status.state}
  | select($before[.id] != .state)
  | "\(.id)  \($before[.id]) -> \(.state)"' oscal-before.json oscal-after.json
```

```
03.05.07  not-satisfied -> satisfied
03.13.11  not-satisfied -> satisfied
```

Two lines, both in the same direction. A regression would appear in this same list as
`satisfied -> not-satisfied`, so an empty result in that direction is the check, not an
assertion in this document.

### 5. What did NOT move, and why that is the point

`03.05.01` (User Identification and Authentication) was still `not-satisfied` after the fix.
It maps to `broken-access-control`, and `server.js` still has unfixed authorization gaps,
**fixing `auth.js` cannot close a control whose evidence lives in another file.** A tool that
let one plausible-looking fix clear an entire control would be pleasant and useless.

The rest remain `not-satisfied` for a different reason: they are backed by **artifact
existence**, not by detector output, and the demo app has not produced those artifacts. These
close by *generating evidence*, not by editing code, and the report names the missing file
rather than making you guess:

```bash
agentic-security compliance --report nist-800-171-r3 --format json \
  | jq -r '.[] | select(.observations[]? | startswith("✗"))
           | "\(.control.id)  \(.observations[] | select(startswith("✗")))"'
```

```
03.04.10  ✗ aibom: expected aibom.json not present.
03.11.02  ✗ cve-alert-daemon: expected cve-alerts/ not present.
03.11.04  ✗ fix-history: expected fix-history/log.json not present.
03.11.04  ✗ triage: expected triage.json not present.
03.12.01  ✗ verifier: expected verifier-runs/ not present.
03.12.02  ✗ fix-history: expected fix-history/log.json not present.
03.12.02  ✗ triage: expected triage.json not present.
03.12.03  ✗ watch-mode: expected watch-status.json not present.
03.14.01  ✗ fix-history: expected fix-history/log.json not present.
03.14.03  ✗ cve-alert-daemon: expected cve-alerts/ not present.
03.14.06  ✗ watch-mode: expected watch-status.json not present.
03.15.01  ✗ compliance-policy: expected compliance-evidence.json not present.
```

Each names the artifact that would satisfy it. Note that an artifact-existence control is
**capped at `partial` and can never read `present`** on the strength of a file existing,
"`threat-model.json` is present" is evidence a file exists, not evidence that threat modelling
happened. That cap is deliberate (see the honesty model above).

### Reproducibility

Add `AGENTIC_SECURITY_DETERMINISTIC=1` and the OSCAL document is byte-identical across
runs, UUIDs become content-derived and timestamps pin to the scan's own clock, so a hash
taken over the document still verifies later:

```bash
AGENTIC_SECURITY_DETERMINISTIC=1 agentic-security compliance --report nist-800-171-r3 --format oscal | shasum -a 256
```

## How it is built

```
docs/standards/NIST_SP_800_171r3_Controls.csv        ← the standard's own text
scripts/nist-800-171/code-testability.json           ← our testability rating + rationale
  └─ scripts/nist-800-171/build-catalog.py           ← joins them by control id
       └─ scripts/nist-800-171/controls.json         ← generated; drift-gated at release
compliance-frameworks/nist-800-171-r3.json           ← control → detector/artifact mapping
```

Regenerate and verify:

```bash
python3 scripts/nist-800-171/build-catalog.py          # regenerate
python3 scripts/nist-800-171/build-catalog.py --check  # exit 1 if stale
```

Mappings point only at detector families this engine actually emits and artifacts it actually
writes. A requirement this engine cannot evidence is left unmapped and reported as a gap,
never given a speculative mapping to improve how the coverage looks.
