# R2 Execution-Verified Exploitability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Promote a finding from "the analyser thinks this is a bug" to "we ran it and watched it break," by executing its proof-of-concept inside the R1 sandbox and recording what actually happened.

**Architecture:** A new `scanner/src/posture/execution-proof.js` takes a finding carrying `f.poc.code`, writes the PoC into a fresh sandbox root, runs it through `runConfined()` from `scanner/src/sandbox/`, and attaches a `proofTier` plus machine-checkable evidence. Nothing in the existing pipeline changes behaviour unless the feature is explicitly enabled.

**Tech Stack:** Node ≥ 24 ESM, the R1 sandbox, `node:fs`/`node:os`/`node:path`. No new dependencies.

## Global Constraints

- ESM throughout `scanner/src/`, Node ≥ 24, **NO new dependencies**.
- Run `npm run build` in `scanner/` after any `scanner/src/` change.
- New test files wired into a scoped script in `scanner/package.json`.
- **Never name any external tool, product, or vendor** in code, comments, docs, test names, or commit messages. Platform names (macOS/Linux) are fine.
- Every stated number from a run in the same session; exit codes captured standalone (`CMD; echo "EXIT=$?"`), never after a pipeline.
- Gates proven in **both directions**.
- Commit after each task. Do not push.

## The honesty rule this feature exists to enforce

A finding may only be labelled `execution-proven` when a PoC **ran to completion inside the sandbox and produced the predicted observable effect**. Everything else is `taint-proven` (the analyser's static reasoning) or `unproven`. Specifically:

- A PoC that could not run (no sandbox, missing runtime, timeout) is **NOT** proof of anything — it must never downgrade *or* upgrade a finding, only record why proof was unavailable.
- A sandbox result of `status:'ok'` does **not** mean no violation occurred — R1's denial signal is best-effort. Proof must come from the PoC's own observable effect, never from the exit code alone.
- Absence of proof is not proof of absence. A PoC that fails to demonstrate the bug marks the finding `proof-failed`, which is a signal for triage — **not** an automatic false-positive dismissal.

## Prerequisite, stated plainly

R1's userspace backend is verified on macOS. Its kernel-namespace backend is **implemented but unverified**, and confines network only — **not writes**. Therefore this feature must **refuse to run** when the active backend is `disabled`, and must record the backend name in its evidence so a proof produced on an unverified backend is identifiable after the fact. Do not treat all backends as equally trustworthy.

---

### Task 1: Proof tier vocabulary and evidence shape

**Files:**
- Create: `scanner/src/posture/proof-tier.js`
- Test: `scanner/test/execution-proof.test.js`
- Modify: `scanner/package.json` (wire into `test:posture`)

**Interfaces:**
- Produces: `PROOF_TIERS` (frozen array), `attachProofTier(finding, evidence) -> finding`, `proofTierOf(finding) -> string`.

Evidence shape (exact):
```js
{ tier, backend, ran: boolean, observed: string|null, reason: string|null, exitCode: number|null, timedOut: boolean, at: string }
```

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/execution-proof.test.js
import { test, describe } from 'node:test';
import assert from 'node:assert';
import { PROOF_TIERS, attachProofTier, proofTierOf } from '../src/posture/proof-tier.js';

describe('proof tier vocabulary', () => {
  test('exposes exactly the four tiers, most-proven first', () => {
    assert.deepEqual([...PROOF_TIERS], ['execution-proven', 'proof-failed', 'taint-proven', 'unproven']);
  });

  test('a finding with no proof attempt reads as taint-proven when the analyser found it', () => {
    assert.equal(proofTierOf({ parser: 'IR-TAINT' }), 'taint-proven');
  });

  test('a finding with no analyser backing reads as unproven', () => {
    assert.equal(proofTierOf({}), 'unproven');
  });

  test('attachProofTier records evidence and sets the tier', () => {
    const f = attachProofTier({ id: 'x' }, {
      tier: 'execution-proven', backend: 'userspace', ran: true,
      observed: 'marker file created', reason: null, exitCode: 0, timedOut: false, at: '2026-07-27T00:00:00.000Z',
    });
    assert.equal(f.proofTier, 'execution-proven');
    assert.equal(f.proofEvidence.backend, 'userspace');
    assert.equal(f.proofEvidence.ran, true);
  });

  test('an unrunnable PoC never yields execution-proven', () => {
    const f = attachProofTier({ id: 'x', parser: 'IR-TAINT' }, {
      tier: 'execution-proven', backend: 'disabled', ran: false,
      observed: null, reason: 'no confinement primitive', exitCode: null, timedOut: false, at: '2026-07-27T00:00:00.000Z',
    });
    // ran:false must be demoted — proof requires the PoC to have actually run.
    assert.notEqual(f.proofTier, 'execution-proven');
    assert.equal(f.proofTier, 'taint-proven');
    assert.match(f.proofEvidence.reason, /confinement/);
  });

  test('rejects a tier outside the vocabulary', () => {
    assert.throws(() => attachProofTier({}, { tier: 'definitely-exploitable', ran: true }), /unknown proof tier/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/execution-proof.test.js; echo "EXIT=$?"`
Expected: FAIL — `Cannot find module '../src/posture/proof-tier.js'`

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/proof-tier.js
// How strongly a finding is backed by evidence.
//
//   execution-proven — a proof-of-concept RAN inside the sandbox and produced
//                      the predicted observable effect. The strongest claim.
//   proof-failed     — a proof-of-concept ran and did NOT demonstrate the bug.
//                      A triage signal, NOT an automatic false-positive verdict:
//                      absence of proof is not proof of absence.
//   taint-proven     — the analyser's static reasoning found it; nothing executed.
//   unproven         — no analyser backing recorded.
export const PROOF_TIERS = Object.freeze([
  'execution-proven', 'proof-failed', 'taint-proven', 'unproven',
]);

// Parsers that represent real analysis rather than a plain pattern match.
const _ANALYSED = new Set(['IR-TAINT', 'MULTI-SINK']);

export function proofTierOf(finding) {
  if (finding?.proofTier) return finding.proofTier;
  return _ANALYSED.has(finding?.parser) ? 'taint-proven' : 'unproven';
}

export function attachProofTier(finding, evidence) {
  if (!PROOF_TIERS.includes(evidence?.tier)) {
    throw new Error(`unknown proof tier: ${evidence?.tier}`);
  }
  let tier = evidence.tier;
  // Guard the central honesty rule: nothing that did not RUN may be called
  // execution-proven or proof-failed. Fall back to the finding's static standing.
  if (!evidence.ran && (tier === 'execution-proven' || tier === 'proof-failed')) {
    tier = proofTierOf({ ...finding, proofTier: undefined });
  }
  return { ...finding, proofTier: tier, proofEvidence: { ...evidence, tier } };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/execution-proof.test.js; echo "EXIT=$?"` → PASS, EXIT=0

- [ ] **Step 5: Wire into `test:posture` in `scanner/package.json`, then run `npm run test:posture; echo "EXIT=$?"` and confirm the file appears in the output.**

- [ ] **Step 6: Commit**

```bash
git add scanner/src/posture/proof-tier.js scanner/test/execution-proof.test.js scanner/package.json
git commit -m "feat(proof): proof-tier vocabulary that refuses to call unrun code proven"
```

---

### Task 2: Run a proof-of-concept in the sandbox

**Files:**
- Create: `scanner/src/posture/execution-proof.js`
- Test: `scanner/test/execution-proof.test.js` (append)

**Interfaces:**
- Consumes: `attachProofTier`, `proofTierOf` (Task 1); `runConfined`, `sandboxAvailable`, `detectBackend` from `../sandbox/index.js`.
- Produces: `proveFinding(finding, { timeoutMs = 10000 }) -> finding` (async).

A finding's PoC lives at `finding.poc = { lang, code, runHint }`. Only `lang === 'js'` is supported in this task; anything else records `reason: 'unsupported poc language'` and leaves the tier alone.

**How proof is observed.** The PoC is written into the sandbox root as `poc.mjs` and run. It signals success by writing a file named `PROVEN` into its working directory. The runner checks for that file — **not** the exit code, because R1's exit codes cannot distinguish a denied run from a clean one.

- [ ] **Step 1: Write the failing test**

```js
// append to scanner/test/execution-proof.test.js
import fs from 'node:fs';
import { proveFinding } from '../src/posture/execution-proof.js';
import { sandboxAvailable } from '../src/sandbox/index.js';

const noSbx = !sandboxAvailable() ? 'skipped: no confinement primitive on this host' : false;

describe('proveFinding', () => {
  test('a PoC that demonstrates the bug is execution-proven', { skip: noSbx }, async () => {
    const f = await proveFinding({
      id: 'a', parser: 'IR-TAINT',
      poc: { lang: 'js', code: `import fs from 'node:fs'; fs.writeFileSync('PROVEN', 'yes');` },
    });
    assert.equal(f.proofTier, 'execution-proven');
    assert.equal(f.proofEvidence.ran, true);
    assert.notEqual(f.proofEvidence.backend, 'disabled');
  });

  test('a PoC that does NOT demonstrate the bug is proof-failed, not dismissed', { skip: noSbx }, async () => {
    const f = await proveFinding({
      id: 'b', parser: 'IR-TAINT',
      poc: { lang: 'js', code: `console.log('nothing to see');` },
    });
    assert.equal(f.proofTier, 'proof-failed');
    // Explicitly NOT a false-positive verdict.
    assert.notEqual(f.proofTier, 'unproven');
  });

  test('a PoC that hangs is timed out and does not become proven', { skip: noSbx }, async () => {
    const f = await proveFinding({
      id: 'c', parser: 'IR-TAINT',
      poc: { lang: 'js', code: `while (true) {}` },
    }, { timeoutMs: 1200 });
    assert.equal(f.proofEvidence.timedOut, true);
    assert.notEqual(f.proofTier, 'execution-proven');
  });

  test('a finding with no PoC is untouched and says why', async () => {
    const f = await proveFinding({ id: 'd', parser: 'IR-TAINT' });
    assert.equal(f.proofTier, 'taint-proven');
    assert.match(f.proofEvidence.reason, /no proof-of-concept/i);
  });

  test('a non-JS PoC records that it is unsupported rather than guessing', async () => {
    const f = await proveFinding({ id: 'e', parser: 'IR-TAINT', poc: { lang: 'php', code: '<?php ?>' } });
    assert.equal(f.proofTier, 'taint-proven');
    assert.match(f.proofEvidence.reason, /unsupported/i);
  });

  test('the sandbox backend is recorded in the evidence', { skip: noSbx }, async () => {
    const f = await proveFinding({ id: 'f', parser: 'IR-TAINT', poc: { lang: 'js', code: `console.log(1);` } });
    assert.ok(typeof f.proofEvidence.backend === 'string' && f.proofEvidence.backend.length > 0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/execution-proof.test.js; echo "EXIT=$?"`
Expected: FAIL — `Cannot find module '../src/posture/execution-proof.js'`

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/execution-proof.js
// Promote a finding to execution-proven by running its proof-of-concept inside
// the confined execution sandbox and observing a real effect.
//
// Proof is a file the PoC writes, NOT an exit code: the sandbox cannot reliably
// distinguish "denied" from "ran and exited 0", so exit status is not evidence.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runConfined, sandboxAvailable, detectBackend } from '../sandbox/index.js';
import { attachProofTier, proofTierOf } from './proof-tier.js';

const PROOF_MARKER = 'PROVEN';

function _evidence(over = {}) {
  return {
    tier: 'taint-proven', backend: detectBackend(), ran: false, observed: null,
    reason: null, exitCode: null, timedOut: false, at: new Date().toISOString(), ...over,
  };
}

export async function proveFinding(finding, { timeoutMs = 10000 } = {}) {
  const poc = finding?.poc;
  if (!poc?.code) {
    return attachProofTier(finding, _evidence({ tier: proofTierOf(finding), reason: 'no proof-of-concept attached' }));
  }
  if (poc.lang !== 'js') {
    return attachProofTier(finding, _evidence({ tier: proofTierOf(finding), reason: `unsupported poc language: ${poc.lang}` }));
  }
  if (!sandboxAvailable()) {
    return attachProofTier(finding, _evidence({ tier: proofTierOf(finding), reason: 'no confinement primitive available; refusing to execute' }));
  }

  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'proof-')));
  try {
    fs.writeFileSync(path.join(root, 'poc.mjs'), poc.code, 'utf8');
    const r = runConfined([process.execPath, 'poc.mjs'], { root, timeoutMs });
    const proven = fs.existsSync(path.join(root, PROOF_MARKER));

    return attachProofTier(finding, _evidence({
      tier: proven ? 'execution-proven' : 'proof-failed',
      backend: r.backend,
      ran: !r.timedOut && r.status !== 'disabled',
      observed: proven ? `proof marker '${PROOF_MARKER}' written by the proof-of-concept` : null,
      reason: proven ? null
        : r.timedOut ? 'proof-of-concept exceeded its time budget'
        : 'proof-of-concept ran but did not demonstrate the predicted effect',
      exitCode: r.exitCode, timedOut: r.timedOut,
    }));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/execution-proof.test.js; echo "EXIT=$?"` → PASS, EXIT=0.
Confirm the sandbox-dependent tests **ran** rather than skipped; if they skipped, report that instead of claiming success.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/execution-proof.js scanner/test/execution-proof.test.js
git commit -m "feat(proof): run a proof-of-concept in the sandbox and record what happened"
```

---

### Task 3: Surface the tier, document it, and gate

**Files:**
- Modify: `scanner/src/report/index.js` (emit `proofTier`/`proofEvidence` when present)
- Create: `scanner/src/posture/CLAUDE.md` entry — append a section (file exists)
- Modify: `docs/ROADMAP.md` (R2 status)
- Test: `scanner/test/execution-proof.test.js` (append)

**Interfaces:** Consumes Tasks 1–2.

- [ ] **Step 1: Write the failing test**

```js
// append to scanner/test/execution-proof.test.js
import { normalizeFindings } from '../src/report/index.js';

describe('report surfacing', () => {
  test('proof tier and evidence survive report normalisation', () => {
    const out = normalizeFindings({ findings: [{
      id: 'z', severity: 'high', file: 'a.js', line: 1, vuln: 'X', cwe: 'CWE-1',
      description: 'd', remediation: 'r', parser: 'IR-TAINT', family: 'f',
      proofTier: 'execution-proven',
      proofEvidence: { tier: 'execution-proven', backend: 'userspace', ran: true, observed: 'marker', reason: null, exitCode: 0, timedOut: false, at: '2026-07-27T00:00:00.000Z' },
    }] });
    const f = out.find(x => x.id === 'z') || out[0];
    assert.equal(f.proofTier, 'execution-proven');
    assert.equal(f.proofEvidence.backend, 'userspace');
  });

  test('a finding without proof fields normalises without inventing them', () => {
    const out = normalizeFindings({ findings: [{
      id: 'y', severity: 'low', file: 'b.js', line: 2, vuln: 'Y', cwe: 'CWE-2',
      description: 'd', remediation: 'r', parser: 'REGEX', family: 'f',
    }] });
    const f = out.find(x => x.id === 'y') || out[0];
    assert.ok(f.proofTier === undefined || f.proofTier === 'unproven');
  });
});
```

- [ ] **Step 2: Run it and confirm it fails for the right reason.** If `normalizeFindings` is not exported under that name, read `scanner/src/report/index.js`, use the real export, and say so in your report — do not invent an API.

Run: `cd scanner && node --test test/execution-proof.test.js; echo "EXIT=$?"`

- [ ] **Step 3: Implement — pass `proofTier` and `proofEvidence` through report normalisation**, alongside the existing `poc` passthrough at `scanner/src/report/index.js:170`. Copy the fields only when present; never synthesise them.

- [ ] **Step 4: Run the test to verify it passes.**

- [ ] **Step 5: Document.** Append a section to `scanner/src/posture/CLAUDE.md` covering: the four tiers and what each means; that proof is observed via a marker file rather than an exit code, and why; that `proof-failed` is a triage signal and **not** a false-positive verdict; and that the backend is recorded because the kernel-namespace backend is unverified and does not confine writes.

- [ ] **Step 6: Full gate.**

```bash
cd scanner && npm run build; echo "BUILD_EXIT=$?"
npm test; echo "TEST_EXIT=$?"
npm run bench:cve-replay:check; echo "CORPUS_EXIT=$?"
npm run bench:self-scan:check; echo "SELFSCAN_EXIT=$?"
```
All four must be 0. If the self-scan gate drifts, **inspect each new finding individually** before touching `BASELINE.json` — a reflexive baseline update turns the precision gate into a rubber stamp.

- [ ] **Step 7: Update `docs/ROADMAP.md` R2 status** with what is verified, on which backend, and what remains (auto-enrolment of proven findings into the corpus is explicitly NOT in this plan — say so).

- [ ] **Step 8: Commit.**

```bash
git add -A
git commit -m "feat(proof): surface proof tier in reports, document the evidence rules"
```

---

## Self-review

**Spec coverage.** "Promote from taint-proven to execution-proven by running the PoC in the sandbox" → Tasks 1–2. "Findings carry the tier explicitly" → Tasks 1 and 3. "Unproven findings are never reported as proven" → Task 1's `ran:false` demotion guard plus its dedicated test. Refusal when no sandbox → Task 2. Backend recorded → Task 2.

**Deliberately out of scope, and stated so the reader is not misled:** auto-enrolment of an execution-proven finding as a corpus entry (the roadmap's stated differentiator) is **not** in this plan. It needs a corpus-entry generator and a `pre:TP post:TN` verification loop, which is its own plan. R2 is not complete until that lands; Task 3 Step 7 must say so in the roadmap rather than marking R2 done.

**Type consistency.** `attachProofTier(finding, evidence) -> finding` and `proofTierOf(finding) -> string` are used identically in Tasks 1–2. The evidence shape is fixed in Task 1 and constructed only via `_evidence()` in Task 2. `runConfined(argv, opts) -> {status, stdout, stderr, exitCode, timedOut, backend}` matches R1's shipped contract.
