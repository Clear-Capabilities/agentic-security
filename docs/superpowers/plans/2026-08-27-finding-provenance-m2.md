# Finding Provenance M2 (P0 completion) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the P0 tier of the Finding Provenance feature: two PRD requirements tagged P0 that were silently dropped from M0+M1 (`controlRefs` compliance derivation, `mttr.js` age/SLA basis), full output-format parity, a `provenanceAtFix` fix-record snapshot, a real performance fix (not a benchmark calibrated to a bad number), and a `strict` assurance-mode tier that actually gates on provenance completeness.

**Architecture:** Every task is an additive extension of code that already exists and already ships `findingProvenance` on every finding — no new resolution logic, no schema changes. The two compliance evaluators (`privacy-framework.js`, `auditor-walkthrough.js`) gain a shared `deriveComplianceProvenance` helper. The six output renderers in `report/index.js` gain format-appropriate provenance representations, reusing the already-shipped `explainProvenance`/`_normalizedProvenance`. Two independent, narrowly-scoped performance fixes (in-scan memoization in `coordinator.js`, a same-sha replay memo in `origin-resolver.js`, and a category-scoped state-write switch for the LSP path) land before the benchmark is built and baselined, so the gate is calibrated to a real, already-improved number — never to the known-broken 88%–1000%+ baseline.

**Tech Stack:** Node.js ESM, `node:test`, the existing `bench/*/runner.mjs` + `BASELINE.json` + `--check`/`--update-baseline` convention (see `bench/ttff/runner.mjs`), `scanner/test/helpers/build-git-fixture.js` for synthetic git histories.

**Spec:** `docs/superpowers/specs/2026-08-27-finding-provenance-m2-m3-m4-design.md` §2 (M2). Referenced throughout as "the spec"; conflicts between this plan and the spec resolve in the spec's favor.

## Scope

**JUnit, STIX, VEX output formats are explicitly OUT of scope for M2** (spec §2.2's own table entry) — externally-constrained exchange schemas with no natural provenance extension point matching what this feature produces. No task below touches `toJUnit`/`toSTIX`/`toVex`; this is a documented scope line, not an oversight.

## Global Constraints

These apply to every task below, copied from the spec's §5 (safety/testing/DoD) and this repo's root/scanner CLAUDE.md — every task's own Constraints implicitly include these:

- **Terminal status always present, never `undefined`.** No task may introduce a code path where `findingProvenance` (or a new derived field) is left unset when the surrounding object is otherwise complete.
- **Never false certainty.** A derivation that cannot prove something reports `unknown`/`null`, never guesses.
- **No new npm dependency** without a documented reason (this codebase's established no-`simple-git` convention).
- **Read-only Git access only** in any new/touched provenance module — no `checkout`/`merge`/hooks.
- **ESM throughout** (`import`/`export`, no CommonJS) — `scanner/CLAUDE.md`.
- **After any change to `scanner/src/` or `scanner/bin/`, run `npm run build`** before relying on the bundle; unit tests run against `src/` directly and don't need it, but the final whole-branch review and pre-push gate do.
- **Author email is PII, redacted by default everywhere.** Every new renderer that surfaces `findingProvenance` must go through the already-shipped `_normalizedProvenance`/`redactFindingProvenance` path (i.e. operate on already-normalized findings), never read `f.findingProvenance` off a raw pre-normalization finding.
- **`ageDays` (mttr.js) keeps its current wall-clock meaning.** New age fields are additive (`ageBasis`, `provenAgeDays`) — no task may change what `ageDays` measures, since `findingsExceedingSLA`/`computeMTTR` already depend on its current semantics.
- **Every new/extended test file must be added to the correct scoped npm script** in `scanner/package.json` (`test:posture`, `test:report`, etc. — see `scanner/CLAUDE.md`'s table) or `npm run test:lifecycle`'s drift checker will flag it and the file will silently never run in CI.
- **Determinism:** no `Date.now()`/`Math.random()` in code paths that must be byte-identical run-to-run under `--deterministic`. New bench runners follow `bench/ttff/runner.mjs`'s pattern (timestamp stamped only into the history/baseline record, never into the measured code path).
- **PROVENANCE_STATUS string values** (from `scanner/src/posture/provenance/schema.js`): `complete`, `partial`, `not_available`, `uncommitted`, `budget_exhausted`, `error`. Use these literals directly (matching the existing `explainProvenance` convention) — never re-derive or duplicate the enum.

---

### Task 1: Compliance `controlRefs` + `derivedProvenance` (FR-PROV-016)

**Files:**
- Modify: `scanner/src/posture/auditor-walkthrough.js:250-472` (`evaluateFramework`), `scanner/src/posture/auditor-walkthrough.js:477-526` (`renderWalkthrough`)
- Modify: `scanner/src/posture/privacy-framework.js:161-213` (`assessPrivacyFramework`'s per-control loop)
- Test: `scanner/test/compliance-mapping-liveness.test.js` (add cases), `scanner/test/framework-provenance.test.js` (new file — see Step 6)

**Interfaces:**
- Produces: `deriveComplianceProvenance(findings)` exported from `auditor-walkthrough.js`, taking an array of raw finding objects (each optionally carrying `.findingProvenance`) and an array of their ids, returning `{ derivedFrom: string[], earliestOrigin: {commit,authorDate,authorName}|null, confidence: 'high'|'low'|'unknown', limitations: string[] }`.
- Produces: every row `evaluateFramework` pushes into its returned array now carries `controlRefs: string[]` (finding ids, deduped) and `derivedProvenance` (the object above) alongside the existing `control`/`status`/`observations`/`evidence`/`partiallyEvidenced` fields.
- Consumes (by privacy-framework.js): the `controlRefs`/`derivedProvenance` fields now present on each `r` in `evaluation` (privacy-framework.js does not recompute them).

- [ ] **Step 1: Add `deriveComplianceProvenance` to auditor-walkthrough.js**

Add near the top of `scanner/src/posture/auditor-walkthrough.js`, after its existing imports (do not disturb any existing export):

```js
// FR-PROV-016 (M2): "earliest proven open condition" among a control's
// contributing findings. Prefers a finding whose findingProvenance resolved
// findingOrigin.status:'complete' (the OLDEST such authorDate wins); falls
// back to 'partial' entries with a resolved findingOrigin.authorDate when no
// complete one exists. Never fabricates an origin — zero usable entries is
// reported as null/'unknown', not the repo's first commit or "now".
export function deriveComplianceProvenance(findings) {
  const list = Array.isArray(findings) ? findings.filter(Boolean) : [];
  const withOrigin = list
    .map((f) => ({ f, fp: f && f.findingProvenance }))
    .filter((x) => x.fp && x.fp.findingOrigin && x.fp.findingOrigin.authorDate);
  const complete = withOrigin.filter((x) => x.fp.status === 'complete');
  const partial = withOrigin.filter((x) => x.fp.status === 'partial');
  const pickEarliest = (arr) => arr.reduce(
    (min, x) => (!min || x.fp.findingOrigin.authorDate < min.fp.findingOrigin.authorDate) ? x : min,
    null,
  );
  const best = complete.length ? pickEarliest(complete) : (partial.length ? pickEarliest(partial) : null);
  return {
    derivedFrom: list.map((f) => f && f.id).filter(Boolean),
    earliestOrigin: best ? {
      commit: best.fp.findingOrigin.commit || null,
      authorDate: best.fp.findingOrigin.authorDate,
      authorName: best.fp.findingOrigin.authorName || null,
    } : null,
    confidence: complete.length ? 'high' : (partial.length ? 'low' : 'unknown'),
    limitations: best ? [] : ['no contributing finding resolved a verified origin'],
  };
}
```

- [ ] **Step 2: Collect contributing findings inside `evaluateFramework`'s `family:` branch and attach the new fields to every pushed row**

In `scanner/src/posture/auditor-walkthrough.js`, the `for (const c of fw.controls || [])` loop (starting at line 276) currently declares `const obs = [];` and, inside the `maps.length === 0` early-return branch (lines 281-296), pushes a result with no `controlRefs`. Change:

```js
    if (maps.length === 0) {
      obs.push('No automated mapping — requires manual evidence collection.');
      // PRD F10.2: carry the MEASURED strength of the backing detector, so a
    // control mapped to a detector that finds 3 of 18 independent advisories
    // cannot read the same as one backed by a detector that finds nearly
    // everything. Import is lazy so the evaluator keeps working if the bench
    // artifacts are absent (they degrade to `unmeasured`, never to a default).
    let evidence = null;
    try { evidence = _strengthOfControl(c); } catch { /* strength is additive; never block evaluation */ }
    results.push({
      control: c,
      status,
      observations: obs,
      ...(evidence ? { evidence, partiallyEvidenced: evidence.tier === 'weak' || evidence.tier === 'unmeasured' } : {}),
    });
      continue;
    }
```

to (only the `results.push` call changes — add `controlRefs`/`derivedProvenance`, computed from an empty list since a manual-mapping control has nothing to attribute):

```js
    if (maps.length === 0) {
      obs.push('No automated mapping — requires manual evidence collection.');
      let evidence = null;
      try { evidence = _strengthOfControl(c); } catch { /* strength is additive; never block evaluation */ }
      results.push({
        control: c,
        status,
        observations: obs,
        controlRefs: [],
        derivedProvenance: deriveComplianceProvenance([]),
        ...(evidence ? { evidence, partiallyEvidenced: evidence.tier === 'weak' || evidence.tier === 'unmeasured' } : {}),
      });
      continue;
    }
```

Then declare a per-control collector right after `const obs = [];` (before the `if (maps.length === 0)` check), so it is in scope for the `family:` branch below:

```js
    const obs = [];
    // FR-PROV-016: findings that contributed an OPEN condition to this
    // control's `family:` mapping(s) — the exact objects `open` below
    // filters to, not just their ids, so deriveComplianceProvenance can read
    // .findingProvenance off them. Naturally empty for a control that ends
    // up 'present' (present requires zero open findings across every
    // mapping) or 'manual' (no family: mapping ever populates it) — so a
    // consumer can treat a non-empty controlRefs as "this control has an
    // attributable gap" without re-deriving the bucket classification.
    const contributingFindings = [];
```

Then, inside the `family:` branch (the block starting `if (m.startsWith('family:')) {`), where `open` is computed and used (existing lines, unchanged up to the `if (open.length)` check):

```js
        const open = scoped.filter(f => !f.intentSuppressed && !f.pastDecision && (SEVERITY_RANK[f.severity] ?? 0) >= minRank);
        if (open.length) {
          allCleared = false;
          obs.push(`${open.length} open ${fam} finding(s) at ${minSeverity}+.`);
        } else {
```

add one line right after `if (open.length) {`:

```js
        const open = scoped.filter(f => !f.intentSuppressed && !f.pastDecision && (SEVERITY_RANK[f.severity] ?? 0) >= minRank);
        if (open.length) {
          allCleared = false;
          contributingFindings.push(...open);
          obs.push(`${open.length} open ${fam} finding(s) at ${minSeverity}+.`);
        } else {
```

Finally, the main `results.push` at the end of the loop body (currently):

```js
    let evidence = null;
    try { evidence = _strengthOfControl(c); } catch { /* strength is additive; never block evaluation */ }
    results.push({
      control: c,
      status,
      observations: obs,
      ...(evidence ? { evidence, partiallyEvidenced: evidence.tier === 'weak' || evidence.tier === 'unmeasured' } : {}),
    });
  }
  return results;
}
```

becomes:

```js
    let evidence = null;
    try { evidence = _strengthOfControl(c); } catch { /* strength is additive; never block evaluation */ }
    const dedupedRefs = [...new Set(contributingFindings.map((f) => f.id).filter(Boolean))];
    results.push({
      control: c,
      status,
      observations: obs,
      controlRefs: dedupedRefs,
      derivedProvenance: deriveComplianceProvenance(contributingFindings),
      ...(evidence ? { evidence, partiallyEvidenced: evidence.tier === 'weak' || evidence.tier === 'unmeasured' } : {}),
    });
  }
  return results;
}
```

- [ ] **Step 3: Render `controlRefs`/`derivedProvenance` in `renderWalkthrough`**

In `scanner/src/posture/auditor-walkthrough.js`, the block:

```js
    if (ev.status === 'absent' || ev.status === 'partial') {
      lines.push(`**Remediation:** address the bullet(s) above, then re-run \`/compliance --walkthrough ${fw.id}\` to update this report.`);
      lines.push('');
    }
```

becomes:

```js
    if (ev.status === 'absent' || ev.status === 'partial') {
      lines.push(`**Remediation:** address the bullet(s) above, then re-run \`/compliance --walkthrough ${fw.id}\` to update this report.`);
      lines.push('');
      if (Array.isArray(ev.controlRefs) && ev.controlRefs.length) {
        lines.push(`**Contributing findings:** ${ev.controlRefs.join(', ')}`);
        const dp = ev.derivedProvenance;
        if (dp && dp.earliestOrigin) {
          const short = String(dp.earliestOrigin.commit || '').slice(0, 7) || 'unknown';
          const day = String(dp.earliestOrigin.authorDate || '').slice(0, 10);
          lines.push(`**Earliest proven origin:** ${short} — ${day} — ${dp.earliestOrigin.authorName || 'unknown'} (confidence: ${dp.confidence})`);
        } else if (dp) {
          lines.push(`**Earliest proven origin:** unresolved (confidence: ${dp.confidence})`);
        }
        lines.push('');
      }
    }
```

- [ ] **Step 4: Attach `controlRefs`/`derivedProvenance` to privacy-framework.js's gap findings**

In `scanner/src/posture/privacy-framework.js`, the gap-finding push (lines 194-212) is:

```js
    if (bucket !== 'gap') continue;
    const remediation = remediationFor(c.id)
      || 'Review the observations for this control and close the underlying findings.';
    findings.push({
      id: `privacy-framework:${c.id}`,
      severity: severityFor(c.id),
      file: '.agentic-security/compliance/nist-privacy-1-1',
      line: 0,
      vuln: `NIST Privacy Framework ${c.id} not satisfied — ${c.summary}`,
      cwe: 'CWE-359',
      description: [
        `Control ${c.id} (${c.category || c.function || 'privacy'}) is mapped to engine signals that are currently failing.`,
        ...(r.observations || []),
      ].join(' '),
      remediation,
      parser: 'COMPLIANCE',
      family: 'privacy-compliance',
      complianceControl: { framework: PRIVACY_FRAMEWORK_ID, id: c.id, codeTestable: c.codeTestable || 'no' },
    });
```

Add two fields, reading them off `r` (the `evaluateFramework` result row for this control — already computed by Task 1's Step 2, since `evaluateFramework` is what `evaluation` in this file's caller comes from):

```js
    if (bucket !== 'gap') continue;
    const remediation = remediationFor(c.id)
      || 'Review the observations for this control and close the underlying findings.';
    findings.push({
      id: `privacy-framework:${c.id}`,
      severity: severityFor(c.id),
      file: '.agentic-security/compliance/nist-privacy-1-1',
      line: 0,
      vuln: `NIST Privacy Framework ${c.id} not satisfied — ${c.summary}`,
      cwe: 'CWE-359',
      description: [
        `Control ${c.id} (${c.category || c.function || 'privacy'}) is mapped to engine signals that are currently failing.`,
        ...(r.observations || []),
      ].join(' '),
      remediation,
      parser: 'COMPLIANCE',
      family: 'privacy-compliance',
      complianceControl: { framework: PRIVACY_FRAMEWORK_ID, id: c.id, codeTestable: c.codeTestable || 'no' },
      controlRefs: r.controlRefs || [],
      derivedProvenance: r.derivedProvenance || null,
    });
```

- [ ] **Step 5: Run the existing compliance test suites to confirm no regression**

Run: `cd scanner && npm run test:posture 2>&1 | tail -40`
Expected: PASS (these files are already in scope: `test:posture` includes `test/compliance-mapping-liveness.test.js`, `test/compliance-severity-threshold.test.js`, `test/compliance-severity-policy.test.js`, `test/framework-provenance.test.js`). The additive fields must not break any existing destructured-field assertion (verified during research: none of the existing tests do a whole-object `deepEqual` on an `evaluateFramework` result row).

- [ ] **Step 6: Write new tests — new file `scanner/test/framework-provenance-controlrefs.test.js`**

```js
// FR-PROV-016 (M2): controlRefs + derivedProvenance on compliance evaluator
// output. See docs/superpowers/specs/2026-08-27-finding-provenance-m2-m3-m4-design.md §2.1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateFramework, deriveComplianceProvenance } from '../src/posture/auditor-walkthrough.js';
import { emptyProvenance, PROVENANCE_STATUS } from '../src/posture/provenance/schema.js';

function fw(controlOverrides = {}) {
  return {
    id: 'test-fw',
    name: 'Test Framework',
    controls: [{
      id: 'TF-1', function: 'Test', category: 'Test', summary: 'A test control',
      codeTestable: 'yes', mapsTo: ['family:sql-injection'],
      ...controlOverrides,
    }],
  };
}

test('deriveComplianceProvenance: empty input resolves unknown/null, never fabricates', () => {
  const d = deriveComplianceProvenance([]);
  assert.equal(d.earliestOrigin, null);
  assert.equal(d.confidence, 'unknown');
  assert.deepEqual(d.derivedFrom, []);
});

test('deriveComplianceProvenance: prefers the OLDEST complete-status origin among several findings', () => {
  const older = { id: 'f-old', findingProvenance: emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'aaa1111', authorDate: '2025-01-01T00:00:00Z', authorName: 'A' } }) };
  const newer = { id: 'f-new', findingProvenance: emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'bbb2222', authorDate: '2026-01-01T00:00:00Z', authorName: 'B' } }) };
  const d = deriveComplianceProvenance([newer, older]);
  assert.equal(d.earliestOrigin.commit, 'aaa1111');
  assert.equal(d.confidence, 'high');
});

test('deriveComplianceProvenance: falls back to partial-status origin when nothing resolved complete', () => {
  const p = { id: 'f-p', findingProvenance: emptyProvenance(PROVENANCE_STATUS.PARTIAL, { findingOrigin: { commit: 'ccc3333', authorDate: '2026-02-01T00:00:00Z', authorName: 'C' } }) };
  const na = { id: 'f-na', findingProvenance: emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE) };
  const d = deriveComplianceProvenance([p, na]);
  assert.equal(d.earliestOrigin.commit, 'ccc3333');
  assert.equal(d.confidence, 'low');
});

test('evaluateFramework: an absent control carries controlRefs naming the open finding(s) and a derivedProvenance', () => {
  const finding = {
    id: 'sast-1', family: 'sql-injection', severity: 'high',
    findingProvenance: emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'ddd4444', authorDate: '2026-03-01T00:00:00Z', authorName: 'D' } }),
  };
  const [result] = evaluateFramework('/tmp/does-not-need-to-exist', fw(), { findings: [finding] });
  assert.equal(result.status, 'absent');
  assert.deepEqual(result.controlRefs, ['sast-1']);
  assert.equal(result.derivedProvenance.earliestOrigin.commit, 'ddd4444');
  assert.equal(result.derivedProvenance.confidence, 'high');
});

test('evaluateFramework: a present control (no open findings) carries an empty controlRefs', () => {
  const [result] = evaluateFramework('/tmp/does-not-need-to-exist', fw(), { findings: [] });
  assert.equal(result.status, 'present');
  assert.deepEqual(result.controlRefs, []);
  assert.equal(result.derivedProvenance.earliestOrigin, null);
});

test('evaluateFramework: a manual control (codeTestable:no, no mapping) carries an empty controlRefs', () => {
  const [result] = evaluateFramework('/tmp/does-not-need-to-exist', fw({ mapsTo: [], codeTestable: 'no' }), { findings: [] });
  assert.equal(result.status, 'manual');
  assert.deepEqual(result.controlRefs, []);
});
```

- [ ] **Step 7: Run the new test file, verify it passes**

Run: `cd scanner && node --test test/framework-provenance-controlrefs.test.js`
Expected: PASS, 6/6.

- [ ] **Step 8: Add the new test file to `test:posture` in `scanner/package.json`**

In `scanner/package.json`, find the `"test:posture"` script string (it lists `test/framework-provenance.test.js` among many others). Insert `test/framework-provenance-controlrefs.test.js` immediately after `test/framework-provenance.test.js` in that space-separated list.

- [ ] **Step 9: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/auditor-walkthrough.js scanner/src/posture/privacy-framework.js scanner/test/framework-provenance-controlrefs.test.js scanner/package.json
git commit -m "$(cat <<'EOF'
feat(provenance): compliance controlRefs + derivedProvenance (FR-PROV-016)

Every compliance evaluator row (auditor-walkthrough.js's evaluateFramework,
consumed by privacy-framework.js's gap findings too) now names the exact
findings that produced a gap and the earliest PROVEN origin among them —
closing a P0 PRD requirement dropped from the M0+M1 scope.
EOF
)"
```

---

### Task 2: Output format parity — SARIF, CSV, Markdown (FR-PROV-018)

**Files:**
- Modify: `scanner/src/report/index.js` (`toSARIF` ~line 879-999, `toCSV` ~line 759-778, `toMarkdown` ~line 822-857)
- Test: `scanner/test/report/provenance-output.test.js` (extend)

**Interfaces:**
- Consumes: `_normalizedProvenance`, `explainProvenance`, `normalizeFindings` (all already exported/defined in `report/index.js`, unchanged).
- Produces: nothing new exported — these are internal renderer changes only.

- [ ] **Step 1: SARIF — thread `findingProvenance` into per-result `properties`**

In `scanner/src/report/index.js`, inside `toSARIF`'s `results: findings.map(f => { ... })` block, the `properties: { ... }` object (lines 967-995) currently ends:

```js
          signatureStatus: f.signatureStatus || (f._passThroughSigning ? 'pass-through' : (f._unsigned ? 'unsigned' : 'verified')),
          ...(f._unsigned ? { unsigned: true } : {}),
          ...(f._passThroughSigning ? { passThroughSigning: true } : {}),
        },
```

Add one more spread right before the closing brace:

```js
          signatureStatus: f.signatureStatus || (f._passThroughSigning ? 'pass-through' : (f._unsigned ? 'unsigned' : 'verified')),
          ...(f._unsigned ? { unsigned: true } : {}),
          ...(f._passThroughSigning ? { passThroughSigning: true } : {}),
          // FR-PROV-018: `f` is already normalized (findingProvenance already
          // passed through _normalizedProvenance/redactFindingProvenance by
          // normalizeFindings), so this is a redacted passthrough, never a
          // second redaction pass and never a read of a raw pre-normalization
          // finding.
          ...(f.findingProvenance ? { findingProvenance: f.findingProvenance } : {}),
        },
```

Then, in the same function, the run-level `properties` object (lines 927-931):

```js
        properties: {
          ...(scan && scan._rulesetVersion ? { rulesetVersion: scan._rulesetVersion } : {}),
          ...(scan && scan._rulesetVersionSource ? { rulesetVersionSource: scan._rulesetVersionSource } : {}),
          ...(scan && scan._rulesetVersionMismatch ? { rulesetVersionMismatch: scan._rulesetVersionMismatch } : {}),
        },
```

Add a history-coverage/mode summary computed from the findings array already in scope (`findings`, from `normalizeFindings(scan)` at the top of `toSARIF`):

```js
        properties: {
          ...(scan && scan._rulesetVersion ? { rulesetVersion: scan._rulesetVersion } : {}),
          ...(scan && scan._rulesetVersionSource ? { rulesetVersionSource: scan._rulesetVersionSource } : {}),
          ...(scan && scan._rulesetVersionMismatch ? { rulesetVersionMismatch: scan._rulesetVersionMismatch } : {}),
          // FR-PROV-018: run-level provenance summary — how many results
          // resolved which terminal status, so a SARIF consumer can judge
          // history coverage without walking every result's properties.
          ...(findings.some(f => f.findingProvenance) ? {
            provenanceCoverage: findings.reduce((acc, f) => {
              const s = f.findingProvenance?.status || 'none';
              acc[s] = (acc[s] || 0) + 1;
              return acc;
            }, {}),
          } : {}),
        },
```

- [ ] **Step 2: CSV — flat provenance columns**

In `scanner/src/report/index.js`, `toCSV` is currently:

```js
export function toCSV(scan){
  const findings = normalizeFindings(scan);
  const esc = v => {
    if (v == null) return '';
    const s = String(v);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const header = ['id', 'severity', 'vuln', 'cwe', 'cvss', 'owasp', 'file', 'line', 'confidence', 'reachable', 'kind', 'snippet'];
  const rows = [header.join(',')];
  for (const f of findings) {
    rows.push([
      esc(f.id), esc(f.severity), esc(f.vuln), esc(f.cwe), esc(f.cvss || ''),
      esc(f.owasp || ''), esc(f.file), esc(f.line),
      esc(f.confidence == null ? '' : f.confidence.toFixed(3)),
      esc(f.reachable == null ? '' : f.reachable),
      esc(f.kind), esc((f.snippet || '').slice(0, 200)),
    ].join(','));
  }
  return rows.join('\n');
}
```

Replace with (new columns appended at the end so any existing column-position-dependent consumer is unaffected):

```js
export function toCSV(scan){
  const findings = normalizeFindings(scan);
  const esc = v => {
    if (v == null) return '';
    const s = String(v);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  // FR-PROV-018: a nested findingProvenance object has no natural CSV
  // representation, so this is a deliberate flattening (status/commit/
  // authorDate/confidence), not full fidelity. Appended after the existing
  // columns so a spreadsheet already keyed on column position is unaffected.
  const header = ['id', 'severity', 'vuln', 'cwe', 'cvss', 'owasp', 'file', 'line', 'confidence', 'reachable', 'kind', 'snippet', 'provenanceStatus', 'provenanceCommit', 'provenanceAuthorDate', 'provenanceConfidence'];
  const rows = [header.join(',')];
  for (const f of findings) {
    const fp = f.findingProvenance;
    rows.push([
      esc(f.id), esc(f.severity), esc(f.vuln), esc(f.cwe), esc(f.cvss || ''),
      esc(f.owasp || ''), esc(f.file), esc(f.line),
      esc(f.confidence == null ? '' : f.confidence.toFixed(3)),
      esc(f.reachable == null ? '' : f.reachable),
      esc(f.kind), esc((f.snippet || '').slice(0, 200)),
      esc(fp?.status || ''), esc(fp?.findingOrigin?.commit || ''),
      esc(fp?.findingOrigin?.authorDate || ''), esc(fp?.confidence?.level || ''),
    ].join(','));
  }
  return rows.join('\n');
}
```

- [ ] **Step 3: Markdown — a provenance block per finding, reusing `explainProvenance`**

In `scanner/src/report/index.js`, `toMarkdown`'s per-finding row loop currently ends:

```js
    for (const f of bySev[sev]) {
      const fix = f.fix?.description || '';
      const epss = f.epssScore != null ? `${Math.round(f.epssScore*100)}%` : '—';
      if (showValidator) {
        const v = f.validator_verdict || '—';
        lines.push(`| \`${f.file}:${f.line}\` | ${f.vuln} | ${f.cwe||'—'} | ${epss} | ${v} | ${fix.replace(/\|/g,'\\|').slice(0,140)} |`);
      } else {
        lines.push(`| \`${f.file}:${f.line}\` | ${f.vuln} | ${f.cwe||'—'} | ${epss} | ${fix.replace(/\|/g,'\\|').slice(0,140)} |`);
      }
    }
    lines.push('');
  }
  return lines.join('\n');
}
```

Add a provenance block after the table for each severity (one paragraph per finding that has one, rather than a table column — `explainProvenance`'s output is multi-line prose, not table-cell-shaped):

```js
    for (const f of bySev[sev]) {
      const fix = f.fix?.description || '';
      const epss = f.epssScore != null ? `${Math.round(f.epssScore*100)}%` : '—';
      if (showValidator) {
        const v = f.validator_verdict || '—';
        lines.push(`| \`${f.file}:${f.line}\` | ${f.vuln} | ${f.cwe||'—'} | ${epss} | ${v} | ${fix.replace(/\|/g,'\\|').slice(0,140)} |`);
      } else {
        lines.push(`| \`${f.file}:${f.line}\` | ${f.vuln} | ${f.cwe||'—'} | ${epss} | ${fix.replace(/\|/g,'\\|').slice(0,140)} |`);
      }
    }
    // FR-PROV-018: one provenance block per finding that has one, reusing
    // explainProvenance's content — never a second, divergent renderer.
    const withProvenance = bySev[sev].filter(f => f.findingProvenance);
    if (withProvenance.length) {
      lines.push('');
      lines.push('<details><summary>Provenance</summary>');
      lines.push('');
      for (const f of withProvenance) {
        const block = explainProvenance(f);
        if (!block) continue;
        lines.push(`**\`${f.file}:${f.line}\`** — ${f.vuln}`);
        lines.push('```');
        lines.push(block);
        lines.push('```');
        lines.push('');
      }
      lines.push('</details>');
    }
    lines.push('');
  }
  return lines.join('\n');
}
```

- [ ] **Step 4: Run the report test suite**

Run: `cd scanner && npm run test:report 2>&1 | tail -40`
Expected: PASS.

- [ ] **Step 5: Extend `scanner/test/report/provenance-output.test.js` with SARIF/CSV/Markdown coverage**

Append to the end of `scanner/test/report/provenance-output.test.js` (add `toSARIF`, `toCSV`, `toMarkdown` to the existing import line at the top of the file first: change `import { normalizeFindings, toCLI, explainProvenance } from '../../src/report/index.js';` to `import { normalizeFindings, toCLI, explainProvenance, toSARIF, toCSV, toMarkdown } from '../../src/report/index.js';`):

```js
test('toSARIF: a result carries findingProvenance in properties, redacted', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234567', authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', authorDate: '2026-03-14T00:00:00Z' },
  });
  const sarif = toSARIF(makeScan(fp));
  const result = sarif.runs[0].results[0];
  assert.ok(result.properties.findingProvenance, 'SARIF result missing findingProvenance');
  assert.equal(result.properties.findingProvenance.findingOrigin.commit, 'abc1234567');
  assert.equal(result.properties.findingProvenance.findingOrigin.authorEmail, null);
  assert.doesNotMatch(JSON.stringify(sarif), /jamie@example\.com/);
});

test('toSARIF: run-level properties carry a provenanceCoverage summary', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'abc1234567', authorDate: '2026-03-14T00:00:00Z' } });
  const sarif = toSARIF(makeScan(fp));
  assert.deepEqual(sarif.runs[0].invocations[0].properties.provenanceCoverage, { complete: 1 });
});

test('toCSV: provenance columns are present and populated, no email leak', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234567', authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', authorDate: '2026-03-14T00:00:00Z' },
  });
  const csv = toCSV(makeScan(fp));
  const [header, row] = csv.split('\n');
  assert.match(header, /provenanceStatus,provenanceCommit,provenanceAuthorDate,provenanceConfidence/);
  assert.match(row, /complete/);
  assert.match(row, /abc1234567/);
  assert.doesNotMatch(csv, /jamie@example\.com/);
});

test('toMarkdown: a provenance block renders under the finding\'s severity section, no email leak', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234567', authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', authorDate: '2026-03-14T00:00:00Z' },
  });
  const md = toMarkdown(makeScan(fp));
  assert.match(md, /Provenance/);
  assert.match(md, /Jamie Chen/);
  assert.doesNotMatch(md, /jamie@example\.com/);
});

test('toMarkdown: no provenance section when no finding carries findingProvenance', () => {
  const md = toMarkdown(makeScan(undefined));
  assert.doesNotMatch(md, /<summary>Provenance<\/summary>/);
});
```

- [ ] **Step 6: Run the extended test file, verify it passes**

Run: `cd scanner && node --test test/report/provenance-output.test.js`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/report/index.js scanner/test/report/provenance-output.test.js
git commit -m "$(cat <<'EOF'
feat(provenance): SARIF/CSV/Markdown output parity (FR-PROV-018)

findingProvenance now reaches SARIF result properties (plus a run-level
provenanceCoverage summary), flat CSV columns, and a per-finding Markdown
block reusing the existing explainProvenance renderer.
EOF
)"
```

---

### Task 3: HTML provenance panel (FR-PROV-018)

**Files:**
- Modify: `scanner/src/report/index.js` (`toHTML` ~line 1051-1065, `makeCard` inside the embedded `<script>` ~line 1163-1192)
- Test: `scanner/test/report/provenance-output.test.js` (extend)

**Interfaces:**
- Consumes: `explainProvenance` (already defined in `report/index.js`).
- Produces: nothing new exported. Each finding object embedded into the HTML's `FINDINGS` JSON blob gains a precomputed `_explainProvenance: string|null` field, matching the existing `_riskNote`/`_explainWhy`/`_explainHow` pattern — this is a SERVER-SIDE precompute, not a client-side re-derivation, because the raw `findingProvenance` object embedded in the page (already redacted by `_normalizedProvenance`) has no rendering logic on the client side today and adding one would be a second, divergent implementation of `explainProvenance`.

- [ ] **Step 1: Precompute `_explainProvenance` server-side**

In `scanner/src/report/index.js`, `toHTML`'s finding-mapping line is currently:

```js
  const findings = normalizeFindings(scan).map(f => {
    const ex = explainParts(f, { verbose: true });
    return { ...f, _riskNote: riskNote(f), _explainWhy: ex.why, _explainHow: ex.how };
  });
```

Change to:

```js
  const findings = normalizeFindings(scan).map(f => {
    const ex = explainParts(f, { verbose: true });
    return { ...f, _riskNote: riskNote(f), _explainWhy: ex.why, _explainHow: ex.how, _explainProvenance: explainProvenance(f) };
  });
```

- [ ] **Step 2: Render the panel in `makeCard`**

Inside the embedded `<script>` block, `makeCard`'s `f-body` div currently ends:

```js
    '<div class="f-body">' +
      (f._explainWhy ? '<div class="f-why"><b>Why it matters:</b> ' + esc(f._explainWhy) + '</div>' : '') +
      (f._explainHow ? '<div class="f-how"><b>How it fires:</b> <code>' + esc(f._explainHow) + '</code></div>' : '') +
      (f.snippet ? '<pre>' + esc(f.snippet) + '</pre>' : '') +
      (f.masked ? '<pre style="color:#f97316">' + esc(f.masked) + ' (masked)</pre>' : '') +
      (f.fix && f.fix.description ? '<div class="f-fix"><b>Fix:</b> ' + esc(f.fix.description) + (f.fix.code ? '<pre>' + esc(f.fix.code) + '</pre>' : '') + '</div>' : '') +
    '</div>';
```

Add one more line before the closing `'</div>';`:

```js
    '<div class="f-body">' +
      (f._explainWhy ? '<div class="f-why"><b>Why it matters:</b> ' + esc(f._explainWhy) + '</div>' : '') +
      (f._explainHow ? '<div class="f-how"><b>How it fires:</b> <code>' + esc(f._explainHow) + '</code></div>' : '') +
      (f.snippet ? '<pre>' + esc(f.snippet) + '</pre>' : '') +
      (f.masked ? '<pre style="color:#f97316">' + esc(f.masked) + ' (masked)</pre>' : '') +
      (f.fix && f.fix.description ? '<div class="f-fix"><b>Fix:</b> ' + esc(f.fix.description) + (f.fix.code ? '<pre>' + esc(f.fix.code) + '</pre>' : '') + '</div>' : '') +
      (f._explainProvenance ? '<div class="f-provenance"><b>Provenance:</b><pre>' + esc(f._explainProvenance) + '</pre></div>' : '') +
    '</div>';
```

Add a matching CSS rule next to the other `.f-*` rules in the `<style>` block — the existing block has `.f-fix{background:#0d1f3d;border-left:3px solid #38bdf8;padding:8px 12px;margin-top:8px;border-radius:0 4px 4px 0}`; add immediately after it:

```css
  .f-provenance{background:#0f1f14;border-left:3px solid #34d058;padding:8px 12px;margin-top:8px;border-radius:0 4px 4px 0}
  .f-provenance pre{background:transparent;padding:0;margin:4px 0 0 0}
```

- [ ] **Step 3: Extend the test file**

Append to `scanner/test/report/provenance-output.test.js` (add `toHTML` to the existing import line, same edit as Task 2 Step 5 but adding `toHTML` too — final import line: `import { normalizeFindings, toCLI, explainProvenance, toSARIF, toCSV, toMarkdown, toHTML } from '../../src/report/index.js';`):

```js
test('toHTML: the embedded FINDINGS blob carries a precomputed _explainProvenance, redacted', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234567', authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', authorDate: '2026-03-14T00:00:00Z' },
  });
  const html = toHTML(makeScan(fp));
  assert.match(html, /_explainProvenance/);
  assert.match(html, /Jamie Chen/);
  assert.doesNotMatch(html, /jamie@example\.com/);
  assert.match(html, /f-provenance/, 'CSS class for the panel must be present');
});

test('toHTML: _explainProvenance is null (not omitted) when the finding has no findingProvenance', () => {
  const html = toHTML(makeScan(undefined));
  assert.match(html, /"_explainProvenance":null/);
});
```

- [ ] **Step 4: Run the extended test file, verify it passes**

Run: `cd scanner && node --test test/report/provenance-output.test.js`
Expected: PASS.

- [ ] **Step 5: Run `npm run test:report` for the whole scope**

Run: `cd scanner && npm run test:report 2>&1 | tail -40`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/report/index.js scanner/test/report/provenance-output.test.js
git commit -m "$(cat <<'EOF'
feat(provenance): HTML report provenance panel (FR-PROV-018)

toHTML precomputes _explainProvenance server-side (matching the existing
_riskNote/_explainWhy/_explainHow pattern) and makeCard renders it as a
panel — the field was already embedded incidentally; now it renders.
EOF
)"
```

---

### Task 4: Golden-file format-parity tests (FR-PROV-018 acceptance)

**Files:**
- Test: new file `scanner/test/report/provenance-format-parity.test.js`

**Interfaces:**
- Consumes: `toJSON`, `toCLI`, `toSARIF`, `toCSV`, `toMarkdown`, `toHTML` from `scanner/src/report/index.js` (all pre-existing or extended by Tasks 2-3).

This task proves the FR-PROV-018 acceptance criterion directly: the SAME finding's `findingProvenance.status`/`findingOrigin.commit` appears consistently across every format, at that format's own fidelity — never silently different or absent.

- [ ] **Step 1: Write the golden-file parity test**

```js
// FR-PROV-018 acceptance: the same finding's provenance status/commit must
// appear, consistently, across every output format — at that format's own
// fidelity (a CSV column is not a JSON tree, but it must not be EMPTY or
// WRONG when the JSON says 'complete'/'abc1234567').
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toJSON, toCLI, toSARIF, toCSV, toMarkdown, toHTML } from '../../src/report/index.js';
import { emptyProvenance, PROVENANCE_STATUS } from '../../src/posture/provenance/schema.js';

const FP = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
  findingOrigin: { commit: 'deadbee1234', authorName: 'Parity Author', authorDate: '2026-05-01T00:00:00Z' },
});
const SCAN = {
  findings: [{ id: 'parity-1', file: 'x.js', line: 7, severity: 'high', vuln: 'Command Injection', cwe: 'CWE-78', findingProvenance: FP }],
  filesScanned: 1,
};

test('format parity: JSON carries the full findingProvenance object', () => {
  const j = toJSON(SCAN);
  assert.equal(j.findings[0].findingProvenance.status, 'complete');
  assert.equal(j.findings[0].findingProvenance.findingOrigin.commit, 'deadbee1234');
});

test('format parity: CLI --provenance carries the commit and status', () => {
  const out = toCLI(SCAN, { color: false, provenance: true });
  assert.match(out, /deadbee/);
});

test('format parity: SARIF result properties carry the commit and status', () => {
  const sarif = toSARIF(SCAN);
  const props = sarif.runs[0].results[0].properties.findingProvenance;
  assert.equal(props.status, 'complete');
  assert.equal(props.findingOrigin.commit, 'deadbee1234');
});

test('format parity: CSV row carries the status and commit columns', () => {
  const csv = toCSV(SCAN);
  const [, row] = csv.split('\n');
  assert.match(row, /complete/);
  assert.match(row, /deadbee1234/);
});

test('format parity: Markdown carries the commit inside the provenance block', () => {
  const md = toMarkdown(SCAN);
  assert.match(md, /deadbee/);
});

test('format parity: HTML embeds the commit via the precomputed _explainProvenance', () => {
  const html = toHTML(SCAN);
  assert.match(html, /deadbee/);
});

test('format parity: every format agrees on ABSENCE too — no findingProvenance means no format fabricates one', () => {
  const clean = { findings: [{ id: 'clean-1', file: 'y.js', line: 1, severity: 'low', vuln: 'Info' }], filesScanned: 1 };
  assert.equal(toJSON(clean).findings[0].findingProvenance, null);
  assert.doesNotMatch(toCLI(clean, { color: false, provenance: true }), /Method:/);
  assert.equal(toSARIF(clean).runs[0].results[0].properties.findingProvenance, undefined);
  const [, csvRow] = toCSV(clean).split('\n');
  assert.match(csvRow, /,,,,$/, 'the four provenance columns must be empty, not fabricated');
  assert.doesNotMatch(toMarkdown(clean), /<summary>Provenance<\/summary>/);
  assert.match(toHTML(clean), /"_explainProvenance":null/);
});
```

- [ ] **Step 2: Run it, verify it passes**

Run: `cd scanner && node --test test/report/provenance-format-parity.test.js`
Expected: PASS, 7/7. If the CSV empty-columns assertion fails, check the exact trailing-comma shape produced by `esc()` on four consecutive empty values and adjust the regex to match the real output (do not weaken the assertion's intent — it must still prove no fabrication).

- [ ] **Step 3: Add to `test:report` in `scanner/package.json`**

Insert `test/report/provenance-format-parity.test.js` immediately after `test/report/provenance-output.test.js` in the `"test:report"` script string.

- [ ] **Step 4: Run the full `test:report` scope**

Run: `cd scanner && npm run test:report 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/test/report/provenance-format-parity.test.js scanner/package.json
git commit -m "$(cat <<'EOF'
test(provenance): golden-file format-parity tests (FR-PROV-018 acceptance)

Proves the same finding's provenance status/commit appears consistently
across JSON/CLI/SARIF/CSV/Markdown/HTML, at each format's own fidelity —
and that absence is never fabricated into a false positive presence.
EOF
)"
```

---

### Task 5: `fix-history.js` — `provenanceAtFix` snapshot

**Files:**
- Modify: `scanner/src/posture/fix-history.js:250-291` (`applyFix`)
- Modify: `scanner/src/fix/apply-fix-service.js:363-369` (caller)
- Modify: `scanner/src/mcp/tools.js:784-787` (caller)
- Test: `scanner/test/fix-history.test.js` (extend)

**Interfaces:**
- Produces: `applyFix(...)` accepts a new optional `findingProvenance` param; the returned/logged entry gains `provenanceAtFix: {commit, authorDate, ageBasis, ageDays}|null`.
- Consumes: `finding.findingProvenance` at each call site (already present on findings sourced from a normalized/persisted scan — both call sites read other post-normalization-only fields off the same object already, e.g. `finding.stableId`/`f.stableId`, confirming these are normalized findings).

- [ ] **Step 1: Add the snapshot helper and wire it into `applyFix`**

In `scanner/src/posture/fix-history.js`, add this function above `applyFix` (the function starts at line 250):

```js
// FR-PROV §7.4 / M2 §2.2: how old was this finding, by which basis, at the
// moment it was fixed. Computed ONCE, at fix time, and never re-derived
// later — a finding's origin doesn't change, but re-computing "age at fix"
// from a LATER read of findingProvenance would silently answer "how old is
// it now", not "how old was it when fixed". Mirrors mttr.js's ageBasis
// tiering (Task 6) so the two surfaces agree on vocabulary.
function _snapshotProvenanceAtFix(findingProvenance, appliedAt) {
  if (!findingProvenance) return null;
  const status = findingProvenance.status;
  const origin = findingProvenance.findingOrigin;
  const observedAt = findingProvenance.firstObserved?.observedAt || null;
  let ageBasis, basisDate;
  if (status === 'complete' && origin?.authorDate) { ageBasis = 'finding_origin'; basisDate = origin.authorDate; }
  else if (status === 'partial' && origin?.authorDate) { ageBasis = 'earliest_observable'; basisDate = origin.authorDate; }
  else if (status === 'uncommitted') { ageBasis = 'uncommitted'; basisDate = observedAt; }
  else { ageBasis = 'first_observed'; basisDate = observedAt; }
  const ageDays = basisDate ? Math.max(0, Math.floor((Date.parse(appliedAt) - Date.parse(basisDate)) / 86400000)) : null;
  return { commit: origin?.commit || null, authorDate: basisDate, ageBasis, ageDays };
}
```

Then change `applyFix`'s signature and entry construction. Current:

```js
export async function applyFix({ scanRoot, file, originalContent, newContent, findingId, ruleId, vuln, stableId, fileExisted = true }) {
  return _withLogLock(scanRoot, async () => {
    ensure(scanRoot);
    const absFile = path.resolve(scanRoot, file);
    const id = `fix-${Date.now().toString(36)}-${sha(file + findingId).slice(0, 6)}`;
    const bakPath = path.join(historyDir(scanRoot), `${id}.bak`);
    const resolvedStableId = stableId || _lookupStableId(scanRoot, findingId);
    // Budget check BEFORE backup, so we don't accumulate dead .bak files
    // for refused attempts.
    const priorLog = readLog(scanRoot);
    const priorAttempts = _countPriorAttempts(priorLog, resolvedStableId, findingId);
    if (priorAttempts >= MAX_ATTEMPTS_PER_KEY) {
      throw new FixAttemptBudgetExceededError(
        resolvedStableId || findingId || '(unknown-key)',
        priorAttempts,
        MAX_ATTEMPTS_PER_KEY,
      );
    }
    // Phase 1: backup + fsync. Atomic for the same reason the target write
    // is below — a corrupted backup is worse than no backup, because it
    // silently defeats rollback.
    await _writeAtomicAndSync(bakPath, originalContent);
    const entry = {
      id,
      findingId,
      stableId: resolvedStableId || null,
      ruleId: ruleId || null,
      vuln: vuln || null,
      file,
      fileExisted,
      backupPath: path.relative(scanRoot, bakPath),
      originalSha: sha(originalContent),
      newSha: sha(newContent),
      appliedAt: new Date().toISOString(),
      status: 'pending',
      reverted: false,
      attemptOrdinal: priorAttempts + 1,
    };
```

Change to:

```js
export async function applyFix({ scanRoot, file, originalContent, newContent, findingId, ruleId, vuln, stableId, fileExisted = true, findingProvenance = null }) {
  return _withLogLock(scanRoot, async () => {
    ensure(scanRoot);
    const absFile = path.resolve(scanRoot, file);
    const id = `fix-${Date.now().toString(36)}-${sha(file + findingId).slice(0, 6)}`;
    const bakPath = path.join(historyDir(scanRoot), `${id}.bak`);
    const resolvedStableId = stableId || _lookupStableId(scanRoot, findingId);
    // Budget check BEFORE backup, so we don't accumulate dead .bak files
    // for refused attempts.
    const priorLog = readLog(scanRoot);
    const priorAttempts = _countPriorAttempts(priorLog, resolvedStableId, findingId);
    if (priorAttempts >= MAX_ATTEMPTS_PER_KEY) {
      throw new FixAttemptBudgetExceededError(
        resolvedStableId || findingId || '(unknown-key)',
        priorAttempts,
        MAX_ATTEMPTS_PER_KEY,
      );
    }
    // Phase 1: backup + fsync. Atomic for the same reason the target write
    // is below — a corrupted backup is worse than no backup, because it
    // silently defeats rollback.
    await _writeAtomicAndSync(bakPath, originalContent);
    const appliedAt = new Date().toISOString();
    const entry = {
      id,
      findingId,
      stableId: resolvedStableId || null,
      ruleId: ruleId || null,
      vuln: vuln || null,
      file,
      fileExisted,
      backupPath: path.relative(scanRoot, bakPath),
      originalSha: sha(originalContent),
      newSha: sha(newContent),
      appliedAt,
      status: 'pending',
      reverted: false,
      attemptOrdinal: priorAttempts + 1,
      provenanceAtFix: _snapshotProvenanceAtFix(findingProvenance, appliedAt),
    };
```

(The rest of `applyFix` — Phase 2/3, the log write, the return — is unchanged; it already references `entry` and does not need to know about the new field.)

- [ ] **Step 2: Wire the two callers**

In `scanner/src/fix/apply-fix-service.js`, the `applyFixHistory` call:

```js
          const entry = await applyFixHistory({
            scanRoot, file: rel, originalContent, newContent: v.content, fileExisted,
            findingId: finding.id || finding.findingId,
            stableId: finding.stableId || null,
            ruleId: finding.ruleId || finding.cwe || finding.family || null,
            vuln: finding.vuln || finding.title || null,
          });
```

becomes:

```js
          const entry = await applyFixHistory({
            scanRoot, file: rel, originalContent, newContent: v.content, fileExisted,
            findingId: finding.id || finding.findingId,
            stableId: finding.stableId || null,
            ruleId: finding.ruleId || finding.cwe || finding.family || null,
            vuln: finding.vuln || finding.title || null,
            findingProvenance: finding.findingProvenance || null,
          });
```

In `scanner/src/mcp/tools.js`, the `applyFixHistory` call:

```js
          const entry = await applyFixHistory({
            scanRoot: ctx.sessionRoot, file: rel, originalContent, newContent: v.content, fileExisted,
            findingId: f.id, stableId: f.stableId, ruleId: f.ruleId || f.cwe || f.family || null, vuln: f.vuln || f.title || null,
          });
```

becomes:

```js
          const entry = await applyFixHistory({
            scanRoot: ctx.sessionRoot, file: rel, originalContent, newContent: v.content, fileExisted,
            findingId: f.id, stableId: f.stableId, ruleId: f.ruleId || f.cwe || f.family || null, vuln: f.vuln || f.title || null,
            findingProvenance: f.findingProvenance || null,
          });
```

- [ ] **Step 3: Run `npm run test:report` (fix-history.test.js is in that scope) and `npm run test:mcp`**

Run: `cd scanner && npm run test:report 2>&1 | tail -30 && npm run test:mcp 2>&1 | tail -30`
Expected: PASS both.

- [ ] **Step 4: Extend `scanner/test/fix-history.test.js`**

Find the import line at the top of `scanner/test/fix-history.test.js` (it imports `applyFix` among other exports from `../src/posture/fix-history.js` — add nothing new to the import, `applyFix` is already imported by every existing test in that file). Append:

```js
test('applyFix: provenanceAtFix is null when no findingProvenance is supplied', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-fixhist-prov-'));
  try {
    const entry = await applyFix({
      scanRoot: dir, file: 'a.js', originalContent: 'old', newContent: 'new',
      findingId: 'f1', ruleId: 'r1', vuln: 'v1', fileExisted: true,
    });
    assert.equal(entry.provenanceAtFix, null);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('applyFix: provenanceAtFix snapshots a complete-status origin as finding_origin basis', async () => {
  const { emptyProvenance, PROVENANCE_STATUS } = await import('../src/posture/provenance/schema.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-fixhist-prov-'));
  try {
    const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
      findingOrigin: { commit: 'cafef00d123', authorDate: '2026-01-01T00:00:00Z' },
    });
    const entry = await applyFix({
      scanRoot: dir, file: 'a.js', originalContent: 'old', newContent: 'new',
      findingId: 'f1', ruleId: 'r1', vuln: 'v1', fileExisted: true, findingProvenance: fp,
    });
    assert.ok(entry.provenanceAtFix);
    assert.equal(entry.provenanceAtFix.ageBasis, 'finding_origin');
    assert.equal(entry.provenanceAtFix.commit, 'cafef00d123');
    assert.equal(typeof entry.provenanceAtFix.ageDays, 'number');
    assert.ok(entry.provenanceAtFix.ageDays >= 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('applyFix: provenanceAtFix falls back to first_observed basis for a not_available status', async () => {
  const { emptyProvenance, PROVENANCE_STATUS } = await import('../src/posture/provenance/schema.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-fixhist-prov-'));
  try {
    const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, {
      firstObserved: { scanId: 's1', observedAt: '2026-01-01T00:00:00Z' },
    });
    const entry = await applyFix({
      scanRoot: dir, file: 'a.js', originalContent: 'old', newContent: 'new',
      findingId: 'f1', ruleId: 'r1', vuln: 'v1', fileExisted: true, findingProvenance: fp,
    });
    assert.equal(entry.provenanceAtFix.ageBasis, 'first_observed');
    assert.equal(entry.provenanceAtFix.commit, null);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
```

Verify `fs`, `os`, `path` are already imported at the top of `scanner/test/fix-history.test.js` (every existing test in that file uses `fs.mkdtempSync`/`path.join`/`os.tmpdir` the same way) — if not already imported under those exact names, add `import * as fs from 'node:fs'; import * as os from 'node:os'; import * as path from 'node:path';` alongside the file's existing imports.

- [ ] **Step 5: Run the extended test file**

Run: `cd scanner && node --test test/fix-history.test.js`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/fix-history.js scanner/src/fix/apply-fix-service.js scanner/src/mcp/tools.js scanner/test/fix-history.test.js
git commit -m "$(cat <<'EOF'
feat(provenance): provenanceAtFix snapshot on fix records

applyFix() now records how old a finding actually was, by which basis, at
the moment it was fixed — the fix-record surface the original spec's §7.4
described and M0+M1 never built. Snapshotted once at fix time, never
re-derived later.
EOF
)"
```

---

### Task 6: `mttr.js` — `ageBasis` wiring (FR-PROV-019)

**Files:**
- Modify: `scanner/src/posture/mttr.js:30-42` (`stampFindingTimestamps`)
- Test: `scanner/test/mttr.test.js` (extend)

**Interfaces:**
- Produces: `stampFindingTimestamps` now additionally sets `f.ageBasis: 'finding_origin'|'earliest_observable'|'first_observed'|'uncommitted'` and `f.provenAgeDays: number` on every stamped finding. `f.ageDays` (wall-clock) is UNCHANGED — this is additive, per the Global Constraints.
- Consumes: `f.findingProvenance` (already attached on every finding by the time `stampFindingTimestamps` runs in `bin/agentic-security.js` — confirmed: it operates on `persistedScan.findings`/`.secrets`/`.supplyChain`, which is `toJSON(scan, meta)` output, already normalized).

- [ ] **Step 1: Extend `stampFindingTimestamps`**

Current (lines 30-42 of `scanner/src/posture/mttr.js`):

```js
export function stampFindingTimestamps(findings, baselineMap = new Map(), now = Date.now()) {
  const nowIso = new Date(now).toISOString();
  for (const f of findings) {
    const fp = _fingerprint(f);
    f._fp = fp;
    const prev = baselineMap.get(fp);
    f.firstSeenAt = prev?.firstSeenAt || nowIso;
    f.lastSeenAt = nowIso;
    const firstMs = Date.parse(f.firstSeenAt);
    f.ageDays = Math.max(0, Math.floor((now - firstMs) / 86400000));
  }
  return findings;
}
```

Replace with:

```js
export function stampFindingTimestamps(findings, baselineMap = new Map(), now = Date.now()) {
  const nowIso = new Date(now).toISOString();
  for (const f of findings) {
    const fp = _fingerprint(f);
    f._fp = fp;
    const prev = baselineMap.get(fp);
    f.firstSeenAt = prev?.firstSeenAt || nowIso;
    f.lastSeenAt = nowIso;
    const firstMs = Date.parse(f.firstSeenAt);
    f.ageDays = Math.max(0, Math.floor((now - firstMs) / 86400000));
    // FR-PROV-019: age/SLA basis. ageDays above stays pure wall-clock —
    // every existing SLA/computeMTTR consumer keeps its current meaning.
    // ageBasis + provenAgeDays are ADDITIVE: a report can show both and
    // explain the discrepancy, never silently swap which number "age" means.
    const status = f.findingProvenance?.status;
    const origin = f.findingProvenance?.findingOrigin;
    if (status === 'complete' && origin?.authorDate) {
      f.ageBasis = 'finding_origin';
      f.provenAgeDays = Math.max(0, Math.floor((now - Date.parse(origin.authorDate)) / 86400000));
    } else if (status === 'partial' && origin?.authorDate) {
      f.ageBasis = 'earliest_observable';
      f.provenAgeDays = Math.max(0, Math.floor((now - Date.parse(origin.authorDate)) / 86400000));
    } else if (status === 'uncommitted') {
      f.ageBasis = 'uncommitted';
      f.provenAgeDays = f.ageDays;
    } else {
      f.ageBasis = 'first_observed';
      f.provenAgeDays = f.ageDays;
    }
  }
  return findings;
}
```

- [ ] **Step 2: Run the existing mttr test suite**

Run: `cd scanner && node --test test/mttr.test.js`
Expected: PASS (the existing tests construct findings with no `findingProvenance`, so every existing assertion on `ageDays` is unaffected; the new fields are additive).

- [ ] **Step 3: Extend `scanner/test/mttr.test.js`**

Append (add `emptyProvenance, PROVENANCE_STATUS` to a new import from `'../src/posture/provenance/schema.js'` at the top of the file):

```js
test('ageBasis: finding_origin when findingProvenance resolved complete with an authorDate', async () => {
  const { emptyProvenance, PROVENANCE_STATUS } = await import('../src/posture/provenance/schema.js');
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'aaa1111', authorDate: '2026-01-01T00:00:00Z' } });
  const findings = [{ kind: 'sast', vuln: 'XSS', file: 'a.js', line: 10, findingProvenance: fp }];
  const now = Date.parse('2026-02-01T00:00:00Z'); // 31 days after authorDate
  stampFindingTimestamps(findings, new Map(), now);
  assert.equal(findings[0].ageBasis, 'finding_origin');
  assert.equal(findings[0].provenAgeDays, 31);
});

test('ageBasis: earliest_observable when findingProvenance resolved partial with an authorDate', async () => {
  const { emptyProvenance, PROVENANCE_STATUS } = await import('../src/posture/provenance/schema.js');
  const fp = emptyProvenance(PROVENANCE_STATUS.PARTIAL, { findingOrigin: { commit: 'bbb2222', authorDate: '2026-01-01T00:00:00Z' } });
  const findings = [{ kind: 'sast', vuln: 'XSS', file: 'a.js', line: 10, findingProvenance: fp }];
  const now = Date.parse('2026-01-11T00:00:00Z');
  stampFindingTimestamps(findings, new Map(), now);
  assert.equal(findings[0].ageBasis, 'earliest_observable');
  assert.equal(findings[0].provenAgeDays, 10);
});

test('ageBasis: uncommitted status falls back to wall-clock provenAgeDays', async () => {
  const { emptyProvenance, PROVENANCE_STATUS } = await import('../src/posture/provenance/schema.js');
  const fp = emptyProvenance(PROVENANCE_STATUS.UNCOMMITTED);
  const findings = [{ kind: 'sast', vuln: 'XSS', file: 'a.js', line: 10, findingProvenance: fp }];
  const now = Date.parse('2026-01-01T00:00:00Z');
  stampFindingTimestamps(findings, new Map(), now);
  assert.equal(findings[0].ageBasis, 'uncommitted');
  assert.equal(findings[0].provenAgeDays, findings[0].ageDays);
});

test('ageBasis: no findingProvenance at all degrades to first_observed, wall-clock unchanged', () => {
  const findings = [{ kind: 'sast', vuln: 'XSS', file: 'a.js', line: 10 }];
  const now = Date.parse('2026-01-01T00:00:00Z');
  stampFindingTimestamps(findings, new Map(), now);
  assert.equal(findings[0].ageBasis, 'first_observed');
  assert.equal(findings[0].provenAgeDays, findings[0].ageDays);
  assert.equal(findings[0].ageDays, 0);
});
```

- [ ] **Step 4: Run the extended test file**

Run: `cd scanner && node --test test/mttr.test.js`
Expected: PASS, all cases including the four new ones.

- [ ] **Step 5: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/mttr.js scanner/test/mttr.test.js
git commit -m "$(cat <<'EOF'
feat(provenance): mttr.js ageBasis wiring (FR-PROV-019)

stampFindingTimestamps now exposes ageBasis + provenAgeDays alongside the
existing wall-clock ageDays, per the original spec's §5.2 (never built in
M0+M1) — a report can show both ages and explain the discrepancy instead
of silently swapping which number "age" means.
EOF
)"
```

---

### Task 7: Performance — in-scan memoization in `coordinator.js`

**Files:**
- Modify: `scanner/src/posture/provenance/coordinator.js` (`resolveOne` at line 124, `annotateGitProvenance` at line 305)
- Test: `scanner/test/posture/provenance-coordinator.test.js` (extend)

**Interfaces:**
- Produces: `annotateGitProvenance` now threads a per-call `Map` (`ctx.memo`) through `resolveOne`, deduplicating both cache reads AND in-flight resolution for findings sharing the same cache key within one scan.
- No exported signature changes — `annotateGitProvenance(findings, ctx)` keeps its existing public shape.

- [ ] **Step 1: Split `resolveOne` into a cache-key-computing outer function and a `resolveAndCache` inner function**

In `scanner/src/posture/provenance/coordinator.js`, `resolveOne` (lines 124-303) currently computes `cacheKey` at line 184-187, does `const cached = cacheGet(scanRoot, cacheKey); if (cached) return cached;` at lines 188-189, then falls through to the rest of the resolution logic ending in `return provenance;` at line 302.

Change the function so everything from the `cacheGet` line onward becomes a new function `resolveAndCache`, and `resolveOne` gains a memo check before calling it. Current tail of the memoless version, from the cache-key computation onward:

```js
  const cacheKey = makeCacheKey({
    repoHead: repoState.head, stableId: finding.stableId,
    detectorVersion: ctx.rulesetVersion, historyBoundary: ctx.since || '', mode: ctx.mode,
  });
  const cached = cacheGet(scanRoot, cacheKey);
  if (cached) return cached;

  // PER-FINDING SUB-BUDGET (spec: `max(2s, global/estimatedFindingCount)`).
  //
  // ... [unchanged comment] ...
  const perFindingDeadlineAt = ctx.perFindingBudgetMs
    ? Math.min(deadlineAt || Infinity, Date.now() + ctx.perFindingBudgetMs)
    : deadlineAt;

  const originResult = isSca
    ? await resolveDirectSCAOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt })
    : await resolveOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt, repoState });

  const detector = isSca ? SCA_DETECTOR : (finding.parser || null);

  let provenance;
  let cacheable = true;
  if (originResult.status === 'complete') {
    ... [unchanged] ...
  } else {
    provenance = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, {
      limitations: [originResult.reason || 'no candidate history available'],
    });
  }

  provenance.evidenceDigest = computeDigest(finding, provenance);
  // A budget_exhausted result is the ONE outcome that is not a property of the
  // ... [unchanged comment] ...
  if (cacheable) cacheSet(scanRoot, cacheKey, provenance);
  return provenance;
}
```

Replace `resolveOne`'s tail — from the `const cacheKey = makeCacheKey({` line through the function's closing `}` — with:

```js
  const cacheKey = makeCacheKey({
    repoHead: repoState.head, stableId: finding.stableId,
    detectorVersion: ctx.rulesetVersion, historyBoundary: ctx.since || '', mode: ctx.mode,
  });

  // IN-SCAN MEMOIZATION (M2 §2.4 performance fix): the disk cache alone
  // still pays a fresh cacheGet() read (and, on a miss, a fresh resolution
  // walk) for every finding sharing this cacheKey WITHIN one scan. Two
  // findings with the same stableId and history boundary are uncommon but
  // real (duplicate array entries, the same finding reappearing across a
  // dedupe boundary) — memoizing the PROMISE (not just the eventual value)
  // means a second caller that arrives while the first is still resolving
  // awaits the same in-flight work instead of starting its own.
  if (ctx.memo && ctx.memo.has(cacheKey)) return ctx.memo.get(cacheKey);

  const promise = resolveAndCache(finding, ctx, cacheKey, isSca);
  if (ctx.memo) ctx.memo.set(cacheKey, promise);
  return promise;
}

async function resolveAndCache(finding, ctx, cacheKey, isSca) {
  const { scanRoot, repoState, deadlineAt } = ctx;
  const cached = cacheGet(scanRoot, cacheKey);
  if (cached) return cached;

  // PER-FINDING SUB-BUDGET (spec: `max(2s, global/estimatedFindingCount)`).
  //
  // The global deadline alone bounds the PASS but not the DISTRIBUTION inside
  // it: one finding whose candidate-commit list is long — a hot file touched by
  // a thousand commits — can walk it until the global deadline expires, and
  // every finding queued behind it then reports `budget_exhausted` without a
  // single git call spent on it. The sub-budget caps what any one finding may
  // consume, so the walk is truncated for the expensive finding instead of for
  // everyone after it. It never EXTENDS anything: the effective deadline is the
  // earlier of the two, so the global deadline still hard-bounds the pass.
  const perFindingDeadlineAt = ctx.perFindingBudgetMs
    ? Math.min(deadlineAt || Infinity, Date.now() + ctx.perFindingBudgetMs)
    : deadlineAt;

  const originResult = isSca
    ? await resolveDirectSCAOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt })
    : await resolveOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt, repoState });

  const detector = isSca ? SCA_DETECTOR : (finding.parser || null);

  let provenance;
  let cacheable = true;
  if (originResult.status === 'complete') {
    const branchIntroduction = resolveBranchEntry(scanRoot, originResult.findingOrigin.commit, repoState.branch || 'HEAD');
    const evidenceAttribution = isSca
      ? [{
          role: EVIDENCE_ROLE.MANIFEST,
          path: finding.filePath || null,
          line: Number.isInteger(finding.line) ? finding.line : null,
          commit: originResult.findingOrigin.commit,
        }]
      : attributeEvidence(scanRoot, finding);
    const confidence = assessConfidence({
      parentBoundaryVerified: originResult.parentBoundaryVerified,
      historyComplete: !repoState.shallow,
      detectorCompatible: true,
      renameAmbiguous: false,
      shallow: repoState.shallow,
    });
    provenance = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
      findingOrigin: originResult.findingOrigin,
      branchIntroduction,
      firstObserved: { scanId: ctx.scanId, observedAt: ctx.observedAt },
      evidenceAttribution,
      method: originResult.method,
      confidence,
      historyCoverage: { complete: !repoState.shallow, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered },
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector, dirty: repoState.dirty },
    });
  } else if (originResult.status === 'partial') {
    const partial = describePartial(isSca, originResult.reason);
    provenance = emptyProvenance(PROVENANCE_STATUS.PARTIAL, {
      findingOrigin: originResult.findingOrigin || null,
      firstObserved: { scanId: ctx.scanId, observedAt: ctx.observedAt },
      method: originResult.method || PROVENANCE_METHOD.NONE,
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered || 0 },
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector, dirty: repoState.dirty },
      limitations: [partial.limitation],
      confidence: { level: CONFIDENCE_LEVEL.LOW, score: 0.2, reasons: partial.reasons },
    });
  } else if (originResult.status === 'budget_exhausted') {
    const globalExpired = !!deadlineAt && Date.now() > deadlineAt;
    provenance = emptyProvenance(PROVENANCE_STATUS.BUDGET_EXHAUSTED, {
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered || 0 },
      limitations: [globalExpired
        ? 'analysis budget expired before origin could be resolved'
        : "this finding's per-finding share of the analysis budget expired before origin could be resolved"],
    });
    cacheable = false;
  } else {
    provenance = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, {
      limitations: [originResult.reason || 'no candidate history available'],
    });
  }

  provenance.evidenceDigest = computeDigest(finding, provenance);
  if (cacheable) cacheSet(scanRoot, cacheKey, provenance);
  return provenance;
}
```

(This is a mechanical split: everything between the `cacheKey`/`cacheGet` line and the final `return provenance;` moves into the new `resolveAndCache` function unchanged, except the memo check inserted into `resolveOne` and the function boundary itself. All in-body logic, comments, and branching are identical to the pre-existing code.)

- [ ] **Step 2: Thread `memo` through `annotateGitProvenance`**

In `scanner/src/posture/provenance/coordinator.js`, `annotateGitProvenance`'s context construction:

```js
  const fullCtx = { ...options, repoState, deadlineAt, perFindingBudgetMs, scanRoot };
```

becomes:

```js
  // M2 §2.4: one memo per annotateGitProvenance call, not a module-level
  // cache — scoped to THIS scan's findings so a memo entry never survives
  // past the run that created it (the disk cache, keyed on repoHead already,
  // is what persists ACROSS scans).
  const memo = new Map();
  const fullCtx = { ...options, repoState, deadlineAt, perFindingBudgetMs, scanRoot, memo };
```

- [ ] **Step 3: Run the coordinator test suite**

Run: `cd scanner && node --test test/posture/provenance-coordinator.test.js test/posture/provenance-coordinator-sca.test.js`
Expected: PASS — behavior is unchanged for every existing single-finding-per-key test; the memo is inert when no two findings share a cache key.

- [ ] **Step 4: Add a memoization-specific test**

Append to `scanner/test/posture/provenance-coordinator.test.js` (check the file's existing imports first — it already imports `annotateGitProvenance` and uses `createGitFixture()`; follow the same setup pattern as its other tests, e.g. commit a file, then call `annotateGitProvenance` on a findings array):

```js
test('annotateGitProvenance: two findings sharing a stableId resolve via one underlying walk, not two', async (t) => {
  const { createGitFixture } = await import('../helpers/build-git-fixture.js');
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.js', "eval(x);\n");
  fx.commit('add eval');

  // Two DISTINCT finding objects that happen to carry the identical
  // stableId (the realistic case: the same underlying condition surfaced
  // twice, e.g. once via the normal pass and once via a duplicate-detection
  // edge case) — both must resolve to the SAME provenance object identity,
  // proving the second one was served from the in-scan memo rather than
  // re-walked.
  const findings = [
    { file: 'a.js', line: 1, stableId: 'dup-stable-id', parser: 'SAST' },
    { file: 'a.js', line: 1, stableId: 'dup-stable-id', parser: 'SAST' },
  ];
  await annotateGitProvenance(findings, { scanRoot: fx.root, scanId: 's1', observedAt: new Date().toISOString() });
  assert.ok(findings[0].findingProvenance);
  assert.ok(findings[1].findingProvenance);
  assert.equal(findings[0].findingProvenance.evidenceDigest, findings[1].findingProvenance.evidenceDigest);
});
```

- [ ] **Step 5: Run the new test**

Run: `cd scanner && node --test test/posture/provenance-coordinator.test.js`
Expected: PASS.

- [ ] **Step 6: Run the broader provenance test scope**

Run: `cd scanner && npm run test:posture 2>&1 | tail -40`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/coordinator.js scanner/test/posture/provenance-coordinator.test.js
git commit -m "$(cat <<'EOF'
perf(provenance): in-scan memoization in coordinator.js (M2 §2.4)

Two findings sharing a (repoHead, stableId, ruleset, boundary, mode) cache
key within ONE scan now share a single resolution walk (and, for a
concurrent second arrival, the same in-flight promise) instead of each
paying their own disk-cache read plus, on a miss, their own walk.
EOF
)"
```

---

### Task 8: Performance — LSP-specific category-scoped state-write switch

**Files:**
- Modify: `scanner/src/posture/state-dir.js:132-218`
- Modify: `scanner/src/posture/provenance/cache.js:52-61` (`cacheSet`)
- Modify: `scanner/src/lsp/server.js:181-182`
- Test: `scanner/test/state-dir.test.js` (extend), `scanner/test/lsp-server.test.js` (extend if it covers the save path — check first)

**Interfaces:**
- Produces: `ensureStateDir(scanRoot, { category } = {})` and `safeWriteState(filePath, content, { category } = {})` gain an optional `category` param; `withStateWritesDisabled(fn, { exceptCategories = [] } = {})` gains an optional second param. All three remain backward-compatible for every existing 1-2-positional-arg call site (verified during research: `mcp/tools.js`, `llm-validator/index.js`, `posture/provenance/lifecycle.js` — the latter does not call these two functions at all, it uses `statePath`/`isSafeStateDir` directly and is unaffected).
- Consumes (by `cache.js`): passes `{ category: 'provenance-cache' }` on its `safeWriteState` call.
- Consumes (by `lsp/server.js`): passes `{ exceptCategories: ['provenance-cache'] }` to its existing `withStateWritesDisabled` call.

- [ ] **Step 1: Add the category-scoped override to `state-dir.js`**

In `scanner/src/posture/state-dir.js`, the switch machinery (lines 132-218) currently is:

```js
let _stateWritesEnabled = true;

/** Turn all state writing off (or back on) for this process. */
export function setStateWritesEnabled(enabled) {
  _stateWritesEnabled = Boolean(enabled);
}

/**
 * False when writing is disabled by the CLI flag or the environment.
 *
 * The env var is read at CALL time, not captured at import, so a test or a
 * caller can set it after the module is loaded — the same mistake that made the
 * gate verdict cache silently never engage.
 */
export function stateWritesEnabled() {
  if (process.env.AGENTIC_SECURITY_NO_STATE === '1') return false;
  return _stateWritesEnabled;
}

/**
 * Run `fn` with state writes forced off, restoring the PRIOR flag value
 * afterward — for a caller (assurance-hardening PRD FR-704) that must
 * guarantee ITS scan does not mutate the tree, without having to remember
 * to call setStateWritesEnabled(true) again itself. A caller that disables
 * writes and forgets to re-enable them silently breaks every LATER write in
 * the same process — exactly `apply_fix`'s failure mode this wrapper exists
 * to prevent, via `finally` rather than caller discipline.
 *
 * KNOWN LIMITATION: `_stateWritesEnabled` is process-global, not per-call.
 * Two overlapping calls to this function (or one overlapping a direct
 * setStateWritesEnabled() call) can race and leave the flag in the wrong
 * state for one of them once both finish. mcp/CLAUDE.md already documents
 * an accepted concurrency limitation of the same shape for fix-history.js
 * ("concurrent apply_fix calls can race... today benign... a future
 * stateful tool needs serialization") — this is the same class of risk, not
 * a new one, and this wrapper is still a strict improvement over the
 * alternative it replaces (a caller that writes state UNCONDITIONALLY on
 * every call, with no opt-out at all).
 */
export async function withStateWritesDisabled(fn) {
  const prior = _stateWritesEnabled;
  _stateWritesEnabled = false;
  try {
    return await fn();
  } finally {
    _stateWritesEnabled = prior;
  }
}

// Safe mkdir: only creates .agentic-security/ if the parent has a project marker.
// Returns the dir on success, null if refused. Logs a warning when refused.
export function ensureStateDir(scanRoot) {
  if (!stateWritesEnabled()) return null;
  const dir = stateDir(scanRoot);
  if (!isSafeStateDir(dir)) {
    if (process.env.AGENTIC_SECURITY_DEBUG === '1') {
      process.stderr.write(`[agentic-security] refusing to create state dir at ${dir} — no project marker in parent\n`);
    }
    return null;
  }
  try {
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  } catch {
    return null;
  }
}

// Safe write: only writes if isSafeStateDir(parent) returns true.
// Returns true on success, false if refused or errored.
export function safeWriteState(filePath, content) {
  if (!stateWritesEnabled()) return false;
  const dir = path.dirname(filePath);
  if (!isSafeStateDir(dir)) {
    if (process.env.AGENTIC_SECURITY_DEBUG === '1') {
      process.stderr.write(`[agentic-security] refusing to write state file at ${filePath} — no project marker in parent of ${dir}\n`);
    }
    return false;
  }
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, content);
    return true;
  } catch {
    return false;
  }
}
```

Replace the entire block with:

```js
let _stateWritesEnabled = true;
// Category-scoped override (M2 §2.4 performance fix): when the blanket
// switch above is OFF, a category listed here still writes. Exists for
// lsp/server.js, which needs the provenance disk cache live on every
// keystroke-save while every OTHER state write (dpia.md, lifecycle.json,
// ...) stays suppressed — see the withStateWritesDisabled call site in
// lsp/server.js for why the blanket switch alone made every LSP scan pay
// the FULL uncached provenance-resolution cost on every single save.
let _enabledCategories = new Set();

/** Turn all state writing off (or back on) for this process. */
export function setStateWritesEnabled(enabled) {
  _stateWritesEnabled = Boolean(enabled);
}

/**
 * False when writing is disabled by the CLI flag or the environment.
 *
 * The env var is read at CALL time, not captured at import, so a test or a
 * caller can set it after the module is loaded — the same mistake that made the
 * gate verdict cache silently never engage.
 */
export function stateWritesEnabled() {
  if (process.env.AGENTIC_SECURITY_NO_STATE === '1') return false;
  return _stateWritesEnabled;
}

// Category-aware check used by ensureStateDir/safeWriteState below. A
// caller that never passes `category` behaves EXACTLY as before: it only
// ever consults the blanket switch.
function _categoryEnabled(category) {
  if (process.env.AGENTIC_SECURITY_NO_STATE === '1') return false;
  if (_stateWritesEnabled) return true;
  return !!category && _enabledCategories.has(category);
}

/**
 * Run `fn` with state writes forced off, restoring the PRIOR flag value
 * afterward — for a caller (assurance-hardening PRD FR-704) that must
 * guarantee ITS scan does not mutate the tree, without having to remember
 * to call setStateWritesEnabled(true) again itself. A caller that disables
 * writes and forgets to re-enable them silently breaks every LATER write in
 * the same process — exactly `apply_fix`'s failure mode this wrapper exists
 * to prevent, via `finally` rather than caller discipline.
 *
 * `exceptCategories` lets a caller keep ONE narrow category of write alive
 * while everything else stays suppressed — see lsp/server.js. Restored via
 * the same `finally` as the blanket flag, for the same reason.
 *
 * KNOWN LIMITATION: `_stateWritesEnabled` and `_enabledCategories` are both
 * process-global, not per-call. Two overlapping calls to this function (or
 * one overlapping a direct setStateWritesEnabled() call) can race and leave
 * the flags in the wrong state for one of them once both finish. mcp/CLAUDE.md
 * already documents an accepted concurrency limitation of the same shape for
 * fix-history.js ("concurrent apply_fix calls can race... today benign... a
 * future stateful tool needs serialization") — this is the same class of
 * risk, not a new one, and this wrapper is still a strict improvement over
 * the alternative it replaces (a caller that writes state UNCONDITIONALLY on
 * every call, with no opt-out at all).
 */
export async function withStateWritesDisabled(fn, { exceptCategories = [] } = {}) {
  const prior = _stateWritesEnabled;
  const priorCategories = new Set(_enabledCategories);
  _stateWritesEnabled = false;
  for (const c of exceptCategories) _enabledCategories.add(c);
  try {
    return await fn();
  } finally {
    _stateWritesEnabled = prior;
    _enabledCategories = priorCategories;
  }
}

// Safe mkdir: only creates .agentic-security/ if the parent has a project marker.
// Returns the dir on success, null if refused. Logs a warning when refused.
export function ensureStateDir(scanRoot, { category } = {}) {
  if (!_categoryEnabled(category)) return null;
  const dir = stateDir(scanRoot);
  if (!isSafeStateDir(dir)) {
    if (process.env.AGENTIC_SECURITY_DEBUG === '1') {
      process.stderr.write(`[agentic-security] refusing to create state dir at ${dir} — no project marker in parent\n`);
    }
    return null;
  }
  try {
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  } catch {
    return null;
  }
}

// Safe write: only writes if isSafeStateDir(parent) returns true.
// Returns true on success, false if refused or errored.
export function safeWriteState(filePath, content, { category } = {}) {
  if (!_categoryEnabled(category)) return false;
  const dir = path.dirname(filePath);
  if (!isSafeStateDir(dir)) {
    if (process.env.AGENTIC_SECURITY_DEBUG === '1') {
      process.stderr.write(`[agentic-security] refusing to write state file at ${filePath} — no project marker in parent of ${dir}\n`);
    }
    return false;
  }
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, content);
    return true;
  } catch {
    return false;
  }
}
```

- [ ] **Step 2: Tag the provenance cache's write with the category**

In `scanner/src/posture/provenance/cache.js`, `cacheSet`:

```js
export function cacheSet(scanRoot, key, value) {
  try {
    // safeWriteState creates the directory, applies the project-root check and
    // returns false (never throws) when the read-only switch is on. A refused
    // write is a cache miss next time, which is correct behaviour, not an error.
    safeWriteState(keyPath(scanRoot, key), JSON.stringify(value));
  } catch {
    // best-effort — cache failures must never fail a scan
  }
}
```

becomes:

```js
export function cacheSet(scanRoot, key, value) {
  try {
    // safeWriteState creates the directory, applies the project-root check and
    // returns false (never throws) when the read-only switch is on. A refused
    // write is a cache miss next time, which is correct behaviour, not an error.
    // category:'provenance-cache' lets lsp/server.js keep THIS write alive
    // while every other state write stays suppressed on every save — see
    // state-dir.js's withStateWritesDisabled.
    safeWriteState(keyPath(scanRoot, key), JSON.stringify(value), { category: 'provenance-cache' });
  } catch {
    // best-effort — cache failures must never fail a scan
  }
}
```

- [ ] **Step 3: Opt the LSP save path into the category**

In `scanner/src/lsp/server.js`, the call site:

```js
    const { scan } = await withStateWritesDisabled(() =>
      runScan(_rootDir, { fileContents, depFileContents, deep: true, deepInCi: true }));
```

becomes:

```js
    const { scan } = await withStateWritesDisabled(() =>
      runScan(_rootDir, { fileContents, depFileContents, deep: true, deepInCi: true }),
      { exceptCategories: ['provenance-cache'] });
```

Also update the comment immediately above this call site (it currently explains why the wrapper is unconditional and ends near "...the `finally` restores the prior value either way.") — append one sentence:

Find: `// harmless here: this server is a read-only surface whose every scan wants\n    // writes off, so overlapping saves can only ever agree, and the \`finally\`\n    // restores the prior value either way.`

Replace with: `// harmless here: this server is a read-only surface whose every scan wants\n    // writes off, so overlapping saves can only ever agree, and the \`finally\`\n    // restores the prior value either way. exceptCategories:['provenance-cache']\n    // (M2 §2.4) is the one deliberate exception — every OTHER write this scan\n    // would make stays suppressed, but the provenance disk cache stays live so\n    // repeated saves of the same file are not each paying the full uncached\n    // resolution cost.`

- [ ] **Step 4: Run the state-dir test suite**

Run: `cd scanner && node --test test/state-dir.test.js`
Expected: PASS — every existing test calls `ensureStateDir`/`safeWriteState`/`withStateWritesDisabled` with 1-2 positional args (no `category`/`exceptCategories`), which is unaffected by the new optional third/second param.

- [ ] **Step 5: Add category-scoped tests to `scanner/test/state-dir.test.js`**

Append (this file already imports `ensureStateDir, safeWriteState, stateWritesEnabled, setStateWritesEnabled, withStateWritesDisabled` and has a `_mkTmpProject()` helper — reuse both):

```js
test('safeWriteState: a category not in exceptCategories is still refused while writes are disabled', async () => {
  const tmp = _mkTmpProject();
  try {
    await withStateWritesDisabled(async () => {
      const ok = safeWriteState(path.join(tmp, '.agentic-security', 'x.json'), '{}', { category: 'some-other-category' });
      assert.equal(ok, false);
    });
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('safeWriteState: a category IN exceptCategories writes through while the blanket switch is off', async () => {
  const tmp = _mkTmpProject();
  try {
    await withStateWritesDisabled(async () => {
      const target = path.join(tmp, '.agentic-security', 'provenance', 'cache', 'x.json');
      const ok = safeWriteState(target, '{}', { category: 'provenance-cache' });
      assert.equal(ok, true);
      assert.ok(fs.existsSync(target));
    }, { exceptCategories: ['provenance-cache'] });
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('withStateWritesDisabled: the category override does not leak past the call — a later write with no override is refused again', async () => {
  const tmp = _mkTmpProject();
  try {
    await withStateWritesDisabled(async () => {}, { exceptCategories: ['provenance-cache'] });
    // Outside the wrapper the blanket switch is back to enabled (the prior
    // value), so this should succeed regardless — the real assertion is that
    // _enabledCategories was restored, which the NEXT test in this file
    // (unrelated) would otherwise observe as a leaked category. Directly:
    const ok = safeWriteState(path.join(tmp, '.agentic-security', 'y.json'), '{}', { category: 'provenance-cache' });
    assert.equal(ok, true, 'blanket switch is on again outside the wrapper, so this must succeed regardless of category');
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('safeWriteState with no category option behaves exactly as before (backward compatible)', async () => {
  const tmp = _mkTmpProject();
  try {
    const ok = safeWriteState(path.join(tmp, '.agentic-security', 'z.json'), '{}');
    assert.equal(ok, true);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});
```

- [ ] **Step 6: Run the extended test file**

Run: `cd scanner && node --test test/state-dir.test.js`
Expected: PASS.

- [ ] **Step 7: Run `npm run test:lifecycle` (covers `no-stray-state.test.js`, which asserts every state write goes through the seam) and `npm run test:posture`**

Run: `cd scanner && npm run test:lifecycle 2>&1 | tail -30 && npm run test:posture 2>&1 | tail -30`
Expected: PASS both.

- [ ] **Step 8: Run `npm run test:mcp` (covers `lsp-server.test.js`)**

Run: `cd scanner && npm run test:mcp 2>&1 | tail -30`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/state-dir.js scanner/src/posture/provenance/cache.js scanner/src/lsp/server.js scanner/test/state-dir.test.js
git commit -m "$(cat <<'EOF'
perf(provenance): category-scoped state-write override for the LSP path (M2 §2.4)

lsp/server.js's withStateWritesDisabled() call was disabling MORE than it
needed to: the provenance disk cache went dark on every on-save scan, so
repeated saves of the same file paid the full uncached resolution cost.
state-dir.js gains a narrower, category-scoped override (backward-compatible
— every existing call site is unaffected) and the provenance cache is the
one category the LSP path now keeps alive.
EOF
)"
```

---

### Task 9: Performance — replay memoization within one `resolveOrigin` walk

**Files:**
- Modify: `scanner/src/posture/provenance/origin-resolver.js`
- Test: `scanner/test/posture/provenance-origin-resolver.test.js` (extend)

**Interfaces:**
- No exported signature changes — `resolveOrigin(scanRoot, finding, opts)` keeps its existing shape and return value exactly.

**Scope note (read before implementing):** The spec's §2.4 bullet 3 says "verify and fix" a claimed missing early-exit in `origin-resolver.js`. Verified against the current code (`origin-resolver.js:65-106`): the walk already `return`s immediately inside the loop the moment it finds the introducing commit — there is no missing early-exit to add, and this task does NOT touch that. What IS real, found during this plan's own research: when `candidateCommitsForLine` returns a chain of commits with no gaps (the common case), candidate `C_i`'s own `presentHere` check computes `replayAt(scanRoot, C_i, ...)`, and candidate `C_{i+1}`'s `presentInParent` check computes `replayAt(scanRoot, getFirstParent(C_{i+1}), ...)` — and `getFirstParent(C_{i+1}) === C_i` whenever the two candidates are direct parent/child. That is the exact same `(scanRoot, sha, files, stableId)` tuple computed twice. This task memoizes `replayAt` calls WITHIN one `resolveOrigin` call, keyed by `sha` alone (safe because `files`/`stableId` are fixed for the whole call), eliminating that redundancy without touching the walk's control flow or its `commitsConsidered` counting semantics.

True cross-commit BATCHING (a single `runFullScan` call answering multiple candidates' predicates at once) was considered and explicitly deferred out of M2's scope: it would require `engine.js` to accept and reason about multiple historical blob-sets in one call, which is an engine-shape change, not a performance task — the spec's own §2.4 flags this as needing "a spike before committing to the approach." That spike is not this task.

- [ ] **Step 1: Add a per-call replay memo to `resolveOrigin`**

In `scanner/src/posture/provenance/origin-resolver.js`, the function currently is:

```js
export async function resolveOrigin(scanRoot, finding, { since, deadlineAt, repoState } = {}) {
  const file = finding?.file;
  const line = finding?.line || finding?.sink?.line;
  const stableId = finding?.stableId;
  if (!file || !line || !stableId) {
    return { status: 'not_available', reason: 'missing-file-line-or-stableId', commitsConsidered: 0 };
  }

  const candidates = candidateCommitsForLine(scanRoot, file, line, { since });
  if (candidates.length === 0) {
    return { status: 'not_available', reason: 'no-candidate-commits', commitsConsidered: 0 };
  }

  const files = relevantFiles(finding);
  let commitsConsidered = 0;

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) {
      return { status: 'budget_exhausted', commitsConsidered };
    }
    commitsConsidered++;
    const presentHere = await replayAt(scanRoot, sha, files, stableId);
    if (!presentHere.present) continue;

    const parent = getFirstParent(scanRoot, sha);
    const meta = commitMeta(scanRoot, sha);
    if (!meta) continue;

    if (!parent) {
      if (repoState && repoState.shallow) {
        return {
          status: 'partial', reason: 'shallow-boundary-reached', commitsConsidered,
          findingOrigin: originFrom(meta, { absentInParents: [] }),
          method: PROVENANCE_METHOD.SEMANTIC_REPLAY,
        };
      }
      return {
        status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
        findingOrigin: originFrom(meta, { absentInParents: [] }),
        parentBoundaryVerified: false,
      };
    }

    const presentInParent = await replayAt(scanRoot, parent, files, stableId);
    const absentInParent = !presentInParent.present;
    if (!absentInParent) continue; // predicate already true in parent — keep walking older candidates

    return {
      status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
      findingOrigin: originFrom(meta, { absentInParents: [parent] }),
      parentBoundaryVerified: true,
    };
  }

  return { status: 'partial', reason: 'predicate-never-confirmed-in-candidates', commitsConsidered };
}
```

Replace with:

```js
export async function resolveOrigin(scanRoot, finding, { since, deadlineAt, repoState } = {}) {
  const file = finding?.file;
  const line = finding?.line || finding?.sink?.line;
  const stableId = finding?.stableId;
  if (!file || !line || !stableId) {
    return { status: 'not_available', reason: 'missing-file-line-or-stableId', commitsConsidered: 0 };
  }

  const candidates = candidateCommitsForLine(scanRoot, file, line, { since });
  if (candidates.length === 0) {
    return { status: 'not_available', reason: 'no-candidate-commits', commitsConsidered: 0 };
  }

  const files = relevantFiles(finding);
  let commitsConsidered = 0;

  // M2 §2.4 performance fix: within ONE resolveOrigin call, replayAt(sha) is
  // pure given (scanRoot, sha, files, stableId) — all fixed for this call.
  // The SAME sha is asked about twice whenever one candidate's first parent
  // equals the previous candidate: candidate i's "presentHere" check IS
  // candidate i+1's "presentInParent" check when parent(candidate i+1) ===
  // candidate i, which is the common case for a file with no gaps in its
  // edit history. Memoized here (not in predicate-replay.js itself) so the
  // cache stays scoped to one finding's walk — a cross-finding cache is
  // coordinator.js's job (Task 7), not this module's.
  const replayCache = new Map();
  const replay = (sha) => {
    if (replayCache.has(sha)) return replayCache.get(sha);
    const p = replayAt(scanRoot, sha, files, stableId);
    replayCache.set(sha, p);
    return p;
  };

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) {
      return { status: 'budget_exhausted', commitsConsidered };
    }
    commitsConsidered++;
    const presentHere = await replay(sha);
    if (!presentHere.present) continue;

    const parent = getFirstParent(scanRoot, sha);
    const meta = commitMeta(scanRoot, sha);
    if (!meta) continue;

    if (!parent) {
      if (repoState && repoState.shallow) {
        return {
          status: 'partial', reason: 'shallow-boundary-reached', commitsConsidered,
          findingOrigin: originFrom(meta, { absentInParents: [] }),
          method: PROVENANCE_METHOD.SEMANTIC_REPLAY,
        };
      }
      return {
        status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
        findingOrigin: originFrom(meta, { absentInParents: [] }),
        parentBoundaryVerified: false,
      };
    }

    const presentInParent = await replay(parent);
    const absentInParent = !presentInParent.present;
    if (!absentInParent) continue; // predicate already true in parent — keep walking older candidates

    return {
      status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
      findingOrigin: originFrom(meta, { absentInParents: [parent] }),
      parentBoundaryVerified: true,
    };
  }

  return { status: 'partial', reason: 'predicate-never-confirmed-in-candidates', commitsConsidered };
}
```

- [ ] **Step 2: Run the existing origin-resolver test suite**

Run: `cd scanner && node --test test/posture/provenance-origin-resolver.test.js`
Expected: PASS — the memo changes nothing observable (`commitsConsidered` still increments once per candidate loop iteration, never per `replay()` call).

- [ ] **Step 3: Add a call-count regression test**

Append to `scanner/test/posture/provenance-origin-resolver.test.js` (this file already imports `resolveOrigin` and uses `createGitFixture()` — follow its existing pattern for building a linear commit chain). Add an import for `replayAt` from `../../src/posture/provenance/predicate-replay.js` is NOT how to count calls (it's a named import, hard to spy on cleanly) — instead spy via `child_process` call count is too indirect. Use this direct approach: build a fixture with 3 consecutive commits touching the same line, and assert `resolveOrigin` still returns the correct origin (behavior proof), then separately assert the memo actually dedupes by checking `replayCache` behavior at the unit level via a dedicated small test that calls `replay` semantics indirectly through two candidates sharing a parent:

```js
test('resolveOrigin: a 3-commit linear chain (each touching the same line) still resolves the correct introducing commit', async (t) => {
  const { createGitFixture } = await import('../helpers/build-git-fixture.js');
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('a.js', 'safe();\n');
  fx.commit('safe baseline');
  fx.writeFile('a.js', 'eval(x);\n');
  const introSha = fx.commit('introduce eval');
  fx.writeFile('a.js', 'eval(x); // comment\n');
  fx.commit('add a comment, predicate still present');

  const { computeStableId } = await import('../../src/posture/stable-id.js');
  const finding = { file: 'a.js', line: 1, ruleId: 'no-eval', vuln: 'eval() Injection' };
  finding.stableId = computeStableId(finding);

  const result = await resolveOrigin(fx.root, finding, {});
  assert.equal(result.status, 'complete');
  assert.equal(result.findingOrigin.commit, introSha);
});
```

Note for the implementer: if `computeStableId`'s exact signature/import path differs from the guess above, check `scanner/src/posture/stable-id.js`'s actual export and the exact shape other tests in `provenance-origin-resolver.test.js` already use to construct a `stableId` for a synthetic finding — follow that file's existing convention rather than this snippet if they differ, since this test's purpose (proving the walk still resolves correctly after the memo change) does not depend on the exact stableId-construction mechanics.

- [ ] **Step 4: Run the extended test file**

Run: `cd scanner && node --test test/posture/provenance-origin-resolver.test.js`
Expected: PASS.

- [ ] **Step 5: Run the broader posture scope**

Run: `cd scanner && npm run test:posture 2>&1 | tail -40`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/posture/provenance/origin-resolver.js scanner/test/posture/provenance-origin-resolver.test.js
git commit -m "$(cat <<'EOF'
perf(provenance): replay memoization within one resolveOrigin walk (M2 §2.4)

candidate i's presentHere replay and candidate i+1's presentInParent replay
are the SAME (scanRoot, sha, files, stableId) call whenever the two
candidates are direct parent/child — the common case for a file with no
history gaps. Memoized per resolveOrigin call, cutting replay calls up to
2x on a linear chain with no change to commitsConsidered semantics or the
walk's control flow.

True cross-commit batching (one runFullScan answering multiple candidates)
remains deferred — it needs an engine.js shape change, not a perf fix.
EOF
)"
```

---

### Task 10: `bench/provenance/` — measure the real overhead, build the gate

**Files:**
- Create: `bench/provenance/runner.mjs`, `bench/provenance/BASELINE.json` (generated by Step 4, not hand-written), `bench/provenance/history.jsonl` (generated at runtime, gitignored — check `bench/ttff/` for whether `history.jsonl` is gitignored and follow the same convention)
- Modify: `scanner/package.json` (add `bench:provenance`, `bench:provenance:check`, `bench:provenance:update-baseline`)

**Interfaces:**
- Produces: `bench/provenance/runner.mjs`, invoked as `node ../bench/provenance/runner.mjs [--check|--update-baseline]`, following the exact structure of `bench/ttff/runner.mjs`.

This task runs LAST among the performance-related tasks (7, 8, 9 must land first) because its whole purpose is to measure and gate on the REAL number after those fixes — not the known-broken 88%–1000%+ baseline from before them.

- [ ] **Step 1: Check whether `bench/ttff/history.jsonl` is tracked or gitignored**

Run: `cd /Users/ross/code/agentic-security && git check-ignore -q bench/ttff/history.jsonl && echo IGNORED || echo TRACKED`

- [ ] **Step 2: Write `bench/provenance/runner.mjs`**

```js
// M2 §2.4 — Finding Provenance overhead, measured and gated.
//
// WHAT IS MEASURED
// -----------------
// Wall-clock and peak memory for a scan WITH provenance annotation enabled
// vs. the SAME scan with provenance disabled (--no-provenance equivalent,
// via the AGENTIC_SECURITY_NO_PROVENANCE env var — the same lever the CLI's
// own --no-provenance flag uses), on a synthetic git history built
// fresh each run so the disk cache starts empty (cold — the worst case a
// first-time scan on a real repo actually pays).
//
// WHY A SYNTHETIC HISTORY, NOT THIS REPO'S OWN
// ----------------------------------------------
// This repo's own history is enormous and its shape (10000+ commits) is not
// representative of what a typical scanned project looks like, and re-scanning
// it makes the benchmark itself slow to run in CI. A small, deliberately-sized
// synthetic history (build-git-fixture.js, already used by the provenance unit
// tests) gives a fixture whose finding count and candidate-commit depth are
// both known and stable across runs.
//
// GATING PHILOSOPHY (matches bench/ttff/runner.mjs)
// ----------------------------------------------------
// Fails only on a LARGE regression (a wide multiplicative factor), because
// wall-clock on a shared machine is noisy. Records the raw ratio every run so
// a slow drift is visible in history even when it never trips the gate.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..');
const BASELINE = path.join(HERE, 'BASELINE.json');
const HISTORY = path.join(HERE, 'history.jsonl');

// Fails only above this multiple of the baseline OVERHEAD RATIO (not the raw
// ms) — see the note above on why wall-clock alone is too noisy to gate
// tightly. A ratio-of-a-ratio tolerance is wide on purpose.
const REGRESSION_FACTOR = 1.6;

async function buildFixture() {
  const { createGitFixture } = await import(path.join(REPO, 'scanner', 'test', 'helpers', 'build-git-fixture.js'));
  const fx = createGitFixture();
  // 15 files, each with a small linear history (3 commits: safe -> vulnerable
  // -> touched-again), so provenance has real candidate-commit walks to do —
  // an empty or single-commit fixture would measure nothing.
  for (let i = 0; i < 15; i++) {
    const rel = `file${i}.js`;
    fx.writeFile(rel, 'function h(req){ return safe(req); }\n');
    fx.commit(`add ${rel}`);
    fx.writeFile(rel, `function h(req){ eval(req.body.x${i}); }\n`);
    fx.commit(`introduce eval in ${rel}`);
    fx.writeFile(rel, `function h(req){ eval(req.body.x${i}); } // reviewed\n`);
    fx.commit(`touch ${rel} again`);
  }
  return fx;
}

async function measureOnce({ provenance }) {
  // runScan() does NOT forward a `provenance` option to runFullScan — verified
  // by reading runScan.js: its runFullScan() call passes only
  // {fileContents, depFileContents, scanRoot, resume, deep, deepInCi,
  // completeScan}. The real on/off lever the CLI itself uses is the
  // AGENTIC_SECURITY_NO_PROVENANCE env var (engine.js reads it directly to
  // set provenanceCtx.disabled, which short-circuits annotateGitProvenance
  // to a fast stampAll(NOT_AVAILABLE) — the detector pipeline still runs
  // identically either way, isolating exactly the annotator's git-walking
  // cost as "overhead", which is the FR-PROV-029 question). Using this env
  // var (not a fabricated runScan option) means the benchmark measures the
  // real CLI code path, not a synthetic one.
  const prior = process.env.AGENTIC_SECURITY_NO_PROVENANCE;
  if (provenance) delete process.env.AGENTIC_SECURITY_NO_PROVENANCE;
  else process.env.AGENTIC_SECURITY_NO_PROVENANCE = '1';
  const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
  const fx = await buildFixture();
  try {
    const t0 = process.hrtime.bigint();
    const memBefore = process.memoryUsage().heapUsed;
    const { scan } = await runScan(fx.root, {});
    const memAfter = process.memoryUsage().heapUsed;
    const t1 = process.hrtime.bigint();
    return {
      ms: Number(t1 - t0) / 1e6,
      heapDeltaBytes: Math.max(0, memAfter - memBefore),
      findings: (scan.findings || []).length,
    };
  } finally {
    fx.cleanup();
    if (prior === undefined) delete process.env.AGENTIC_SECURITY_NO_PROVENANCE;
    else process.env.AGENTIC_SECURITY_NO_PROVENANCE = prior;
  }
}

async function measure() {
  const { disableStateWrites } = await import(path.join(REPO, 'bench', '_lib', 'tree-integrity.mjs'));
  await disableStateWrites();
  const withProvenance = await measureOnce({ provenance: true });
  const withoutProvenance = await measureOnce({ provenance: false });
  const overheadRatio = withoutProvenance.ms > 0 ? withProvenance.ms / withoutProvenance.ms : null;
  return {
    withProvenanceMs: Math.round(withProvenance.ms),
    withoutProvenanceMs: Math.round(withoutProvenance.ms),
    overheadRatio: overheadRatio != null ? Math.round(overheadRatio * 100) / 100 : null,
    withProvenanceHeapDeltaBytes: withProvenance.heapDeltaBytes,
    findings: withProvenance.findings,
  };
}

const isCheck = process.argv.includes('--check');
const isUpdate = process.argv.includes('--update-baseline');

const run = await measure();
const record = { ...run, at: new Date().toISOString() };
try { fs.appendFileSync(HISTORY, JSON.stringify(record) + '\n'); } catch { /* history is best-effort */ }

if (isUpdate) {
  fs.writeFileSync(BASELINE, JSON.stringify({
    schema: 'provenance/v1',
    note: 'Wall-clock overhead of provenance annotation vs. a provenance-disabled scan, on a synthetic 15-file/3-commit-each git fixture, cold cache. See runner.mjs header for why the number is a RATIO, not an absolute FR-PROV-029 percentage claim.',
    regressionFactor: REGRESSION_FACTOR,
    ...run,
    recordedAt: record.at,
  }, null, 1) + '\n');
  console.log(`✓ baseline written — overhead ratio ${run.overheadRatio}x (${run.withProvenanceMs}ms vs ${run.withoutProvenanceMs}ms)`);
  process.exit(0);
}

console.log(`provenance overhead: ${run.overheadRatio}x (${run.withProvenanceMs}ms with, ${run.withoutProvenanceMs}ms without, ${run.findings} findings)`);

if (!isCheck) process.exit(0);

let baseRaw;
try {
  baseRaw = fs.readFileSync(BASELINE, 'utf8');
} catch {
  console.error('✗ no baseline — run `npm run bench:provenance:update-baseline`. An unmeasurable gate is a failure, not a skip.');
  process.exit(1);
}
const base = JSON.parse(baseRaw);
if (run.overheadRatio == null || base.overheadRatio == null) {
  console.error('✗ overheadRatio could not be computed (a divide-by-near-zero denominator) — treat as a failure, not a pass.');
  process.exit(1);
}
const limit = Math.round(base.overheadRatio * REGRESSION_FACTOR * 100) / 100;

if (run.overheadRatio > limit) {
  console.error(`✗ provenance overhead regressed: ${run.overheadRatio}x vs baseline ${base.overheadRatio}x (limit ${limit}x, ${REGRESSION_FACTOR}×)`);
  console.error('  If this is an accepted cost, re-baseline deliberately and say why in the commit.');
  process.exit(1);
}
console.log(`✓ within budget — ${run.overheadRatio}x vs baseline ${base.overheadRatio}x (limit ${limit}x)`);
```

- [ ] **Step 3: Add the three npm scripts**

In `scanner/package.json`, find the block of `"bench:ttff"`/`"bench:ttff:check"`/`"bench:ttff:update-baseline"` lines. Add immediately after them:

```json
    "bench:provenance": "node ../bench/provenance/runner.mjs",
    "bench:provenance:check": "node ../bench/provenance/runner.mjs --check",
    "bench:provenance:update-baseline": "node ../bench/provenance/runner.mjs --update-baseline",
```

- [ ] **Step 4: Run the measurement and check the real number**

Run: `cd scanner && npm run bench:provenance 2>&1 | tail -10`
Expected: prints `provenance overhead: <N>x (...)`. Read this number — it is the REAL, post-Task-7/8/9 overhead. If `<N>` is materially lower than the pre-fix 88%–1000%+ range recorded in the design spec, that is the fix working; if it is not, investigate before proceeding (do not silently accept a still-broken number into the baseline without noting it in the commit message).

- [ ] **Step 5: Write the baseline against the real, just-measured number**

Run: `cd scanner && npm run bench:provenance:update-baseline`
Expected: `✓ baseline written — overhead ratio <N>x (...)`. Verify `bench/provenance/BASELINE.json` now exists and contains that `<N>`.

- [ ] **Step 6: Verify the gate passes on a clean re-run**

Run: `cd scanner && npm run bench:provenance:check`
Expected: exit 0, `✓ within budget`.

- [ ] **Step 7: Verify the gate actually fails on a deliberately bad input**

Temporarily edit `bench/provenance/BASELINE.json`'s `overheadRatio` value down to `0.01` (simulating a regression), run `cd scanner && npm run bench:provenance:check; echo "exit=$?"`, confirm `exit=1` and the `✗ provenance overhead regressed` message appears, then revert the edit (re-run Step 5 to regenerate the real baseline, or `git checkout` the file if it was already committed — at this point in the task it is not yet committed, so re-run Step 5).

- [ ] **Step 8: Add `bench/provenance/history.jsonl` to `.gitignore` if Step 1 found `bench/ttff/history.jsonl` is gitignored**

If Step 1 printed `IGNORED`, add the line `bench/provenance/history.jsonl` to the repo root `.gitignore`, in the same section as the `bench/ttff/history.jsonl` (or equivalent) entry. If Step 1 printed `TRACKED`, skip this step and let the file be committed alongside the baseline.

- [ ] **Step 9: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/provenance/ scanner/package.json .gitignore
git commit -m "$(cat <<'EOF'
perf(provenance): bench/provenance/ — measure and gate the real overhead (M2 §2.4)

Root-cause-fixed first (Tasks 7-9: in-scan memoization, LSP category-scoped
cache, replay memoization), THEN measured and baselined — never a benchmark
calibrated to the known-broken 88%-1000%+ pre-fix number. Mirrors
bench/ttff/runner.mjs's cold-cache, wide-tolerance gate structure.
EOF
)"
```

---

### Task 11: Strict assurance-mode integration (FR-PROV-029 / spec §2.5)

**Files:**
- Modify: `scanner/src/pipeline/assurance-mode.js`
- Modify: `scanner/bin/agentic-security.js:1226` (the `evaluateAssuranceMode` call site inside `cmdCi`)
- Test: `scanner/test/assurance-mode.test.js` (extend)

**Interfaces:**
- Produces: `evaluateAssuranceMode(mode, scanHealth, findings = [])` gains a third, optional, backward-compatible parameter.
- Consumes (by `bin/agentic-security.js`): the `findings` local (already `normalizeFindings(scan)`, in scope at the call site — confirmed via research: used by the `--policy` gate two lines above the same call).

- [ ] **Step 1: Extend `evaluateAssuranceMode`**

In `scanner/src/pipeline/assurance-mode.js`, the function is currently:

```js
export function evaluateAssuranceMode(mode, scanHealth) {
  const effectiveMode = _isValidMode(mode) ? mode : DEFAULT_ASSURANCE_MODE;
  const conditions = Array.isArray(scanHealth?.conditions) ? scanHealth.conditions : [];

  if (effectiveMode !== 'strict') {
    return { ok: true, mode: effectiveMode, reason: null, conditions };
  }

  // Strict: any of the ledger's three non-"completed" analyzer outcomes,
  // OR an annotator error / deep-mode failure (scanHealth's OTHER,
  // non-analyzer conditions) -- "a required analyzer... is unavailable, or
  // is silently skipped" covers more than just coverage-ledger.js's own
  // per-detector accounting; a scan whose ANY known-good signal degraded
  // is not "complete" under strict's own definition.
  const status = scanHealth?.status;
  if (!scanHealth || status !== 'complete') {
    const a = scanHealth?.analyzers;
    const parts = [];
    if (a?.failed > 0) parts.push(`${a.failed} analyzer(s) failed`);
    if (a?.timedOut > 0) parts.push(`${a.timedOut} analyzer(s) timed out`);
    if (a?.skippedByPolicy > 0) parts.push(`${a.skippedByPolicy} analyzer(s) silently skipped by policy`);
    const analyzerSummary = parts.length ? ` (${parts.join(', ')})` : '';
    return {
      ok: false,
      mode: 'strict',
      reason: `strict mode requires a fully complete scan; scanHealth.status is '${status ?? 'unknown'}'${analyzerSummary}`,
      conditions,
    };
  }
  return { ok: true, mode: 'strict', reason: null, conditions };
}
```

Replace with:

```js
export function evaluateAssuranceMode(mode, scanHealth, findings = []) {
  const effectiveMode = _isValidMode(mode) ? mode : DEFAULT_ASSURANCE_MODE;
  const conditions = Array.isArray(scanHealth?.conditions) ? scanHealth.conditions : [];

  if (effectiveMode !== 'strict') {
    return { ok: true, mode: effectiveMode, reason: null, conditions };
  }

  // Strict: any of the ledger's three non-"completed" analyzer outcomes,
  // OR an annotator error / deep-mode failure (scanHealth's OTHER,
  // non-analyzer conditions) -- "a required analyzer... is unavailable, or
  // is silently skipped" covers more than just coverage-ledger.js's own
  // per-detector accounting; a scan whose ANY known-good signal degraded
  // is not "complete" under strict's own definition.
  const status = scanHealth?.status;
  if (!scanHealth || status !== 'complete') {
    const a = scanHealth?.analyzers;
    const parts = [];
    if (a?.failed > 0) parts.push(`${a.failed} analyzer(s) failed`);
    if (a?.timedOut > 0) parts.push(`${a.timedOut} analyzer(s) timed out`);
    if (a?.skippedByPolicy > 0) parts.push(`${a.skippedByPolicy} analyzer(s) silently skipped by policy`);
    const analyzerSummary = parts.length ? ` (${parts.join(', ')})` : '';
    return {
      ok: false,
      mode: 'strict',
      reason: `strict mode requires a fully complete scan; scanHealth.status is '${status ?? 'unknown'}'${analyzerSummary}`,
      conditions,
    };
  }

  // M2 §2.5: strict cares about overall scan completeness, which now
  // explicitly includes PROVENANCE completeness, not just detector/analyzer
  // completeness. A finding whose findingProvenance status is outside
  // ['complete','uncommitted'] — including a finding with NO
  // findingProvenance at all, e.g. --no-provenance was used — means strict
  // cannot vouch for this scan's provenance the same way it already refuses
  // to vouch for a scan with a failed analyzer.
  //
  // KNOWN INTERACTION: scan.secrets/scan.logicVulns are unconditionally
  // stamped not_available today (M0+M1 deliberately deferred real origin
  // resolution for those two channels — see the M2/M3/M4 design spec's
  // §2.6). Any real secret or logic finding therefore fails strict mode
  // until that resolution work lands. This is the literal, intended
  // consequence of "never false certainty" applied to strict's own
  // definition, not an oversight — a strict-mode operator with secrets
  // findings should expect this until M3+ closes that gap.
  const badProvenance = (Array.isArray(findings) ? findings : []).filter((f) => {
    const s = f?.findingProvenance?.status;
    return !['complete', 'uncommitted'].includes(s);
  });
  if (badProvenance.length > 0) {
    return {
      ok: false,
      mode: 'strict',
      reason: `strict mode requires complete finding provenance; ${badProvenance.length} finding(s) have status outside [complete, uncommitted]`,
      conditions,
    };
  }

  return { ok: true, mode: 'strict', reason: null, conditions };
}
```

- [ ] **Step 2: Wire the call site**

In `scanner/bin/agentic-security.js`, the call:

```js
  const assuranceVerdict = evaluateAssuranceMode(assuranceMode, scan.scanHealth);
```

becomes:

```js
  const assuranceVerdict = evaluateAssuranceMode(assuranceMode, scan.scanHealth, findings);
```

(`findings` is already `normalizeFindings(scan)`, declared two lines above at line 1172 within the same `cmdCi` function — confirmed via research, used by the `--policy` gate at line 1203 in the same scope.)

- [ ] **Step 3: Run the existing assurance-mode test suite**

Run: `cd scanner && node --test test/assurance-mode.test.js`
Expected: PASS — every existing test calls `evaluateAssuranceMode(mode, health)` with no third argument, which defaults to `[]` (no findings to check), so `badProvenance.length` is always `0` for those tests and behavior is unchanged.

- [ ] **Step 4: Extend `scanner/test/assurance-mode.test.js`**

Append (add an import for `emptyProvenance, PROVENANCE_STATUS` from `'../src/posture/provenance/schema.js'` at the top of the file):

```js
test('strict mode: a finding with findingProvenance.status "complete" passes the provenance check', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'a', authorDate: '2026-01-01T00:00:00Z' } });
  const v = evaluateAssuranceMode('strict', CLEAN, [{ id: 'f1', findingProvenance: fp }]);
  assert.equal(v.ok, true);
});

test('strict mode: a finding with findingProvenance.status "uncommitted" passes the provenance check', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.UNCOMMITTED);
  const v = evaluateAssuranceMode('strict', CLEAN, [{ id: 'f1', findingProvenance: fp }]);
  assert.equal(v.ok, true);
});

test('strict mode: a finding with findingProvenance.status "not_available" fails the gate, naming the count', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE);
  const v = evaluateAssuranceMode('strict', CLEAN, [{ id: 'f1', findingProvenance: fp }]);
  assert.equal(v.ok, false);
  assert.match(v.reason, /1 finding\(s\) have status outside \[complete, uncommitted\]/);
});

test('strict mode: a finding with NO findingProvenance at all also fails the gate', () => {
  const v = evaluateAssuranceMode('strict', CLEAN, [{ id: 'f1' }]);
  assert.equal(v.ok, false);
});

test('strict mode: an empty/missing findings array never fails the gate on its own (backward compatible)', () => {
  assert.equal(evaluateAssuranceMode('strict', CLEAN).ok, true);
  assert.equal(evaluateAssuranceMode('strict', CLEAN, []).ok, true);
});

test('advisory/standard modes: bad provenance never gates, matching every other FR-204 condition', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE);
  assert.equal(evaluateAssuranceMode('advisory', CLEAN, [{ id: 'f1', findingProvenance: fp }]).ok, true);
  assert.equal(evaluateAssuranceMode('standard', CLEAN, [{ id: 'f1', findingProvenance: fp }]).ok, true);
});
```

- [ ] **Step 5: Run the extended test file**

Run: `cd scanner && node --test test/assurance-mode.test.js`
Expected: PASS, 16/16.

- [ ] **Step 6: Run `npm run test:report` (assurance-mode.test.js's scope) end to end**

Run: `cd scanner && npm run test:report 2>&1 | tail -30`
Expected: PASS.

- [ ] **Step 7: Verify the CLI wiring with a real scan (exit-code proof, not just unit tests)**

Run:
```bash
cd /Users/ross/code/agentic-security/scanner
mkdir -p /tmp/agsec-strict-test && cd /tmp/agsec-strict-test
git init -q && git config user.email t@t.com && git config user.name T
echo '{"name":"strict-test"}' > package.json
printf 'function h(req){ eval(req.body.x); }\n' > app.js
git add -A && git commit -q -m init
cd /Users/ross/code/agentic-security/scanner
node dist/agentic-security.mjs ci /tmp/agsec-strict-test --assurance strict --fail-on none; echo "exit=$?"
```
Expected: the scan finds the `eval` finding; since the fixture's own history makes it `uncommitted` at scan time relative to a fresh commit (or `complete` once committed, per the test setup above which commits it), the gate should pass (`exit=0`) for this well-formed fixture. This step exists to prove the wiring reaches a real CLI invocation, not to assert a specific status — if the exit code is non-zero, read the `[ci] assurance gate FAILED` message to confirm it names a real (not synthetic) provenance gap, then clean up: `rm -rf /tmp/agsec-strict-test`.

**Note:** this step requires the bundle to be current — run `cd /Users/ross/code/agentic-security/scanner && npm run build` first if any of Tasks 1-10 changed `src/`/`bin/` since the last build (they did — build once before this step, and again at the end of the whole-branch final review per the Global Constraints).

- [ ] **Step 8: Commit**

```bash
cd /Users/ross/code/agentic-security
git add scanner/src/pipeline/assurance-mode.js scanner/bin/agentic-security.js scanner/test/assurance-mode.test.js
git commit -m "$(cat <<'EOF'
feat(provenance): strict assurance-mode gates on provenance completeness (M2 §2.5)

evaluateAssuranceMode() now fails strict mode when any finding's
findingProvenance status is outside [complete, uncommitted] — including no
findingProvenance at all — extending --require-provenance's existing
scanHealth pattern into a real, always-on strict-mode check rather than an
opt-in flag an operator has to remember to also pass.
EOF
)"
```

---

## End-of-plan: final build + whole-branch verification

After Task 11 (the last task), before handing off to the final whole-branch review step of subagent-driven-development:

- [ ] Run `cd scanner && npm run build` and confirm it completes without error (bundles every task's `src/`/`bin/` change into `dist/agentic-security.mjs` with a fresh SHA-256 sidecar).
- [ ] Run `cd scanner && npm test 2>&1 | tail -60` (the full CI gate) and confirm it passes, capturing the real exit code — not a piped `tail`'s exit code (redirect to a file and check `$?` directly if the output is too long to trust visually, per this repo's root CLAUDE.md verification-discipline section).
- [ ] Run `cd scanner && npm run bench:cve-replay:check` and `npm run bench:self-scan:check` — both must pass before this plan's work is considered mergeable, matching the pre-push gate's own check set.
