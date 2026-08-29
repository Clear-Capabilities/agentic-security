// Finding-provenance OUTPUT surface (Finding Provenance M0/M1, Task 16).
//
// Everything the earlier tasks built lives inside the engine's in-memory
// finding objects. This file pins the three places it becomes visible:
//   1. `normalizeFindings()` — the canonical shape every JSON/SARIF/HTML/CSV/
//      JUnit/MCP consumer derives from.
//   2. `explainProvenance()` / `toCLI(..., {provenance:true})` — the human
//      rendering.
//   3. `explain_finding` (MCP) — the agent-facing rendering.
//
// The load-bearing property across all three is REDACTION: an author email is
// PII that must not leak into a report by default, including raw JSON.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeFindings, toCLI, explainProvenance, toSARIF, toCSV, toMarkdown, toHTML } from '../../src/report/index.js';
import { emptyProvenance, PROVENANCE_STATUS } from '../../src/posture/provenance/schema.js';

function makeScan(findingProvenance) {
  return {
    findings: [{ id: 'f1', file: 'a.js', line: 1, severity: 'high', vuln: 'SQL Injection', cwe: 'CWE-89', findingProvenance }],
    filesScanned: 1,
  };
}

test('normalizeFindings carries findingProvenance through and redacts email by default', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234', authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', authorDate: '2026-03-14T00:00:00Z' },
  });
  const [f] = normalizeFindings(makeScan(fp));
  assert.ok(f.findingProvenance);
  assert.equal(f.findingProvenance.findingOrigin.authorName, 'Jamie Chen');
  assert.equal(f.findingProvenance.findingOrigin.authorEmail, null);
});

test('normalizeFindings keeps `provenance` (AI-authorship) and `findingProvenance` (git origin) as SEPARATE keys', () => {
  // The two names mean completely different things — posture/ai-code-fingerprint.js
  // owns `provenance`/`provenanceScore`. Neither may overwrite the other.
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234', authorName: 'Jamie Chen', authorDate: '2026-03-14T00:00:00Z' },
  });
  const scan = makeScan(fp);
  scan.findings[0].provenance = { model: 'some-assistant', signals: ['comment-density'] };
  scan.findings[0].provenanceScore = 0.75;
  const [f] = normalizeFindings(scan);
  assert.deepEqual(f.provenance, { model: 'some-assistant', signals: ['comment-density'] });
  assert.equal(f.provenanceScore, 0.75);
  assert.equal(f.findingProvenance.status, 'complete');
  assert.equal(f.findingProvenance.findingOrigin.commit, 'abc1234');
});

test('normalizeFindings emits findingProvenance:null when a finding has none', () => {
  const [f] = normalizeFindings(makeScan(undefined));
  assert.equal(f.findingProvenance, null);
  assert.ok('findingProvenance' in f, 'the key must exist even when unpopulated');
});

test('normalizeFindings carries findingProvenance on the secret / logic / sca channels too', () => {
  // pipeline/finding-schema.js requires findingProvenance on EVERY channel,
  // not just scan.findings — normalizeFindings is what every channel flows
  // through, so all four push sites must pass it on.
  const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['x'] });
  const scan = {
    findings: [],
    secrets: [{ id: 's1', file: 'a.js', line: 2, findingProvenance: fp }],
    logicVulns: [{ id: 'l1', vuln: 'IDOR', file: 'b.js', line: 3, findingProvenance: fp }],
    supplyChain: [{ type: 'vulnerable_dep', name: 'left-pad', version: '1.0.0', file: 'package.json', findingProvenance: fp }],
  };
  const out = normalizeFindings(scan);
  assert.equal(out.length, 3);
  for (const f of out) {
    assert.ok(f.findingProvenance, `${f.kind} finding lost findingProvenance`);
    assert.equal(f.findingProvenance.status, 'not_available');
  }
});

// Second independent Finding Provenance PRD audit (Task 7, item 4):
// `stableId` was emitted for the SAST channel only — report/index.js's sole
// site was inside the `scan.findings` push, so a consumer of a secret/logic/
// sca finding could never recompute `findingProvenance.evidenceDigest`
// (coordinator.js's `computeDigest` binds `stableId` as its first input) for
// three of the four channels. Same golden fixture as the test above, plus a
// real `stableId` on each entry, now asserted through on all four.
test('normalizeFindings carries stableId through on ALL FOUR channels, not just SAST', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['x'] });
  const scan = {
    findings: [{ id: 'f1', file: 'x.js', line: 1, severity: 'high', vuln: 'SQLi', cwe: 'CWE-89', stableId: 'sast-stable-1', findingProvenance: fp }],
    secrets: [{ id: 's1', file: 'a.js', line: 2, stableId: 'secret-stable-1', findingProvenance: fp }],
    logicVulns: [{ id: 'l1', vuln: 'IDOR', file: 'b.js', line: 3, stableId: 'logic-stable-1', findingProvenance: fp }],
    supplyChain: [{ type: 'vulnerable_dep', name: 'left-pad', version: '1.0.0', file: 'package.json', stableId: 'sca-stable-1', findingProvenance: fp }],
  };
  const out = normalizeFindings(scan);
  assert.equal(out.length, 4);
  const byKind = Object.fromEntries(out.map((f) => [f.kind, f]));
  assert.equal(byKind.sast.stableId, 'sast-stable-1');
  assert.equal(byKind.secret.stableId, 'secret-stable-1');
  assert.equal(byKind.logic.stableId, 'logic-stable-1');
  assert.equal(byKind.sca.stableId, 'sca-stable-1');
});

// The honest-degrade half of the same fix: a finding with no stableId (never
// routed through the backfill — e.g. a synthetic-line logicVulns producer,
// or an sca entry annotateGitProvenance never saw) must surface `null`, not
// fabricate one and not throw.
test('normalizeFindings emits stableId:null (not fabricated) when a channel entry has none', () => {
  const scan = {
    findings: [{ id: 'f1', file: 'x.js', line: 1, severity: 'high', vuln: 'SQLi' }],
    secrets: [{ id: 's1', file: 'a.js', line: 2 }],
    logicVulns: [{ id: 'l1', vuln: 'IDOR', file: 'b.js', line: 3 }],
    supplyChain: [{ type: 'vulnerable_dep', name: 'left-pad', version: '1.0.0', file: 'package.json' }],
  };
  const out = normalizeFindings(scan);
  for (const f of out) {
    assert.equal(f.stableId, null, `${f.kind} finding fabricated a stableId it was never given`);
  }
});

test('explainProvenance renders a human block for a complete origin', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234567', authorName: 'Jamie Chen', authorDate: '2026-03-14T00:00:00Z' },
  });
  const text = explainProvenance({ findingProvenance: fp });
  assert.match(text, /abc1234/);
  assert.match(text, /Jamie Chen/);
  assert.match(text, /Method:/);
  assert.match(text, /Confidence:/);
});

test('explainProvenance handles not_available without throwing', () => {
  const text = explainProvenance({ findingProvenance: emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['not a git repo'] }) });
  assert.match(text, /NOT AVAILABLE/);
  assert.match(text, /not a git repo/);
});

test('explainProvenance handles every terminal status without throwing, and returns null for none', () => {
  for (const status of Object.values(PROVENANCE_STATUS)) {
    const text = explainProvenance({ findingProvenance: emptyProvenance(status) });
    assert.equal(typeof text, 'string', `status ${status} produced no block`);
    assert.match(text, /Method:/, `status ${status} dropped the method line`);
  }
  assert.equal(explainProvenance({ findingProvenance: null }), null);
  assert.equal(explainProvenance({}), null);
  assert.equal(explainProvenance(null), null);
  // A malformed provenance object (no confidence, no method) must degrade, not throw.
  assert.doesNotThrow(() => explainProvenance({ findingProvenance: { status: 'complete', findingOrigin: {} } }));
});

test('explainProvenance surfaces branch entry and first-observed when present', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'aaaaaaa1111', authorName: 'Jamie Chen', authorDate: '2026-03-14T00:00:00Z' },
    branchIntroduction: { commit: 'bbbbbbb2222', relationship: 'merge-base' },
    firstObserved: { scanId: 'scan-9', observedAt: '2026-04-01T10:00:00Z' },
  });
  const text = explainProvenance({ findingProvenance: fp });
  assert.match(text, /Branch entry:\s+bbbbbbb/);
  assert.match(text, /merge-base/);
  assert.match(text, /First observed:\s+scan-9/);
});

test('toCLI with provenance:true includes the provenance block in output', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'abc1234567', authorName: 'Jamie Chen', authorDate: '2026-03-14T00:00:00Z' } });
  const out = toCLI(makeScan(fp), { color: false, provenance: true });
  assert.match(out, /Jamie Chen/);
  const outWithout = toCLI(makeScan(fp), { color: false, provenance: false });
  assert.doesNotMatch(outWithout, /Jamie Chen/);
  // Default (no options at all) must not print it either.
  assert.doesNotMatch(toCLI(makeScan(fp), { color: false }), /Jamie Chen/);
});

test('toCLI --provenance never leaks an author email', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234567', authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', authorDate: '2026-03-14T00:00:00Z' },
  });
  const out = toCLI(makeScan(fp), { color: false, provenance: true });
  assert.doesNotMatch(out, /jamie@example\.com/);
});

test('explain_finding (MCP) returns a redacted findingProvenance', async (t) => {
  const os = await import('node:os');
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { explain_finding } = await import('../../src/mcp/tools.js');

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'prov-mcp-'));
  t.after(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234567', authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', authorDate: '2026-03-14T00:00:00Z' },
  });
  fs.writeFileSync(path.join(root, '.agentic-security', 'last-scan.json'), JSON.stringify({
    findings: [{ id: 'f1', severity: 'high', file: 'a.js', line: 1, vuln: 'SQL Injection', cwe: 'CWE-89', findingProvenance: fp }],
  }));

  const res = await explain_finding.handler({ finding_id: 'f1' }, { sessionRoot: root });
  assert.ok(res.findingProvenance, 'explain_finding dropped findingProvenance');
  assert.equal(res.findingProvenance.findingOrigin.authorName, 'Jamie Chen');
  assert.equal(res.findingProvenance.findingOrigin.authorEmail, null);
  assert.doesNotMatch(JSON.stringify(res), /jamie@example\.com/);
});

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
