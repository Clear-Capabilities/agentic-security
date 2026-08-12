// Renderer tests: the "likely lower risk" demotion note (so a hardcoded
// severity isn't taken at face value) + verdict discoverability lines.
import { test } from 'node:test';
import assert from 'node:assert';
import { toCLI, toProTable, toHTML, toShipVerdict, exitCodeFor, toSARIF, toSTIX, normalizeFindings } from '../src/report/index.js';

const demoted = {
  unreachable: { severity: 'critical', cwe: 'CWE-94', file: 'a.js', line: 1, vuln: 'Code injection', unreachableInProd: true, mitigationVerdict: 'unreachable-in-prod' },
  lowExploit:  { severity: 'high', cwe: 'CWE-79', file: 'b.js', line: 2, vuln: 'Reflected XSS', exploitabilityTier: 'low' },
  lowConf:     { severity: 'critical', cwe: 'CWE-89', file: 'c.js', line: 3, vuln: 'SQL injection', confidenceTier: 'low', confidence: 0.4 },
  clean:       { severity: 'critical', cwe: 'CWE-78', file: 'd.js', line: 4, vuln: 'Command injection', mitigationVerdict: 'exposed-in-prod' },
  mediumNoteNa:{ severity: 'medium', cwe: 'CWE-200', file: 'e.js', line: 5, vuln: 'Info leak', exploitabilityTier: 'low' },
};
const scan = { findings: Object.values(demoted) };

const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

test('toCLI — risk note on demoted high/critical, not on a clean critical', () => {
  const out = stripAnsi(toCLI(scan, { color: false }));
  assert.match(out, /Code injection\n\s+↓ likely lower risk — not reachable in prod/);
  assert.match(out, /Reflected XSS\n\s+↓ likely lower risk — low exploitability/);
  assert.match(out, /SQL injection\n\s+↓ lower confidence/);
  // The clean critical gets no note line.
  assert.doesNotMatch(out, /Command injection\n\s+↓/);
});

test('toCLI — no note on a medium finding (only flags overstated high/critical)', () => {
  const out = toCLI({ findings: [demoted.mediumNoteNa] }, { color: false });
  assert.doesNotMatch(out, /↓/);
});

test('toProTable — risk note rendered under the row', () => {
  const out = toProTable(scan, { color: false, profile: { confidenceMin: 0 } });
  assert.match(out, /↓ likely lower risk — not reachable in prod/);
  assert.match(out, /↓ likely lower risk — low exploitability/);
});

// S7 (Stage 1 correctness audit) — toProTable's mitre/capec columns read
// f.mitreAttack/f.attckTechnique/f.capec, but no code anywhere in the repo
// ever sets those first two names — the real field posture/attack-taxonomy.js
// stamps is f.attck. The mitre column rendered "—" for every finding.
test('toProTable --columns mitre renders the real f.attck field, not the never-set f.mitreAttack', () => {
  const tagged = { severity: 'critical', cwe: 'CWE-1236', file: 'a.js', line: 1, vuln: 'Injection', attck: 'T1190' };
  const out = toProTable({ findings: [tagged] }, { color: false, columns: 'mitre', profile: { confidenceMin: 0 } });
  assert.match(out, /T1190/);
  assert.doesNotMatch(out, /—\s+Injection/);
});

// posture/composite-risk.js's own header calls compositeRisk "the canonical
// sort key... used by agents and UI as the canonical sort key" — but it was
// dropped by normalizeFindings, so toProTable fell back to the older `triage`
// field. Now that it survives, the sort should prefer it.
test('toProTable sorts by compositeRisk when present, ahead of a higher-triage-but-lower-compositeRisk finding', () => {
  const lowRiskHighTriage = { severity: 'low', cwe: 'CWE-1', file: 'a.js', line: 1, vuln: 'Low priority', triage: 0.9, compositeRisk: 10 };
  const highRiskLowTriage = { severity: 'low', cwe: 'CWE-2', file: 'b.js', line: 2, vuln: 'High priority', triage: 0.1, compositeRisk: 95 };
  const out = toProTable({ findings: [lowRiskHighTriage, highRiskLowTriage] }, { color: false, profile: { confidenceMin: 0 } });
  const iHigh = out.indexOf('High priority');
  const iLow = out.indexOf('Low priority');
  assert.ok(iHigh >= 0 && iLow >= 0 && iHigh < iLow, 'the higher-compositeRisk finding must sort first');
});

test('toHTML — embeds the precomputed risk note for demoted findings, null otherwise', () => {
  const html = toHTML(scan);
  assert.match(html, /"_riskNote":"likely lower risk — not reachable in prod"/);
  assert.match(html, /"_riskNote":"likely lower risk — low exploitability"/);
  assert.match(html, /"_riskNote":null/);          // the clean critical
  assert.match(html, /class="f-note"/);            // the badge render + CSS exist
});

test('toShipVerdict — footer points to /triage --explain and the html report when findings exist', () => {
  const out = toShipVerdict(scan, { color: false });
  assert.match(out, /Want more detail\?/);
  assert.match(out, /\/triage --explain/);
  assert.match(out, /--format html/);
});

test('toShipVerdict — clean scan shows no "want more detail" footer', () => {
  const out = toShipVerdict({ findings: [] }, { color: false });
  assert.match(out, /Safe to deploy/);
  assert.doesNotMatch(out, /Want more detail\?/);
});

// ── Inline explain depth (why it matters / how it fires / fix) ──────────────
const explainable = {
  severity: 'critical', cwe: 'CWE-89', file: 'app.js', line: 7, vuln: 'SQL Injection',
  narration: 'An attacker sends UNION-style SQL in a request parameter. The driver executes it verbatim and returns rows from any readable table. Typical impact: full user-table dump. Recovery: incident response and notification.',
  whyFired: { detector: 'sast/sql-injection', parser: 'STRUCTURAL', evidence: { sourceSnippet: 'req.params.id', sinkSnippet: 'db.query(`... ${req.params.id}`)', pathSteps: [], sanitizers: [], guards: [] }, considered: { reachabilityFilter: 'kept' } },
  // Engine pre-normalize shape: fix=string description, code=string (normalizeFindings wraps these into {description, code}).
  fix: 'Use a parameterized query with bound params.',
  code: 'db.query("SELECT * FROM users WHERE id = ?", [id]);',
};

test('toCLI — renders inline why/how/fix from narration + whyFired', () => {
  const out = stripAnsi(toCLI({ findings: [explainable] }, { color: false }));
  assert.match(out, /why: An attacker sends UNION-style SQL.*returns rows from any readable table\./);
  assert.match(out, /how: sast\/sql-injection \(STRUCTURAL\).*req\.params\.id → db\.query/);
  assert.match(out, /fix: Use a parameterized query with bound params\./);
  // default (non-verbose) trims narration to 2 sentences and omits fix code.
  assert.doesNotMatch(out, /Recovery: incident response/);
  assert.doesNotMatch(out, /SELECT \* FROM users WHERE id = \?/);
});

test('toCLI --verbose — full narration + fix code', () => {
  const out = stripAnsi(toCLI({ findings: [explainable] }, { color: false, verbose: true }));
  assert.match(out, /Recovery: incident response and notification\./); // full narration
  assert.match(out, /SELECT \* FROM users WHERE id = \?/);             // fix code
});

test('toProTable — adds a one-line "why" under the row', () => {
  const out = stripAnsi(toProTable({ findings: [explainable] }, { color: false, profile: { confidenceMin: 0 } }));
  assert.match(out, /↳ An attacker sends UNION-style SQL in a request parameter\./);
});

test('toHTML — embeds why/how depth for the browser render', () => {
  const html = toHTML({ findings: [explainable] });
  assert.match(html, /"_explainWhy":"An attacker sends UNION-style SQL/);
  assert.match(html, /"_explainHow":"sast\/sql-injection/);
  assert.match(html, /class="f-why"/);
  assert.match(html, /Why it matters:/);
});

test('explain depth degrades gracefully when fields are absent', () => {
  const bare = { severity: 'high', cwe: 'CWE-79', file: 'x.js', line: 1, vuln: 'XSS' };
  const out = stripAnsi(toCLI({ findings: [bare] }, { color: false }));
  assert.doesNotMatch(out, /\n\s+why:/);
  assert.doesNotMatch(out, /\n\s+how:/);
});

// ── toShipVerdict must not claim safety the exit code disagrees with ────────
// CMP-4 (Stage-0 capability audit, 2026). _withConfidence filtered the WHOLE
// finding set before toShipVerdict computed severity counts or the safe/
// not-safe headline — so a critical below the confidence floor was invisible
// to a human reading the verdict, while exitCodeFor (which reads the
// UNFILTERED set) still exits 3 for the same scan. Reproduced live: two
// critical findings at confidence 0.85/0.6 (vibecoder floor 0.9) rendered
// "✅ Safe to deploy · 0 critical · 0 high · 0 advisory".
const stripAnsi2 = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

test('toShipVerdict: a below-floor critical still shows "Not safe to deploy" and is counted', () => {
  const scan = { findings: [
    { severity: 'critical', vuln: 'A', confidence: 0.85, file: 'a.js', line: 1, cwe: 'CWE-89' },
    { severity: 'critical', vuln: 'B', confidence: 0.6, file: 'b.js', line: 2, cwe: 'CWE-78' },
  ] };
  const out = stripAnsi2(toShipVerdict(scan, { color: false, profile: { confidenceMin: 0.9, showTaxonomy: false } }));
  assert.match(out, /Not safe to deploy/,
    'a critical below the confidence floor must still fail the headline verdict');
  assert.match(out, /2 critical/,
    `expected the critical count to include both findings regardless of confidence, got: ${out.match(/\d+ critical/)}`);
  assert.equal(exitCodeFor(scan), 3, 'sanity: exit code already correctly saw both criticals');
});

test('toShipVerdict: below-floor findings are disclosed, not silently dropped', () => {
  const scan = { findings: [
    { severity: 'low', vuln: 'Noisy', confidence: 0.2, file: 'a.js', line: 1, cwe: 'CWE-1' },
  ] };
  const out = stripAnsi2(toShipVerdict(scan, { color: false, profile: { confidenceMin: 0.9, showTaxonomy: false } }));
  assert.match(out, /1.*below.*confidence|confidence.*1/i,
    `a filtered-out finding must be disclosed by count, not silently vanish. got:\n${out}`);
});

test('toShipVerdict: a genuinely clean scan (nothing filtered) still says Safe to deploy with no disclosure noise', () => {
  const out = stripAnsi2(toShipVerdict({ findings: [] }, { color: false }));
  assert.match(out, /Safe to deploy/);
  assert.doesNotMatch(out, /below.*confidence/i);
});

// ── CMP-3: normalizeFindings must carry the schema's `remediation` field ────
//
// Most detectors set `remediation` (the field the schema in root CLAUDE.md
// actually requires); a minority of older detectors set `fix` instead.
// normalizeFindings only ever read `fix`, so every consumer downstream of it
// (SARIF fixes[]/fullDescription, the Markdown Fix column, the CLI inline
// "fix:" line) rendered empty for the majority of detectors.

test('CMP-3: normalizeFindings carries remediation through into .fix and .remediation', () => {
  const f = { severity: 'high', vuln: 'SQLi', file: 'a.js', line: 1, cwe: 'CWE-89', remediation: 'Use a parameterized query.' };
  const [out] = normalizeFindings({ findings: [f] });
  assert.equal(out.remediation, 'Use a parameterized query.');
  assert.equal(out.fix?.description, 'Use a parameterized query.');
});

test('CMP-3: a `fix` string still wins when both fix and remediation are set (existing precedent, unchanged)', () => {
  const f = { severity: 'high', vuln: 'X', file: 'a.js', line: 1, fix: 'from fix field', remediation: 'from remediation field' };
  const [out] = normalizeFindings({ findings: [f] });
  assert.equal(out.remediation, 'from fix field');
});

test('CMP-3: secrets and logicVulns channels also carry remediation through', () => {
  const scan = {
    secrets: [{ severity: 'high', vuln: 'Hardcoded key', file: 's.js', line: 1, remediation: 'Rotate the key; load from env.' }],
    logicVulns: [{ severity: 'medium', vuln: 'Broken authz', file: 'l.js', line: 1, remediation: 'Check ownership before returning the resource.' }],
  };
  const out = normalizeFindings(scan);
  assert.equal(out.find(x => x.kind === 'secret').remediation, 'Rotate the key; load from env.');
  assert.equal(out.find(x => x.kind === 'logic').remediation, 'Check ownership before returning the resource.');
});

test('CMP-3: toSARIF emits fixes[] and a real fullDescription from a remediation-only finding', () => {
  const f = { severity: 'critical', vuln: 'SQL Injection', file: 'a.js', line: 1, cwe: 'CWE-89', remediation: 'Use a parameterized query with bound params.' };
  const sarif = toSARIF({ findings: [f] }, {});
  const result = sarif.runs[0].results[0];
  assert.ok(Array.isArray(result.fixes) && result.fixes.length === 1,
    'a remediation-only finding must produce a SARIF fixes[] entry, not silently omit it');
  assert.match(result.fixes[0].description.text, /parameterized query/);
  const rule = sarif.runs[0].tool.driver.rules[0];
  assert.match(rule.fullDescription.text, /parameterized query/,
    'fullDescription must not degrade to the bare rule title when remediation is present');
});

test('CMP-3: toCLI renders the inline fix line for a remediation-only finding (not just fix-field ones)', () => {
  const f = { severity: 'high', vuln: 'Broken AuthZ', file: 'a.js', line: 1, cwe: 'CWE-862', remediation: 'Verify the caller owns the resource before returning it.' };
  const out = stripAnsi2(toCLI({ findings: [f] }, { color: false }));
  assert.match(out, /fix: Verify the caller owns the resource before returning it\./);
});

// Stage 6 correctness audit: a real `description` field (distinct from
// `vuln`/`remediation`, set by ~47 SAST detectors) was silently dropped by
// normalizeFindings, and SARIF/STIX's description-shaped fields preferred
// remediation text over it whenever both were present.
test('Stage6: normalizeFindings carries `description` through for the SAST channel', () => {
  const f = { severity: 'high', vuln: 'Missing auth', file: 'a.js', line: 1, description: 'The specific why-this-fired narrative.' };
  const [out] = normalizeFindings({ findings: [f] });
  assert.equal(out.description, 'The specific why-this-fired narrative.');
});

test('Stage6: normalizeFindings carries `description` through for secrets and logicVulns channels', () => {
  const scan = {
    secrets: [{ severity: 'high', vuln: 'Hardcoded key', file: 's.js', line: 1, description: 'secret desc' }],
    logicVulns: [{ severity: 'medium', vuln: 'Broken authz', file: 'l.js', line: 1, description: 'logic desc' }],
  };
  const out = normalizeFindings(scan);
  assert.equal(out.find(x => x.kind === 'secret').description, 'secret desc');
  assert.equal(out.find(x => x.kind === 'logic').description, 'logic desc');
});

test('Stage6: toSARIF prefers a real description over remediation text when both are present', () => {
  const f = {
    severity: 'critical', vuln: 'SQL Injection', file: 'a.js', line: 1, cwe: 'CWE-89',
    description: 'User input reaches a raw query without parameterization.',
    remediation: 'Use a parameterized query with bound params.',
  };
  const sarif = toSARIF({ findings: [f] }, {});
  const rule = sarif.runs[0].tool.driver.rules[0];
  const result = sarif.runs[0].results[0];
  assert.match(rule.fullDescription.text, /reaches a raw query/, 'fullDescription must prefer description over remediation');
  assert.match(result.message.text, /reaches a raw query/, 'result message must prefer description over remediation');
  assert.doesNotMatch(rule.fullDescription.text, /parameterized query/);
});

test('Stage6: toSTIX prefers a real description over remediation text when both are present', () => {
  const f = {
    severity: 'critical', vuln: 'SQL Injection', file: 'a.js', line: 1, cwe: 'CWE-89',
    description: 'User input reaches a raw query without parameterization.',
    remediation: 'Use a parameterized query with bound params.',
  };
  const stix = toSTIX({ findings: [f] }, {});
  const vuln = stix.objects.find(o => o.type === 'vulnerability');
  assert.match(vuln.description, /reaches a raw query/);
  assert.doesNotMatch(vuln.description, /parameterized query/);
});

test('Stage6: riskNote flags a confidence-0 finding, not just confidence-0.05 (boundary bug)', () => {
  const zero = { severity: 'critical', vuln: 'X', file: 'a.js', line: 1, confidence: 0 };
  const low = { severity: 'critical', vuln: 'Y', file: 'a.js', line: 2, confidence: 0.05 };
  const out = stripAnsi2(toCLI({ findings: [zero, low] }, { color: false }));
  const notes = (out.match(/lower confidence — verify before prioritising/g) || []).length;
  assert.equal(notes, 2, 'both the confidence-0 and confidence-0.05 findings should get the downgrade note');
});

test('Stage6: toHTML honors meta.startedAt for generatedAt (determinism parity with every other emitter)', () => {
  const scan = { findings: [] };
  const fixed = '1970-01-01T00:00:00.000Z';
  const html1 = toHTML(scan, { startedAt: fixed });
  const html2 = toHTML(scan, { startedAt: fixed });
  assert.equal(html1, html2, 'toHTML must be byte-identical across runs when meta.startedAt is fixed');
  assert.match(html1, /generated 1970-01-01T00:00:00\.000Z/);
});
