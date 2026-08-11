// Renderer tests: the "likely lower risk" demotion note (so a hardcoded
// severity isn't taken at face value) + verdict discoverability lines.
import { test } from 'node:test';
import assert from 'node:assert';
import { toCLI, toProTable, toHTML, toShipVerdict, exitCodeFor } from '../src/report/index.js';

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
