// Renderer tests: the "likely lower risk" demotion note (so a hardcoded
// severity isn't taken at face value) + verdict discoverability lines.
import { test } from 'node:test';
import assert from 'node:assert';
import { toCLI, toProTable, toHTML, toShipVerdict } from '../src/report/index.js';

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
