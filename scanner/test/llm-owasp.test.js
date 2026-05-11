// OWASP LLM Top 10 — per-category detector coverage.
//
// Each fixture file demonstrates exactly one vulnerability class. We assert
// the corresponding detector fires (positive) and that the clean fixture is
// silent (negative). Together the positives should produce findings tagged
// with owaspLlm = LLM01, LLM05, LLM06, LLM07, LLM08, LLM09, LLM10.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanLLMOwasp } from '../src/sast/llm-owasp.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX_DIR = path.join(__dirname, 'fixtures', 'llm-owasp');

function scanFixture(name) {
  const fp = path.join(FIX_DIR, name);
  const raw = fs.readFileSync(fp, 'utf8');
  // Use a non-test path so _NONPROD_PATH_RE in the detector doesn't skip the file.
  return scanLLMOwasp(`app/llm-owasp/${name}`, raw);
}

const POSITIVES = [
  { file: 'vuln-llm01-dynamic-system.py',    owaspLlm: 'LLM01' },
  { file: 'vuln-llm05-html-output.py',       owaspLlm: 'LLM05' },
  { file: 'vuln-llm06-exec.py',              owaspLlm: 'LLM06' },
  { file: 'vuln-llm07-secrets-in-prompt.py', owaspLlm: 'LLM07' },
  { file: 'vuln-llm08-rag-ingest.py',        owaspLlm: 'LLM08' },
  { file: 'vuln-llm09-misinformation.py',    owaspLlm: 'LLM09' },
  { file: 'vuln-llm10-no-budget.py',         owaspLlm: 'LLM10' },
];

for (const { file, owaspLlm } of POSITIVES) {
  test(`OWASP LLM Top 10 — ${owaspLlm} fires on ${file}`, () => {
    const findings = scanFixture(file);
    const hit = findings.find((f) => f.owaspLlm === owaspLlm);
    assert.ok(
      hit,
      `Expected ${owaspLlm} finding on ${file}; got: ${findings.map(f => f.owaspLlm).join(', ') || '(none)'}`
    );
  });
}

test('OWASP LLM Top 10 — clean fixture produces no LLM Top 10 findings', () => {
  const findings = scanFixture('clean-llm-ok.py');
  assert.equal(
    findings.length,
    0,
    `Expected 0 findings on clean fixture; got: ${findings.map(f => f.owaspLlm + ' ' + f.vuln).join(' | ')}`,
  );
});

test('OWASP LLM Top 10 — owaspLlm tag persists through report serialization', async () => {
  const { runScan } = await import('../src/runScan.js');
  const { normalizeFindings } = await import('../src/report/index.js');
  const { scan } = await runScan(FIX_DIR);
  const norm = normalizeFindings(scan);
  const tagged = norm.filter(f => f.owaspLlm && /^LLM\d{2}$/.test(f.owaspLlm));
  assert.ok(tagged.length >= POSITIVES.length, `expected ≥${POSITIVES.length} tagged findings, got ${tagged.length}`);
});
