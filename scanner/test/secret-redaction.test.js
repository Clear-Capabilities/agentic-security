// Stage 4 correctness audit (coverage breadth, secrets): three secret
// detectors (engine.js's scanEntropySecrets and scanCredentials,
// sast/secret-concat.js's scanSecretConcat) all stored the RAW, unmasked
// source line in `snippet` — even though each one computed a correctly
// redacted `masked` value right next to it. Nothing downstream ever
// redacts `snippet` again (normalizeFindings copies it through verbatim,
// and toHTML/toCSV/toJUnit all render it directly), so the plaintext
// credential each detector exists to find flowed straight into every
// report format this scanner emits, including the persisted
// last-scan.json. A scanner whose purpose is finding secrets must not
// leak the secrets it finds into its own output.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { normalizeFindings, toHTML, toCSV } from '../src/report/index.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-secretredact-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('a hardcoded GitHub token does not appear raw in normalized findings, HTML, or CSV output', async () => {
  const TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz12';
  const dir = mkTmp('github-token', {
    'config.js': `const GITHUB_TOKEN = "${TOKEN}";\n`,
  });
  const { scan } = await runScan(dir);
  const norm = normalizeFindings(scan);
  const secretFindings = norm.filter(f => f.kind === 'secret');
  assert.ok(secretFindings.length >= 1, 'expected at least one secret finding');
  for (const f of secretFindings) {
    assert.ok(!f.snippet.includes(TOKEN), `raw token leaked in normalized snippet: ${f.snippet}`);
  }
  const html = toHTML(scan, {});
  assert.ok(!html.includes(TOKEN), 'raw token leaked into HTML report');
  const csv = toCSV(scan, {});
  assert.ok(!csv.includes(TOKEN), 'raw token leaked into CSV report');
});

test('a split-concatenation secret (secret-concat.js) does not appear raw in normalized findings', async () => {
  const dir = mkTmp('concat', {
    // Split across two literals to evade the contiguous-token scanners —
    // exactly the shape secret-concat.js exists to catch.
    'aws.js': `const AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';\n`,
  });
  const { scan } = await runScan(dir);
  const norm = normalizeFindings(scan);
  const concatFindings = norm.filter(f => f.parser === 'SECRET-CONCAT' || /split across concatenated/i.test(f.vuln || ''));
  assert.ok(concatFindings.length >= 1, 'expected a secret-concat finding');
  for (const f of concatFindings) {
    // The raw source splits the secret across two literals ('AKIA' + 'IOSFODNN7EXAMPLE'),
    // so the *joined* string never appears verbatim even pre-fix — assert on the literal
    // piece that actually appears in the unredacted source line instead.
    assert.ok(!f.snippet.includes('IOSFODNN7EXAMPLE'), `raw secret literal leaked in snippet: ${f.snippet}`);
  }
});
