// Taint-recall PRD (80%): Ruby catalog additions found missing during the
// full CFG rebuild's audit of still-0%-taint corpus entries.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-rb-catalog-${name}-`));
  fs.writeFileSync(path.join(dir, 'app.rb'), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('rb-redirect-to: redirect_to(params-derived) fires Open Redirect via IR-TAINT', async () => {
  const dir = mkTmp('redirect', `
class C
  def go(params)
    redirect_to params[:next]
  end
end
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /redirect/i.test(f.vuln)),
    `expected Open Redirect, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('rb-render: render inline: with tainted interpolation fires Reflected XSS via IR-TAINT', async () => {
  const dir = mkTmp('render', `
class C
  def show(params)
    render inline: "<h1>Hello #{params[:name]}</h1>"
  end
end
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected Reflected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('rb-uri-open: URI.open(params-derived) fires SSRF via IR-TAINT (direct, non-nested call)', async () => {
  const dir = mkTmp('ssrf', `
require "open-uri"
def fetch(url)
  URI.open(url)
end
def handler(params)
  fetch(params[:url])
end
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ssrf/i.test(f.vuln)),
    `expected SSRF, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('rb-file-read: File.read(concatenated) fires Path Traversal via IR-TAINT (direct, non-nested call)', async () => {
  const dir = mkTmp('path', `
def read(name)
  File.read("/var/data/" + name)
end
def handler(params)
  read(params[:file])
end
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /path traversal/i.test(f.vuln)),
    `expected Path Traversal, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});
