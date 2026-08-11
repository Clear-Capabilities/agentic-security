// S7 (Stage 1 correctness audit) — root CLAUDE.md documents four separate
// finding channels: scan.findings (SAST), scan.secrets, scan.supplyChain
// (SCA), scan.logicVulns (business-logic). `--only sast|sca|secrets` only
// ever cleared three of the four buckets in every branch — scan.logicVulns
// was never touched regardless of which value was passed. For --only sast
// that's correct (business-logic is source analysis, part of the SAST
// pillar), but for --only sca and --only secrets it meant a business-logic
// finding (neither SCA nor secrets) leaked into a single-pillar scan's
// output AND its exit code, since normalizeFindings()/exitCodeFor() both
// fold scan.logicVulns in.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const cli = path.resolve(here, '..', 'dist', 'agentic-security.mjs');
const fixture = path.resolve(here, 'fixtures', 'vulnerable-js');

// A real business-logic finding that lands specifically in scan.logicVulns
// (sast/logic.js#scanBusinessLogic, pushed into the `aLogic` array in
// engine.js — distinct from posture/business-logic.js's scanBusinessLogicV2,
// which pushes into scan.findings/SAST and was already correctly cleared).
const LOGIC_VULN_ROUTE = `
app.post('/api/users/:id', (req, res) => {
  user.isAdmin = req.body.isAdmin;
  user.save();
  res.json({ ok: true });
});
`;
const LOGIC_VULN_MATCH = 'Privilege Field Set from Request Body';

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'agsec-only-'));
  for (const entry of await fsp.readdir(fixture, { withFileTypes: true })) {
    if (entry.isFile()) await fsp.copyFile(path.join(fixture, entry.name), path.join(dir, entry.name));
  }
  await fsp.writeFile(path.join(dir, 'routes.js'), LOGIC_VULN_ROUTE);
  return dir;
}

function runScanOnly(dir, only) {
  return spawnSync('node', [cli, 'scan', dir, '--format', 'json', '--no-network', '--only', only], { encoding: 'utf8' });
}

test('--only sast keeps business-logic findings (they are source analysis)', async () => {
  const dir = await mkProject();
  try {
    const r = runScanOnly(dir, 'sast');
    assert.ok(r.status <= 3, `expected a verdict exit (<=3), got ${r.status}: ${r.stderr}`);
    const out = JSON.parse(r.stdout);
    assert.ok(out.findings.some(f => f.vuln === LOGIC_VULN_MATCH),
      `expected the business-logic finding to survive --only sast, got families: ${out.findings.map(f => f.family).join(', ')}`);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('--only sca clears business-logic findings from output and exit code', async () => {
  const dir = await mkProject();
  try {
    const full = runScanOnly(dir, 'sca');
    assert.ok(full.status <= 3, `expected a verdict exit (<=3), got ${full.status}: ${full.stderr}`);
    const out = JSON.parse(full.stdout);
    assert.ok(!out.findings.some(f => f.vuln === LOGIC_VULN_MATCH),
      `expected no business-logic finding under --only sca, got: ${JSON.stringify(out.findings.map(f => f.vuln))}`);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('--only secrets clears business-logic findings from output', async () => {
  const dir = await mkProject();
  try {
    const r = runScanOnly(dir, 'secrets');
    assert.ok(r.status <= 3, `expected a verdict exit (<=3), got ${r.status}: ${r.stderr}`);
    const out = JSON.parse(r.stdout);
    assert.ok(!out.findings.some(f => f.vuln === LOGIC_VULN_MATCH),
      `expected no business-logic finding under --only secrets, got: ${JSON.stringify(out.findings.map(f => f.vuln))}`);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});
