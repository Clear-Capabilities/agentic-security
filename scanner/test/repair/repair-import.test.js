// Verified remediation M4-01: external finding intake (FR-13). SARIF 2.1.0 and the normalized format, confinement of hostile reports,
// mapping to the current source, deduplication with provenance, signed import records, and imported findings repaired through the same
// contract workflow (or refuted, or refused). A skip is not a pass.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { importReport, saveImport, loadImport, decide, importedFinding, confineLocation } from '../../src/repair/import.js';
import { planFromInputs } from '../../src/repair/intake.js';
import { runRepair } from '../../src/repair/coordinator.js';
import { queueProposer } from '../../src/repair/candidates.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { runFullScan } from '../../src/engine.js';

import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const FIX = path.join(SCANNER, 'test', 'fixtures', 'repair');
const ON = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } });
const SARIF = fs.readFileSync(path.join(FIX, 'imports', 'ssrf-preview.sarif.json'), 'utf8');
const policy = { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 2 } };

const copy = (name) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), `ri-${name}-`)); fs.cpSync(path.join(FIX, name), d, { recursive: true }); return d; };
const git = (root, ...args) => { const r = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); return r.stdout.trim(); };
const gitRepo = (root) => { git(root, 'init', '-q'); git(root, 'config', 'user.email', 't@example.invalid'); git(root, 'config', 'user.name', 't'); git(root, 'add', '-A'); git(root, 'commit', '-qm', 'base'); return git(root, 'rev-parse', 'HEAD'); };

let ready = false; let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const unmet = unmetControls(await probeControls({}), [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  ready = (backend === 'userspace' || backend === 'namespace') && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); the imported-finding execution tests are UNVERIFIED here`;
});
const needs = (fn) => async (t) => (ready ? fn(t) : t.skip(whyNot));

describe('[FR-13] parsing, confinement, mapping and deduplication (no execution)', () => {
  test('[AC-13.5] hostile locations are rejected with reasons; hostile text stays inert, capped data and sets nothing', () => {
    const root = copy('ssrf-preview');
    const r = importReport({ root, format: 'sarif', text: SARIF, reportName: 'scan.sarif' });
    assert.equal(r.ok, true);
    const reasons = r.record.rejected.map((x) => x.reason).sort();
    assert.deepEqual(reasons, ['a file URI outside the project', 'a path that leaves the project', 'a reserved path (version control, verifier state, dependencies)', 'the https scheme is not a project file']);
    const json = JSON.stringify(r.record);
    assert.ok(!/"(?:approval|policy|execution|allowExecution)"\s*:/.test(json), 'no report field becomes policy');
    assert.ok(r.record.rejected.some((x) => /Ignore previous instructions/.test(x.untrustedText)), 'text is kept as data under untrustedText');
    for (const [uri, why] of [['/etc/passwd', /absolute/], ['src/%2e%2e/%2e%2e/x', /leaves the project/], ['node_modules/x/index.js', /reserved/], ['data:text/plain,hi', /data scheme/]]) assert.match(confineLocation(root, uri).rejected || '', why, uri);
    fs.symlinkSync('/etc', path.join(root, 'etc-link'));
    assert.match(confineLocation(root, 'etc-link/passwd').rejected, /link that leaves the project/);
  });

  test('two tools at the same place merge with both sources; the same CWE on another line and an unsupported CWE stay separate', () => {
    const r = importReport({ root: copy('ssrf-preview'), format: 'sarif', text: SARIF });
    const f = r.record.findings;
    assert.equal(f.length, 3);
    const merged = f.find((x) => x.line === 8);
    assert.deepEqual(merged.sources.map((s) => s.tool.name).sort(), ['external-scanner-a', 'external-scanner-b']);
    assert.equal(merged.mapping, 'relocated', 'tool A reported line 7; its snippet is on line 8');
    assert.equal(f.find((x) => x.line === 10).sources.length, 1);
    const xss = f.find((x) => x.cwe === 'CWE-79');
    assert.equal(xss.disposition, 'unsupported');
    assert.equal(xss.plannable, false);
  });

  test('[AC-13.4] a revision this repository lacks, an ambiguous snippet and a changed file without a snippet block planning; a rename is followed', () => {
    const root = copy('ssrf-preview');
    const base = gitRepo(root);
    const norm = (findings, revision) => JSON.stringify({ schema: 'agentic-security/external-findings', schemaVersion: '1.0.0', tool: { name: 't' }, ...(revision ? { revision } : {}), findings });
    const one = (extra) => importReport({ root, format: 'normalized', text: norm([{ cwe: 'CWE-918', file: 'src/app.mjs', startLine: 8, ...extra }], extra.revision) }).record.findings[0];
    assert.equal(one({ revision: 'f'.repeat(40) }).mapping, 'revision-unknown');
    fs.appendFileSync(path.join(root, 'src', 'app.mjs'), '// res.end(text);\n');
    git(root, 'commit', '-qam', 'change');
    assert.equal(one({ revision: base }).mapping, 'revision-mismatch', 'changed since the reported revision and no snippet');
    assert.equal(one({ revision: base, snippet: 'res.end(text);' }).mapping, 'ambiguous');
    assert.equal(one({ revision: base, snippet: 'await fetch(target)' }).mapping, 'exact');
    git(root, 'mv', 'src/app.mjs', 'src/preview.mjs');
    git(root, 'commit', '-qm', 'rename');
    const renamed = one({ revision: base, snippet: 'await fetch(target)' });
    assert.equal(renamed.mapping, 'renamed');
    assert.equal(renamed.file, 'src/preview.mjs');
    assert.equal(one({ startLine: 999 }).mapping, 'missing', 'the old path no longer exists at HEAD');
  });

  test('[AC-13.2] the import record is signed: a hand-edited record is refused, and an accepted risk is never planned', () => {
    const root = copy('ssrf-preview');
    const r = importReport({ root, format: 'sarif', text: SARIF });
    const f = saveImport(root, r.record);
    const id = r.record.importId;
    const target = r.record.findings.find((x) => x.line === 8).importedId;
    assert.ok(importedFinding(root, id, target).finding);
    assert.equal(decide(root, id, target, { disposition: 'accepted-risk', reason: '' }).ok, false, 'a reason is required');
    assert.equal(decide(root, id, target, { disposition: 'accepted-risk', reason: 'behind an egress proxy that enforces the allowlist' }).ok, true);
    assert.match(importedFinding(root, id, target).reason, /accepted risk/);
    const doc = JSON.parse(fs.readFileSync(f, 'utf8'));
    doc.findings[0].mapping = 'exact'; doc.findings[0].family = 'sql-injection';
    fs.writeFileSync(f, JSON.stringify(doc));
    assert.match(loadImport(root, id).reason, /signature does not verify/);
    assert.equal(planFromInputs({ root, profilePath: path.join(root, 'profile.json'), importId: id, findingId: target }).status, 'blocked');
  });
});

describe('[FR-13] imported findings through the repair workflow, executed', () => {
  test('[AC-13.1] a finding the internal detector does not report is repaired when the contract establishes it; apply still needs the signed scan', needs(async () => {
    const root = copy('ssrf-preview');
    const original = fs.readFileSync(path.join(root, 'src', 'app.mjs'), 'utf8');
    const internal = await runFullScan({ fileContents: { 'src/app.mjs': original }, scanRoot: root, provenance: false }, () => {});
    assert.ok(!internal.findings.some((f) => f.cwe === 'CWE-918'), 'the internal detector does not recognise this request forgery');
    const r = importReport({ root, format: 'sarif', text: SARIF });
    saveImport(root, r.record);
    const target = r.record.findings.find((x) => x.line === 8);
    const p = planFromInputs({ root, profilePath: path.join(root, 'profile.json'), importId: r.record.importId, findingId: target.importedId });
    assert.ok(p.plan, [...p.problems, ...p.blocked].join('; '));
    assert.equal(p.plan.contract.family, 'ssrf');
    assert.equal(p.plan.finding.custody, 'imported');
    assert.equal(p.plan.finding.sourceTool, 'external-scanner-a');
    const FETCH = '      const r = await fetch(target);\n';
    const fixed = original.replace(FETCH, () => "      const ALLOWED = new Set(['api.partner.test', 'cdn.partner.test']);\n      let next = new URL(target); let r;\n      for (let hop = 0; ; hop++) {\n        if (hop > 3 || next.protocol !== 'http:' || next.username || next.password || !ALLOWED.has(next.hostname)) { res.writeHead(403); res.end('destination not allowed'); return; }\n        r = await fetch(next, { redirect: 'manual' });\n        if (r.status < 300 || r.status > 399) break;\n        next = new URL(r.headers.get('location'), next);\n      }\n");
    const noScan = await runRepair({ root, plan: p.plan, config: ON, proposers: [queueProposer([{ files: { 'src/app.mjs': fixed } }])], policy, apply: {} });
    assert.equal(noScan.record.disposition, 'verified-for-contract', noScan.record.reasons.join('; '));
    assert.equal(noScan.record.application, 'not-applied');
    assert.match(noScan.record.reasons.join(' '), /integrity check failed/);
    assert.equal(fs.readFileSync(path.join(root, 'src', 'app.mjs'), 'utf8'), original, 'an imported finding cannot create the signed scan it needs');
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"preview","version":"1.0.0","type":"module"}\n');
    const scan = spawnSync(process.execPath, [path.join(SCANNER, 'bin', 'agentic-security.js'), 'scan', root], { cwd: root, encoding: 'utf8', timeout: 180000, maxBuffer: 64 << 20 });
    assert.ok(fs.existsSync(path.join(root, '.agentic-security', 'last-scan.json.sig')), `the CLI scan wrote signed state (exit ${scan.status})`);
    const withScan = await runRepair({ root, plan: p.plan, config: ON, proposers: [queueProposer([{ files: { 'src/app.mjs': fixed } }])], policy, apply: {} });
    assert.equal(withScan.record.application, 'applied', withScan.record.reasons.join('; '));
  }));

  test('[AC-13.3] an imported finding the original does not reproduce is refuted and no patch is proposed', needs(async () => {
    const root = copy('sql-notes');
    const app = path.join(root, 'src', 'app.mjs');
    const SQL = "        const rows = db.prepare(`SELECT title, body FROM notes WHERE owner = '${user}' AND title = '${title}'`).all();";
    fs.writeFileSync(app, fs.readFileSync(app, 'utf8').replace(SQL, () => "        const rows = db.prepare('SELECT title, body FROM notes WHERE owner = ? AND title = ?').all(user, title);"));
    const r = importReport({ root, format: 'normalized', text: fs.readFileSync(path.join(FIX, 'imports', 'safe-sql.normalized.json'), 'utf8') });
    assert.equal(r.record.findings[0].mapping, 'exact');
    saveImport(root, r.record);
    const p = planFromInputs({ root, profilePath: path.join(root, 'profile.json'), importId: r.record.importId, findingId: r.record.findings[0].importedId });
    assert.ok(p.plan, [...p.problems, ...p.blocked].join('; '));
    const before = fs.readFileSync(app, 'utf8');
    const run = await runRepair({ root, plan: p.plan, config: ON, proposers: [queueProposer([{ files: { 'src/app.mjs': before.replace('ORDER', 'ORDER') + '\n' } }])], policy });
    assert.equal(run.record.disposition, 'refuted-finding', run.record.reasons.join('; '));
    assert.equal(run.record.candidates.length, 0, 'no candidate is judged for a refuted finding');
    assert.equal(fs.readFileSync(app, 'utf8'), before);
  }));
});
