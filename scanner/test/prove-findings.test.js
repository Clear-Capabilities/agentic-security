// R2 — automatic PoC synthesis + tier promotion during a scan.
//
// The refusals matter more than the acceptances here. A synthesized PoC that
// runs but proves nothing yields `proof-failed`, which is a triage signal
// ABOUT THE FINDING — so a template that fires on a shape it cannot actually
// exploit manufactures evidence against real bugs. Each refusal below is a
// case where the generated script would have been a guess.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { synthesizeInProcessPoc, _internals } from '../src/posture/poc-inprocess.js';
import { annotateExecutionProofs, renderProofSummary, proveEnabled } from '../src/posture/prove-findings.js';
import { sandboxAvailable } from '../src/sandbox/index.js';

const VULN = [
  "const { exec } = require('child_process');",
  'module.exports = function handler(req, res) {',
  "  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));",
  '};',
].join('\n');

const cmdi = (over = {}) => ({
  family: 'command-injection', cwe: 'CWE-78', file: 'handler.js',
  vuln: 'Command Injection (User-Controlled Input)', ...over,
});

// Sandbox proofs get a generous time budget in tests. The PoC itself runs in
// ~120ms, but the release gate saturates the machine and a confined process can
// take seconds just to start there — and a timed-out run has `ran:false`, which
// correctly demotes a proof whose marker was already written. Raising the
// budget does not weaken any assertion: the marker must still appear. The
// PRODUCT default stays at 10s; only these tests ask for headroom, so what they
// measure is the marker rather than the load average.
const BUDGET = { timeoutMs: 45000 };

// ------------------------------------------------------------ synthesis

test('synthesizes a PoC for a shell-sink handler reading req.query', () => {
  const r = synthesizeInProcessPoc(cmdi(), VULN);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.poc.kind, 'in-process');
  assert.equal(r.poc.paramKey, 'host');
  assert.equal(r.poc.paramSource, 'query');
  assert.deepEqual(r.poc.requires, ['handler.js']);
  assert.match(r.poc.code, /PROVEN/);
  assert.match(r.poc.code, /unref\(\)/, 'the safety timer must not hold the event loop open');
});

test('refuses an argv-form sink — absence of proof there would say nothing', () => {
  const argv = VULN.replace("exec('ping -c 1 ' + req.query.host,", "execFile('ping', ['-c','1', req.query.host],");
  const r = synthesizeInProcessPoc(cmdi(), argv);
  assert.equal(r.ok, false);
  assert.match(r.reason, /argv array/);
});

test('refuses a family whose exploitation is not marker-observable', () => {
  for (const family of ['xss', 'crypto-weak-hash', 'sqli', undefined]) {
    const r = synthesizeInProcessPoc(cmdi({ family }), VULN);
    assert.equal(r.ok, false, `family ${family} must be refused`);
    assert.match(r.reason, /marker-observable/);
  }
});

test('refuses when no exported two-argument handler exists', () => {
  const noHandler = "const { exec } = require('child_process');\nexec('ping ' + process.argv[2]);\n";
  const r = synthesizeInProcessPoc(cmdi(), noHandler);
  assert.equal(r.ok, false);
  assert.match(r.reason, /two-argument/);
});

test('refuses a one-argument export rather than inventing an interface', () => {
  const oneArg = "const { exec } = require('child_process');\nmodule.exports = function (req) { exec('ping ' + req.query.h); };\n";
  const r = synthesizeInProcessPoc(cmdi(), oneArg);
  assert.equal(r.ok, false);
  assert.match(r.reason, /two-argument/);
});

test('refuses when the handler reads no request property', () => {
  const noSrc = "const { exec } = require('child_process');\nmodule.exports = function (req, res) { exec('ping localhost', () => res.send('x')); };\n";
  const r = synthesizeInProcessPoc(cmdi(), noSrc);
  assert.equal(r.ok, false);
  assert.match(r.reason, /injection point is unknown/);
});

test('binds to the request identifier the export actually declares', () => {
  // Reads `request.query.h` while binding (request, response). A template that
  // assumed `req` would build a PoC on a name the handler never uses.
  const renamed = [
    "const { exec } = require('child_process');",
    'module.exports = function (request, response) {',
    "  exec('ping ' + request.query.h, () => response.send('x'));",
    '};',
  ].join('\n');
  const r = synthesizeInProcessPoc(cmdi(), renamed);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.poc.paramKey, 'h');
});

test('a decoy request read on an unrelated identifier does not become the injection point', () => {
  const decoy = [
    "const { exec } = require('child_process');",
    'const other = { query: { ignored: 1 } };',
    'module.exports = function (req, res) {',
    "  exec('ping ' + req.body.target, () => res.send(String(other.query.ignored)));",
    '};',
  ].join('\n');
  const r = synthesizeInProcessPoc(cmdi(), decoy);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.poc.paramSource, 'body');
  assert.equal(r.poc.paramKey, 'target');
});

test('supports a named export', () => {
  const named = VULN.replace('module.exports =', 'exports.ping =');
  const r = synthesizeInProcessPoc(cmdi(), named);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.poc.handler, 'exports.ping');
  assert.match(r.poc.code, /import \{ ping \}/);
});

test('refuses non-JavaScript and missing content', () => {
  assert.equal(synthesizeInProcessPoc(cmdi({ file: 'app.py' }), VULN).ok, false);
  assert.equal(synthesizeInProcessPoc(cmdi(), '').ok, false);
  assert.equal(synthesizeInProcessPoc(cmdi(), null).ok, false);
});

// ------------------------------------------------------------ promotion

test('proving is OFF unless explicitly enabled', async () => {
  assert.equal(proveEnabled({}), false);
  assert.equal(proveEnabled({ AGENTIC_SECURITY_PROVE: '0' }), false);
  assert.equal(proveEnabled({ AGENTIC_SECURITY_PROVE: '1' }), true);

  const findings = [cmdi()];
  const s = await annotateExecutionProofs(findings, { fileContents: { 'handler.js': VULN }, env: {} });
  assert.equal(s.enabled, false);
  assert.match(s.reason, /not enabled/);
  assert.equal(findings[0].proofTier, undefined, 'no tier may move while the feature is off');
  assert.equal(renderProofSummary(s), null);
});

test('a real scan-shaped run promotes a genuinely exploitable finding', async (t) => {
  if (!sandboxAvailable()) {
    t.skip('SKIPPED, NOT PASSED: no confinement backend on this host');
    return;
  }
  const findings = [cmdi()];
  const s = await annotateExecutionProofs(findings, {
    fileContents: { 'handler.js': VULN }, env: { AGENTIC_SECURITY_PROVE: '1' },
  });
  assert.equal(s.enabled, true);
  assert.equal(s.attempted, 1);
  assert.equal(s.proven, 1, JSON.stringify(findings[0].proofEvidence));
  assert.equal(findings[0].proofTier, 'execution-proven');
  assert.equal(findings[0].proofEvidence.ran, true);
  assert.match(renderProofSummary(s), /1 execution-proven of 1 attempted/);
});

test('an unsynthesizable finding is skipped, never attempted and never demoted', async (t) => {
  const findings = [cmdi({ family: 'xss' })];
  const s = await annotateExecutionProofs(findings, {
    fileContents: { 'handler.js': VULN }, env: { AGENTIC_SECURITY_PROVE: '1' },
  });
  // Host-independent, and the part that actually matters: a finding we cannot
  // build a PoC for must keep its static standing on ANY host.
  assert.equal(s.attempted, 0);
  assert.equal(findings[0].proofTier, undefined,
    'a finding we cannot build a PoC for keeps its static standing');

  // The per-candidate skip COUNT is only reached when a sandbox exists — with
  // no confinement backend the annotator returns before it can classify
  // anything, which is the correct fail-closed order. Asserting the count
  // unconditionally made this test pass on the macOS dev host and fail on a CI
  // runner that restricts unprivileged namespaces: a host-dependent assertion
  // dressed up as a behavioural one.
  if (!sandboxAvailable()) {
    t.diagnostic('skip-count assertion not checked: no confinement backend on this host');
    assert.equal(s.enabled, false);
    assert.match(s.reason, /no confinement backend/);
    return;
  }
  assert.equal(s.skipped, 1);
});

test('the per-scan cap is reported, not applied silently', async (t) => {
  if (!sandboxAvailable()) {
    t.skip('SKIPPED, NOT PASSED: no confinement backend on this host');
    return;
  }
  const findings = [cmdi(), cmdi(), cmdi()];
  const s = await annotateExecutionProofs(findings, {
    fileContents: { 'handler.js': VULN }, maxCandidates: 1, env: { AGENTIC_SECURITY_PROVE: '1' },
  });
  assert.equal(s.attempted, 1);
  assert.equal(s.capped, 2);
  assert.match(renderProofSummary(s), /2 eligible finding\(s\) NOT attempted/);
});

test('the whole loop runs off a real scan, and stays off by default', async (t) => {
  const { runScan } = await import('../src/runScan.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'prove-scan-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"f","version":"1.0.0"}');
    fs.writeFileSync(path.join(dir, 'handler.js'), VULN + '\n');

    const off = await runScan(dir);
    assert.equal(off.scan.executionProof.enabled, false);
    assert.ok(!off.scan.findings.some(f => f.proofTier), 'a default scan must promote nothing');

    if (!sandboxAvailable()) {
      t.diagnostic('cross-check with proving enabled skipped: no confinement backend');
      return;
    }
    process.env.AGENTIC_SECURITY_PROVE = '1';
    try {
      const on = await runScan(dir);
      assert.equal(on.scan.executionProof.enabled, true);
      assert.equal(on.scan.executionProof.proven, 1);
      assert.ok(on.scan.findings.some(f => f.proofTier === 'execution-proven'));
    } finally { delete process.env.AGENTIC_SECURITY_PROVE; }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the marker payload writes only inside the sandbox root', () => {
  // Guards against someone "improving" the payload into something that
  // touches the wider filesystem or the network.
  const r = synthesizeInProcessPoc(cmdi(), VULN);
  assert.equal(r.ok, true);
  assert.match(r.poc.code, /x; > PROVEN/);
  assert.doesNotMatch(r.poc.code, /https?:|curl|wget|rm\s|\/etc\/|\.\.\//);
  assert.equal(_internals.MARKER, 'PROVEN');
});

// --- aggregate time budget ------------------------------------------------
//
// A count cap bounds nothing in time, and CI proved the backend's own timeout
// could not be taken on faith. `now` is injected so the budget can be tested
// without burning wall-clock.

test('the aggregate budget stops the loop and reports what it did not attempt', async () => {
  const findings = [cmdi(), cmdi(), cmdi(), cmdi()];
  // A clock that jumps past the budget after the first candidate.
  let t = 0;
  const now = () => { t += 60_000; return t; };
  const s = await annotateExecutionProofs(findings, {
    fileContents: { 'handler.js': VULN },
    env: { AGENTIC_SECURITY_PROVE: '1' },
    totalBudgetMs: 100_000,
    now,
  });
  if (!s.enabled) return; // no sandbox on this host; nothing to bound
  assert.ok(s.attempted < findings.length, 'the budget must actually stop the loop');
  assert.equal(s.attempted + s.budgetExhausted, findings.length,
    'every candidate must be either attempted or reported as unattempted');
  assert.match(renderProofSummary(s), /aggregate time budget exhausted/);
  assert.match(renderProofSummary(s), /unattempted, not unprovable/);
});

test('findings left unattempted by the budget keep their static tier', async () => {
  const findings = [cmdi(), cmdi()];
  let t = 0;
  const now = () => { t += 60_000; return t; };
  const s = await annotateExecutionProofs(findings, {
    fileContents: { 'handler.js': VULN },
    env: { AGENTIC_SECURITY_PROVE: '1' },
    totalBudgetMs: 1,
    now,
  });
  if (!s.enabled) return;
  assert.equal(s.attempted, 0, 'an already-exhausted budget must attempt nothing');
  assert.equal(s.budgetExhausted, 2);
  for (const f of findings) {
    assert.equal(f.proofTier, undefined, 'an unattempted finding must not be demoted');
  }
});

test('a generous budget does not interfere', async (t) => {
  if (!sandboxAvailable()) { t.skip('SKIPPED, NOT PASSED: no confinement backend'); return; }
  const findings = [cmdi()];
  const s = await annotateExecutionProofs(findings, {
    fileContents: { 'handler.js': VULN }, env: { AGENTIC_SECURITY_PROVE: '1' },
  });
  assert.equal(s.budgetExhausted, 0);
  assert.equal(s.proven, 1);
});

// --- webhook signature bypass (PRD Epic 1.1) -------------------------------
//
// A different KIND of evidence from the injection classes: nothing is injected,
// so nothing writes the marker on its own. The defect is the handler accepting
// a request it should have rejected, so the PoC observes the acceptance and
// records it. Conflating the two is how a template asserts something it never
// saw, which is why the "no decision" case below matters.

const WEBHOOK_VULN = [
  'module.exports = function handler(req, res) {',
  '  const evt = req.body;',
  '  recordPayment(evt.amount);',
  "  res.send('ok');",
  '};',
  'function recordPayment(){}',
].join('\n');

const webhookFinding = (over = {}) => ({
  family: 'webhook-missing-signature-verification', cwe: 'CWE-345', file: 'hook.js',
  vuln: 'Webhook — Missing Signature Verification', severity: 'high', ...over,
});

test('a webhook handler with no verification synthesizes a behavioural PoC', () => {
  const r = synthesizeInProcessPoc(webhookFinding(), WEBHOOK_VULN);
  assert.equal(r.ok, true, r.reason);
  assert.match(r.poc.observes, /accepted an unsigned webhook/);
  assert.match(r.poc.code, /decided === "accepted"/,
    'the marker must be written ONLY on an observed acceptance');
});

test('the marker write is GUARDED by an observed acceptance', () => {
  // "No reply" is not "rejected", and neither is an acceptance. The only line
  // that writes the marker must sit behind the acceptance check — an
  // unconditional write would report every handler as proven.
  const r = synthesizeInProcessPoc(webhookFinding(), WEBHOOK_VULN);
  const writes = r.poc.code.split('\n').filter(l => l.includes('writeFileSync'));
  assert.equal(writes.length, 1, 'exactly one marker write is expected');
  assert.match(writes[0], /if \(decided === "accepted"\)/,
    'the marker write is not guarded by the acceptance observation');
  assert.match(r.poc.code, /let decided = null/, 'the initial state must be "no decision"');
});

test('the guard actually holds when executed: no decision writes no marker', async (t) => {
  // Asserted by RUNNING it, because the property is about behaviour and a
  // source-shape check can only suggest it. A handler that never replies is the
  // case a naive template gets wrong.
  if (!sandboxAvailable()) { t.skip('SKIPPED, NOT PASSED: no confinement backend'); return; }
  const { proveFinding } = await import('../src/posture/execution-proof.js');
  const SILENT = [
    'module.exports = function handler(req, res) {',
    '  const evt = req.body;',
    '  // never replies at all',
    '};',
  ].join('\n');
  const poc = synthesizeInProcessPoc(webhookFinding(), SILENT);
  assert.equal(poc.ok, true, poc.reason);
  const r = await proveFinding({ ...webhookFinding(), poc: poc.poc }, { files: { 'hook.js': SILENT }, ...BUDGET });
  assert.notEqual(r.proofTier, 'execution-proven',
    'a handler that never decided was reported as having accepted the request');
});

test('a 4xx reply is a rejection whatever the body says', () => {
  const r = synthesizeInProcessPoc(webhookFinding(), WEBHOOK_VULN);
  assert.match(r.poc.code, /c >= 400/, 'status codes must decide acceptance, not the body');
});

test('a handler that does not read the body is refused', () => {
  // Then "it accepted an unsigned request" is not a statement about a webhook.
  const noBody = "module.exports = function handler(req, res) { res.send('ok'); };";
  const r = synthesizeInProcessPoc(webhookFinding(), noBody);
  assert.equal(r.ok, false);
  assert.match(r.reason, /does not read/);
});

test('a file that already verifies signatures is refused, not guessed at', () => {
  // Whether the check guards THIS path is a static question; an execution
  // template must not answer it by assumption.
  const verified = [
    "const crypto = require('crypto');",
    'module.exports = function handler(req, res) {',
    "  const mac = crypto.createHmac('sha256', KEY).update(req.rawBody).digest('hex');",
    '  if (mac !== req.headers.sig) return res.status(401).send("no");',
    '  recordPayment(req.body.amount);',
    "  res.send('ok');",
    '};',
  ].join('\n');
  const r = synthesizeInProcessPoc(webhookFinding(), verified);
  assert.equal(r.ok, false);
  assert.match(r.reason, /static question/);
});

test('the webhook class proves in the sandbox, and a fixed handler does not', async (t) => {
  if (!sandboxAvailable()) { t.skip('SKIPPED, NOT PASSED: no confinement backend'); return; }
  const { proveFinding } = await import('../src/posture/execution-proof.js');

  const vulnPoc = synthesizeInProcessPoc(webhookFinding(), WEBHOOK_VULN);
  const provenR = await proveFinding({ ...webhookFinding(), poc: vulnPoc.poc },
    { files: { 'hook.js': WEBHOOK_VULN }, ...BUDGET });
  assert.equal(provenR.proofTier, 'execution-proven', JSON.stringify(provenR.proofEvidence));

  // A handler that rejects unsigned requests must NOT prove. Settled by running
  // it, not by pattern-matching the source.
  const FIXED = [
    'module.exports = function handler(req, res) {',
    "  const sig = req.headers['x-signature'];",
    "  if (!sig || sig !== 'expected') return res.status(401).send('bad signature');",
    '  recordPayment(req.body.amount);',
    "  res.send('ok');",
    '};',
    'function recordPayment(){}',
  ].join('\n');
  const fixedPoc = synthesizeInProcessPoc(webhookFinding(), FIXED);
  assert.equal(fixedPoc.ok, true, 'the fixed handler should still be synthesizable — execution decides');
  const fixedR = await proveFinding({ ...webhookFinding(), poc: fixedPoc.poc },
    { files: { 'hook.js': FIXED }, ...BUDGET });
  assert.notEqual(fixedR.proofTier, 'execution-proven',
    'a handler that rejects unsigned requests must never be reported as proven');
  assert.equal(fixedR.proofEvidence.ran, true, 'and the refusal must come from a RUN, not a skip');
});


// ── SQL injection: proven at the driver boundary ────────────────────────────
//
// The point of this class is that it needed no running database. The question
// "was the payload SQL text or a bound parameter?" is fully answered where the
// query crosses into the driver, so that is where the PoC observes.

const SQLI_VULN = [
  "const mysql = require('mysql');",
  'const db = mysql.createConnection({ host: "localhost" });',
  'module.exports = function handler(req, res) {',
  '  db.query("SELECT * FROM users WHERE id = \'" + req.query.id + "\'", (e, rows) => res.json(rows));',
  '};',
].join('\n');

const SQLI_FIXED = [
  "const mysql = require('mysql');",
  'const db = mysql.createConnection({ host: "localhost" });',
  'module.exports = function handler(req, res) {',
  '  db.query("SELECT * FROM users WHERE id = ?", [req.query.id], (e, rows) => res.json(rows));',
  '};',
].join('\n');

const sqli = (over = {}) => ({
  family: 'sql-injection', cwe: 'CWE-89', file: 'users.js',
  vuln: 'SQL Injection (String Concatenation)', ...over,
});

test('the SQL class ships a driver stub as a support file, not as the source', () => {
  const r = synthesizeInProcessPoc(sqli(), SQLI_VULN);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.poc.driver, 'mysql');
  assert.deepEqual(r.poc.requires, ['users.js']);
  assert.ok(r.poc.extraFiles['node_modules/mysql/index.js'], 'no driver stub was emitted');
});

test('a file with no recognised driver is refused — there is no boundary to watch', () => {
  const noDriver = [
    'module.exports = function handler(req, res) {',
    '  res.json(lookup("SELECT * FROM users WHERE id = \'" + req.query.id + "\'"));',
    '};',
  ].join('\n');
  const r = synthesizeInProcessPoc(sqli(), noDriver);
  assert.equal(r.ok, false);
  assert.match(r.reason, /no recognised database driver/);
});

test('the SQL payload carries syntax, not just a sentinel', () => {
  // Matching on a bare sentinel would also match a correctly parameterised
  // call, which would report a fixed handler as vulnerable.
  const r = synthesizeInProcessPoc(sqli(), SQLI_VULN);
  assert.match(r.poc.code, /OR '1'='1'/);
  assert.match(r.poc.code, /select\|insert\|update\|delete/i);
});

test('SQL injection proves in the sandbox, and a parameterised query does not', async (t) => {
  if (!sandboxAvailable()) { t.skip('SKIPPED, NOT PASSED: no confinement backend'); return; }
  const { proveFinding } = await import('../src/posture/execution-proof.js');
  const { mergePocFiles } = await import('../src/posture/prove-findings.js');

  const vulnPoc = synthesizeInProcessPoc(sqli(), SQLI_VULN);
  assert.equal(vulnPoc.ok, true, vulnPoc.reason);
  const proven = await proveFinding({ ...sqli(), poc: vulnPoc.poc },
    { files: mergePocFiles(vulnPoc.poc, SQLI_VULN), ...BUDGET });
  assert.equal(proven.proofTier, 'execution-proven', JSON.stringify(proven.proofEvidence));

  // The fixed handler is still SYNTHESIZABLE — execution decides, not a source
  // pattern. This is the direction that catches a template matching too loosely.
  const fixedPoc = synthesizeInProcessPoc(sqli(), SQLI_FIXED);
  assert.equal(fixedPoc.ok, true, 'a parameterised handler must still be attempted');
  const fixed = await proveFinding({ ...sqli(), poc: fixedPoc.poc },
    { files: mergePocFiles(fixedPoc.poc, SQLI_FIXED), ...BUDGET });
  assert.notEqual(fixed.proofTier, 'execution-proven',
    'a bound parameter must never be reported as SQL injection');
  assert.equal(fixed.proofEvidence.ran, true, 'and the refusal must come from a RUN, not a skip');
});


// ── Path traversal ──────────────────────────────────────────────────────────

const TRAVERSAL_VULN = [
  "const fs = require('fs');",
  "const path = require('path');",
  'module.exports = function handler(req, res) {',
  "  const p = path.join('public', req.query.file);",
  "  res.send(fs.readFileSync(p, 'utf8'));",
  '};',
].join('\n');

const TRAVERSAL_FIXED = [
  "const fs = require('fs');",
  "const path = require('path');",
  'module.exports = function handler(req, res) {',
  "  const p = path.join('public', path.basename(req.query.file));",
  "  try { res.send(fs.readFileSync(p, 'utf8')); } catch { res.status(404).send('no'); }",
  '};',
].join('\n');

const traversal = (over = {}) => ({
  family: 'path-traversal', cwe: 'CWE-22', file: 'files.js',
  vuln: 'Path Traversal (User-Controlled Path)', ...over,
});

test('a streamed response is refused — its failure would be the harness talking', () => {
  const streamed = [
    "const fs = require('fs');",
    'module.exports = function handler(req, res) {',
    '  fs.createReadStream(req.query.file).pipe(res);',
    '};',
  ].join('\n');
  const r = synthesizeInProcessPoc(traversal(), streamed);
  assert.equal(r.ok, false);
  assert.match(r.reason, /harness talking/);
});

test('a file with no read sink is refused', () => {
  const noRead = [
    'module.exports = function handler(req, res) {',
    '  res.send(req.query.file);',
    '};',
  ].join('\n');
  const r = synthesizeInProcessPoc(traversal(), noRead);
  assert.equal(r.ok, false);
  assert.match(r.reason, /no readFile\/sendFile sink/);
});

test('path traversal proves in the sandbox, and a basename guard does not', async (t) => {
  if (!sandboxAvailable()) { t.skip('SKIPPED, NOT PASSED: no confinement backend'); return; }
  const { proveFinding } = await import('../src/posture/execution-proof.js');

  const vulnPoc = synthesizeInProcessPoc(traversal(), TRAVERSAL_VULN);
  assert.equal(vulnPoc.ok, true, vulnPoc.reason);
  const proven = await proveFinding({ ...traversal(), poc: vulnPoc.poc },
    { files: { 'files.js': TRAVERSAL_VULN }, ...BUDGET });
  assert.equal(proven.proofTier, 'execution-proven', JSON.stringify(proven.proofEvidence));

  // Unlike the webhook class this template does NOT read the source for a
  // guard — it runs the guarded handler and lets the absence of the sentinel
  // settle it.
  const fixedPoc = synthesizeInProcessPoc(traversal(), TRAVERSAL_FIXED);
  assert.equal(fixedPoc.ok, true, 'a guarded handler must still be attempted');
  const fixed = await proveFinding({ ...traversal(), poc: fixedPoc.poc },
    { files: { 'files.js': TRAVERSAL_FIXED }, ...BUDGET });
  assert.notEqual(fixed.proofTier, 'execution-proven',
    'a handler that strips the traversal must never be reported as proven');
  assert.equal(fixed.proofEvidence.ran, true);
});


// ── the file set materialised into the sandbox ──────────────────────────────

test('a support file can never replace the vulnerable source', async () => {
  // Otherwise a template could swap out the code the PoC is supposed to
  // exploit and prove a fact about itself.
  const { mergePocFiles } = await import('../src/posture/prove-findings.js');
  const files = mergePocFiles(
    { requires: ['app.js'], extraFiles: { 'app.js': 'ATTACKER', 'node_modules/x/index.js': 'stub' } },
    'REAL SOURCE',
  );
  assert.equal(files['app.js'], 'REAL SOURCE');
  assert.equal(files['node_modules/x/index.js'], 'stub');
});


// ── the webhook guard is REACHED, not just satisfied ────────────────────────

test('a silent handler runs to completion so the marker check actually executes', async (t) => {
  if (!sandboxAvailable()) { t.skip('SKIPPED, NOT PASSED: no confinement backend'); return; }
  const { proveFinding } = await import('../src/posture/execution-proof.js');
  const SILENT = [
    'module.exports = function handler(req, res) {',
    '  const payload = req.body;',
    '  void payload; // never replies',
    '};',
  ].join('\n');
  const poc = synthesizeInProcessPoc(webhookFinding(), SILENT);
  assert.equal(poc.ok, true);
  const r = await proveFinding({ ...webhookFinding(), poc: poc.poc }, { files: { 'hook.js': SILENT }, ...BUDGET });
  assert.notEqual(r.proofTier, 'execution-proven');
  // The positive control. With an unref'd timer Node exits code 13 with the
  // promise still pending and the marker check below the await NEVER RUNS —
  // "no marker" would then be true for a reason that has nothing to do with
  // the guard, and the assertion above would pass vacuously.
  assert.equal(r.proofEvidence.exitCode, 0,
    'the PoC must run to completion, or the guard was never evaluated');
});
