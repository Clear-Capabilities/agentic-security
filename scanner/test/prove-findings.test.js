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
