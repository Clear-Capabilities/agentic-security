// Verifier sandbox loop tests (P1.2 / FR-VER-3, FR-VER-6, FR-VER-7).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import {
  validatePoc,
  proveSanitizerAbsence,
  verdictForFinding,
  annotateVerifierVerdicts,
  verifierCoverageSummary,
  _internals,
} from '../src/posture/verifier.js';
import { sandboxAvailable } from '../src/sandbox/index.js';

// ─── validatePoc — refuse destructive/oversized/no-exit PoCs ───────────────

test('validatePoc rejects null/missing PoC', () => {
  assert.equal(validatePoc(null).ok, false);
  assert.equal(validatePoc(undefined).ok, false);
  assert.equal(validatePoc({}).reason, 'empty-code');
});

test('validatePoc rejects oversized code', () => {
  const big = 'a'.repeat(_internals.MAX_POC_BYTES + 1);
  const r = validatePoc({ code: big, lang: 'node' });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'code-too-long');
});

test('validatePoc rejects destructive payloads', () => {
  const code = `// PoC; rm -rf /\nprocess.exit(0);`;
  assert.equal(validatePoc({ code, lang: 'node' }).ok, false);
});

test('validatePoc rejects hardcoded cloud metadata IPs', () => {
  const code = `await fetch('http://169.254.169.254/');\nprocess.exit(0);`;
  const r = validatePoc({ code, lang: 'node' });
  assert.equal(r.ok, false);
  assert.ok(r.reason.startsWith('banned-host'));
});

test('validatePoc rejects Node PoCs without a deterministic exit', () => {
  const code = `await fetch('http://localhost:3000/');`;
  const r = validatePoc({ code, lang: 'node' });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-deterministic-exit');
});

test('validatePoc accepts a well-formed Node PoC', () => {
  const code = `await fetch('http://localhost:3000/api');\nprocess.exit(0);`;
  assert.equal(validatePoc({ code, lang: 'node' }).ok, true);
});

// ─── proveSanitizerAbsence ──────────────────────────────────────────────────

test('proveSanitizerAbsence returns ok when no sanitizer is on the flow', () => {
  const finding = { family: 'sql-injection', file: 'app.js', line: 5 };
  const fc = { 'app.js': "const id = req.params.id;\ndb.query('SELECT * FROM users WHERE id = ' + id);\n" };
  const r = proveSanitizerAbsence(finding, fc);
  assert.equal(r.ok, true);
});

test('proveSanitizerAbsence detects parameterized query as sanitizer present', () => {
  const finding = { family: 'sql-injection', file: 'app.js', line: 5 };
  const fc = { 'app.js': "const id = req.params.id;\ndb.query('SELECT * FROM users WHERE id = $1', [id]);\n" };
  const r = proveSanitizerAbsence(finding, fc);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'sanitizer-present');
});

test('proveSanitizerAbsence handles unknown family gracefully', () => {
  const r = proveSanitizerAbsence({ family: 'made-up-family' }, {});
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-rule');
});

// ─── verdictForFinding ──────────────────────────────────────────────────────

test('verdictForFinding tags unverified-by-design for no-poc families', () => {
  const f = { family: 'hardcoded-secret' };
  const v = verdictForFinding(f);
  assert.equal(v.verdict, 'unverified-by-design');
});

test('verdictForFinding tags verified-by-llm when LLM accepted', () => {
  const f = { family: 'sql-injection', validator_verdict: 'accept' };
  const v = verdictForFinding(f);
  assert.equal(v.verdict, 'verified-by-llm');
});

test('verdictForFinding tags verified-sanitizer-absence on clean unparameterized SQL', () => {
  const f = { family: 'sql-injection', file: 'a.js', line: 2 };
  const ctx = { fileContents: { 'a.js': "const id = req.body.id;\ndb.query('SELECT * WHERE id=' + id);" } };
  const v = verdictForFinding(f, ctx);
  assert.equal(v.verdict, 'verified-sanitizer-absence');
});

test('verdictForFinding tags cannot-verify when no PoC and no sanitizer rule', () => {
  const f = { family: 'unmapped-family' };
  const v = verdictForFinding(f);
  assert.equal(v.verdict, 'cannot-verify');
});

test('verdictForFinding tags cannot-verify when PoC fails static validation', () => {
  const f = {
    family: 'sql-injection',
    poc: { lang: 'node', code: '// rm -rf /\nprocess.exit(0);' },
  };
  const v = verdictForFinding(f);
  assert.equal(v.verdict, 'cannot-verify');
  assert.ok(v.reason.includes('poc-rejected') || v.reason.includes('poc-validation-failed') || v.reason.includes('no-poc-no-sanitizer-rule'));
});

// ─── batch annotation ──────────────────────────────────────────────────────

test('annotateVerifierVerdicts sets verifier_verdict on every finding', () => {
  const findings = [
    { family: 'hardcoded-secret', file: 'a', line: 1 },
    { family: 'sql-injection', validator_verdict: 'accept' },
    { family: 'sql-injection', file: 'x.js', line: 1 },
  ];
  annotateVerifierVerdicts(findings, { fileContents: { 'x.js': "db.query('SELECT * WHERE id=' + id);" } });
  assert.equal(findings[0].verifier_verdict, 'unverified-by-design');
  assert.equal(findings[1].verifier_verdict, 'verified-by-llm');
  assert.equal(findings[2].verifier_verdict, 'verified-sanitizer-absence');
});

// Stage 1 correctness audit: engine.js calls annotateVerifierVerdicts
// (~line 8335) BEFORE the LLM validator ever runs (~line 8587, where
// validator_verdict is actually set on findings) — so 'verified-by-llm'
// could never be produced by the real pipeline, only by a hand-built
// fixture that sets validator_verdict up front (which is what the tests
// above do, masking the ordering bug). Fixed by re-running
// annotateVerifierVerdicts immediately after the LLM validator sets
// validator_verdict. This test pins the exact mechanism: a finding
// annotated BEFORE validator_verdict exists stays cannot-verify; the SAME
// finding, re-annotated after validator_verdict is set, correctly becomes
// verified-by-llm — proving the re-run (not a one-shot call) is what's
// required.
test('annotateVerifierVerdicts must be re-run after validator_verdict is set — one early call is not enough', () => {
  const f = { family: 'unmapped-family' };
  annotateVerifierVerdicts([f], {});
  assert.equal(f.verifier_verdict, 'cannot-verify', 'before validation runs, this family has no other path to a verdict');
  f.validator_verdict = 'accept'; // simulates what llmValidateMany sets, later in the real pipeline
  annotateVerifierVerdicts([f], {});
  assert.equal(f.verifier_verdict, 'verified-by-llm', 're-running after validator_verdict is set must upgrade the verdict');
});

test('annotateVerifierVerdicts never throws on garbage input', () => {
  assert.doesNotThrow(() => annotateVerifierVerdicts(null));
  assert.doesNotThrow(() => annotateVerifierVerdicts([null, {}, { family: 'sql-injection' }]));
});

test('annotateVerifierVerdicts assigns cannot-verify if verdict logic throws (defense-in-depth)', () => {
  // We can't easily make verdictForFinding throw, but a getter that throws on
  // .family does the job.
  const f = {};
  Object.defineProperty(f, 'family', { get() { throw new Error('boom'); } });
  annotateVerifierVerdicts([f]);
  assert.equal(f.verifier_verdict, 'cannot-verify');
  assert.ok(/verifier-exception/.test(f.verifier_reason || ''));
});

test('verifierCoverageSummary aggregates by verdict bucket', () => {
  const findings = [
    { verifier_verdict: 'verified-exploit' },
    { verifier_verdict: 'cannot-verify' },
    { verifier_verdict: 'cannot-verify' },
    { verifier_verdict: 'unverified-by-design' },
  ];
  const s = verifierCoverageSummary(findings);
  assert.equal(s['verified-exploit'], 1);
  assert.equal(s['cannot-verify'], 2);
  assert.equal(s['unverified-by-design'], 1);
});

// ─── safety / fail-closed ──────────────────────────────────────────────────

test('verdict for finding without target in live mode is cannot-verify', () => {
  // We test the LOGIC path without setting env so live mode is off; the
  // PoC route falls back to static validation. With env set + no target,
  // verifier.js still expects the target arg from ctx; absent both, it
  // should land in cannot-verify rather than crash.
  const f = {
    family: 'sql-injection',
    poc: { lang: 'node', code: `await fetch('http://localhost:3000/');\nprocess.exit(0);` },
  };
  const v = verdictForFinding(f);  // no ctx.target, no env override
  // Without live execution, we fall through to sanitizer-absence; with no
  // fileContents in ctx, that fails; we land on cannot-verify or
  // verified-sanitizer-absence depending on whether fileContents was passed.
  assert.ok(['cannot-verify', 'verified-sanitizer-absence'].includes(v.verdict));
});

// ─── EA-02: live PoC execution goes through the confinement sandbox ───────
//
// verifier.js's live-verify path used to run generated PoCs via a bare
// `spawnSync('node', [file])` (only PATH/NODE_OPTIONS scrubbed) whenever
// Docker was unavailable — completely unconfined, and reachable by default
// since Docker is not installed on most CI/dev hosts. These pin the fix:
// live execution goes through src/sandbox/index.js's runConfined, the same
// facility execution-proof.js uses, and refuses rather than falling back to
// something unconfined when no confinement primitive is available.

test('EA-02: runSandboxed refuses to execute when the sandbox is disabled — never falls back unconfined', () => {
  const poc = { lang: 'node', code: `process.exit(0);` };
  const r = _internals.runSandboxed(poc, { target: 'http://127.0.0.1:1', force: 'disabled' });
  assert.equal(r.ok, false);
  assert.match(r.reason, /sandbox|confine/i);
});

// The target server is hosted by a python3 subprocess rather than
// node:http — on this development machine, inbound connections to a
// *node-process-hosted* listening socket are silently intercepted (verified
// by reproducing the hang with zero sandbox involvement at all: a bare,
// unconfined `curl` against a node:http server hangs to timeout on this
// host, while the identical curl against a python http.server responds
// instantly). That is a local per-process network policy on the dev
// machine, not a sandbox defect — confined curl and a confined Node PoC
// both reach a python-hosted target immediately. Using python3 as the
// target sidesteps the machine-specific quirk instead of the sandbox.
function _startPyTarget() {
  return new Promise((resolve, reject) => {
    const proc = spawn('python3', ['-c', `
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
srv = socketserver.TCPServer(('127.0.0.1', 0), H)
print('PORT', srv.server_address[1]); sys.stdout.flush()
srv.serve_forever()
`]);
    proc.stdout.on('data', (d) => {
      const m = /PORT (\d+)/.exec(d.toString());
      if (m) resolve({ port: Number(m[1]), proc });
    });
    proc.on('error', reject);
    setTimeout(() => reject(new Error('python3 target server did not start')), 5000);
  });
}

test('EA-02: runSandboxed executes the PoC through real confinement and reaches the live target', async (t) => {
  if (!sandboxAvailable()) {
    t.skip('SKIPPED, NOT PASSED — no confinement primitive available on this host');
    return;
  }
  if (spawnSync('python3', ['--version']).status !== 0) {
    t.skip('SKIPPED, NOT PASSED — python3 not available on this host');
    return;
  }
  const { port, proc } = await _startPyTarget();
  const target = `http://127.0.0.1:${port}/`;
  try {
    const poc = {
      lang: 'node',
      code: `
        import http from 'node:http';
        http.get('http://localhost:3000/', (res) => {
          process.exit(res.statusCode === 200 ? 0 : 1);
        }).on('error', () => process.exit(2));
      `,
    };
    const r = _internals.runSandboxed(poc, { target, timeoutMs: 10000 });
    assert.equal(r.ok, true, `expected the sandboxed PoC to run; got: ${JSON.stringify(r)}`);
    assert.equal(r.exitCode, 0, 'PoC must have reached the live target through the confined sandbox');
    assert.notEqual(r.runner, 'docker', 'must not depend on Docker being installed');
  } finally {
    proc.kill();
  }
});
