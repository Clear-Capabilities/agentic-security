// PRD F4.5 — deploy-time gate telemetry: replay known-bad diffs, assert the exit code.
//
// `/setup --ci` and the pre-deploy gate exist, and nothing measured whether they
// actually BLOCK what they should. A CI gate that exits 0 on a critical finding
// is worse than no gate: the build goes green and the team believes it was
// checked. Nothing here tested the number CI actually reads.
//
// So this replays real vulnerable projects through the SHIPPED CLI and asserts
// the process exit code — not the finding list, not a report string. The exit
// code is the entire interface between this tool and a CI system, and it is the
// one thing no other test covers.
//
// BOTH directions are asserted for every policy. A gate that always fails is as
// broken as one that always passes; it just fails in the direction that gets it
// disabled rather than the one that ships a vulnerability.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'bin', 'agentic-security.js');

// Documented contract (bin/agentic-security.js --help):
//   0 = clean   1 = low/medium   2 = high   3 = critical   4 = error
const EXIT = { CLEAN: 0, LOW_MED: 1, HIGH: 2, CRITICAL: 3, ERROR: 4 };

function project(files) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'deploy-gate-'));
  fs.writeFileSync(path.join(d, 'package.json'), '{"name":"g","version":"1.0.0"}');
  for (const [name, body] of Object.entries(files)) {
    const p = path.join(d, name);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
  }
  return d;
}

// `ci` is the DEPLOY GATE surface and has different exit semantics from `scan`:
// 0 = the gate passed, non-zero = it blocked. `scan` encodes severity instead
// (0/1/2/3/4). `--fail-on` is documented as a CI-MODE policy and is only read by
// `ci` — applying it to `scan` looked like a bug in a first draft of this file
// and was a bug in the test.
function runCiGate(dir, ...args) {
  const r = spawnSync(process.execPath, [CLI, 'ci', '.', ...args], {
    cwd: dir, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, AGENTIC_SECURITY_OFFLINE: '1' },
  });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function runGate(dir, ...args) {
  const r = spawnSync(process.execPath, [CLI, 'scan', '.', '--format', 'json', ...args], {
    cwd: dir, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, AGENTIC_SECURITY_OFFLINE: '1' },
  });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// A command-injection sink reached from an Express request — critical, and the
// shape a deploy gate exists to stop.
const KNOWN_BAD = {
  'app.js': [
    "const { exec } = require('child_process');",
    "const express = require('express');",
    'const app = express();',
    "app.get('/ping', (req, res) => {",
    '  exec(`ping -c 1 ${req.query.host}`, (e, out) => res.send(out));',
    '});',
    'module.exports = app;',
  ].join('\n'),
};

const KNOWN_GOOD = {
  'app.js': [
    "const { execFile } = require('child_process');",
    "const express = require('express');",
    'const app = express();',
    "app.get('/ping', (req, res) => {",
    "  execFile('ping', ['-c', '1', String(req.query.host)], (e, out) => res.send(out));",
    '});',
    'module.exports = app;',
  ].join('\n'),
};

test('a known-bad diff does NOT exit 0 — the gate blocks', () => {
  const d = project(KNOWN_BAD);
  try {
    const r = runGate(d);
    assert.notEqual(r.status, EXIT.CLEAN,
      `a command-injection sink reached from req.query exited 0 — CI would have gone green.\n${r.stderr.slice(0, 400)}`);
    assert.notEqual(r.status, EXIT.ERROR, `the scan errored rather than reporting: ${r.stderr.slice(0, 400)}`);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('correct code does NOT trip a high/critical gate', () => {
  // The direction that gets a gate switched off. Without this, a scanner that
  // failed unconditionally would pass the test above.
  //
  // Asserted against HIGH/CRITICAL rather than exit 0, because the fixture
  // legitimately carries a LOW advisory (x-powered-by) and 1 is the documented
  // code for low/medium. Demanding a finding-free project would have been
  // testing the wrong contract — a first draft of this test did exactly that
  // and failed for the wrong reason.
  //
  // This assertion is what caught the session's worst false positive: the
  // command-injection rule matched `execFile`/`spawn` — the ARGV forms that are
  // the canonical FIX — and rated correct code critical, while its own
  // remediation text said "Use execFile with argument array".
  const d = project(KNOWN_GOOD);
  try {
    const r = runGate(d);
    assert.ok(r.status < EXIT.HIGH,
      `an argv-form execFile with no injection exited ${r.status} (>= high); a gate that blocks safe code gets disabled.\n${r.stdout.slice(0, 400)}`);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('ci --fail-on none reports without blocking', () => {
  // The advisory mode a team uses while adopting the tool. Both directions:
  // if this blocks, adoption is broken; if the DEFAULT did not block, the gate
  // is useless. Asserting only one of them would miss a gate stuck open.
  const d = project(KNOWN_BAD);
  try {
    const blocking = runCiGate(d).status;
    const advisory = runCiGate(d, '--fail-on', 'none').status;
    assert.notEqual(blocking, 0, 'precondition: the ci gate must block this fixture by default');
    assert.equal(advisory, 0, '--fail-on none must report without failing the build');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a raised --fail-on threshold lets a lower-severity finding through', () => {
  // Policy must actually be read. A gate that ignores --fail-on and blocks on
  // everything looks identical to a working one until it blocks a release
  // nobody expected it to.
  const d = project({
    'app.js': "const crypto = require('crypto');\nmodule.exports = () => crypto.createHash('md5').update('x').digest('hex');\n",
  });
  try {
    const strict = runCiGate(d, '--fail-on', 'low').status;
    const lenient = runCiGate(d, '--fail-on', 'critical').status;
    assert.ok(lenient <= strict,
      `raising the threshold must not make the gate stricter (critical=${lenient}, low=${strict})`);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('the exit code is a documented value, never an accident', () => {
  // Any status outside the contract is a bug in the interface CI depends on —
  // an uncaught throw surfacing as 1, say, is indistinguishable from "found
  // something low severity".
  const d = project(KNOWN_BAD);
  try {
    const r = runGate(d);
    assert.ok(Object.values(EXIT).includes(r.status),
      `exit ${r.status} is outside the documented contract (0/1/2/3/4)`);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('an unreadable project reports an ERROR code, not a clean one', () => {
  // Failing open is the dangerous direction: a gate that cannot scan must not
  // report success. This is the same rule dependency-currency applies to an
  // unreachable registry.
  const r = spawnSync(process.execPath, [CLI, 'scan', '/nonexistent-path-for-gate-test', '--format', 'json'], {
    encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
    env: { ...process.env, AGENTIC_SECURITY_OFFLINE: '1' },
  });
  assert.notEqual(r.status, EXIT.CLEAN, 'a scan that could not run must not exit 0');
});
