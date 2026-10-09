// CORE-004: unified configuration, bounded I/O and feature rollout.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  FEATURES, LIMITS, resolveAssuranceConfig, featureStatus, runFeature, evaluateRequirements, envPresent,
  describeAssuranceConfig, limitValues, RESULT_STATUSES,
} from '../../src/posture/assurance/config.js';
import { guardedModelCall, readFileBounded, capOutput, withDeadline, retryBounded } from '../../src/posture/assurance/bounded-io.js';
import { verifyEgressAuditLog } from '../../src/egress/audit.js';
import { runScan } from '../../src/runScan.js';
import { normalizeFindings } from '../../src/report/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(HERE, '../../src/posture/assurance');
const FIXTURE = path.resolve(HERE, '../fixtures/vulnerable-js');

function project(files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'assurance-cfg-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"t"}');
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(root, '.agentic-security', name), content);
  return root;
}
const cleanup = (root) => fs.rmSync(root, { recursive: true, force: true });
const ENV = {}; // an isolated environment: tests never read the real process.env

function cfg(root, extra = {}) {
  return resolveAssuranceConfig({ scanRoot: root, env: ENV, platform: 'linux', ...extra });
}

// A key assembled at runtime so no continuous secret literal sits in the source.
const CANARY = 'sk_' + 'live_' + '0123456789' + 'abcdefghij' + 'ABCD';

// ---------------------------------------------------------------- AC01

test('[CORE-004.AC01] the egress policy is evaluated before the transport is touched: a denying policy means zero calls', async () => {
  const root = project({ 'egress-policy.yml': 'mode: deny\n' });
  try {
    let calls = 0;
    const config = cfg(root, { overrides: { features: { 'model-routing': true } } });
    const r = await guardedModelCall({
      config, featureId: 'model-routing', scanRoot: root, endpoint: 'http://127.0.0.1:11434', purpose: 'routing-probe',
      text: 'hello', call: async () => { calls += 1; return 'x'; },
    });
    assert.equal(r.status, 'blocked');
    assert.equal(r.code, 'egress-denied');
    assert.equal(calls, 0);
    // local-only mode: a non-loopback endpoint is denied, a loopback one is allowed
    fs.writeFileSync(path.join(root, '.agentic-security', 'egress-policy.yml'), 'mode: local-only\n');
    const remote = await guardedModelCall({
      config, featureId: 'model-routing', scanRoot: root, endpoint: 'https://api.example.com/v1', purpose: 'routing-probe',
      text: 'hello', call: async () => { calls += 1; return 'x'; },
    });
    assert.equal(remote.code, 'egress-denied');
    assert.equal(calls, 0);
    const local = await guardedModelCall({
      config, featureId: 'model-routing', scanRoot: root, endpoint: 'http://127.0.0.1:11434', purpose: 'routing-probe',
      text: 'hello', call: async () => { calls += 1; return 'fine'; },
    });
    assert.equal(local.status, 'ok');
    assert.equal(calls, 1);
  } finally { cleanup(root); }
});

test('[CORE-004.AC01] the transport only ever receives redacted text', async () => {
  const root = project();
  try {
    let seen = null;
    const config = cfg(root, { overrides: { features: { 'model-routing': true } } });
    const r = await guardedModelCall({
      config, featureId: 'model-routing', scanRoot: root, endpoint: 'http://127.0.0.1:11434', purpose: 'routing-probe',
      text: `const apiKey = "${CANARY}"; // contact alice@example.com`, call: async (req) => { seen = req.text; return 'ok'; },
    });
    assert.equal(r.status, 'ok');
    assert.ok(seen !== null);
    assert.ok(!seen.includes(CANARY), 'secret reached the transport');
    assert.ok(r.redactions >= 1);
    // a proprietary path is withheld whole
    fs.writeFileSync(path.join(root, '.agentic-security', 'egress-policy.yml'), 'proprietaryPaths:\n  - "secret/**"\n');
    seen = null;
    await guardedModelCall({
      config, featureId: 'model-routing', scanRoot: root, endpoint: 'http://127.0.0.1:11434', purpose: 'routing-probe',
      text: 'proprietary algorithm body', filePath: 'secret/algo.js', call: async (req) => { seen = req.text; return 'ok'; },
    });
    assert.ok(!seen.includes('proprietary algorithm body'));
  } finally { cleanup(root); }
});

test('[CORE-004.AC01] every call decision lands in the existing egress audit chain', async () => {
  const root = project({ 'egress-policy.yml': 'mode: local-only\n' });
  try {
    const config = cfg(root, { overrides: { features: { 'model-routing': true } } });
    await guardedModelCall({ config, featureId: 'model-routing', scanRoot: root, endpoint: 'https://api.example.com', purpose: 'p1', text: 'a', call: async () => 'x' });
    await guardedModelCall({ config, featureId: 'model-routing', scanRoot: root, endpoint: 'http://127.0.0.1:1', purpose: 'p2', text: 'b', call: async () => 'x' });
    const log = path.join(root, '.agentic-security', 'egress-audit.log');
    const lines = fs.readFileSync(log, 'utf8').trim().split('\n').map(l => JSON.parse(l));
    assert.deepEqual(lines.map(l => [l.purpose, l.outcome]), [['p1', 'deny'], ['p2', 'allow']]);
    assert.equal(verifyEgressAuditLog(log).ok, true);
  } finally { cleanup(root); }
});

test('[CORE-004.AC01] timeout, retry, output, request and file-size limits are finite and enforced', async () => {
  const root = project();
  try {
    const config = cfg(root, { overrides: { features: { 'model-routing': true }, limits: { timeoutMs: 40, retries: 2, maxOutputBytes: 10, maxRequestBytes: 64 } } });
    const base = { config, featureId: 'model-routing', scanRoot: root, endpoint: 'http://127.0.0.1:1', purpose: 'p' };
    // timeout: a hanging transport is cut off and aborted
    let aborted = false;
    const t0 = Date.now();
    const hung = await guardedModelCall({ ...base, text: 'x', call: ({ signal }) => new Promise((_, rej) => { signal.addEventListener('abort', () => { aborted = true; rej(new Error('aborted')); }); }) });
    assert.equal(hung.code, 'timeout');
    assert.ok(Date.now() - t0 < 2000);
    assert.equal(aborted, true);
    // retries: bounded to retries+1 attempts, only for retryable failures
    let attempts = 0;
    const flaky = await guardedModelCall({ ...base, text: 'x', call: async () => { attempts += 1; const e = new Error('503'); e.retryable = true; throw e; } });
    assert.equal(flaky.status, 'blocked');
    assert.equal(attempts, 3);
    attempts = 0;
    await guardedModelCall({ ...base, text: 'x', call: async () => { attempts += 1; throw new Error('fatal'); } });
    assert.equal(attempts, 1, 'a non-retryable failure is not retried');
    // output cap
    const big = await guardedModelCall({ ...base, text: 'x', call: async () => 'abcdefghijklmnopqrstuvwxyz' });
    assert.equal(big.status, 'degraded');
    assert.equal(big.truncated, true);
    assert.equal(Buffer.byteLength(big.text), 10);
    // request cap: the transport is never invoked
    let invoked = 0;
    const over = await guardedModelCall({ ...base, text: 'y'.repeat(500), call: async () => { invoked += 1; return 'x'; } });
    assert.equal(over.code, 'limit-exceeded');
    assert.equal(invoked, 0);
    // file-size cap
    const fp = path.join(root, 'big.txt');
    fs.writeFileSync(fp, 'z'.repeat(1000));
    assert.equal(readFileBounded(fp, 999).code, 'limit-exceeded');
    assert.equal(readFileBounded(fp, 1000).status, 'ok');
    assert.equal(readFileBounded(root, 1000).status, 'blocked', 'a directory is not a bounded file');
    assert.equal(readFileBounded(fp, 0).code, 'invalid-config');
    // helpers on their own
    assert.deepEqual(capOutput('héllo', 2), { text: 'h', truncated: true, bytes: 6 });
    assert.equal((await withDeadline(async () => 7, 1000)).value, 7);
    const r = await retryBounded(async () => ({ status: 'error', error: Object.assign(new Error('x'), { retryable: true }) }), { retries: 99 });
    assert.ok(r.attempts <= 11, 'retries are clamped to a finite ceiling');
  } finally { cleanup(root); }
});

test('[CORE-004.AC01] limits must be finite integers within a ceiling; anything else is rejected, not clamped silently', () => {
  const root = project({ 'assurance.yml': 'limits:\n  timeoutMs: 999999999\n  retries: 1\n' });
  try {
    const c = cfg(root);
    assert.ok(c.errors.some(e => /timeoutMs/.test(e.path) && /between/.test(e.message)));
    assert.equal(c.limits.timeoutMs.value, LIMITS.timeoutMs.default, 'a bad limits block is dropped whole');
    for (const bad of [Infinity, NaN, -1, 1.5, '10', null]) {
      const c2 = cfg(root, { overrides: { limits: { timeoutMs: bad } } });
      assert.ok(c2.errors.length > 0, String(bad));
      assert.equal(c2.limits.timeoutMs.value, LIMITS.timeoutMs.default);
    }
    for (const spec of Object.values(LIMITS)) assert.ok(Number.isFinite(spec.default) && Number.isFinite(spec.max));
    const d = describeAssuranceConfig(cfg(root));
    assert.match(d.limits.maxMemoryMiB.enforced, /not enforced by this layer/);
    assert.match(d.limits.timeoutMs.enforced, /withDeadline/);
  } finally { cleanup(root); }
});

test('[CORE-004.AC01] the assurance layer ships no HTTP client of its own', () => {
  for (const f of fs.readdirSync(SRC).filter(n => n.endsWith('.js'))) {
    const text = fs.readFileSync(path.join(SRC, f), 'utf8').replace(/^\s*\/\/.*$/gm, '');
    assert.ok(!/\bfetch\s*\(|node:https?|node:net|node:tls|node:dgram|\bXMLHttpRequest\b/.test(text), `${f} contains a network client`);
    // baseline capture runs read-only git and version queries; nothing else may spawn a process
    if (f !== 'baseline.js') assert.ok(!/child_process/.test(text), `${f} spawns a process`);
  }
});

// ---------------------------------------------------------------- AC02

test('[CORE-004.AC02] defaults: every new feature is off and nothing is enabled by absence of configuration', () => {
  const root = project();
  try {
    const c = cfg(root);
    for (const id of Object.keys(FEATURES)) {
      assert.equal(c.features[id].enabled, false, id);
      assert.equal(c.features[id].source, 'default');
      assert.equal(featureStatus(c, id).status, 'disabled');
    }
    assert.deepEqual(c.errors, []);
  } finally { cleanup(root); }
});

test('[CORE-004.AC02] precedence: kill switch > override > environment > project file > default, in both directions', () => {
  const root = project({ 'assurance.yml': 'features:\n  deployment-boundaries:\n    enabled: true\n  portfolio-assurance:\n    enabled: false\n' });
  try {
    const on = (c, id) => c.features[id].enabled;
    // file < default
    assert.equal(on(cfg(root), 'deployment-boundaries'), true);
    assert.equal(cfg(root).features['deployment-boundaries'].source, 'project-file');
    // env beats file, both ways
    assert.equal(on(cfg(root, { env: { AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '0' } }), 'deployment-boundaries'), false);
    assert.equal(on(cfg(root, { env: { AGENTIC_SECURITY_ASSURANCE_PORTFOLIO_ASSURANCE: '1' } }), 'portfolio-assurance'), true);
    // override beats env, both ways
    const envOn = { AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '1' };
    assert.equal(on(cfg(root, { env: envOn, overrides: { features: { 'deployment-boundaries': false } } }), 'deployment-boundaries'), false);
    assert.equal(cfg(root, { env: envOn, overrides: { features: { 'deployment-boundaries': false } } }).features['deployment-boundaries'].source, 'override');
    // kill switch beats everything
    for (const kill of [{ AGENTIC_SECURITY_NO_DEPLOYMENT_BOUNDARIES: '1' }, { AGENTIC_SECURITY_NO_ASSURANCE: '1' }]) {
      const c = cfg(root, { env: { ...envOn, ...kill }, overrides: { features: { 'deployment-boundaries': true } } });
      assert.equal(on(c, 'deployment-boundaries'), false);
      assert.equal(c.features['deployment-boundaries'].source, 'kill-switch');
      assert.equal(featureStatus(c, 'deployment-boundaries').code, 'kill-switch');
    }
    // a kill switch of 0 or empty is not a kill switch
    assert.equal(on(cfg(root, { env: { AGENTIC_SECURITY_NO_DEPLOYMENT_BOUNDARIES: '0' } }), 'deployment-boundaries'), true);
  } finally { cleanup(root); }
});

test('[CORE-004.AC02] high-risk execution is operator opt-in: a project file cannot enable it, the environment can', () => {
  const root = project({ 'assurance.yml': 'features:\n  verification-oracles:\n    enabled: true\n  capability-enforcement:\n    enabled: true\n' });
  try {
    const c = cfg(root);
    assert.equal(c.features['verification-oracles'].enabled, false);
    assert.equal(c.features['verification-oracles'].source, 'project-file-refused');
    assert.ok(c.features['verification-oracles'].notes.some(n => /refused/.test(n)));
    assert.equal(featureStatus(c, 'verification-oracles').status, 'disabled');
    const op = cfg(root, { env: { AGENTIC_SECURITY_ASSURANCE_VERIFICATION_ORACLES: '1' } });
    assert.equal(op.features['verification-oracles'].enabled, true);
    assert.equal(featureStatus(op, 'verification-oracles').status, 'ok');
    // every high-risk feature is covered by the rule
    const risky = Object.entries(FEATURES).filter(([, f]) => f.risk === 'high-risk-execution').map(([id]) => id);
    assert.ok(risky.length >= 3);
  } finally { cleanup(root); }
});

test('[CORE-004.AC02] schema validation: invalid configuration fails closed and is reported', () => {
  const cases = {
    'unknown feature': 'features:\n  teleporter:\n    enabled: true\n',
    'non-boolean': 'features:\n  deployment-boundaries:\n    enabled: "yes please"\n',
    'unknown key': 'features:\n  deployment-boundaries:\n    enabled: true\n    turbo: true\n',
    'unknown top-level key': 'turbo: 1\n',
    'bad version': 'version: 9\nfeatures:\n  deployment-boundaries:\n    enabled: true\n',
    'not a mapping': '- a\n- b\n',
    'not yaml': 'features: [unclosed\n',
  };
  for (const [name, yml] of Object.entries(cases)) {
    const root = project({ 'assurance.yml': yml });
    try {
      const c = cfg(root);
      assert.ok(c.errors.length > 0, `${name}: expected an error`);
      assert.ok(c.errors.every(e => e.code === 'invalid-config'), name);
      if (['non-boolean', 'unknown key'].includes(name)) {
        assert.equal(c.features['deployment-boundaries'].enabled, false, `${name} must fail closed`);
        assert.equal(featureStatus(c, 'deployment-boundaries').code, 'invalid-config');
      }
      if (['bad version', 'not a mapping', 'not yaml'].includes(name)) assert.equal(c.features['deployment-boundaries'].enabled, false, name);
    } finally { cleanup(root); }
  }
  const root = project();
  try {
    const c = cfg(root, { env: { AGENTIC_SECURITY_ASSURANCE_MODEL_ROUTING: 'maybe' } });
    assert.equal(c.features['model-routing'].enabled, false);
    assert.ok(c.errors.length > 0);
    // a valid file still works
    fs.writeFileSync(path.join(root, '.agentic-security', 'assurance.yml'), 'version: 1\nfeatures:\n  deployment-boundaries:\n    enabled: true\n    limits: {}\n');
    assert.deepEqual(cfg(root).errors, []);
  } finally { cleanup(root); }
});

test('[CORE-004.AC02] unsupported platforms are disclosed with a typed result, not a silent no-op', () => {
  const root = project();
  try {
    const mac = cfg(root, { platform: 'darwin', env: { AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT: '1' } });
    const s = featureStatus(mac, 'capability-enforcement');
    assert.equal(s.status, 'unsupported');
    assert.equal(s.code, 'platform-unsupported');
    assert.match(s.reason, /only advertised on Linux/);
    assert.ok(s.supportedPlatforms.includes('linux'));
    const win = cfg(root, { platform: 'win32', env: { AGENTIC_SECURITY_ASSURANCE_VERIFICATION_ORACLES: '1' } });
    assert.equal(featureStatus(win, 'verification-oracles').status, 'unsupported');
    const linux = cfg(root, { platform: 'linux', env: { AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT: '1' } });
    assert.equal(featureStatus(linux, 'capability-enforcement').status, 'ok');
    const d = describeAssuranceConfig(mac).features.find(f => f.id === 'capability-enforcement');
    assert.equal(d.platformSupported, false);
    assert.match(d.platformNote, /Linux/);
    for (const r of [s, featureStatus(linux, 'capability-enforcement')]) assert.ok(RESULT_STATUSES.includes(r.status));
  } finally { cleanup(root); }
});

test('[CORE-004.AC02] a disabled feature is inert: its body never runs and the existing scan result is unchanged', async () => {
  const root = project();
  try {
    let ran = 0;
    const off = await runFeature(cfg(root), 'verification-oracles', {}, async () => { ran += 1; });
    assert.equal(off.status, 'disabled');
    const killed = await runFeature(cfg(root, { env: { AGENTIC_SECURITY_ASSURANCE_VERIFICATION_ORACLES: '1', AGENTIC_SECURITY_NO_ASSURANCE: '1' } }), 'verification-oracles', {}, async () => { ran += 1; });
    assert.equal(killed.status, 'blocked');
    assert.equal(ran, 0);
    const on = await runFeature(cfg(root, { env: { AGENTIC_SECURITY_ASSURANCE_VERIFICATION_ORACLES: '1' } }), 'verification-oracles', {}, async ({ limits }) => { ran += 1; return limits.timeoutMs; });
    assert.equal(on.status, 'ok');
    assert.equal(on.value, LIMITS.timeoutMs.default);
    assert.equal(ran, 1);

    // scan parity: the layer has no ambient effect on a real scan, whatever it is configured to
    const ids = async () => (normalizeFindings((await runScan(FIXTURE)).scan)).map(f => `${f.id}|${f.severity}|${f.vuln}`).sort();
    const before = await ids();
    const saved = { ...process.env };
    try {
      for (const id of Object.keys(FEATURES)) process.env[`AGENTIC_SECURITY_ASSURANCE_${id.toUpperCase().replace(/-/g, '_')}`] = '1';
      cfg(root, { env: process.env }); // resolving the config under an all-on environment
      const during = await ids();
      assert.deepEqual(during, before);
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    }
    assert.ok(before.length >= 10);
  } finally { cleanup(root); }
});

// ---------------------------------------------------------------- AC03

test('[CORE-004.AC03] a missing provider, credential, collector, backend or dependency yields a typed result and the call never happens', async () => {
  const root = project();
  try {
    const config = cfg(root, { env: { AGENTIC_SECURITY_ASSURANCE_MODEL_ROUTING: '1', AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '1', AGENTIC_SECURITY_ASSURANCE_VERIFICATION_ORACLES: '1' } });
    let called = 0;
    const call = async () => { called += 1; return 'x'; };

    // provider: no endpoint configured. No default, no cloud fallback, even with an ambient vendor key present.
    const saved = process.env.OPENAI_API_KEY; process.env.OPENAI_API_KEY = 'sk-should-never-be-used';
    try {
      const noProvider = await guardedModelCall({ config, featureId: 'model-routing', scanRoot: root, endpoint: null, purpose: 'p', text: 'x', call });
      assert.equal(noProvider.status, 'blocked');
      assert.equal(noProvider.code, 'missing-provider');
    } finally { if (saved === undefined) delete process.env.OPENAI_API_KEY; else process.env.OPENAI_API_KEY = saved; }

    // credential
    const noCred = await guardedModelCall({
      config, featureId: 'model-routing', scanRoot: root, endpoint: 'http://127.0.0.1:1', purpose: 'p', text: 'x', call,
      requirements: [{ kind: 'credential', name: 'ROUTING_KEY', present: envPresent('ROUTING_KEY', {}) }],
    });
    assert.equal(noCred.code, 'missing-credential');
    assert.equal(called, 0);
    const withCred = await guardedModelCall({
      config, featureId: 'model-routing', scanRoot: root, endpoint: 'http://127.0.0.1:1', purpose: 'p', text: 'x', call,
      requirements: [{ kind: 'credential', name: 'ROUTING_KEY', present: envPresent('ROUTING_KEY', { ROUTING_KEY: 'v' }) }],
    });
    assert.equal(withCred.status, 'ok');

    // collector, backend, dependency, via runFeature
    for (const [kind, code] of [['collector', 'missing-collector'], ['execution-backend', 'missing-execution-backend'], ['dependency', 'missing-dependency']]) {
      const feature = kind === 'collector' ? 'deployment-boundaries' : 'verification-oracles';
      const r = await runFeature(config, feature, { requirements: [{ kind, name: 'thing', present: () => false }] }, async () => { called += 1; });
      assert.equal(r.status, 'blocked', kind);
      assert.equal(r.code, code, kind);
      assert.equal(r.missing[0].name, 'thing');
    }
    // a probe that throws counts as missing
    assert.equal(evaluateRequirements([{ kind: 'dependency', name: 'x', present: () => { throw new Error('boom'); } }]).missingRequired.length, 1);
    assert.equal(called, 1, 'only the credentialed call ran');
  } finally { cleanup(root); }
});

test('[CORE-004.AC03] optional gaps degrade instead of blocking, and unrelated work proceeds', async () => {
  const root = project();
  try {
    const config = cfg(root, { env: { AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '1', AGENTIC_SECURITY_ASSURANCE_PORTFOLIO_ASSURANCE: '1' } });
    const degraded = await runFeature(config, 'deployment-boundaries', {
      requirements: [{ kind: 'collector', name: 'k8s-export', optional: true, present: () => false }, { kind: 'dependency', name: 'yaml', present: () => true }],
    }, async ({ missingOptional }) => missingOptional.map(m => m.name));
    assert.equal(degraded.status, 'degraded');
    assert.equal(degraded.code, 'missing-collector');
    assert.deepEqual(degraded.value, ['k8s-export']);
    const blocked = await runFeature(config, 'deployment-boundaries', { requirements: [{ kind: 'dependency', name: 'x', present: () => false }] }, async () => 1);
    assert.equal(blocked.status, 'blocked');
    // another feature is unaffected by the blocked one
    const other = await runFeature(config, 'portfolio-assurance', {}, async () => 'done');
    assert.equal(other.status, 'ok');
    assert.equal(other.value, 'done');
  } finally { cleanup(root); }
});

test('[CORE-004.AC03] no interactive prompt and no credential read path exists in the layer', () => {
  for (const f of fs.readdirSync(SRC).filter(n => n.endsWith('.js'))) {
    const text = fs.readFileSync(path.join(SRC, f), 'utf8').replace(/^\s*\/\/.*$/gm, '');
    assert.ok(!/node:readline|process\.stdin|\bprompt\s*\(|AskUserQuestion|inquirer/.test(text), `${f} can prompt`);
  }
  // credential probes report presence only: the value is never placed in a result
  const r = evaluateRequirements([{ kind: 'credential', name: 'K', present: envPresent('K', { K: 'super-secret-value' }) }]);
  assert.ok(!JSON.stringify(r).includes('super-secret-value'));
});

test('[CORE-004.AC02] the config file name, version, risk classes and result codes are the documented ones', async () => {
  const C = await import('../../src/posture/assurance/config.js');
  assert.equal(C.CONFIG_FILE, 'assurance.yml');
  assert.equal(C.CONFIG_VERSION, 1);
  assert.deepEqual([...C.RISK_CLASSES], ['passive', 'model-network', 'high-risk-execution']);
  assert.ok(Object.values(FEATURES).every(f => C.RISK_CLASSES.includes(f.risk)));
  // every code a typed result in this suite carries is declared
  for (const code of ['kill-switch', 'platform-unsupported', 'invalid-config', 'egress-denied', 'limit-exceeded', 'timeout', 'missing-provider', 'missing-credential', 'missing-collector', 'missing-execution-backend', 'missing-dependency', 'disabled']) {
    assert.ok(C.RESULT_CODES.includes(code), code);
  }
});

test('[CORE-004.AC03] limitValues returns plain numbers for a runner', () => {
  const root = project();
  try {
    const v = limitValues(cfg(root, { overrides: { limits: { timeoutMs: 5000 } } }));
    assert.equal(v.timeoutMs, 5000);
    assert.equal(v.retries, LIMITS.retries.default);
  } finally { cleanup(root); }
});
