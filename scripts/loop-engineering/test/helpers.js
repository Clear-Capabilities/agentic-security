// Test harness: builds a disposable git repo with a tiny PRD, a finite profile,
// tagged suites and a scriptable mock worker, then drives the REAL run.mjs
// (controller, guardian, dashboard) against it as subprocesses.
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawn } from 'node:child_process';
import { identityMatches, startTimeOf, scanEnvMarker } from '../lib/procscan.mjs';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const RUN_MJS = join(HERE, '..', 'run.mjs');
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function prdText(reqs) {
  const totW = reqs.reduce((n, r) => n + r.weight, 0);
  const totC = reqs.reduce((n, r) => n + r.criteria.length, 0);
  const body = reqs.map((r) => [
    `### ${r.id} — ${r.title || 'Requirement ' + r.id}`, '',
    `Weight: ${r.weight} | Dependencies: ${r.deps?.length ? r.deps.join(', ') : 'none'} | Verification suite: \`${r.suite || 'suite-' + r.id}\``, '',
    r.desc || 'Mini requirement.', '', 'Acceptance:', '',
    ...r.criteria.map((c, i) => `- **${r.id}.AC${String(i + 1).padStart(2, '0')}:** ${c}`), '',
  ].join('\n')).join('\n');
  return `# Mini PRD\n\n## 8. Atomic implementation requirements\n\nInitial manifest: **${reqs.length} required requirements, ${totW} total weight points, ${totC} acceptance criteria**.\n\n${body}\n## 9. Quality\n\nend\n`;
}

export function baseProfile(reqs, over = {}) {
  const suites = {};
  for (const r of reqs) {
    const s = r.suite || 'suite-' + r.id;
    suites[s] = { kind: 'node-test', cwd: '.', executable: 'node', files: [`t/${s}.test.js`], timeoutSeconds: 30, ...(r.requiresTools ? { requiresTools: r.requiresTools } : {}) };
  }
  const watch = {};
  for (const p of ['LOOP', 'CORE', 'HS', 'NIX', 'X', 'QA', 'DOC', 'REL']) watch[p] = ['t/**', 'flag-*', 'src/**'];
  return {
    profileVersion: 1, name: 'mini',
    platforms: { supported: ['darwin', 'linux'], unsupported: ['win32'] },
    limits: {
      heartbeatSeconds: 1, workerIdleSeconds: 3, noProgressSeconds: 6, subprocessWallSeconds: 20, killGraceSeconds: 1,
      claudeAttemptSeconds: 12, claudeMaxTurns: 80, attemptsPerRequirement: 3, sameFailureRepeats: 2, runWallSeconds: 600, runMaxAttempts: 40,
      claudeBudgetUsd: 50, perAttemptBudgetUsd: 6, retryBackoffMaxSeconds: 1, minAttemptBudgetUsd: 1,
      resource: { maxRssMiB: 2048, maxOutputMiB: 64, maxLogMiB: 2, minFreeDiskGiB: 1 }, ...(over.limits || {}),
    },
    worker: {
      concurrency: 1, command: 'claude', permissionMode: 'dontAsk', permissionPrompts: 'none', mcp: 'disabled',
      allowedTools: ['Read', 'Edit', 'Bash(node:*)'],
      disallowedTools: ['Bash(git push:*)', 'Bash(npm publish:*)', 'Bash(nixos-rebuild:*)'],
      protectedPaths: ['.loop-engineering/'], honestLimits: [],
    },
    serve: { host: '127.0.0.1', port: 4317, lingerSeconds: 3 },
    approvedExecutables: ['node', 'npm', 'git', 'python3'],
    suites: { ...suites, ...(over.suites || {}) }, watch: { ...watch, ...(over.watch || {}) },
    baselineGates: over.baselineGates || [], finalGates: over.finalGates || [],
    testHarness: { argv: [process.execPath, 'worker.mjs'], monitorMs: 150, heartbeatMs: 300, graceMs: 600, ...(over.testHarness || {}) },
    ...(over.extra || {}),
  };
}

export const suiteSource = (reqId, ids) => `import test from 'node:test';
import fs from 'node:fs';
${ids.map((id) => `test('[${id}] flag-${reqId} exists', () => { if (!fs.existsSync('flag-${reqId}')) throw new Error('flag-${reqId} missing'); });`).join('\n')}
`;

export const WORKER_SRC = `// scriptable mock worker. Reads worker-mode.json: {default, perReq:{ID:mode}}.
import fs from 'node:fs';
import { spawn } from 'node:child_process';
let prompt = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => { prompt += d; });
process.stdin.on('end', run);
const out = (o) => process.stdout.write(JSON.stringify(o) + '\\n');
function run() {
  const id = (/REQUIREMENT ([A-Z]+-\\d+)/.exec(prompt) || [])[1];
  let cfg = {}; try { cfg = JSON.parse(fs.readFileSync('worker-mode.json', 'utf8')); } catch {}
  const mode = (cfg.perReq && cfg.perReq[id]) || cfg.default || 'fix';
  fs.appendFileSync('worker-calls.log', id + ' ' + mode + ' ' + process.pid + '\\n');
  out({ type: 'system', subtype: 'init', session_id: 's-' + process.pid, model: 'mock' });
  out({ type: 'assistant', message: { id: 'm1', content: [{ type: 'text', text: 'working on ' + id }], usage: { input_tokens: 10, output_tokens: 5 } } });
  const result = (extra = {}) => out({ type: 'result', subtype: 'success', is_error: false, result: 'LOOP_RESULT: {"requirement":"' + id + '","claims":"done"}', total_cost_usd: cfg.cost ?? 0.01, num_turns: 1, permission_denials: [], ...extra });
  switch (mode) {
    case 'fix': fs.writeFileSync('flag-' + id, 'ok'); result(); process.exit(0); break;
    case 'claim-done': result({ result: 'All criteria are complete and verified. LOOP_RESULT: {"requirement":"' + id + '","claims":"100% complete"}' }); process.exit(0); break;
    case 'noop': result(); process.exit(0); break;
    case 'silent-hang': setInterval(() => {}, 1000); break;
    case 'noisy-loop': { const l = 'x'.repeat(2000); const p = () => { for (let i = 0; i < 100; i++) process.stdout.write(l + '\\n'); setImmediate(p); }; p(); break; }
    case 'stdin-wait': process.stdin.resume(); setInterval(() => {}, 1000); break;
    case 'orphan': {
      const c = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { detached: true, stdio: 'ignore' }); c.unref();
      fs.writeFileSync('orphan.pid', String(c.pid)); setInterval(() => {}, 1000); break;
    }
    case 'auth-fail': process.stderr.write('Error: Not logged in. Please run /login\\n'); process.exit(1); break;
    case 'bad-flag': process.stderr.write('error: unknown option --bogus-flag\\n'); process.exit(2); break;
    case 'net-fail': process.stderr.write('fetch failed: getaddrinfo ENOTFOUND api.anthropic.com\\n'); process.exit(1); break;
    case 'error-result': out({ type: 'result', subtype: 'error_during_execution', is_error: true, result: 'boom', total_cost_usd: 0.02, num_turns: 1, permission_denials: [] }); process.exit(0); break;
    case 'no-result': process.exit(0); break;
    case 'truncated': process.stdout.write('{"type":"assistant","message":{"id":"m2","content":[{"type":"te'); process.exit(0); break;
    case 'denied': result({ permission_denials: [{ tool_name: 'Bash', tool_input: {} }] }); process.exit(0); break;
    case 'die': process.kill(process.pid, 'SIGKILL'); break;
    case 'flood-steady': { const l = 'y'.repeat(2000); setInterval(() => { for (let i = 0; i < 50; i++) process.stdout.write(l + '\\n'); }, 5); break; }
    case 'overspend': out({ type: 'system', subtype: 'cost', total_cost_usd: cfg.overspendUsd ?? 99 }); setInterval(() => {}, 1000); break;
    case 'cheap-fix': out({ type: 'system', subtype: 'cost', total_cost_usd: 0.5 }); fs.writeFileSync('flag-' + id, 'ok'); result(); process.exit(0); break;
    case 'chatter': { const t = setInterval(() => { out({ type: 'assistant', message: { id: 'same', content: [{ type: 'text', text: 'still thinking' }], usage: {} } }); }, 100); void t; break; }
    case 'secret': { const k = ['sk', 'ant', 'api03'].join('-') + 'Z'.repeat(30); out({ type: 'assistant', message: { id: 'sec', content: [{ type: 'text', text: 'key ' + k + ' and GITHUB_TOKEN=ghp_' + 'a'.repeat(30) }], usage: {} } }); process.stderr.write('Authorization: Bearer ' + 'q'.repeat(24) + '\\n'); for (let i = 0; i < 4000; i++) process.stdout.write('{"type":"user","message":{"content":[]},"pad":"' + 'x'.repeat(900) + '"}\\n'); fs.writeFileSync('flag-' + id, 'ok'); result(); process.exit(0); break; }
    case 'tamper': fs.appendFileSync('t/suite-' + id + '.test.js', '\\n// tampered by the worker\\n'); setInterval(() => {}, 1000); break;
    case 'forge': { fs.writeFileSync('done.json', JSON.stringify({ requirement: id, done: true, verified: true })); fs.mkdirSync('.loop-engineering/forged', { recursive: true }); fs.writeFileSync('.loop-engineering/forged/' + id + '.json', JSON.stringify({ requirement: id, result: 'pass', criteria: [], signature: 'f'.repeat(64) })); result({ result: 'ALL DONE 100% LOOP_RESULT: {"requirement":"' + id + '","claims":"verified complete"}' }); process.exit(0); break; }
    case 'slow': setTimeout(() => { fs.writeFileSync('flag-' + id, 'ok'); result(); process.exit(0); }, cfg.slowMs || 1500); break;
    case 'many-turns': { let i = 0; const t = setInterval(() => { out({ type: 'assistant', message: { id: 'mt' + (i++), content: [{ type: 'text', text: 't' }], usage: {} } }); }, 5); break; }
    default: process.exit(0);
  }
}
`;

export class MiniRepo {
  constructor(reqs, { profile = {}, suiteSources = null, workerMode = null, env = {} } = {}) {
    this.reqs = reqs;
    this.root = mkdtempSync(join(tmpdir(), 'loop-mini-'));
    this.env = { ...process.env, LOOP_ENGINEERING_REPO: this.root, LOOP_ENGINEERING_TEST_HARNESS: '1', ...env };
    execFileSync('git', ['init', '-q'], { cwd: this.root });
    writeFileSync(join(this.root, '.gitignore'), '.loop-engineering/\nworker-calls.log\norphan.pid\n');
    mkdirSync(join(this.root, 't'), { recursive: true });
    writeFileSync(join(this.root, 'PRD.md'), prdText(reqs));
    this.profile = baseProfile(reqs, profile);
    writeFileSync(join(this.root, 'profile.json'), JSON.stringify(this.profile, null, 2));
    for (const r of reqs) {
      const s = r.suite || 'suite-' + r.id;
      const src = suiteSources?.[s] ?? suiteSource(r.id, r.criteria.map((_, i) => `${r.id}.AC${String(i + 1).padStart(2, '0')}`));
      writeFileSync(join(this.root, 't', `${s}.test.js`), src);
    }
    writeFileSync(join(this.root, 'worker.mjs'), WORKER_SRC);
    writeFileSync(join(this.root, 'worker-mode.json'), JSON.stringify(workerMode || { default: 'fix' }));
    this.pids = new Set();
  }
  setMode(m) { writeFileSync(join(this.root, 'worker-mode.json'), JSON.stringify(m)); }
  path(...p) { return join(this.root, ...p); }
  read(p) { return readFileSync(this.path(p), 'utf8'); }
  exists(p) { return existsSync(this.path(p)); }
  writeProfile(p) { this.profile = p; writeFileSync(this.path('profile.json'), JSON.stringify(p, null, 2)); }

  // Run run.mjs and capture output; never hangs the test.
  cli(args, { timeoutMs = 60000, env = {} } = {}) {
    return new Promise((resolve) => {
      const t0 = Date.now();
      const c = spawn(process.execPath, [RUN_MJS, ...args], { cwd: this.root, env: { ...this.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
      let so = '', se = '';
      c.stdout.on('data', (d) => { so += d; }); c.stderr.on('data', (d) => { se += d; });
      const to = setTimeout(() => { c.kill('SIGKILL'); }, timeoutMs);
      c.on('close', (code) => { clearTimeout(to); resolve({ code, stdout: so, stderr: se, ms: Date.now() - t0 }); });
    });
  }
  async init(extra = []) { return this.cli(['init', '--prd', 'PRD.md', '--profile', 'profile.json', '--skip-baseline-gates', ...extra]); }
  async status() { const r = await this.cli(['status', '--json']); return JSON.parse(r.stdout); }
  state() { const cur = this.read('.loop-engineering/current-run').trim(); return JSON.parse(this.read(`.loop-engineering/runs/${cur}/state.json`)); }
  runId() { return this.read('.loop-engineering/current-run').trim(); }
  runPath(...p) { return this.path('.loop-engineering', 'runs', this.runId(), ...p); }
  async waitFor(pred, { timeoutMs = 30000, everyMs = 200, label = 'condition' } = {}) {
    const end = Date.now() + timeoutMs;
    let last;
    while (Date.now() < end) { try { last = await pred(); if (last) return last; } catch { /* retry */ } await sleep(everyMs); }
    throw new Error(`timed out waiting for ${label}`);
  }
  // Best-effort teardown: stop owned processes, then remove the directory.
  async cleanup() {
    let id = null;
    try {
      id = this.runId();
      await this.cli(['stop', '--run', id], { timeoutMs: 20000 });
    } catch { /* not started */ }
    // Only jobs belonging to THIS repo's run; other tests run in parallel.
    if (id) for (const h of scanEnvMarker('LOOP_ENGINEERING_JOB', `${id}:`, [])) { try { process.kill(h.pid, 'SIGKILL'); } catch { /* */ } }
    for (const f of ['orphan.pid']) {
      try { const p = Number(readFileSync(this.path(f), 'utf8')); if (p) process.kill(p, 'SIGKILL'); } catch { /* */ }
    }
    try { rmSync(this.root, { recursive: true, force: true }); } catch { /* */ }
  }
}

export const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
export { identityMatches, startTimeOf };
