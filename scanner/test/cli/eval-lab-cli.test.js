// End-to-end CLI coverage for the Eval Lab and the model router (PRD 6), through the real spawned CLI with stdin closed.
// The definition of done: one command compares a deterministic baseline, a local model and two external model configurations
// across quality, proof, remediation, cost, latency and repeatability; then the router explains which model gets which task.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const FX = fileURLToPath(new URL('../fixtures/eval-lab', import.meta.url));
const ARM = path.join(FX, 'fake-arm.mjs');
const REPRO = path.join(FX, 'proof/cases/vuln.reproducer.json');
const run = (dir, args, { env = {}, timeout = 280000 } = {}) => spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env } });
const sandbox = sandboxAvailable() ? false : 'no confinement backend on this host';

const fake = (id, profile, model, extra = {}) => ({ id, kind: 'model', tasks: ['detect', 'falsify', 'exploit', 'patch'], model, adapter: { type: 'command', argv: [process.execPath, ARM, profile, REPRO], timeoutMs: 60000 }, price: { inputPerMTok: 3, outputPerMTok: 15 }, ...extra });
const ARMS = [
  { id: 'baseline', kind: 'deterministic', tasks: ['detect'], adapter: { type: 'builtin-scanner', layer: 'deep-taint' } },
  fake('local-model', 'good', { id: 'qwen-coder', provider: 'ollama', local: true, endpoint: 'http://127.0.0.1:11434' }, { price: { inputPerMTok: 0, outputPerMTok: 0 } }),
  fake('external-a', 'good', { id: 'frontier-a', provider: 'acme', local: false, endpoint: 'https://api.acme.invalid' }, { price: { inputPerMTok: 15, outputPerMTok: 75 } }),
  fake('external-b', 'noisy', { id: 'budget-b', provider: 'bolt', local: false, endpoint: 'https://api.bolt.invalid' }, { price: { inputPerMTok: 0.5, outputPerMTok: 2 } }),
];
function project() {
  const dir = mkTestTmp('lab-cli-'); fs.mkdirSync(path.join(dir, '.git'));
  fs.writeFileSync(path.join(dir, 'arms.json'), JSON.stringify({ arms: ARMS }));
  return dir;
}
const DS = path.join(FX, 'proof/dataset.json');
const common = (dir) => ['--dataset', DS, '--arms', path.join(dir, 'arms.json'), '--tasks', 'detect,falsify,exploit,patch', '--repeats', '3', '--concurrency', '4', '--timeout', '90'];

test('usage and preconditions: typed exit codes, no prompts, nothing run or stored on a refusal', () => {
  const dir = project();
  assert.equal(run(dir, ['eval']).status, 4);
  assert.equal(run(dir, ['eval', 'run']).status, 4);
  assert.equal(run(dir, ['eval', 'report']).status, 4);
  assert.equal(run(dir, ['eval', 'report', 'elab-nope']).status, 4);
  assert.equal(run(dir, ['models', 'route']).status, 4);
  assert.equal(run(dir, ['models', 'route', 'explain']).status, 4);
  const noExt = run(dir, ['eval', 'run', ...common(dir)]);
  assert.equal(noExt.status, 4); assert.match(noExt.stderr, /external-a, external-b/); assert.match(noExt.stderr, /--allow-external/);
  assert.equal(fs.existsSync(path.join(dir, '.agentic-security', 'eval-lab')), false);
  const badTasks = run(dir, ['eval', 'run', '--dataset', DS, '--arms', path.join(dir, 'arms.json'), '--allow-external', '--tasks', 'hunt']);
  assert.equal(badTasks.status, 4);
  const badNum = run(dir, ['eval', 'run', '--dataset', DS, '--arms', path.join(dir, 'arms.json'), '--allow-external', '--repeats', '0']);
  assert.equal(badNum.status, 4);
  fs.writeFileSync(path.join(dir, 'bad-arms.json'), JSON.stringify([{ id: 'x', kind: 'model', tasks: ['detect'], model: { id: 'm', provider: 'p' }, adapter: { type: 'command', argv: 'node x.js' } }]));
  const badArms = run(dir, ['eval', 'run', '--dataset', DS, '--arms', path.join(dir, 'bad-arms.json')]);
  assert.equal(badArms.status, 4); assert.match(badArms.stderr, /model\.local must be true or false/); assert.match(badArms.stderr, /argv must be a non-empty array/);
  const weak = JSON.parse(fs.readFileSync(DS, 'utf8')); weak.dataset.leakagePolicy.mode = 'off';
  fs.writeFileSync(path.join(dir, 'weak.json'), JSON.stringify(weak));
  const badDs = run(dir, ['eval', 'run', '--dataset', path.join(dir, 'weak.json'), '--arms', path.join(dir, 'arms.json'), '--allow-external']);
  assert.equal(badDs.status, 4); assert.match(badDs.stderr, /must be "enforce"/);
  assert.equal(run(dir, ['models', 'route', 'explain', 'hunt']).status, 1, 'no benchmark yet: a typed "no recommendation", not a guess');
});

test('one command compares a baseline, a local model and two external configurations across everything; the router then explains', { skip: sandbox, timeout: 600000 }, () => {
  const dir = project();
  const bench = run(dir, ['models', 'benchmark', ...common(dir), '--allow-external']);
  assert.equal(bench.status, 0, bench.stdout + bench.stderr);
  const out = bench.stdout;
  for (const arm of ['baseline', 'local-model', 'external-a', 'external-b']) assert.ok(out.includes(`| ${arm} |`), `${arm} missing from the report`);
  for (const section of ['## detect', '## falsify', '## exploit', '## patch', '## Cost, speed and reliability', '## Intelligence per dollar', '## Dollars per outcome']) assert.ok(out.includes(section), section);
  assert.match(out, /Leakage audit: clean/); assert.match(out, /Scanner: /); assert.match(out, /Machine: /);
  assert.match(out, /Run stored: elab-/); assert.match(out, /Scoreboard updated\./);
  assert.match(out, /\| external-a \| .* \|/);

  // stored, listed, reportable in every format
  const runId = /Run stored: (elab-[0-9a-f]+)/.exec(out)[1];
  assert.match(run(dir, ['eval', 'list']).stdout, new RegExp(runId));
  const rep = (fmt) => run(dir, ['eval', 'report', runId, '--format', fmt]);
  const json = JSON.parse(rep('json').stdout);
  const by = Object.fromEntries(json.arms.map((a) => [a.id, a]));
  assert.equal(by['external-a'].tasks.exploit.confirmationRate.mean, 1);
  assert.equal(by['external-a'].tasks.exploit.falseConfirmationRate.mean, 0);
  assert.equal(by['external-a'].tasks.patch.validPatchRate.mean, 1);
  assert.equal(by['external-b'].tasks.patch.validPatchRate.mean, 0, 'a patch that keeps the flaw does not count');
  assert.equal(by['external-b'].tasks.falsify.falseConfirmationRate.mean, 1);
  assert.equal(by['local-model'].economics.usd.mean, 0, 'a local model priced at zero costs nothing');
  assert.ok(by['external-a'].economics.usd.mean > by['external-b'].economics.usd.mean);
  assert.equal(by['external-a'].tasks.patch.validPatchRate.representative, true);
  assert.equal(by.baseline.runs, 1);
  assert.ok(by.baseline.tasks.detect);
  assert.equal(by.baseline.tasks.exploit, undefined, 'the scanner does not do exploit; it is absent, not zero');
  assert.match(rep('csv').stdout, /^arm,kind,task,metric/);
  assert.match(rep('html').stdout, /^<!doctype html>/);
  assert.ok(JSON.parse(rep('chart').stdout).series.length > 5);
  const file = path.join(dir, 'report.md');
  assert.equal(run(dir, ['eval', 'report', runId, '--format', 'md', '--out', file]).status, 0);
  assert.match(fs.readFileSync(file, 'utf8'), new RegExp(`# Eval Lab report ${runId}`));
  assert.equal(run(dir, ['eval', 'report', runId, '--format', 'pdf']).status, 4);
  assert.match(run(dir, ['eval', 'compare', runId]).stdout, /Intelligence per dollar/);

  // routing: independent per task, explained, and honest about what it cannot say
  const hunt = run(dir, ['models', 'route', 'explain', 'hunt', '--policy', 'balanced']);
  assert.equal(hunt.status, 0, hunt.stdout + hunt.stderr);
  assert.match(hunt.stdout, /^Recommended: /); assert.match(hunt.stdout, /Detection quality: /); assert.match(hunt.stdout, /Median cost: /); assert.match(hunt.stdout, /Median latency: /);
  const patch = run(dir, ['models', 'route', 'explain', 'patch-generation', '--policy', 'best-quality', '--json']);
  const pj = JSON.parse(patch.stdout);
  assert.equal(pj.ok, true); assert.ok(['ollama/qwen-coder', 'acme/frontier-a'].includes(pj.recommended.model), pj.recommended.model);
  const localOnly = JSON.parse(run(dir, ['models', 'route', 'explain', 'exploit-generation', '--policy', 'local-only', '--json']).stdout);
  assert.equal(localOnly.recommended.model, 'ollama/qwen-coder'); assert.ok(localOnly.excluded.some((e) => /not a local model/.test(e.reasons.join())));
  const cheap = run(dir, ['models', 'route', 'explain', 'hunt', '--policy', 'lowest-cost-above-quality-threshold', '--threshold', '0.9']);
  assert.equal(cheap.status, 0, cheap.stdout);
  const noThreshold = run(dir, ['models', 'route', 'explain', 'hunt', '--policy', 'lowest-cost-above-quality-threshold']);
  assert.equal(noThreshold.status, 4);
  const tm = run(dir, ['models', 'route', 'explain', 'threat-model']);
  assert.equal(tm.status, 1); assert.match(tm.stdout, /no-benchmark-for-task/);
  assert.equal(run(dir, ['models', 'route', 'explain', 'hunt', '--policy', 'cheapest']).status, 4);

  // a hand-edited scoreboard cannot steer routing
  const sbFile = path.join(dir, '.agentic-security', 'eval-lab', 'scoreboard.json');
  fs.writeFileSync(sbFile, fs.readFileSync(sbFile, 'utf8').replace(/"mean":\s*[0-9.]+/, '"mean":0.999'));
  const tampered = run(dir, ['models', 'route', 'explain', 'hunt']);
  assert.equal(tampered.status, 1); assert.match(tampered.stderr, /integrity check/);
  // and a hand-edited run is not reported
  const runFile = path.join(dir, '.agentic-security', 'eval-lab', 'runs', `${runId}.json`);
  fs.writeFileSync(runFile, fs.readFileSync(runFile, 'utf8').replace('"complete":true', '"complete":false'));
  const badRun = run(dir, ['eval', 'report', runId]);
  assert.equal(badRun.status, 1); assert.match(badRun.stderr, /integrity check/);
});

test('with outbound model use denied by the egress policy, the external arms are blocked and recorded, the local arm still runs', { skip: sandbox, timeout: 300000 }, () => {
  const dir = project();
  const r = run(dir, ['eval', 'run', '--dataset', DS, '--arms', path.join(dir, 'arms.json'), '--allow-external', '--tasks', 'detect', '--repeats', '3', '--json'], { env: { AGENTIC_SECURITY_EGRESS_DENY: '1' } });
  const body = JSON.parse(r.stdout);
  const by = Object.fromEntries(body.report.arms.map((a) => [a.id, a]));
  assert.equal(by['local-model'].tasks.detect.recall.mean, 1);
  assert.equal(by['external-a'].tasks.detect.completion.mean, 0); assert.equal(by['external-a'].economics.failures, 6);
  assert.equal(by['external-b'].tasks.detect.completion.mean, 0);
  const stored = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'eval-lab', 'runs', `${body.runId}.json`), 'utf8'));
  assert.ok(stored.attempts.filter((a) => a.armId === 'external-a').every((a) => a.status === 'blocked' && /egress policy/.test(a.reason)));
});

test('run-to-run comparison refuses different datasets, and shows deltas for the same one', { skip: sandbox, timeout: 300000 }, () => {
  const dir = project();
  const args = ['eval', 'run', '--dataset', DS, '--arms', path.join(dir, 'arms.json'), '--allow-external', '--tasks', 'detect', '--repeats', '3', '--json'];
  const a = JSON.parse(run(dir, args).stdout).runId;
  const b = JSON.parse(run(dir, args).stdout).runId;
  const same = run(dir, ['eval', 'compare', a, b]);
  assert.equal(same.status, 0, same.stderr); assert.match(same.stdout, /local-model detect\/f1: 100\.0% -> 100\.0% \(\+0\.0 points\)/);
  const other = JSON.parse(run(dir, ['eval', 'run', '--dataset', path.join(FX, 'detect/dataset.json'), '--arms', path.join(dir, 'arms.json'), '--allow-external', '--tasks', 'detect', '--repeats', '3', '--json']).stdout).runId;
  const diff = run(dir, ['eval', 'compare', a, other]);
  assert.equal(diff.status, 1); assert.match(diff.stderr, /different datasets/);
  assert.equal(run(dir, ['eval', 'compare', a, other, '--allow-different-datasets']).status, 0);
});
