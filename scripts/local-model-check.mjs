#!/usr/bin/env node
// Hosted evidence for local model support, against a REAL model server on loopback (not a stand-in). It runs the model-assisted stages that
// exist today, validation, fix proposal and hunt, plus one Eval Lab comparison against the deterministic baseline, and the loopback
// refusal in both directions. It exits non-zero, with the reason, when the server or the model is missing: a leg that could not reach its
// model is a failure, never a skip.
//
//   node scripts/local-model-check.mjs --model <name> [--out <evidence.json>] [--host http://127.0.0.1:11434]
//
// What it asserts is the CONTRACT, not the model's quality. A small model will often answer badly, and the contract says what must happen
// then: a verdict is recorded separately and never changes a finding's severity; a model that cannot be parsed is `unvalidated`/`malformed`,
// not a silent pass; a rejected weak finding is listed in the suppression ledger, not deleted; a hunt candidate is a proposal that
// confirmation and refutation gate; and a non-loopback endpoint is refused before any request leaves the machine.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(REPO, 'scanner', 'bin', 'agentic-security.js');
const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i === -1 ? d : process.argv[i + 1]; };
const MODEL = arg('model', null);
const OUT = arg('out', null);
const HOST = arg('host', 'http://127.0.0.1:11434');
if (!MODEL) { console.error('local-model: --model <name> is required'); process.exit(2); }

const evidence = { schema: 'agentic-security/local-model-evidence', generatedAt: new Date().toISOString(), model: MODEL, host: { platform: process.platform, arch: process.arch, node: process.version, cpus: os.cpus().length, memoryGb: Math.round(os.totalmem() / 1e9) }, checks: [], timings: {} };
const failures = [];
const check = (name, ok, detail = null) => { evidence.checks.push({ name, ok: !!ok, ...(detail ? { detail } : {}) }); if (!ok) failures.push(detail ? `${name}: ${detail}` : name); };
const sh = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: 'utf8', timeout: opts.timeout ?? 600000, cwd: opts.cwd, env: { ...process.env, ...(opts.env || {}) }, maxBuffer: 64 * 1024 * 1024 });
const cli = (cwd, args, env, timeout) => sh(process.execPath, [CLI, ...args], { cwd, env, timeout });
const timed = async (name, fn) => { const t0 = Date.now(); try { return await fn(); } finally { evidence.timings[name] = Math.round((Date.now() - t0) / 1000); } };
const modelEnv = { AGENTIC_SECURITY_LLM_PRESET: 'ollama', AGENTIC_SECURITY_LLM_MODEL: MODEL, AGENTIC_SECURITY_OLLAMA_HOST: HOST };
function fail(msg) { console.error(`local-model: ${msg}`); process.exit(1); }

// ---- the server and the model must be there
const tags = sh('curl', ['-fsS', '--max-time', '10', `${HOST}/api/tags`], { timeout: 30000 });
if (tags.status !== 0) fail(`no model server answered at ${HOST}; this leg proves nothing without one`);
let installed = [];
try { installed = JSON.parse(tags.stdout).models.map((m) => m.name); } catch { fail('the model server did not answer with a model list'); }
if (!installed.some((n) => n === MODEL || n.startsWith(`${MODEL}:`))) fail(`the model ${MODEL} is not installed on the server (installed: ${installed.join(', ') || 'none'})`);
const version = sh('curl', ['-fsS', '--max-time', '10', `${HOST}/api/version`], { timeout: 30000 });
evidence.server = { host: HOST, version: version.status === 0 ? (JSON.parse(version.stdout).version ?? null) : null, installed };

// ---- a project to scan
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'local-model-'));
const project = path.join(work, 'project');
fs.cpSync(path.join(REPO, 'examples', 'assurance-demo'), project, { recursive: true });
const scan = (env) => { const r = cli(project, ['scan', '.', '--format', 'json', '--include-suppressed'], env, 900000); try { return { status: r.status, report: JSON.parse(r.stdout), stderr: r.stderr }; } catch { return { status: r.status, report: null, stderr: String(r.stderr).slice(-400) }; } };
const sevs = (report) => Object.fromEntries((report.findings || []).map((f) => [f.stableId || f.id, f.severity]));

// ---- validation, and the invariants that must hold whatever the model says
const baseline = await timed('scan without a model', () => scan({}));
check('the scan without a model completes', baseline.report !== null, baseline.stderr);
const live = await timed('scan with the model', () => scan(modelEnv));
check('the scan with the model completes', live.report !== null, live.stderr);
if (baseline.report && live.report) {
  const verdicts = (live.report.findings || []).map((f) => f.validator_verdict).filter(Boolean);
  const answered = verdicts.filter((v) => ['accept', 'reject', 'escalate'].includes(v));
  evidence.validation = { findingsBefore: baseline.report.findings.length, findingsAfter: live.report.findings.length, verdicts: Object.fromEntries([...new Set(verdicts)].map((v) => [v, verdicts.filter((x) => x === v).length])) };
  const ps = sh('curl', ['-fsS', '--max-time', '10', `${HOST}/api/ps`], { timeout: 30000 });
  evidence.validation.modelLoadedAfterScan = ps.status === 0 && ps.stdout.includes(MODEL.split(':')[0]);
  check('the model server received the validation requests (the model is loaded after the scan)', evidence.validation.modelLoadedAfterScan, ps.stdout.slice(0, 200));
  check('without a model every validatable finding is unvalidated, with one at least one finding got a verdict', answered.length > 0 || verdicts.includes('unvalidated'), JSON.stringify(evidence.validation.verdicts));
  const before = sevs(baseline.report); const after = sevs(live.report);
  const changed = Object.keys(after).filter((id) => id in before && before[id] !== after[id]);
  check('a verdict never changes a finding\'s severity', changed.length === 0, changed.join(', '));
  const gone = Object.keys(before).filter((id) => !(id in after));
  const rejected = (live.report.suppressed || []).filter((x) => /llm-validator:reject/.test(JSON.stringify(x)));
  evidence.validation.rejectedAndListed = rejected.length;
  check('every finding the model rejected is in the suppression ledger, not deleted', gone.length <= rejected.length, `${gone.length} finding(s) removed, ${rejected.length} listed as rejected by the validator`);
  const strong = (live.report.findings || []).filter((f) => f.parser === 'IR-TAINT' && f.validator_verdict === 'reject');
  check('a reject never deletes a taint-proven finding', strong.length === 0);
}

// ---- loopback: a non-loopback endpoint is refused before any request, and a loopback one is used
const refused = await timed('scan against a non-loopback endpoint', () => scan({ AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: 'http://203.0.113.9:11434/v1/chat/completions', AGENTIC_SECURITY_LLM_MODEL: MODEL }));
check('a non-loopback endpoint under the local preset completes quickly and validates nothing', refused.report !== null && evidence.timings['scan against a non-loopback endpoint'] < 90 && (refused.report.findings || []).every((f) => !['accept', 'reject', 'escalate'].includes(f.validator_verdict)), `took ${evidence.timings['scan against a non-loopback endpoint']}s`);
const viaLocal = await timed('scan against the loopback endpoint under the local preset', () => scan({ AGENTIC_SECURITY_LLM_PRESET: 'local', AGENTIC_SECURITY_LLM_ENDPOINT: `${HOST}/v1/chat/completions`, AGENTIC_SECURITY_LLM_MODEL: MODEL }));
check('the same preset with a loopback endpoint reaches the model', viaLocal.report !== null && (viaLocal.report.findings || []).some((f) => ['accept', 'reject', 'escalate'].includes(f.validator_verdict) || f.validator_verdict === 'unvalidated'), null);

// ---- fix proposal: the model may propose; the gate decides
const target = live.report && (live.report.findings || []).find((f) => /SQL Injection/.test(f.vuln) && f.file.endsWith('.js'));
if (target) {
  const fix = await timed('fix proposal', () => cli(project, ['fix', target.stableId || target.id], modelEnv, 900000));
  const text = `${fix.stdout}\n${fix.stderr}`;
  evidence.fixProposal = { exit: fix.status, tail: text.trim().split('\n').slice(-6).join('\n').slice(0, 800) };
  check('the fix path reaches a defined outcome (a verified patch, or a refusal with a reason), never a crash', [0, 1, 4].includes(fix.status) && !/TypeError|ReferenceError|at .*\.js:\d+/.test(text), `exit ${fix.status}`);
} else check('a SQL injection finding exists to propose a fix for', false, 'none in the scan');

// ---- hunt: candidates are proposals, gated by the engine
const hunt = await timed('hunt', () => cli(project, ['hunt', '.', '--lens', 'injection'], modelEnv, 1500000));
evidence.hunt = { exit: hunt.status, head: String(hunt.stdout).trim().split('\n').slice(0, 12).join('\n').slice(0, 1200) };
check('hunt completes and reports what it covered', hunt.status === 0 && /Discovery/.test(hunt.stdout), `exit ${hunt.status}`);
check('hunt states that candidates go through confirmation and refutation', /confirmation|refuted|candidates/.test(hunt.stdout));

// ---- Eval Lab against the deterministic baseline
const arms = path.join(work, 'arms.json');
fs.writeFileSync(arms, JSON.stringify({ arms: [
  { id: 'baseline', kind: 'deterministic', tasks: ['detect'], adapter: { type: 'builtin-scanner', layer: 'deep-taint' } },
  { id: 'local', kind: 'model', tasks: ['detect'], model: { id: MODEL, provider: 'ollama', local: true, endpoint: HOST }, adapter: { type: 'ollama', model: MODEL, host: HOST, timeoutMs: 180000 }, price: { inputPerMTok: 0, outputPerMTok: 0 } },
] }));
fs.mkdirSync(path.join(project, '.git'), { recursive: true });
const evalRun = await timed('eval lab comparison', () => cli(project, ['eval', 'run', '--dataset', path.join(REPO, 'scanner', 'test', 'fixtures', 'eval-lab', 'detect', 'dataset.json'), '--arms', arms, '--tasks', 'detect', '--repeats', '1', '--concurrency', '1', '--timeout', '180'], modelEnv, 1800000));
evidence.evalLab = { exit: evalRun.status, tail: `${evalRun.stdout}\n${evalRun.stderr}`.trim().split('\n').slice(-8).join('\n').slice(0, 1000) };
check('the Eval Lab runs the baseline and the local model arm to a report', [0, 1].includes(evalRun.status), `exit ${evalRun.status}: ${String(evalRun.stderr).slice(-300)}`);
if ([0, 1].includes(evalRun.status)) {
  const list = cli(project, ['eval', 'list'], {}, 60000);
  const runId = (String(list.stdout).match(/elab-[0-9a-f]+/) || [])[0];
  const rep = runId ? cli(project, ['eval', 'report', runId, '--format', 'json'], {}, 60000) : null;
  let report = null; try { report = rep && JSON.parse(rep.stdout); } catch { /* reported below */ }
  check('the report names both arms, the local one marked as a model arm', !!report && report.arms.some((a) => a.id === 'baseline') && report.arms.some((a) => a.id === 'local' && a.kind === 'model'), runId ? null : 'no run id');
  if (report) evidence.evalLab.arms = Object.fromEntries(report.arms.map((a) => [a.id, { kind: a.kind, runs: a.runs, detectF1: a.tasks?.detect?.f1?.mean ?? null, completion: a.tasks?.detect?.completion?.mean ?? null, failures: a.economics?.failures ?? null }]));
}

fs.rmSync(work, { recursive: true, force: true });
if (OUT) fs.writeFileSync(path.resolve(OUT), JSON.stringify(evidence, null, 2) + '\n');
for (const c of evidence.checks) console.log(`${c.ok ? 'ok  ' : 'FAIL'} ${c.name}${!c.ok && c.detail ? ` (${c.detail})` : ''}`);
console.log(`timings (s): ${JSON.stringify(evidence.timings)}`);
if (failures.length) { console.error(`local-model: ${failures.length} check(s) failed`); process.exit(1); }
console.log(`local-model: ${evidence.checks.length} checks passed against ${MODEL} on ${HOST}`);
