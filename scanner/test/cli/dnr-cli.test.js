// End-to-end coverage for the detection-and-response loop (PRD 7), through the real spawned CLI with stdin closed.
// The required scenario: introduce an exploitable flaw, detect it, prove it, generate the detection, hunt historical logs,
// patch, replay the exploit, confirm the fix, and keep the recurrence rule.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';
import { signLastScan } from '../../src/posture/integrity.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const FIX = fileURLToPath(new URL('../fixtures', import.meta.url));
const LOGS = path.join(FIX, 'dnr/logs');
const run = (dir, args, timeout = 60000) => spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'] });
const sandbox = sandboxAvailable() ? false : 'no confinement backend on this host';

const ATTACK = { method: 'POST', path: '/api/export', parameter: 'filename', location: 'body', payloadClass: 'command-injection', sink: 'execSync()' };
const REPRO = { schema: 'agentic-security/reproducer', version: 1, findingId: 'F1', lang: 'javascript', sources: { 'app.mjs': 'app.mjs' }, run: ['{{NODE}}', 'app.mjs', 'touch {{CANARY:command}}'], oracle: { type: 'command_execution', params: { canary: 'command' } }, network: 'none', attack: ATTACK };
const SAFE_LINE = "spawnSync('echo', ['hello', userInput], { stdio: 'ignore', shell: false });";

function project({ attack = ATTACK, withFix = true } = {}) {
  const dir = mkTestTmp('dnr-cli-');
  fs.mkdirSync(path.join(dir, '.git'));
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  fs.copyFileSync(path.join(FIX, 'proof-fabric/command-injection/vulnerable/app.mjs'), path.join(dir, 'app.mjs'));
  fs.writeFileSync(path.join(dir, 'repro.json'), JSON.stringify({ ...REPRO, attack }));
  const finding = { id: 'F1', stableId: 'F1', severity: 'critical', vuln: 'command injection', cwe: 'CWE-78', file: 'app.mjs', line: 4, parser: 'IR-TAINT', ...(withFix ? { fix: { replaceLine: SAFE_LINE } } : {}) };
  const body = JSON.stringify({ findings: [finding] });
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), body);
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));
  fs.writeFileSync(path.join(dir, '.agentic-security', 'findings.json'), body);
  return dir;
}

test('usage and preconditions are typed exit codes, never prompts, and never leave state behind', () => {
  const dir = project();
  assert.equal(run(dir, ['dnr']).status, 4);
  assert.equal(run(dir, ['dnr', 'generate']).status, 4);
  assert.equal(run(dir, ['dnr', 'bogus', 'F1']).status, 4);
  const noProof = run(dir, ['dnr', 'generate', 'F1']);
  assert.equal(noProof.status, 4); assert.match(noProof.stderr, /prove it first/);
  assert.equal(fs.existsSync(path.join(dir, '.agentic-security', 'dnr')), false, 'a refused generate stores nothing');
  assert.equal(run(dir, ['dnr', 'hunt', 'F1']).status, 4);
  assert.match(run(dir, ['dnr', 'hunt', 'F1']).stderr, /needs --logs/);
  assert.equal(run(dir, ['dnr', 'window', 'F1']).status, 4);
  assert.equal(run(dir, ['dnr', 'generate', 'NOPE', '--allow-unproven']).status, 4);
  assert.equal(run(dir, ['dnr', 'generate', 'F1', '--allow-unproven', '--format', 'bogus']).status, 4);
});

test('--allow-unproven builds a lower-confidence detection and says so; it never claims exploit proof', () => {
  const dir = project();
  const r = run(dir, ['dnr', 'generate', 'F1', '--allow-unproven', '--json']);
  const out = JSON.parse(r.stdout);
  assert.equal(out.ir.grounding, 'static-only');
  assert.ok(out.ir.limitations.some((l) => /not executed/.test(l)));
  assert.equal(out.ir.endpoint, null, 'no proof, no reproducer facts: no endpoint is invented');
  assert.equal(out.outputs.sigma.applicable, false);
  assert.equal(r.status, 1, 'a detection that could not be validated is not a success');
  assert.equal(JSON.parse(run(dir, ['dnr', 'show', 'F1', '--json']).stdout).enabled, false);
});

test('a reproducer with hostile attack facts is refused before anything runs', () => {
  const dir = project({ attack: { ...ATTACK, path: '/a"; rm -rf /' } });
  const r = run(dir, ['triage', 'exploit', 'F1', '--prove', '--reproducer', path.join(dir, 'repro.json')]);
  assert.equal(r.status, 4);
  assert.match(r.stderr, /attack\.path/);
});

test('hunting a path that does not exist is TELEMETRY_UNAVAILABLE with its own exit code', { skip: sandbox }, () => {
  const dir = project();
  assert.equal(run(dir, ['triage', 'exploit', 'F1', '--prove', '--reproducer', path.join(dir, 'repro.json')]).status, 0);
  const r = run(dir, ['dnr', 'hunt', 'F1', '--logs', path.join(dir, 'no-such-logs')]);
  assert.equal(r.status, 12, r.stdout + r.stderr);
  assert.match(r.stdout, /TELEMETRY_UNAVAILABLE/);
});

test('Find -> Prove -> Hunt -> Scope -> Fix -> Verify -> Detect, end to end', { skip: sandbox, timeout: 240000 }, () => {
  const dir = project();
  const repro = path.join(dir, 'repro.json');

  // PROVE
  const prove = run(dir, ['triage', 'exploit', 'F1', '--prove', '--reproducer', repro]);
  assert.equal(prove.status, 0, prove.stdout + prove.stderr);
  assert.match(prove.stdout, /Evidence: EXPLOIT_CONFIRMED/);
  assert.match(prove.stdout, /Reproductions: 3\/3/);

  // GENERATE DETECTION, validated before it is enabled
  const gen = run(dir, ['dnr', 'generate', 'F1', '--format', 'sigma']);
  assert.equal(gen.status, 0, gen.stdout + gen.stderr);
  assert.match(gen.stdout, /Validation: VALIDATED/);
  assert.match(gen.stdout, /recurrence rule enabled/);
  assert.match(gen.stdout, /cs-uri-stem: "\/api\/export"/);
  const out = path.join(dir, 'rules');
  assert.equal(run(dir, ['dnr', 'generate', 'F1', '--out', out]).status, 0);
  const written = fs.readdirSync(out);
  assert.ok(written.some((f) => f.endsWith('.sigma.yml')) && written.some((f) => f.endsWith('.waf.conf')), written.join(','));
  assert.ok(!written.some((f) => f.includes('yara')), 'YARA is not written for a request-shaped class');
  const showProof = run(dir, ['proof', 'show', 'F1']);
  assert.match(showProof.stdout, /Detection: det-[0-9a-f]{12} \(VALIDATED, enabled\)/, 'the proof links to the detection');

  // HUNT: the exploit is in the structured logs; the access log cannot show request bodies; the clean log has nothing
  const hit = run(dir, ['dnr', 'hunt', 'F1', '--logs', path.join(LOGS, 'app.jsonl')]);
  assert.equal(hit.status, 10, hit.stdout + hit.stderr);
  assert.match(hit.stdout, /Hunt: OBSERVED/);
  assert.match(hit.stdout, /Matches: 2/);
  assert.doesNotMatch(hit.stdout + JSON.stringify(fs.readdirSync(path.join(dir, '.agentic-security', 'dnr'))), /abcd1234efgh5678secretvalue/);
  const blind = run(dir, ['dnr', 'hunt', 'F1', '--logs', path.join(LOGS, 'incomplete')]);
  assert.equal(blind.status, 11, 'logs that cannot show the parameter are INCONCLUSIVE');
  assert.match(blind.stdout, /do not read this as "not exploited"/);
  const clean = run(dir, ['dnr', 'hunt', 'F1', '--logs', path.join(LOGS, 'clean')]);
  assert.equal(clean.status, 0);
  assert.match(clean.stdout, /does not establish that the vulnerability was not exploited/);
  // nothing stored stays readable as plaintext secrets
  const stored = fs.readdirSync(path.join(dir, '.agentic-security', 'dnr', fs.readdirSync(path.join(dir, '.agentic-security', 'dnr'))[0]));
  assert.ok(stored.some((n) => n.startsWith('hunt-')) && stored.some((n) => n.startsWith('detection-')));

  // SCOPE: the earlier OBSERVED hunt is not hidden by the later clean one
  const mid = run(dir, ['dnr', 'status', 'F1']);
  assert.match(mid.stdout, /\[x\] HUNT\s+\d+ day\(s\) of telemetry searched, 2 matching event\(s\) observed; other hunt\(s\): /);
  assert.match(mid.stdout, /\[ \] FIX/);

  // FIX with proof, then VERIFY: the original exploit is replayed against the patched code
  const fix = run(dir, ['fix', '--finding', 'F1', '--apply', '--require-proof', '--reproducer', repro], 180000);
  assert.equal(fix.status, 0, fix.stdout + fix.stderr);
  assert.match(fix.stdout, /Post-patch exploit: BLOCKED/);
  assert.match(fix.stdout, /Evidence: FIX_VERIFIED/);
  assert.match(fs.readFileSync(path.join(dir, 'app.mjs'), 'utf8'), /shell: false/);

  // DETECT: the recurrence rule survives the fix, and the unified view shows every step
  const end = run(dir, ['dnr', 'status', 'F1']);
  for (const step of ['FIND', 'PROVE', 'HUNT', 'FIX', 'VERIFY', 'DETECT']) assert.match(end.stdout, new RegExp(`\\[x\\] ${step}`), `${step}\n${end.stdout}`);
  assert.match(end.stdout, /Original exploit blocked/);
  assert.match(end.stdout, /Recurrence rule enabled/);
  const again = run(dir, ['dnr', 'hunt', 'F1', '--logs', path.join(LOGS, 'app.jsonl')]);
  assert.equal(again.status, 10, 'after the fix the same rule still detects the exploit shape in new traffic');
  assert.equal(JSON.parse(run(dir, ['dnr', 'status', 'F1', '--json']).stdout).links.detection.id.startsWith('det-'), true);
});

test('a patch that does not block the exploit leaves FIX and VERIFY unconfirmed, and the detection stays', { skip: sandbox, timeout: 240000 }, () => {
  const dir = project({ withFix: false });
  const f = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), 'utf8'));
  f.findings[0].fix = { replaceLine: "try { execSync(`echo hello; ${userInput}`, { stdio: 'ignore' }); } catch { /* still unsafe */ }" };
  const body = JSON.stringify(f);
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), body);
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));
  const repro = path.join(dir, 'repro.json');
  assert.equal(run(dir, ['triage', 'exploit', 'F1', '--prove', '--reproducer', repro]).status, 0);
  assert.equal(run(dir, ['dnr', 'generate', 'F1']).status, 0);
  const fix = run(dir, ['fix', '--finding', 'F1', '--apply', '--require-proof', '--reproducer', repro], 180000);
  assert.notEqual(fix.status, 0, 'a fix that does not block the exploit is refused');
  assert.match(fix.stdout + fix.stderr, /still succeeds|not proof-verified/i);
  const view = run(dir, ['dnr', 'status', 'F1']).stdout;
  assert.match(view, /\[~\] FIX\s+Fix not verified/);
  assert.match(view, /\[~\] VERIFY/);
  assert.match(view, /\[x\] DETECT/);
});

test('window: deployment history is required, and an unresolvable history is partial or unavailable, never a made-up window', () => {
  const dir = project();
  const dep = path.join(dir, 'deploys.json');
  fs.writeFileSync(dep, JSON.stringify([{ commit: 'deadbeef', deployedAt: '2024-03-05T00:00:00Z', environment: 'prod' }]));
  const r = run(dir, ['dnr', 'window', 'F1', '--deployments', dep, '--json']);
  assert.equal(r.status, 1);
  const w = JSON.parse(r.stdout);
  assert.equal(w.status, 'unavailable');
  assert.equal(w.observableWindow, null);
  assert.ok(w.unknowns.length >= 2);
});
