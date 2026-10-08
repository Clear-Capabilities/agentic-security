// CI hang protection, and the shape of the emulated-NixOS retry.
//
// A hosted job with no `timeout-minutes` inherits GitHub's six hour default, so a stalled download holds a runner for six hours and
// reports nothing: the Neovim install step once hung for 55 minutes on exactly this. These tests pin, from the workflow text itself:
//   - every job has a deadline;
//   - every step that downloads or installs over the network has its own, shorter, deadline;
//   - every hand-written download is bounded per attempt and retried a bounded number of times;
//   - the Nix installer, which cannot be wrapped in a shell loop, is attempted at most twice with both attempts visible;
//   - the emulated aarch64 guest is run at most twice, the first failure is kept and announced, and a failed second attempt fails the job.
// A test that only passes on today's workflows would rot, so each rule is also exercised on a deliberately bad snippet.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as yaml from 'js-yaml';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const WF_DIR = join(ROOT, '.github', 'workflows');
const WORKFLOWS = readdirSync(WF_DIR).filter((f) => f.endsWith('.yml')).sort().map((f) => ({ file: f, doc: yaml.load(readFileSync(join(WF_DIR, f), 'utf8')) }));

const NETWORK_RUN = /\b(npm (ci|install)|apt-get|curl|wget|docker (run|pull)|pip3? install|cabal (update|install)|nix (build|develop)|gradlew)\b/;
const NETWORK_USES = /^(cachix\/install-nix-action|haskell-actions\/setup|actions\/setup-java|gradle\/actions\/|actions\/(upload|download)-artifact)/;

/** Pure: the problems with one workflow document. Used on the real files and on bad snippets. */
export function hangProblems(file, doc) {
  const problems = [];
  for (const [name, job] of Object.entries(doc.jobs || {})) {
    if (job.uses) continue; // a reusable-workflow call carries its deadline in the called workflow
    if (!Number.isInteger(job['timeout-minutes'])) problems.push(`${file}: job "${name}" has no timeout-minutes`);
    for (const step of job.steps || []) {
      const label = `${file}: job "${name}", step "${step.name || String(step.run || step.uses).split('\n')[0].slice(0, 50)}"`;
      const run = String(step.run || '');
      const uses = String(step.uses || '');
      const network = NETWORK_RUN.test(run) || NETWORK_USES.test(uses);
      if (network && !Number.isInteger(step['timeout-minutes'])) problems.push(`${label} touches the network with no timeout-minutes`);
      for (const line of run.split('\n').filter((l) => /\bcurl\b/.test(l) && !/^\s*#/.test(l))) {
        const stmt = run.slice(run.indexOf(line)).split(/\n\s*\n/)[0];
        if (!/--max-time\b/.test(stmt) || !/--retry\b/.test(stmt)) problems.push(`${label} has a curl with no --max-time/--retry`);
      }
      if (/\bapt-get\b/.test(run) && !(/for attempt in/.test(run) && /\btimeout \d+ sudo apt-get/.test(run))) {
        problems.push(`${label} runs apt-get without a bounded retry loop`);
      }
    }
  }
  return problems;
}

test('every job in every workflow has a deadline, and every network step has its own', () => {
  const all = WORKFLOWS.flatMap((w) => hangProblems(w.file, w.doc));
  assert.deepEqual(all, []);
});

test('the rules catch what they exist to catch', () => {
  const bad = yaml.load(`
jobs:
  hung:
    runs-on: ubuntu-latest
    steps:
      - name: Install Neovim
        run: sudo apt-get update && sudo apt-get install -y neovim
      - run: npm ci
      - run: curl -sSL -o x https://example.invalid/x
      - uses: cachix/install-nix-action@v31
`);
  const p = hangProblems('bad.yml', bad);
  assert.ok(p.some((x) => /job "hung" has no timeout-minutes/.test(x)));
  assert.ok(p.some((x) => /Install Neovim.*no timeout-minutes/.test(x)));
  assert.ok(p.some((x) => /apt-get without a bounded retry loop/.test(x)));
  assert.ok(p.some((x) => /npm ci.*no timeout-minutes/.test(x)));
  assert.ok(p.some((x) => /curl with no --max-time\/--retry/.test(x)));
  assert.ok(p.some((x) => /install-nix-action.*no timeout-minutes/.test(x)));
  const good = yaml.load(`
jobs:
  fine:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Install
        timeout-minutes: 5
        run: |
          for attempt in 1 2 3; do
            timeout 120 sudo apt-get install -y neovim && exit 0
          done
          exit 1
      - run: curl -sSL --max-time 60 --retry 3 -o x https://example.invalid/x
        timeout-minutes: 3
`);
  assert.deepEqual(hangProblems('good.yml', good), []);
});

test('npm installs in CI have a bounded request deadline and retry count', () => {
  for (const f of ['ci.yml', 'bench.yml', 'release.yml', 'sard-full-test-split.yml', 'dependency-currency.yml']) {
    const env = WORKFLOWS.find((w) => w.file === f).doc.env || {};
    assert.ok(Number(env.NPM_CONFIG_FETCH_TIMEOUT) > 0 && Number(env.NPM_CONFIG_FETCH_TIMEOUT) <= 120000, `${f} must set a request deadline`);
    assert.ok(Number(env.NPM_CONFIG_FETCH_RETRIES) >= 2 && Number(env.NPM_CONFIG_FETCH_RETRIES) <= 10, `${f} must set a bounded retry count`);
  }
});

test('every Nix installer is attempted at most twice, with attempt 2 conditional on attempt 1 not succeeding', () => {
  for (const w of WORKFLOWS) {
    for (const [name, job] of Object.entries(w.doc.jobs || {})) {
      const installs = (job.steps || []).filter((s) => String(s.uses || '').startsWith('cachix/install-nix-action'));
      if (installs.length === 0) continue;
      assert.equal(installs.length, 2, `${w.file}:${name} must have exactly two install attempts`);
      const [one, two] = installs;
      assert.equal(one['continue-on-error'], true, `${w.file}:${name} attempt 1 must not fail the job on its own`);
      assert.ok(one.id, `${w.file}:${name} attempt 1 needs an id for attempt 2 to depend on`);
      assert.match(String(two.if), new RegExp(`steps\\.${one.id}\\.outcome != 'success'`), `${w.file}:${name} attempt 2 must run only when attempt 1 did not succeed`);
      assert.notEqual(two['continue-on-error'], true, `${w.file}:${name} a failed attempt 2 must fail the job`);
      for (const s of installs) assert.ok(Number.isInteger(s['timeout-minutes']) && s['timeout-minutes'] <= 15, `${w.file}:${name} installer attempts need a short deadline`);
    }
  }
});

test('job names that branch protection and the release gate know are unchanged', () => {
  const tiers = JSON.parse(readFileSync(join(ROOT, '.github', 'required-checks.json'), 'utf8'));
  const names = new Set();
  for (const w of WORKFLOWS) for (const [key, job] of Object.entries(w.doc.jobs || {})) names.add(job.name ? job.name : key);
  const known = [...(tiers.blocking || []), ...(tiers.informational || [])];
  for (const n of known) {
    const base = n.replace(/ \(.*\)$/, '');
    assert.ok([...names].some((x) => x === n || x.startsWith(base)), `required check "${n}" no longer corresponds to any job`);
  }
});

// ------------------------------------------------------------ emulated retry
const CI = WORKFLOWS.find((w) => w.file === 'ci.yml').doc;
const REMOTE_TEXT = readFileSync(join(WF_DIR, 'verify-remote.yml'), 'utf8');

test('the emulated aarch64 guest runs at most twice, and a retry is never silent', () => {
  const steps = CI.jobs['nixos-runtime'].steps;
  const one = steps.find((s) => s.id === 'aarch64_try1');
  const two = steps.find((s) => s.id === 'aarch64_try2');
  assert.ok(one && two, 'both attempts exist as named steps');
  assert.equal(one['continue-on-error'], true);
  assert.notEqual(two['continue-on-error'], true, 'a failed second attempt must fail the job');
  assert.match(two.if, /steps\.aarch64_try1\.outcome == 'failure'/);
  assert.equal(steps.filter((s) => /nixos-host-aarch64-emulated/.test(String(s.run || ''))).length, 2, 'exactly two builds of the emulated check');
  assert.match(two.run, /::warning/, 'the retry prints a warning annotation');
  assert.match(two.run, /GITHUB_STEP_SUMMARY/, 'the retry is written to the job summary');
  assert.match(two.run, /tail -n \d+ \/tmp\/aarch64-attempt-1\.log/, 'the first failure is printed again next to the second attempt');
  const keep = steps.filter((s) => String(s.uses || '').startsWith('actions/upload-artifact') && /aarch64/.test(s.with?.name || ''));
  assert.equal(keep.length, 2, 'the log of each failed attempt is kept');
  assert.match(keep[0].if, /aarch64_try1\.outcome == 'failure'/);
  assert.match(keep[1].if, /aarch64_try2\.outcome == 'failure'/);
  assert.ok(CI.jobs['nixos-runtime']['timeout-minutes'] <= 360, 'a hosted job is capped at six hours; a larger value would be silently ignored');
  assert.ok(CI.jobs['nixos-runtime']['timeout-minutes'] >= one['timeout-minutes'] + two['timeout-minutes'], 'the job deadline must cover both attempts');
});

test('the remote verification leg keeps the first failed attempt and records the second attempt as the leg result', () => {
  const doc = yaml.load(REMOTE_TEXT);
  const step = doc.jobs['nixos-aarch64-emulated'].steps.find((s) => /nixos-host-aarch64-emulated/.test(String(s.run || '')));
  const body = step.run;
  assert.equal((body.match(/nix build \.#checks\.x86_64-linux\.nixos-host-aarch64-emulated/g) || []).length, 2, 'at most two attempts');
  assert.match(body, /build-aarch64-attempt1\.log/);
  assert.match(body, /aarch64\.attempt1\.exit/);
  assert.match(body, /::warning/);
  assert.match(body, /timeout 150m nix build/);
  assert.match(body, /echo \$rc > "\$OUT\/aarch64\.exit"/, 'the recorded exit code is the final attempt, which can only be 0 if attempt 2 passed');
  assert.ok(doc.jobs['nixos-aarch64-emulated']['timeout-minutes'] <= 360);
  assert.ok(step['timeout-minutes'] >= 300, 'the step deadline covers both 150 minute attempts');
});

// -------------------------------------------------- emulated guest robustness
const FLAKE = readFileSync(join(ROOT, 'flake.nix'), 'utf8');
const SUITE = readFileSync(join(ROOT, 'scanner', 'test', 'nix', 'nixos-host-runtime.test.js'), 'utf8');

test('the NixOS suite scales every timeout through one clamped factor, and the native default is the original budgets', () => {
  assert.match(SUITE, /AGENTIC_SECURITY_TEST_TIMEOUT_SCALE/);
  assert.match(SUITE, /rawScale >= 1 && rawScale <= 20 \? rawScale : 1/, 'unset, invalid or out-of-range scales fall back to 1');
  const code = SUITE.replace(/\/\/.*$/gm, '');
  const literals = [...code.matchAll(/(?:timeout|timeoutMs)(?::|\s*=)\s*(\d[\d_]*)/g)].map((m) => m[0]);
  assert.deepEqual(literals, [], `every timeout in the suite must go through T(): ${literals.join(', ')}`);
  for (const original of ['T(900000)', 'T(300000)', 'T(20000)', 'T(240000)']) assert.ok(code.includes(original), `${original} keeps the original budget at scale 1`);
});

test('the emulated NixOS guest gets bounded waits, more resources and a scale factor, and the native guest is unchanged', () => {
  assert.match(FLAKE, /emulated = guest != system;/);
  assert.match(FLAKE, /scale = 6;/);
  assert.ok(6 <= 20, 'the flake scale is inside the suite clamp');
  assert.match(FLAKE, /succeedTimeout = if emulated then ", timeout=3600" else "";/, 'native commands get no new argument');
  assert.match(FLAKE, /daemonWait = if emulated then .*nix-daemon\.socket.* else "";/, 'the daemon wait is emulated-only');
  assert.match(FLAKE, /scalePrefix = if emulated then "AGENTIC_SECURITY_TEST_TIMEOUT_SCALE=\$\{toString scale\} " else "";/);
  assert.match(FLAKE, /suiteTimeout = if emulated then 10800 else 5400;/, 'native keeps its 5400 s bound');
  assert.match(FLAKE, /virtualisation\.memorySize = if emulated then 4096 else 3072;/);
  assert.match(FLAKE, /virtualisation\.cores = nixpkgs\.lib\.mkIf emulated 2;/, 'cores are only set for the emulated guest');
  assert.match(FLAKE, /wait_for_unit\("multi-user\.target", timeout=3600\)/, 'the boot wait is unchanged');
  assert.match(FLAKE, /range\(180\)/, 'the patched driver boot wait is unchanged');
  // every guest command in the test script carries the (possibly empty) bound
  const script = FLAKE.slice(FLAKE.indexOf("testScript = ''"), FLAKE.indexOf("copy_from_machine"));
  const succeeds = script.split('\n').filter((l) => /machine\.succeed\(/.test(l));
  assert.ok(succeeds.length >= 5);
  for (const l of succeeds) assert.match(l, /\$\{succeedTimeout\}\)\s*$/, `unbounded guest command: ${l.trim()}`);
});
