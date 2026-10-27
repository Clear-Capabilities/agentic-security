#!/usr/bin/env node
// Measures the Exploit Proof Fabric's PRD 1 success metrics on the fixture corpus (scanner/test/fixtures/proof-fabric):
//   * reproduction success on the vulnerable fixtures the host can run (target: at least 90%);
//   * false EXPLOIT_CONFIRMED on the mitigated fixtures (target: 0);
//   * a hanging reproducer is reported as degraded / incomplete evidence, never as "not exploitable" (target: 100% of timeouts);
//   * proof timing is reported on its own (`timing.proofMs`), independent of any scan.
//
//   node bench/proof-fabric/measure.mjs [--rounds 3] [--out bench/proof-fabric/RESULT.json] [--require-container] [--expect-mode <mode>] [--check <committed.json>]
//
//   --require-container   run every proof in a container and treat a missing engine or image as a failure, never a fallback to local confinement
//   --expect-mode <mode>  fail unless every measured run executed in <mode> (`container` or `local-confined`), so a leg named for one environment
//                         cannot quietly measure another
//   --check <file>        compare to a committed result and fail on a lower reproduction rate, any false confirmation, a timeout that was not
//                         degraded, or a class that was measured then and is not now
//
// Fixtures whose language cannot run on this host (no JDK, no .NET) are listed as `unsupported`, never counted as passes or failures.
// This measures the fixture corpus, which the authors wrote: it is a regression and sanity measure of the mechanism, not an
// estimate of how often a real finding can be proven.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SCANNER = path.join(ROOT, 'scanner/src/posture/proof-fabric');
const { proveFinding } = await import(path.join(SCANNER, 'orchestrator.js'));
const { languageSupport } = await import(path.join(SCANNER, 'runner.js'));
const { sandboxAvailable, detectBackend } = await import(path.join(ROOT, 'scanner/src/sandbox/index.js'));

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i === -1 ? d : process.argv[i + 1]; };
const ROUNDS = Math.max(1, Number(arg('rounds', 3)));
const OUT = arg('out', null);
const REQUIRE_CONTAINER = process.argv.includes('--require-container');
const EXPECT_MODE = arg('expect-mode', REQUIRE_CONTAINER ? 'container' : null);
const CHECK = arg('check', null);
const FIX = path.join(ROOT, 'scanner/test/fixtures/proof-fabric');
const classes = fs.readdirSync(FIX).filter((n) => fs.existsSync(path.join(FIX, n, 'reproducer.json'))).sort();
if (!REQUIRE_CONTAINER && !sandboxAvailable()) { console.error('no confinement backend on this host: nothing can be measured'); process.exit(2); }

// What the proofs actually ran in. A leg named for one environment must not quietly measure another, so the modes are counted from the results
// themselves, and for a container run the engine and the images (by id) are recorded: two runs with the same image id ran on the same base.
function environmentOf(all) {
  const modes = {};
  for (const r of all) modes[r.mode ?? 'unknown'] = (modes[r.mode ?? 'unknown'] ?? 0) + 1;
  const env = { modes };
  if (REQUIRE_CONTAINER) {
    const engine = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8', timeout: 15000 });
    env.engine = { name: 'docker', serverVersion: engine.status === 0 ? engine.stdout.trim() : null };
    env.images = {};
    for (const lang of [...new Set(all.map((r) => r.lang))].sort()) {
      const image = ({ javascript: 'node:24-slim', typescript: 'node:24-slim', python: 'python:3-slim', java: 'eclipse-temurin:21', c: 'gcc:latest', cpp: 'gcc:latest', csharp: 'mcr.microsoft.com/dotnet/sdk:8.0', haskell: 'haskell:9' })[lang];
      const id = image ? spawnSync('docker', ['image', 'inspect', '--format', '{{.Id}}', image], { encoding: 'utf8', timeout: 15000 }) : null;
      env.images[lang] = { image: image ?? null, id: id && id.status === 0 ? id.stdout.trim() : null };
    }
  }
  return env;
}

const rows = []; const skipped = [];
for (const cls of classes) {
  const dir = path.join(FIX, cls);
  const reproducer = JSON.parse(fs.readFileSync(path.join(dir, 'reproducer.json'), 'utf8'));
  // inside a container the toolchain is the image's, not the host's
  const sup = REQUIRE_CONTAINER ? { supported: true } : languageSupport(reproducer.lang);
  if (!sup.supported) { skipped.push({ class: cls, lang: reproducer.lang, reason: sup.reason }); continue; }
  // The haskell:9 image is wired (runner.js) but its toolchain layout for a non-root user has not been run against a real engine, so the
  // container leg does not claim it until someone sets AGENTIC_SECURITY_PROOF_CONTAINER_HASKELL=1 and the leg passes.
  if (REQUIRE_CONTAINER && reproducer.lang === 'haskell' && process.env.AGENTIC_SECURITY_PROOF_CONTAINER_HASKELL !== '1') { skipped.push({ class: cls, lang: reproducer.lang, reason: 'the haskell:9 image path (runner.js, container.js CONTAINER_PATH includes /opt/ghc/bin) has never been run against a real container engine, so the non-root toolchain layout (PATH, HOME, writable ghc/cabal dirs under --read-only) is unconfirmed; set AGENTIC_SECURITY_PROOF_CONTAINER_HASKELL=1 with the image present locally (docker pull haskell:9) to include it' }); continue; }
  if (reproducer.network === 'callback' && (REQUIRE_CONTAINER || detectBackend() !== 'userspace')) { skipped.push({ class: cls, lang: reproducer.lang, reason: REQUIRE_CONTAINER ? 'a container has no network, so a reproducer that needs the loopback callback listener cannot run in one' : `mediated network is unsupported on the ${detectBackend()} backend` }); continue; }
  for (let r = 0; r < ROUNDS; r++) {
    for (const side of ['vulnerable', 'mitigated']) {
      const res = await proveFinding({ finding: { id: reproducer.findingId, stableId: reproducer.findingId, parser: 'IR-TAINT' }, reproducer, sourceRoot: path.join(dir, side), policy: { requireContainer: REQUIRE_CONTAINER, timeoutMs: 20000 } });
      if (side === 'vulnerable' && res.state !== 'EXPLOIT_CONFIRMED') process.stderr.write(`unconfirmed ${cls} (${res.outcome}): ${JSON.stringify({ degradation: res.degradation, attempts: res.attempts?.detail?.slice(0, 1) })}\n`);
      rows.push({ class: cls, lang: reproducer.lang, side, round: r, mode: res.environment?.mode ?? null, state: res.state, confirmed: res.state === 'EXPLOIT_CONFIRMED', successes: res.attempts.successes, proofMs: res.timing.proofMs });
    }
  }
}

// timeouts: a reproducer that never returns
const hang = { schema: 'agentic-security/reproducer', version: 1, findingId: 'bench-hang', lang: 'javascript', files: { 'h.mjs': 'setInterval(() => {}, 1000);' }, run: ['{{NODE}}', 'h.mjs'], oracle: { type: 'command_execution', params: { canary: 'command' } }, network: 'none' };
const hangDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proof-hang-'));
const timeouts = [];
for (let i = 0; i < ROUNDS; i++) {
  const res = await proveFinding({ finding: { id: 'bench-hang', stableId: 'bench-hang', parser: 'IR-TAINT' }, reproducer: hang, sourceRoot: hangDir, policy: { timeoutMs: 1500 } });
  timeouts.push({ state: res.state, degraded: res.degradation.some((d) => /timed-out|incomplete/.test(d)), reportedAsNegative: res.state === 'NOT_EXPLOITABLE' || res.outcome === 'not-exploitable', degradation: res.degradation });
}
fs.rmSync(hangDir, { recursive: true, force: true });

const vuln = rows.filter((r) => r.side === 'vulnerable'); const mit = rows.filter((r) => r.side === 'mitigated');
const pct = (n, d) => (d ? Number(((n / d) * 100).toFixed(1)) : null);
const result = {
  schema: 'agentic-security/proof-fabric-measurement', measuredAt: new Date().toISOString(), rounds: ROUNDS,
  host: { platform: process.platform, arch: process.arch, node: process.version, backend: REQUIRE_CONTAINER ? 'container' : detectBackend() },
  environment: environmentOf(rows),
  classesMeasured: [...new Set(rows.map((r) => r.class))], classesSkipped: skipped,
  reproduction: { runs: vuln.length, confirmed: vuln.filter((r) => r.confirmed).length, ratePercent: pct(vuln.filter((r) => r.confirmed).length, vuln.length), targetPercent: 90 },
  falseConfirmations: { runs: mit.length, confirmed: mit.filter((r) => r.confirmed).length, target: 0 },
  timeouts: { runs: timeouts.length, representedAsDegraded: timeouts.filter((t) => t.degraded && !t.reportedAsNegative).length, ratePercent: pct(timeouts.filter((t) => t.degraded && !t.reportedAsNegative).length, timeouts.length), targetPercent: 100 },
  proofTiming: { medianMs: [...vuln.map((r) => r.proofMs)].sort((a, b) => a - b)[Math.floor(vuln.length / 2)] ?? null, maxMs: Math.max(0, ...vuln.map((r) => r.proofMs)), note: 'reported by the proof result itself (timing.proofMs), independent of scan time' },
  perClass: Object.fromEntries([...new Set(rows.map((r) => r.class))].map((c) => [c, { vulnerableConfirmed: `${vuln.filter((r) => r.class === c && r.confirmed).length}/${vuln.filter((r) => r.class === c).length}`, mitigatedConfirmed: `${mit.filter((r) => r.class === c && r.confirmed).length}/${mit.filter((r) => r.class === c).length}` }])),
  verdict: {
    reproduction: vuln.length > 0 && vuln.filter((r) => r.confirmed).length / vuln.length >= 0.9 ? 'met' : 'NOT MET',
    falseConfirmations: mit.every((r) => !r.confirmed) ? 'met' : 'NOT MET',
    timeouts: timeouts.every((t) => t.degraded && !t.reportedAsNegative) ? 'met' : 'NOT MET',
  },
};
// the environment gate: every run must have executed in the mode the leg is named for
const wrongMode = EXPECT_MODE ? rows.filter((r) => r.mode !== EXPECT_MODE).length : 0;
result.verdict.environment = EXPECT_MODE ? (wrongMode === 0 && rows.length > 0 ? 'met' : 'NOT MET') : 'not asserted';
if (EXPECT_MODE) result.environment.expected = EXPECT_MODE;

// comparison to a committed result: a worse number fails, a better one passes
const problems = [];
if (CHECK) {
  const base = JSON.parse(fs.readFileSync(path.resolve(ROOT, CHECK), 'utf8'));
  if (result.reproduction.ratePercent === null || result.reproduction.ratePercent < base.reproduction.ratePercent) problems.push(`reproduction ${result.reproduction.ratePercent}% is below the committed ${base.reproduction.ratePercent}%`);
  if (result.falseConfirmations.confirmed > 0) problems.push(`${result.falseConfirmations.confirmed} false confirmation(s) on mitigated fixtures`);
  if (result.timeouts.ratePercent !== 100) problems.push(`timeouts represented as degraded: ${result.timeouts.ratePercent}%`);
  for (const c of base.classesMeasured) if (!result.classesMeasured.includes(c)) problems.push(`class ${c} was measured in the committed result and is not now`);
  if (problems.length) result.verdict.comparison = 'NOT MET'; else result.verdict.comparison = 'met';
}
const text = `${JSON.stringify(result, null, 2)}\n`;
if (OUT) fs.writeFileSync(path.resolve(ROOT, OUT), text);
process.stdout.write(text);
for (const p of problems) process.stderr.write(`proof-fabric measurement: ${p}\n`);
process.exit(Object.values(result.verdict).every((v) => v === 'met' || v === 'not asserted') ? 0 : 1);
