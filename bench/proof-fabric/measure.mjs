#!/usr/bin/env node
// Measures the Exploit Proof Fabric's PRD 1 success metrics on the fixture corpus (scanner/test/fixtures/proof-fabric):
//   * reproduction success on the vulnerable fixtures the host can run (target: at least 90%);
//   * false EXPLOIT_CONFIRMED on the mitigated fixtures (target: 0);
//   * a hanging reproducer is reported as degraded / incomplete evidence, never as "not exploitable" (target: 100% of timeouts);
//   * proof timing is reported on its own (`timing.proofMs`), independent of any scan.
//
//   node bench/proof-fabric/measure.mjs [--rounds 3] [--out bench/proof-fabric/RESULT.json]
//
// Fixtures whose language cannot run on this host (no JDK, no .NET) are listed as `unsupported`, never counted as passes or failures.
// This measures the fixture corpus, which the authors wrote: it is a regression and sanity measure of the mechanism, not an
// estimate of how often a real finding can be proven.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SCANNER = path.join(ROOT, 'scanner/src/posture/proof-fabric');
const { proveFinding } = await import(path.join(SCANNER, 'orchestrator.js'));
const { languageSupport } = await import(path.join(SCANNER, 'runner.js'));
const { sandboxAvailable, detectBackend } = await import(path.join(ROOT, 'scanner/src/sandbox/index.js'));

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i === -1 ? d : process.argv[i + 1]; };
const ROUNDS = Math.max(1, Number(arg('rounds', 3)));
const OUT = arg('out', null);
const FIX = path.join(ROOT, 'scanner/test/fixtures/proof-fabric');
const classes = fs.readdirSync(FIX).filter((n) => fs.existsSync(path.join(FIX, n, 'reproducer.json'))).sort();
if (!sandboxAvailable()) { console.error('no confinement backend on this host: nothing can be measured'); process.exit(2); }

const rows = []; const skipped = [];
for (const cls of classes) {
  const dir = path.join(FIX, cls);
  const reproducer = JSON.parse(fs.readFileSync(path.join(dir, 'reproducer.json'), 'utf8'));
  const sup = languageSupport(reproducer.lang);
  if (!sup.supported) { skipped.push({ class: cls, lang: reproducer.lang, reason: sup.reason }); continue; }
  if (reproducer.network === 'callback' && detectBackend() !== 'userspace') { skipped.push({ class: cls, lang: reproducer.lang, reason: `mediated network is unsupported on the ${detectBackend()} backend` }); continue; }
  for (let r = 0; r < ROUNDS; r++) {
    for (const side of ['vulnerable', 'mitigated']) {
      const res = await proveFinding({ finding: { id: reproducer.findingId, stableId: reproducer.findingId, parser: 'IR-TAINT' }, reproducer, sourceRoot: path.join(dir, side), policy: { timeoutMs: 20000 } });
      rows.push({ class: cls, lang: reproducer.lang, side, round: r, state: res.state, confirmed: res.state === 'EXPLOIT_CONFIRMED', successes: res.attempts.successes, proofMs: res.timing.proofMs });
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
  host: { platform: process.platform, arch: process.arch, node: process.version, backend: detectBackend() },
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
const text = `${JSON.stringify(result, null, 2)}\n`;
if (OUT) fs.writeFileSync(path.resolve(ROOT, OUT), text);
process.stdout.write(text);
process.exit(Object.values(result.verdict).every((v) => v === 'met') ? 0 : 1);
