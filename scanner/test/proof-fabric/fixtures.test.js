// Runs the proof-fabric's own fixture corpus (test/fixtures/proof-fabric/<class>/{vulnerable,mitigated}) through the
// real confined runner. A vulnerable implementation must reach EXPLOIT_CONFIRMED; its mitigated sibling must not
// advance past REPRODUCER_GENERATED for the same reproducer. All execution happens inside the existing confined
// sandbox (src/sandbox), with no outbound network except the runner-owned loopback listener for the ssrf case.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { proveFinding } from '../../src/posture/proof-fabric/orchestrator.js';
import { sandboxAvailable, detectBackend } from '../../src/sandbox/index.js';
import { languageSupport } from '../../src/posture/proof-fabric/runner.js';
import { skipUnlessRuns } from '../helpers/toolchain-probe.js';

const FIXTURES_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/proof-fabric');
const CLASSES = fs.readdirSync(FIXTURES_ROOT).filter((n) => fs.existsSync(path.join(FIXTURES_ROOT, n, 'reproducer.json')));

for (const cls of CLASSES) {
  const dir = path.join(FIXTURES_ROOT, cls);
  const reproducer = JSON.parse(fs.readFileSync(path.join(dir, 'reproducer.json'), 'utf8'));
  // Mediated network (the runner's own loopback callback listener) needs the userspace backend specifically —
  // runner.js refuses `network: 'callback'` on anything else, and that is correct: mediated network is documented
  // as unsupported on the Linux namespace backend (root CLAUDE.md, src/sandbox/CLAUDE.md). A callback-mode fixture
  // genuinely cannot reach EXPLOIT_CONFIRMED there, so the test must skip, loudly, rather than fail or pass vacuously.
  const needsCallback = reproducer.network === 'callback';
  const lang = languageSupport(reproducer.lang);
  const skip = !sandboxAvailable() ? 'no confinement backend on this host'
    : !lang.supported ? `${reproducer.lang} cannot run on this host (${lang.reason}); the runner reports it as unsupported, never as a pass`
    : (needsCallback && detectBackend() !== 'userspace') ? `mediated network (network: 'callback') is unsupported on the ${detectBackend()} backend`
    : (['python', 'java'].includes(reproducer.lang) ? skipUnlessRuns(reproducer.lang) : false);

  test(`fixture ${cls}: vulnerable implementation reaches EXPLOIT_CONFIRMED`, { skip }, async () => {
    const r = await proveFinding({
      finding: { id: reproducer.findingId, stableId: reproducer.findingId, parser: 'IR-TAINT' },
      reproducer, sourceRoot: path.join(dir, 'vulnerable'), policy: { timeoutMs: 15000 },
    });
    assert.equal(r.state, 'EXPLOIT_CONFIRMED', `${cls}: expected EXPLOIT_CONFIRMED, got ${r.state} (${r.outcome}); degradation=${r.degradation.join(',')}`);
    assert.equal(r.attempts.successes, 3);
    assert.equal(r.independentReplay.status, 'confirmed');
  });

  test(`fixture ${cls}: mitigated implementation is never EXPLOIT_CONFIRMED by the same reproducer`, { skip }, async () => {
    const r = await proveFinding({
      finding: { id: reproducer.findingId, stableId: reproducer.findingId, parser: 'IR-TAINT' },
      reproducer, sourceRoot: path.join(dir, 'mitigated'), policy: { timeoutMs: 15000 },
    });
    assert.notEqual(r.state, 'EXPLOIT_CONFIRMED');
    assert.notEqual(r.outcome, 'exploit-confirmed');
  });
}

test('fixture corpus covers the PRD-required classes', () => {
  const required = ['command-injection', 'path-traversal', 'ssrf', 'insecure-deserialization', 'unsafe-file-write', 'auth-bypass', 'sql-injection', 'buffer-overflow'];
  for (const r of required) assert.ok(CLASSES.includes(r), `missing fixture class: ${r}`);
});
