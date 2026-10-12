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
import { sandboxAvailable } from '../../src/sandbox/index.js';

const FIXTURES_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/proof-fabric');
const CLASSES = fs.readdirSync(FIXTURES_ROOT).filter((n) => fs.existsSync(path.join(FIXTURES_ROOT, n, 'reproducer.json')));

for (const cls of CLASSES) {
  const dir = path.join(FIXTURES_ROOT, cls);
  const reproducer = JSON.parse(fs.readFileSync(path.join(dir, 'reproducer.json'), 'utf8'));

  test(`fixture ${cls}: vulnerable implementation reaches EXPLOIT_CONFIRMED`, { skip: !sandboxAvailable() && 'no confinement backend on this host' }, async () => {
    const r = await proveFinding({
      finding: { id: reproducer.findingId, stableId: reproducer.findingId, parser: 'IR-TAINT' },
      reproducer, sourceRoot: path.join(dir, 'vulnerable'), policy: { timeoutMs: 15000 },
    });
    assert.equal(r.state, 'EXPLOIT_CONFIRMED', `${cls}: expected EXPLOIT_CONFIRMED, got ${r.state} (${r.outcome}); degradation=${r.degradation.join(',')}`);
    assert.equal(r.attempts.successes, 3);
    assert.equal(r.independentReplay.status, 'confirmed');
  });

  test(`fixture ${cls}: mitigated implementation is never EXPLOIT_CONFIRMED by the same reproducer`, { skip: !sandboxAvailable() && 'no confinement backend on this host' }, async () => {
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
