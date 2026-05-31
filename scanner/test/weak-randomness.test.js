import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateF1 } from './helpers/f1.js';
import { scanWeakRandomness } from '../src/sast/weak-randomness.js';

test('weak-rng: camelCase security carrier (newToken) fires and is classified CWE-338', () => {
  const src = "function newToken() {\n  let s = '';\n  for (let i = 0; i < 32; i++) s += Math.floor(Math.random() * 16).toString(16);\n  return s;\n}\n";
  const out = scanWeakRandomness('tok.js', src);
  assert.ok(out.length >= 1, 'Math.random in newToken() is flagged');
  assert.equal(out[0].cwe, 'CWE-338');
});

test('weak-rng: Math.random with no security context stays silent', () => {
  assert.deepEqual(scanWeakRandomness('a.js', 'const jitter = Math.random() * 100;'), []);
});

test('Weak randomness detector: vulnerable fixtures fire, clean fixtures are silent', async () => {
  await evaluateF1({
    name: 'weak-randomness',
    fixtureDir: 'weak-randomness',
    labels: [
      { file: 'vulnerable/app.js', positive: true, matcher: /Insecure Randomness.*Math\.random/i },
      { file: 'vulnerable/app.py', positive: true, matcher: /Insecure Randomness.*random/i },
      { file: 'vulnerable/app.go', positive: true, matcher: /Insecure Randomness.*rand/i },
      { file: 'clean/app.js',      positive: false, matcher: /Insecure Randomness/i },
      { file: 'clean/app.py',      positive: false, matcher: /Insecure Randomness/i },
    ],
    floors: { precision: 0.85, recall: 0.85, f1: 0.85 },
  });
});
