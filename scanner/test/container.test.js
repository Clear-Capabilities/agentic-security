// 0.9.0 Feat-14: Container layer scan — F1 over labelled Dockerfile fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateF1 } from './helpers/f1.js';

const LABELS = [
  { file: 'vuln-debian9.dockerfile',   positive: true,  matcher: /Container base image.*EOL/i },
  { file: 'vuln-node12.dockerfile',    positive: true,  matcher: /Container base image.*EOL/i },
  { file: 'vuln-python27.dockerfile',  positive: true,  matcher: /Container base image.*EOL/i },
  { file: 'vuln-floating.dockerfile',  positive: true,  matcher: /Container base image.*floating/i },
  { file: 'safe-modern.dockerfile',    positive: false, matcher: /Container base image/i },
  { file: 'safe-pinned.dockerfile',    positive: false, matcher: /Container base image/i },
];

test('Container scan — F1 evaluation', async () => {
  await evaluateF1({
    name: 'Container-detector',
    fixtureDir: 'container',
    labels: LABELS,
    floors: { f1: 0.85, precision: 0.83, recall: 0.83 },
  });
});

// Stage 4 correctness audit: sca/container.js parses `apt-get install`/
// `apk add` lines from a Dockerfile and stashes the packages on
// `findings[0]._containerPackages` — its own comment says "so the engine
// can consume them downstream" — but nothing in engine.js ever read that
// field. Dockerfile-declared OS packages never reached scan.components or
// scan.supplyChain, so they were never checked against OSV even though the
// extraction logic to find them already existed and ran on every scan.
test('engine wiring: apt-get-installed packages in a Dockerfile reach scan.components', async () => {
  const { runFullScan } = await import('../src/engine.js');
  const fileContents = {
    'Dockerfile': [
      'FROM debian:12-slim',
      'RUN apt-get update && apt-get install -y curl=7.88.1-10 openssl=3.0.11-1',
    ].join('\n'),
  };
  const result = await runFullScan({ fileContents, scanRoot: '/tmp/agentic-security-container-pkg-wiring-test' });
  const names = (result.components || []).map(c => c.name);
  assert.ok(names.includes('curl'), `expected curl to reach scan.components; got ${names.join(', ')}`);
  assert.ok(names.includes('openssl'), `expected openssl to reach scan.components; got ${names.join(', ')}`);
});
