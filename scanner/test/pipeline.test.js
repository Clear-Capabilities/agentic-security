// 0.7.0 Feat-9: Pipeline / GH Actions integrity — F1 over labelled fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateF1 } from './helpers/f1.js';
import { scanPipeline } from '../src/sast/pipeline.js';
import { scanIaC } from '../src/engine.js';

// Note: fixture dir scoped to the parent so the `.github/workflows/` prefix is
// preserved in the relative path the detector matches against.
const LABELS = [
  { file: '.github/workflows/vuln-floating-tag.yml',     positive: true,  matcher: /floating tag/i },
  { file: '.github/workflows/vuln-write-all.yml',        positive: true,  matcher: /write-all/i },
  { file: '.github/workflows/vuln-secret-echo.yml',      positive: true,  matcher: /secret echoed/i },
  { file: '.github/workflows/vuln-script-injection.yml', positive: true,  matcher: /untrusted github\.event/i },
  { file: '.github/workflows/vuln-oidc-no-aud.yml',      positive: true,  matcher: /OIDC.*aud/i },
  { file: '.github/workflows/vuln-major-tag.yml',        positive: true,  matcher: /major-version tag/i },
  { file: '.github/workflows/safe-pinned.yml',           positive: false, matcher: /Pipeline:/i },
  { file: '.github/workflows/safe-min-perms.yml',        positive: false, matcher: /Pipeline:/i },
  { file: '.github/workflows/safe-oidc-with-aud.yml',    positive: false, matcher: /OIDC.*aud/i },
  // Stage 4 correctness audit: the rule's own `fix` text recommends piping
  // untrusted github.event values through an env var (`env: TITLE: ${{ … }}`
  // then `run: echo "$TITLE"`) instead of interpolating directly into the
  // shell — but the detector regex matches the literal `${{ github.event.* }}`
  // text anywhere in the file, including inside the safe env: assignment it
  // itself recommends. Following the tool's own advice still trips it.
  { file: '.github/workflows/safe-env-interpolation.yml', positive: false, matcher: /untrusted github\.event/i },
];

test('Pipeline integrity — F1 evaluation', async () => {
  await evaluateF1({
    name: 'Pipeline-detector',
    fixtureDir: 'pipeline-integrity',
    labels: LABELS,
    floors: { f1: 0.85, precision: 0.83, recall: 0.83 },
  });
});

test('pipeline: github.event.* piped through env: (the recommended-safe pattern) does not fire "untrusted input" — direct run: interpolation still does', () => {
  const safe = `
on: issue_comment
jobs:
  build:
    steps:
      - env:
          TITLE: \${{ github.event.issue.title }}
        run: |
          echo "Processing: $TITLE"
`;
  const safeFindings = scanPipeline('.github/workflows/x.yml', safe);
  assert.equal(safeFindings.filter(f => /untrusted github\.event/i.test(f.vuln)).length, 0,
    `expected the env: pattern to be silent; got ${JSON.stringify(safeFindings.map(f => f.vuln))}`);

  const vuln = `
on: issue_comment
jobs:
  build:
    steps:
      - run: echo "Processing: \${{ github.event.issue.title }}"
`;
  const vulnFindings = scanPipeline('.github/workflows/x.yml', vuln);
  assert.ok(vulnFindings.some(f => /untrusted github\.event/i.test(f.vuln)),
    'expected direct run: interpolation to still fire');
});

// engine.js's scanIaC carries a second, overlapping copy of the same
// github.event.* rule (different wording, same regex shape, same bug).
test('scanIaC: github.event.* piped through env: does not fire; direct run: interpolation still does', () => {
  const safe = `
on: issue_comment
jobs:
  build:
    steps:
      - env:
          TITLE: \${{ github.event.issue.title }}
        run: |
          echo "Processing: $TITLE"
`;
  const safeFindings = scanIaC('.github/workflows/x.yml', safe);
  assert.equal(safeFindings.filter(f => /untrusted github\.event/i.test(f.vuln)).length, 0,
    `expected the env: pattern to be silent; got ${JSON.stringify(safeFindings.map(f => f.vuln))}`);

  const vuln = `
on: issue_comment
jobs:
  build:
    steps:
      - run: echo "Processing: \${{ github.event.issue.title }}"
`;
  const vulnFindings = scanIaC('.github/workflows/x.yml', vuln);
  assert.ok(vulnFindings.some(f => /untrusted github\.event/i.test(f.vuln)),
    'expected direct run: interpolation to still fire');
});
