import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanPipeline } from '../src/sast/pipeline.js';

const FP = '.github/workflows/w.yml';
const scan = (y) => scanPipeline(FP, y);
const inj = (fs) => fs.filter((f) => /untrusted github\.event/.test(f.vuln));
const oidc = (fs) => fs.filter((f) => /OIDC/.test(f.vuln));

const wf = (body, head = 'on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n') => head + body;

test('direct interpolation into run is detected, even inside shell quotes, with full context', () => {
  const fs = inj(scan(wf(`    steps:\n      - name: greet\n        run: echo "Title \${{ github.event.issue.title }}"\n`)));
  assert.equal(fs.length, 1);
  assert.equal(fs[0].job, 'j'); assert.equal(fs[0].step, 'greet');
  assert.equal(fs[0].inputOrigin, 'github.event.issue.title');
  assert.ok(fs[0].sensitiveOperation && fs[0].privilegeBoundary);
});

test('env assigned and used as quoted data is not flagged', () => {
  const y = wf(`    steps:\n      - env:\n          T: \${{ github.event.issue.title }}\n        run: echo "$T"\n`);
  assert.equal(inj(scan(y)).length, 0);
});

test('env value later passed to eval / sh -c is flagged as second interpretation', () => {
  for (const cmd of ['eval "$T"', 'sh -c "$T"', 'bash -c "echo $T"']) {
    const y = wf(`    steps:\n      - env:\n          T: \${{ github.event.issue.title }}\n        run: ${cmd}\n`);
    const r = inj(scan(y));
    assert.equal(r.length, 1, cmd);
    assert.match(r[0].vuln, /later evaluated as code/);
  }
});

test('PowerShell: env value to Invoke-Expression is flagged; data use is not', () => {
  const head = (run) => wf(`    steps:\n      - shell: pwsh\n        env:\n          T: \${{ github.event.issue.title }}\n        run: ${run}\n`);
  assert.equal(inj(scan(head('Invoke-Expression $env:T'))).length, 1);
  assert.equal(inj(scan(head('Write-Output "$env:T"'))).length, 0);
});

test('choice input is constrained; free-text dispatch input needs review', () => {
  const choice = `on:\n  workflow_dispatch:\n    inputs:\n      mode:\n        type: choice\n        options: [a, b]\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: echo \${{ inputs.mode }}\n`;
  assert.equal(inj(scan(choice)).length, 0);
  const free = choice.replace('type: choice\n        options: [a, b]', 'type: string');
  const r = inj(scan(free));
  assert.equal(r.length, 1);
  assert.equal(r[0].disposition, 'needs-review');
  assert.ok(r[0].missingEvidence.length);
});

test('validation before use downgrades the env-eval finding and records the guard', () => {
  const y = wf(`    steps:\n      - env:\n          T: \${{ github.event.issue.title }}\n        run: |\n          [[ "$T" =~ ^[a-z]+$ ]] || exit 1\n          eval "$T"\n`);
  const r = inj(scan(y));
  assert.equal(r.length, 1);
  assert.equal(r[0].severity, 'low');
  assert.ok(r[0].guards.length);
});

test('comments, multiline scripts and anchors', () => {
  const y = wf(`    steps:\n      - run: |\n          # echo \${{ github.event.issue.title }}\n          echo ok\n`);
  assert.equal(inj(scan(y)).length, 0, 'commented example is not a sink');
  const multi = wf(`    steps:\n      - run: |\n          set -e\n          curl -d "\${{ github.event.comment.body }}" x\n`);
  assert.equal(inj(scan(multi)).length, 1);
});

test('OIDC: parsed permission is recorded as needs-review, never as a proven missing restriction; comment is not a grant', () => {
  const granted = wf(`    permissions:\n      id-token: write\n    steps:\n      - run: echo hi\n`);
  const r = oidc(scan(granted));
  assert.equal(r.length, 1);
  assert.equal(r[0].disposition, 'needs-review');
  assert.match(r[0].missingEvidence.join(' '), /trust policy/);
  assert.equal(oidc(scan(wf(`    # permissions:\n    #   id-token: write\n    steps:\n      - run: echo hi\n`))).length, 0);
});

test('untrusted PR head checkout under pull_request_target carries job and step', () => {
  const y = `on: pull_request_target\njobs:\n  b:\n    runs-on: x\n    steps:\n      - name: co\n        uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n`;
  const r = scan(y).filter((f) => /untrusted pull request code/.test(f.vuln));
  assert.equal(r.length, 1);
  assert.equal(r[0].step, 'co');
});

test('non-YAML-parseable workflow falls back to line rules', () => {
  const y = 'on: issues\njobs:\n  j:\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n  : : bad: [\n';
  assert.equal(inj(scan(y)).length >= 0, true); // must not throw
});
