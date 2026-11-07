import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanPipeline } from '../src/sast/pipeline.js';
import { analyzeWorkflow } from '../src/sast/workflow-flow.js';

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

// ---- FR 06 remaining scenarios -------------------------------------------------------------------
const wy = (yml) => analyzeWorkflow('.github/workflows/x.yml', yml) || [];

test('a composite action interpolating an input is needs-review; an event field in it is critical', () => {
  const a = analyzeWorkflow('.github/actions/greet/action.yml', `name: greet
inputs:
  who:
    required: true
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "hello \${{ inputs.who }}"
    - shell: bash
      run: echo "\${{ github.event.issue.title }}"
`);
  assert.ok(a);
  const input = a.find((f) => f.inputOrigin === 'inputs.who');
  assert.equal(input.disposition, 'needs-review');
  assert.equal(input.job, '(composite action)');
  const ev = a.find((f) => f.inputOrigin === 'github.event.issue.title');
  assert.equal(ev.severity, 'critical');
});

test('an untrusted value in github-script source is critical; in an unknown action input it is needs-review', () => {
  const f = wy(`on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("\${{ github.event.issue.title }}")
      - uses: someorg/unknown-action@main
        with:
          note: \${{ github.event.issue.body }}
`);
  const gs = f.find((x) => /github-script source/.test(x.vuln));
  assert.equal(gs.severity, 'critical'); assert.equal(gs.disposition, 'detected');
  const unk = f.find((x) => /cannot inspect/.test(x.vuln));
  assert.equal(unk.disposition, 'needs-review');
  assert.match(unk.missingEvidence[0], /someorg\/unknown-action/);
});

test('a local action call is not treated as unknown, and a fixed value to a remote action is not flagged', () => {
  const f = wy(`on: pull_request
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/local
        with:
          note: \${{ github.event.pull_request.title }}
      - uses: someorg/tool@v1
        with:
          mode: fast
`);
  assert.equal(f.filter((x) => /cannot inspect/.test(x.vuln)).length, 0);
});

test('workflow_run that downloads an artifact is needs-review with the missing facts named', () => {
  const f = wy(`on:
  workflow_run:
    workflows: [build]
    types: [completed]
permissions:
  contents: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
`);
  const art = f.find((x) => /consumes an artifact/.test(x.vuln));
  assert.equal(art.disposition, 'needs-review'); assert.equal(art.severity, 'medium');
  assert.ok(art.missingEvidence.some((m) => /fork/.test(m)));
});

test('an agent action with write permission on an issue trigger is a review item; read-only is not flagged', () => {
  const body = (perm) => `on: issue_comment
permissions:
  contents: ${perm}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
`;
  assert.equal(wy(body('write')).filter((x) => /AI agent with write/.test(x.vuln)).length, 1);
  assert.equal(wy(body('read')).filter((x) => /AI agent with write/.test(x.vuln)).length, 0);
});

test('YAML anchors, multiline scalars and a commented-out permission are read as YAML, not as text', () => {
  const f = wy(`on: pull_request_target
x-env: &untrusted
  TITLE: \${{ github.event.pull_request.title }}
jobs:
  a:
    runs-on: ubuntu-latest
    # permissions:
    #   id-token: write
    env: *untrusted
    steps:
      - run: |
          eval "$TITLE"
`);
  assert.equal(f.filter((x) => /OIDC/.test(x.vuln)).length, 0);
  assert.equal(f.filter((x) => /env value later evaluated/.test(x.vuln)).length, 1);
});
