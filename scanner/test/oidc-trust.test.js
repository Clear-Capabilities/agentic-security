import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyOidcTrust, applyOidcTrust } from '../src/sast/oidc-trust.js';

const tf = (sub) => `resource "aws_iam_role" "ci" {
  assume_role_policy = jsonencode({
    Statement = [{ Principal = { Federated = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" }
      Condition = { StringLike = { "token.actions.githubusercontent.com:sub" = "${sub}" } } }]
  })
}`;

test('restrictive, permissive, mismatched and absent policies are told apart', () => {
  assert.equal(classifyOidcTrust({ 'iam.tf': tf('repo:acme/app:ref:refs/heads/main') }, { ownRepository: 'acme/app' }).status, 'restrictive');
  assert.equal(classifyOidcTrust({ 'iam.tf': tf('repo:acme/*') }).status, 'permissive');
  assert.equal(classifyOidcTrust({ 'iam.tf': tf('*') }).status, 'permissive');
  assert.equal(classifyOidcTrust({ 'iam.tf': tf('repo:other/app:ref:refs/heads/main') }, { ownRepository: 'acme/app' }).status, 'mismatched');
  assert.equal(classifyOidcTrust({ 'main.tf': 'resource "x" "y" {}' }).status, 'absent');
});

test('a trust statement with no subject condition is permissive', () => {
  assert.equal(classifyOidcTrust({ 'p.json': '{"Principal":{"Federated":"token.actions.githubusercontent.com"}}' }).status, 'permissive');
});

test('repository evidence never closes a finding; absent stays unchanged and permissive raises it', () => {
  const mk = () => ({ vuln: 'Pipeline: OIDC id-token: write, cloud trust policy and audience not verifiable from the repository', severity: 'low', disposition: 'needs-review' });
  const a = mk(); applyOidcTrust([a], {});
  assert.equal(a.oidcTrust.status, 'absent'); assert.equal(a.severity, 'low'); assert.equal(a.disposition, 'needs-review');
  const p = mk(); applyOidcTrust([p], { 'iam.tf': tf('repo:acme/*') });
  assert.equal(p.severity, 'high');
  const r = mk(); applyOidcTrust([r], { 'iam.tf': tf('repo:acme/app:environment:prod') });
  assert.equal(r.disposition, 'needs-review'); assert.ok(r.missingEvidence.length);
});

test('end to end: a composite action and a permissive trust policy reach the JSON report with full context', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { runScan } = await import('../src/runScan.js');
  const { toJSON } = await import('../src/report/index.js');
  const { mkTestTmp } = await import('./helpers/tmp.js');
  const d = mkTestTmp('agsec-oidc-');
  const w = (rel, c) => { fs.mkdirSync(path.dirname(path.join(d, rel)), { recursive: true }); fs.writeFileSync(path.join(d, rel), c); };
  w('package.json', '{}');
  w('.github/workflows/ci.yml', 'on: issues\npermissions:\n  id-token: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/g\n');
  w('.github/actions/g/action.yml', 'name: g\ninputs:\n  who:\n    required: true\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo "${{ inputs.who }}"\n');
  w('infra/iam.tf', 'x = "token.actions.githubusercontent.com:sub" = "repo:acme/*"\n');
  const { scan, meta } = await runScan(d, {});
  const out = toJSON(scan, meta).findings;
  const oidc = out.find((f) => /OIDC/.test(f.vuln));
  assert.equal(oidc.oidcTrust.status, 'permissive');
  assert.equal(oidc.severity, 'high');
  const comp = out.find((f) => f.workflow === '.github/actions/g/action.yml');
  for (const k of ['workflow', 'job', 'step', 'inputOrigin', 'sensitiveOperation', 'privilegeBoundary']) assert.ok(comp[k], k);
  assert.equal(comp.disposition, 'needs-review');
});
