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

test('a policy that trusts this repository among others is not a mismatch; one that trusts only others is', () => {
  const two = `${tf('repo:acme/app:ref:refs/heads/main')}\n${tf('repo:acme/infra:ref:refs/heads/main')}`;
  assert.equal(classifyOidcTrust({ 'iam.tf': two }, { ownRepository: 'acme/app' }).status, 'restrictive');
  assert.equal(classifyOidcTrust({ 'iam.tf': two }, { ownRepository: 'Acme/App' }).status, 'restrictive', 'GitHub names are case-insensitive');
  assert.equal(classifyOidcTrust({ 'iam.tf': two }, { ownRepository: 'acme/web' }).status, 'mismatched');
});

test('the finding records where the repository name came from, or that it was unknown', () => {
  const mk = () => ({ vuln: 'Pipeline: OIDC id-token: write, cloud trust policy and audience not verifiable from the repository', severity: 'low' });
  const known = mk(); applyOidcTrust([known], { 'iam.tf': tf('repo:acme/app:ref:refs/heads/main') }, { ownRepository: 'acme/app', ownRepositoryBasis: 'git remote origin' });
  assert.equal(known.oidcTrust.ownRepositoryBasis, 'git remote origin');
  const unknown = mk(); applyOidcTrust([unknown], { 'iam.tf': tf('repo:acme/app:ref:refs/heads/main') });
  assert.match(unknown.oidcTrust.ownRepositoryBasis, /mismatched check was not made/);
});

test('resolveOwnRepository reads a GitHub origin in every URL form, and only trusts GITHUB_REPOSITORY for its own checkout', async () => {
  const fs = await import('node:fs');
  const { spawnSync } = await import('node:child_process');
  const { mkTestTmp } = await import('./helpers/tmp.js');
  const { resolveOwnRepository } = await import('../src/sast/oidc-trust.js');
  const repo = (url) => {
    const d = mkTestTmp('oidc-own-');
    spawnSync('git', ['init', '-q'], { cwd: d });
    if (url) spawnSync('git', ['remote', 'add', 'origin', url], { cwd: d });
    return d;
  };
  for (const url of ['https://github.com/acme/app.git', 'https://github.com/acme/app', 'git@github.com:acme/app.git', 'ssh://git@github.com/acme/app.git']) {
    assert.deepEqual(resolveOwnRepository(repo(url), {}), { name: 'acme/app', basis: 'git remote origin' }, url);
  }
  assert.equal(resolveOwnRepository(repo('https://gitlab.com/acme/app.git'), {}), null);
  const bare = repo(null);
  assert.equal(resolveOwnRepository(bare, { GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'acme/app', GITHUB_WORKSPACE: '/elsewhere' }), null, 'another checkout');
  assert.deepEqual(resolveOwnRepository(bare, { GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'acme/app', GITHUB_WORKSPACE: bare }), { name: 'acme/app', basis: 'GITHUB_REPOSITORY (GitHub Actions)' });
  fs.rmSync(bare, { recursive: true, force: true });
});
