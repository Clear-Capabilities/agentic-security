// Epic D: the service scope across repositories at exact revisions, and identity propagation between them. D-AC01 (exact-revision
// provenance through one finding), D-AC02 (spoofed forwarded identity and tenant from a message), D-AC04 (missing or unauthorised
// repositories are visible gaps, never fetched), D-AC06 (a partial scope never reports complete coverage).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolveServiceScope, identityPropagation, readComponentSources } from '../../src/contracts/service-scope.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FX = path.join(HERE, '..', 'fixtures', 'contract-service');
const git = (cwd, ...a) => execFileSync('git', a, { cwd, encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid' } }).trim();

function repos() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'svc-scope-'));
  const heads = {};
  for (const r of ['gateway', 'api', 'worker']) {
    const d = path.join(base, r); fs.mkdirSync(d);
    fs.copyFileSync(path.join(FX, r, `${r}.js`), path.join(d, `${r}.js`));
    git(d, 'init', '-q'); git(d, 'add', '.'); git(d, 'commit', '-q', '-m', 'fixture');
    heads[r] = git(d, 'rev-parse', 'HEAD');
  }
  return { base, heads };
}
const contractFor = (heads, over = {}) => ({ scope: { environment: 'isolated-test', repositories: ['gateway', 'api', 'worker'].map((id) => ({ id, revision: over[id] ?? heads[id] })) } });

test('D-AC01/D-AC06: three repositories at their pinned commits resolve; the scope is complete and each carries its exact revision', () => {
  const { base, heads } = repos();
  try {
    const s = resolveServiceScope({ contract: contractFor(heads), rootMap: { gateway: path.join(base, 'gateway'), api: path.join(base, 'api'), worker: path.join(base, 'worker') }, authorized: ['gateway', 'api', 'worker'] });
    assert.equal(s.state, 'complete'); assert.equal(s.complete, true);
    assert.deepEqual(s.repositories.map((r) => [r.id, r.state, r.observedRevision === heads[r.id]]), [['gateway', 'resolved', true], ['api', 'resolved', true], ['worker', 'resolved', true]]);
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('D-AC04/D-AC06: unauthorised, missing, non-git and wrong-revision repositories are distinct visible gaps and the scope is partial', () => {
  const { base, heads } = repos();
  try {
    const plain = path.join(base, 'plain'); fs.mkdirSync(plain);
    const s = resolveServiceScope({
      contract: { scope: { environment: 'isolated-test', repositories: [
        { id: 'gateway', revision: heads.gateway }, { id: 'api', revision: 'a'.repeat(40) }, { id: 'worker', revision: heads.worker }, { id: 'billing', revision: 'b'.repeat(40) }, { id: 'ledger', revision: 'c'.repeat(40) },
      ] } },
      rootMap: { gateway: path.join(base, 'gateway'), api: path.join(base, 'api'), ledger: plain },
      authorized: ['gateway', 'api', 'billing', 'ledger'],
    });
    assert.deepEqual(s.repositories.map((r) => [r.id, r.state]), [['gateway', 'resolved'], ['api', 'version-mismatch'], ['worker', 'access-denied'], ['billing', 'repository-unavailable'], ['ledger', 'revision-unknown']]);
    assert.equal(s.state, 'partial'); assert.equal(s.complete, false);
    assert.equal(s.repositories.find((r) => r.id === 'worker').root, null, 'an unauthorised repository is never read, not even located');
    assert.deepEqual(s.gaps.map((g) => g.code).sort(), ['access-denied', 'repository-unavailable', 'revision-unknown', 'version-mismatch']);
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('D-AC02: the API trusting the forwarded tenant header and the worker taking the tenant from the message are supported candidates; the gateway\'s verified claim is established', () => {
  const comps = ['gateway', 'api', 'worker'].map((r) => ({ repository: r, files: readComponentSources(path.join(FX, r)) }));
  const out = identityPropagation(comps);
  assert.deepEqual(out.transitions.map((t) => [t.component, t.kind, t.established]), [['gateway', 'signed-claim', true], ['gateway', 'forwards-header', true], ['api', 'caller-supplied-header', false], ['worker', 'message-field', false]]);
  assert.deepEqual(out.candidates.map((c) => [c.component, c.kind]), [['api', 'spoofable-forwarded-identity'], ['worker', 'tenant-from-message-unverified']]);
  assert.ok(out.candidates.every((c) => c.established === false && c.evidence === 'static-pattern'));
  // a consumer that verifies a signed envelope before using the tenant is not a candidate
  const verified = identityPropagation([{ repository: 'worker', files: { 'w.js': "queue.consume('q', async (msg, db) => {\n  const claims = jwt.verify(msg.token, key);\n  const tenant = msg.tenantId;\n  await db.updateOne(msg.id, { tenant });\n});\n" } }]);
  assert.deepEqual(verified.candidates, []);
  // a header read whose use is not traced is unresolved, not dismissed
  const untraced = identityPropagation([{ repository: 'api', files: { 'a.js': "export function f(req) {\n  const t = req.headers['x-tenant'];\n  return audit(t);\n}\n" } }]);
  assert.deepEqual(untraced.unresolved.map((u) => u.kind), ['header-identity-use-not-traced']);
});
