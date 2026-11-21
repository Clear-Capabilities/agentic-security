// Authorization step deviation (CWE-863), src/sast/authz-step-deviation.js: a handler that authenticates and skips the
// permission check its directory's handlers make after authenticating.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanAuthzStepDeviation, isAuthnCall, isPermissionCall } from '../src/sast/authz-step-deviation.js';
import { runScan } from '../src/runScan.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, 'fixtures', 'authz-step-deviation');

function readTree(root) {
  const out = {};
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p); else out[path.relative(root, p)] = fs.readFileSync(p, 'utf8');
    }
  })(root);
  return out;
}

const stepped = (name, authn = 'authenticateHttpRequest') => `
export async function ${name}(req: any, res: any) {
  const auth = await ${authn}(req);
  if (!auth.ok) { res.statusCode = 401; return res.end(); }
  const scope = requireScopeForAction("${name}", auth.scopes);
  if (!scope.allowed) { res.statusCode = 403; return res.end(); }
  res.end("ok");
}
`;
const bare = (name, authn = 'authenticateHttpRequest') => `
export async function ${name}(req: any, res: any) {
  const auth = await ${authn}(req);
  if (!auth.ok) { res.statusCode = 401; return res.end(); }
  res.end("everything");
}
`;

test('vulnerable fixture: the handler that skips the scope check is reported on its authentication test', () => {
  const out = scanAuthzStepDeviation(readTree(path.join(FIX, 'vulnerable')));
  assert.equal(out.length, 1);
  assert.equal(out[0].file, path.join('api', 'exports.ts'));
  assert.equal(out[0].line, 5);
  assert.equal(out[0].cwe, 'CWE-863');
  assert.equal(out[0].family, 'authz-step-deviation');
  assert.match(out[0].vuln, /requireScopeForAction\(\)/);
  // It authenticates with the function the siblings' wrapper delegates to.
  assert.match(out[0].vuln, /verifyCaller\(\)/);
  assert.equal(out[0].evidenceSiblings.length, 3);
});

test('clean fixture: every handler takes the step, nothing is reported', () => {
  assert.deepEqual(scanAuthzStepDeviation(readTree(path.join(FIX, 'clean'))), []);
});

test('no majority: three stepped handlers against four bare ones is not a convention', () => {
  const fc = {};
  for (const n of ['a', 'b', 'c']) fc[`api/${n}.ts`] = stepped(`handle_${n}`);
  for (const n of ['d', 'e', 'f', 'g']) fc[`api/${n}.ts`] = bare(`handle_${n}`);
  assert.deepEqual(scanAuthzStepDeviation(fc), []);
});

test('two stepped siblings are too few', () => {
  const fc = { 'api/a.ts': stepped('handleA'), 'api/b.ts': stepped('handleB'), 'api/c.ts': bare('handleC') };
  assert.deepEqual(scanAuthzStepDeviation(fc), []);
});

test('a handler authenticating through an unrelated function is held to no convention', () => {
  const fc = {};
  for (const n of ['A', 'B', 'C']) fc[`api/${n}.ts`] = stepped(`handle${n}`);
  fc['api/hook.ts'] = bare('handleHook', 'authenticateWebhookSignature');
  assert.deepEqual(scanAuthzStepDeviation(fc), []);
});

test('the convention is per directory: a bare handler elsewhere is not compared', () => {
  const fc = {};
  for (const n of ['A', 'B', 'C']) fc[`api/${n}.ts`] = stepped(`handle${n}`);
  fc['public/health.ts'] = bare('handleHealth');
  assert.deepEqual(scanAuthzStepDeviation(fc), []);
});

test('an authentication whose result is not tested is a lookup, not a gate', () => {
  const fc = {};
  for (const n of ['A', 'B', 'C']) fc[`api/${n}.ts`] = stepped(`handle${n}`);
  fc['api/d.ts'] = `
export async function handleD(req: any, res: any) {
  const auth = await authenticateHttpRequest(req);
  res.end(JSON.stringify({ greeting: "hello" }));
}
`;
  assert.deepEqual(scanAuthzStepDeviation(fc), []);
});

test('a wrapper named for authentication is neither counted nor reported, and test files are skipped', () => {
  const fc = {};
  for (const n of ['A', 'B', 'C']) fc[`api/${n}.ts`] = stepped(`handle${n}`);
  fc['api/wrap.ts'] = `
export async function authenticateAdminRequest(req: any) {
  const auth = await authenticateHttpRequest(req);
  if (!auth.ok) throw new Error("denied");
  return auth;
}
`;
  fc['api/d.test.ts'] = bare('handleD');
  assert.deepEqual(scanAuthzStepDeviation(fc), []);
  fc['api/d.ts'] = bare('handleD');
  const out = scanAuthzStepDeviation(fc);
  assert.equal(out.length, 1);
  assert.equal(out[0].file, 'api/d.ts');
});

test('Python: the same convention in a views module', () => {
  const view = (name, checked) => `
def ${name}(request):
    user = authenticate_request(request)
    if user is None:
        return {"error": "unauthorized"}, 401
${checked ? `    if not has_permission(user, "${name}"):\n        return {"error": "forbidden"}, 403\n` : ''}    return {"ok": True}
`;
  const fc = {};
  for (const n of ['list_reports', 'list_invoices', 'list_users']) fc[`app/views_${n}.py`] = view(n, true);
  fc['app/views_export.py'] = view('export_all', false);
  const out = scanAuthzStepDeviation(fc);
  assert.equal(out.length, 1);
  assert.equal(out[0].file, 'app/views_export.py');
  assert.equal(out[0].line, 4);
});

test('call classification: authentication and permission names are disjoint', () => {
  for (const n of ['authenticateHttpRequest', 'authorizeGatewayConnect', 'verifyToken', 'requireAuth', 'get_current_user']) assert.ok(isAuthnCall(n), n);
  for (const n of ['authorizeOperatorScopesForMethod', 'requireScopeForAction', 'has_permission', 'checkRole', 'can']) {
    assert.ok(isPermissionCall(n), n);
    assert.ok(!isAuthnCall(n), n);
  }
  for (const n of ['ensureAuthProfileStore', 'requireSessionKey', 'checkout', 'validated']) assert.ok(!isAuthnCall(n), n);
});

test('end to end: the finding survives a full scan of the vulnerable fixture and is absent from the clean one', async () => {
  for (const [side, expected] of [['vulnerable', 1], ['clean', 0]]) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asd-'));
    fs.cpSync(path.join(FIX, side), dir, { recursive: true });
    try {
      const { scan } = await runScan(dir);
      const hits = (scan.findings || []).filter(f => f.family === 'authz-step-deviation');
      assert.equal(hits.length, expected, side);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});
