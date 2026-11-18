// Recall sub-plan 1 (docs/superpowers/plans/2026-11-14-recall-sibling-authz.md): a request handler that takes a subject its sibling
// handlers pass through an authorization check, and checks nothing itself.
//
// The fixtures are a generic CRUD controller per language, written from the shape, not copied from any advisory. The rule asserts an
// ABSENCE, so most cases below prove it REFUSES to fire.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanAuthzSubjectConsistency } from '../src/sast/authz-subject-consistency.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'authz-subject-consistency');
const read = (side, f) => fs.readFileSync(path.join(FIX, side, f), 'utf8');
const lineOf = (code, needle) => code.split('\n').findIndex((l) => l.includes(needle)) + 1;

for (const [file, handler, expectLine] of [
  ['InvoiceController.php', 'show', "return view('invoices.show'"],
  ['ProjectController.java', 'settings', 'SettingsDTO settings = projectService.settings'],
  ['routes.ts', 'GET /v1/teams/:teamId/audit-log', 'loadAuditLog(teamId)'],
]) {
  test(`${file}: the one handler that skips its siblings' authorization check is reported, where the check belongs`, () => {
    const code = read('vulnerable', file);
    const out = scanAuthzSubjectConsistency(file, code);
    assert.equal(out.length, 1, JSON.stringify(out, null, 1));
    const f = out[0];
    assert.equal(f.cwe, 'CWE-285');
    assert.equal(f.family, 'broken-access-control');
    assert.equal(f.line, lineOf(code, expectLine));
    assert.match(f.vuln, new RegExp(handler.replace(/[/:]/g, '.')));
    assert.ok(f.evidenceSiblings.length >= 3, 'carries the guarded siblings');
    for (const k of ['id', 'severity', 'file', 'line', 'vuln', 'cwe', 'description', 'remediation', 'parser', 'family']) assert.ok(f[k] !== undefined, k);
  });

  test(`${file}: the fixed version, with the check added, reports nothing`, () => {
    assert.deepEqual(scanAuthzSubjectConsistency(file, read('clean', file)), []);
  });
}

const php = (methods) => `<?php\nclass C extends Controller\n{\n${methods.join('\n')}\n}\n`;
const guarded = (name) => `    public function ${name}(Invoice $invoice)\n    {\n        $this->authorize('update', $invoice);\n        return $invoice;\n    }\n`;
const bare = (name, body = 'return $invoice;') => `    public function ${name}(Invoice $invoice)\n    {\n        ${body}\n    }\n`;

test('two guarded siblings are not a convention: nothing is reported', () => {
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', php([guarded('a'), guarded('b'), bare('c')])), []);
});

test('a guarded minority is not a convention: nothing is reported', () => {
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', php([guarded('a'), guarded('b'), guarded('c'), bare('d'), bare('e'), bare('f')])), []);
});

test('a handler that applies a different authorization check is not reported', () => {
  const code = php([guarded('a'), guarded('b'), guarded('c'), bare('d', "abort_unless(Gate::allows('view-invoices'), 403); return $invoice;")]);
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', code), []);
});

test('a handler that delegates to a guarded sibling is not reported', () => {
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', php([guarded('a'), guarded('b'), guarded('c'), bare('d', 'return $this->a($invoice);')])), []);
});

test('a private helper is not a handler, so it is not reported', () => {
  const helper = '    private function load(Invoice $invoice)\n    {\n        return $invoice;\n    }\n';
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', php([guarded('a'), guarded('b'), guarded('c'), helper])), []);
});

test('authentication is not authorization: an authenticate() call does not make a sibling guarded', () => {
  const authn = (name) => `    public function ${name}(Invoice $invoice)\n    {\n        $this->authenticateUser($invoice);\n        return $invoice;\n    }\n`;
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', php([authn('a'), authn('b'), authn('c'), bare('d')])), []);
});

test('a check written only in a comment does not count as a guard', () => {
  const commented = (name) => `    public function ${name}(Invoice $invoice)\n    {\n        // $this->authorize('update', $invoice);\n        return $invoice;\n    }\n`;
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', php([commented('a'), commented('b'), commented('c'), bare('d')])), []);
});

test('a handler that never takes the guarded subject is not compared against it', () => {
  const other = '    public function index(Request $request)\n    {\n        return Invoice::all();\n    }\n';
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', php([guarded('a'), guarded('b'), guarded('c'), other])), []);
});

test('the request context passed to every guard is not a subject', () => {
  const route = (p, g) => `  app.get("${p}", async (c) => {\n${g ? '    const d = await requireAdmin(c);\n    if (d) return d;\n' : ''}    return c.json(await load());\n  });\n`;
  const code = `export function r(app) {\n${route('/a', true)}${route('/b', true)}${route('/c', true)}${route('/d', false)}}\n`;
  assert.deepEqual(scanAuthzSubjectConsistency('r.ts', code), []);
});

test('routes are compared with the routes under the same path parameter, not with every route that reads a same-named variable', () => {
  const r = (m, p, g) => `  app.${m}("${p}", async (c) => {\n    const teamId = c.req.param("teamId");\n${g ? '    const d = await requireTeamAccess(c, teamId);\n    if (d) return d;\n' : ''}    return c.json(await load(teamId));\n  });\n`;
  const internal = ['/internal/a', '/internal/b', '/internal/c'].map((p) => r('post', p, false)).join('');
  const code = `export function r(app) {\n${r('get', '/teams/:teamId/a', true)}${r('get', '/teams/:teamId/b', true)}${r('get', '/teams/:teamId/c', true)}${r('get', '/teams/:teamId/d', false)}${internal}}\n`;
  const out = scanAuthzSubjectConsistency('r.ts', code);
  assert.deepEqual(out.map((f) => f.vuln.split(' takes')[0]), ['Missing authorization: GET /teams/:teamId/d']);
});

test('a read handler is compared with guarded reads: when only the writes are checked, an unchecked read is not reported', () => {
  const w = (name, verb) => `  @${verb}Mapping("/p/{projectId}")\n  public void ${name}(@PathVariable String projectId) {\n    if (!permissionValidator.canEditProject(projectId)) { throw new AccessDeniedException("no"); }\n    service.${name}(projectId);\n  }\n`;
  const read = '  @GetMapping("/p/{projectId}")\n  public ProjectDTO get(@PathVariable String projectId) {\n    return service.get(projectId);\n  }\n';
  const code = `public class P {\n${w('update', 'Put')}${w('remove', 'Delete')}${w('rename', 'Patch')}${read}}\n`;
  assert.deepEqual(scanAuthzSubjectConsistency('P.java', code), []);
});

test('the permission model is not a handler: a method whose own name is a permission check is not reported', () => {
  const code = php([guarded('a'), guarded('b'), guarded('c'), bare('canView')]);
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', code), []);
});

test('test code is not analysed', () => {
  for (const f of ['tests/Feature/InvoiceControllerTest.php', 'src/test/java/x/ProjectControllerTest.java', 'src/routes.test.ts', 'src/__tests__/routes.ts']) {
    assert.deepEqual(scanAuthzSubjectConsistency(f, read('vulnerable', f.endsWith('.php') ? 'InvoiceController.php' : f.endsWith('.java') ? 'ProjectController.java' : 'routes.ts')), [], f);
  }
});

test('an authorization annotation above a multi-line mapping annotation still counts', () => {
  const g = (name) => `  @PreAuthorize(value = "@pv.canEdit(#projectId)")\n  @PutMapping(value = "/p/{projectId}/${name}", consumes = {\n      "application/json"})\n  public void ${name}(@PathVariable String projectId) {\n    service.${name}(projectId);\n  }\n`;
  const code = `public class P {\n${g('a')}${g('b')}${g('c')}${g('d')}}\n`;
  assert.deepEqual(scanAuthzSubjectConsistency('P.java', code), []);
  // and the same file with one annotation removed reports exactly that method
  const bad = code.replace('  @PreAuthorize(value = "@pv.canEdit(#projectId)")\n  @PutMapping(value = "/p/{projectId}/d"', '  @PutMapping(value = "/p/{projectId}/d"');
  assert.deepEqual(scanAuthzSubjectConsistency('P.java', bad).map((f) => f.vuln.split(' takes')[0]), ['Missing authorization: d']);
});

test('a handler that only redirects exposes nothing, so it is not reported', () => {
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', php([guarded('a'), guarded('b'), guarded('c'), bare('d', "return redirect()->route('invoices.show', $invoice->id);")])), []);
});

test('files in other languages and files with no authorization checks are ignored', () => {
  assert.deepEqual(scanAuthzSubjectConsistency('a.py', 'def a(x):\n    authorize(x)\n'), []);
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', php([bare('a'), bare('b'), bare('c'), bare('d')])), []);
  assert.deepEqual(scanAuthzSubjectConsistency('C.php', ''), []);
});

// Action-keyed checks (`userHasAccess('publish')` in `publish()`): the framework's handlers for the same action must run them too.
test('ReportBehavior.php: an action handler that skips the check its action applies by name is reported at its first statement', () => {
  const code = read('vulnerable', 'ReportBehavior.php');
  const out = scanAuthzSubjectConsistency('ReportBehavior.php', code);
  assert.deepEqual(out.map((f) => f.line), [lineOf(code, "$report = $this->loadReport(post('id'));")]);
  assert.equal(out[0].cwe, 'CWE-285');
  assert.match(out[0].vuln, /onPublish serves the 'publish' action/);
  assert.deepEqual(scanAuthzSubjectConsistency('ReportBehavior.php', read('clean', 'ReportBehavior.php')), []);
});

test('one action keyed by name is not a convention, and a helper with no handler prefix is not an entry point', () => {
  const one = read('vulnerable', 'ReportBehavior.php').replace(/userHasAccess\('archive'\)/g, "userHasAccess('other')");
  assert.deepEqual(scanAuthzSubjectConsistency('ReportBehavior.php', one), []);
  const helper = read('vulnerable', 'ReportBehavior.php').replace('function onPublish()', 'function publishPreview()');
  assert.deepEqual(scanAuthzSubjectConsistency('ReportBehavior.php', helper), []);
});

// A role check names no subject: when the siblings check the subject itself, a role-only handler is still an outlier.
test('TenantResource.java: handlers gated only by a global role while siblings check the tenant are reported', () => {
  const code = read('vulnerable', 'TenantResource.java');
  const out = scanAuthzSubjectConsistency('TenantResource.java', code);
  assert.deepEqual(out.map((f) => f.vuln.split(' takes')[0]), ['Missing authorization: get', 'Missing authorization: getUserRoles']);
  assert.deepEqual(scanAuthzSubjectConsistency('TenantResource.java', read('clean', 'TenantResource.java')), []);
});

test('a local read from the caller identity, and a delegating handler, are not outliers; throwIfNotFound is not a guard', () => {
  const code = read('vulnerable', 'TenantResource.java');
  const names = scanAuthzSubjectConsistency('TenantResource.java', code).map((f) => f.vuln);
  assert.ok(!names.some((v) => /updateMine|renameAll/.test(v)));
  const notFound = code.replace(/throwIfCannotManageTenant\(tenant\);/g, 'throwIfNotFound(tenant);');
  assert.deepEqual(scanAuthzSubjectConsistency('TenantResource.java', notFound), []);
});

// Class-level check while the record is in hand (PHP policy calls).
test('TicketController.php: a handler holding a record that only checks the class is reported at the class check', () => {
  const code = read('vulnerable', 'TicketController.php');
  const out = scanAuthzSubjectConsistency('TicketController.php', code);
  const lines = code.split('\n');
  const at = lines.findIndex((l, i) => i > lineOf(code, 'function attachments') && l.includes("authorize('view', Ticket::class)")) + 1;
  assert.deepEqual(out.map((f) => f.line), [at]);
  assert.equal(out[0].cwe, 'CWE-863');
  assert.match(out[0].vuln, /attachments/);
});

test('TicketController.php: the fixed version, and a listing that holds no single record, report nothing', () => {
  assert.deepEqual(scanAuthzSubjectConsistency('TicketController.php', read('clean', 'TicketController.php')), []);
});

test('a class-only check is not reported when the file checks records for a different ability only', () => {
  const code = read('vulnerable', 'TicketController.php').replace(/authorize\('view', \$ticket\)/g, "authorize('delete', $ticket)");
  assert.deepEqual(scanAuthzSubjectConsistency('TicketController.php', code), []);
});
