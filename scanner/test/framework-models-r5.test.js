// Framework request sources and dangerous sinks, round five
// (src/dataflow/catalog-framework-models.js plus the IR and engine support
// they needed). Every model family has a vulnerable file that must produce an
// IR-TAINT finding with the stated CWE and a clean twin (the safe form of the
// same API, or the standard sanitizer) that must be silent or labelled
// sanitized. The fixtures are synthetic and written from the framework APIs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { mkTestTmp } from './helpers/tmp.js';
import { parseKotlinFile, parseGoFile, parseJsFile, buildProjectIR } from '../src/ir/index.js';
import { matchSinkOrSanitizer, matchSource } from '../src/dataflow/catalog.js';
import { FRAMEWORK_MODELS } from '../src/dataflow/catalog-framework-models.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, 'fixtures');

const VULNERABLE = {
  'r5-framework-js': {
    'fastify-read.js': 'CWE-22', 'hapi-execfile.js': 'CWE-78', 'spawn-shell.js': 'CWE-78', 'vm-eval.js': 'CWE-94',
    'axios-post.js': 'CWE-918', 'prisma-raw.js': 'CWE-89', 'res-write.js': 'CWE-79', 'res-location.js': 'CWE-601',
    'next-route.ts': 'CWE-78', 'next-fetch-url.ts': 'CWE-918', 'server-action.ts': 'CWE-73', 'send-file.js': 'CWE-22',
    'unserialize.js': 'CWE-502', 'lodash-template.js': 'CWE-1336', 'timer-string.js': 'CWE-95',
  },
  'r5-framework-py': {
    'flask_route_param.py': 'CWE-22', 'fastapi_plain_param.py': 'CWE-78', 'requests_put.py': 'CWE-918',
    'django_redirect.py': 'CWE-601', 'django_httpresponse.py': 'CWE-79', 'starlette_fileresponse.py': 'CWE-22',
    're_search.py': 'CWE-1333', 'yaml_unsafe.py': 'CWE-502', 'django_rawsql.py': 'CWE-89', 'flask_get_json_remove.py': 'CWE-22',
  },
  'r5-framework-jvm': {
    'JaxrsPing.java': 'CWE-78', 'RestProxy.java': 'CWE-918', 'DocReader.java': 'CWE-22', 'Redirector.java': 'CWE-601',
    'PatternSearch.java': 'CWE-1333', 'SessionLoader.java': 'CWE-502', 'UserQuery.java': 'CWE-89',
    'PingController.kt': 'CWE-78', 'KtorRoutes.kt': 'CWE-601',
  },
  'r5-framework-go': {
    'header_exec.go': 'CWE-78', 'pathvalue_open.go': 'CWE-22', 'newrequest.go': 'CWE-918', 'write_html.go': 'CWE-79',
    'gin_sql.go': 'CWE-89', 'template_html.go': 'CWE-79',
  },
  'r5-framework-php': {
    'laravel_http.php': 'CWE-918', 'laravel_redirect.php': 'CWE-601', 'file_read.php': 'CWE-22', 'db_select.php': 'CWE-89',
    'preg.php': 'CWE-1333', 'symfony_response.php': 'CWE-79', 'popen.php': 'CWE-78',
  },
  'r5-framework-rb': {
    'send_file_controller.rb': 'CWE-22', 'kernel_open_controller.rb': 'CWE-78', 'net_http_controller.rb': 'CWE-918',
    'open3_controller.rb': 'CWE-78', 'instance_eval_controller.rb': 'CWE-95', 'regexp_controller.rb': 'CWE-1333',
  },
  'r5-framework-cs': {
    'FilesController.cs': 'CWE-22', 'UsersController.cs': 'CWE-89', 'ProxyController.cs': 'CWE-918',
    'ProfileController.cs': 'CWE-79', 'SearchController.cs': 'CWE-1333', 'ToolsController.cs': 'CWE-78',
  },
};

async function taintByFile(dir) {
  const tmp = mkTestTmp('as-r5-models-');
  fs.cpSync(dir, tmp, { recursive: true });
  const { scan } = await runScan(tmp, { deep: true, deepInCi: true });
  const byFile = new Map();
  for (const f of (scan.findings || []).filter((x) => x.parser === 'IR-TAINT')) {
    const base = path.basename(f.file || '');
    if (!byFile.has(base)) byFile.set(base, []);
    byFile.get(base).push(f);
  }
  return byFile;
}

const show = (fs_) => (fs_ || []).map((f) => `${f.cwe}@${f.line}${f.sanitized ? '(sanitized)' : ''}`).join(', ') || '(none)';

for (const [fixture, expected] of Object.entries(VULNERABLE)) {
  test(`${fixture}: every vulnerable file fires with its CWE`, async () => {
    const byFile = await taintByFile(path.join(FIX, fixture, 'vulnerable'));
    for (const [file, cwe] of Object.entries(expected)) {
      const got = byFile.get(file) || [];
      assert.ok(got.some((f) => f.cwe === cwe && !f.sanitized), `${fixture}/vulnerable/${file}: expected ${cwe}, got ${show(got)}`);
    }
    // Every vulnerable file is listed, so a fixture added without an expectation fails here.
    for (const file of fs.readdirSync(path.join(FIX, fixture, 'vulnerable'))) assert.ok(expected[file], `${file} has no expectation`);
  });

  test(`${fixture}: every clean file is silent or labelled sanitized`, async () => {
    const dir = path.join(FIX, fixture, 'clean');
    const byFile = await taintByFile(dir);
    for (const file of fs.readdirSync(dir)) {
      const live = (byFile.get(file) || []).filter((f) => !f.sanitized);
      assert.equal(live.length, 0, `${fixture}/clean/${file}: expected no unsanitized finding, got ${show(byFile.get(file))}`);
    }
  });
}

// ── IR support the models needed ─────────────────────────────────────────

test('Kotlin: annotated parameters are kept and reported (a function with `@PathVariable("id")` used to vanish)', () => {
  const ir = parseKotlinFile('A.kt', [
    'class A {',
    '  @GetMapping("/p/{id}")',
    '  fun p(@RequestParam("q") q: String, @PathVariable("id") id: String, page: Int, name: String) { }',
    '}',
  ].join('\n'));
  const fn = ir.functions.find((f) => f.name === 'p');
  assert.ok(fn, 'the function is parsed');
  assert.deepEqual(fn.params, ['q', 'id', 'page', 'name']);
  const ann = fn.paramAnnotations.map((a) => `${a.name}:${a.decorator}`);
  assert.ok(ann.includes('q:RequestParam') && ann.includes('id:PathVariable'));
  assert.ok(ann.includes('name:ImplicitSpringMappedParam'), 'a plain String parameter of a mapped method is implicitly request-bound');
  assert.ok(!ann.some((a) => a.startsWith('page:Implicit')), 'an Int parameter is not');
});

test('Kotlin: the not-null assertion `x!!` lowers like `x`', () => {
  const ir = parseKotlinFile('A.kt', 'fun f() {\n  val n = read()\n  sink(n!!)\n}\n');
  const call = Object.values(ir.functions[0].cfg.nodes).find((n) => n.kind === 'call' && n.callee === 'sink');
  assert.deepEqual(call.args, [{ kind: 'ident', name: 'n' }]);
});

test('Go: a []byte conversion carries its operand (it lowered to unknown)', () => {
  const ir = parseGoFile('a.go', 'package main\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tw.Write([]byte("<p>" + q))\n}\n');
  const call = Object.values(ir.functions[0].cfg.nodes).find((n) => n.kind === 'call');
  assert.equal(call.args[0].kind, 'tpl');
});

test('JS: parameters of a "use server" module\'s exported functions are server-action parameters; other modules are not', () => {
  const ann = (code) => (parseJsFile('a.ts', code).functions.find((f) => f.name === 'act')?.paramAnnotations || []).map((a) => a.decorator);
  assert.ok(ann("'use server';\nexport async function act(form) { return form; }").includes('js:server-action'));
  assert.ok(ann("export async function act(form) { 'use server'; return form; }").includes('js:server-action'));
  assert.ok(!ann('export async function act(form) { return form; }').includes('js:server-action'));
});

test('Python: route handler parameters are marked, except numeric-typed, numeric-converter and injected ones', () => {
  const { perFile } = buildProjectIR({ 'a.py': [
    'from fastapi import FastAPI, Depends',
    'app = FastAPI()',
    '@app.get("/items/{item}")',
    'def get_item(item: str, page: int = 1, db = Depends(get_db), q: str = None):',
    '    return item',
    '@app.route("/u/<int:uid>/<name>")',
    'def user(uid, name):',
    '    return name',
    '@cache.get("key")',
    'def cached(x):',
    '    return x',
  ].join('\n') });
  const fns = perFile['a.py'].functions;
  const marked = (n) => (fns.find((f) => f.name === n).paramAnnotations || []).filter((a) => a.decorator === 'py:route-param').map((a) => a.name);
  assert.deepEqual(marked('get_item'), ['item', 'q']);
  assert.deepEqual(marked('user'), ['name']);
  assert.deepEqual(marked('cached'), [], 'a decorator whose first argument is not a route path marks nothing');
});

// ── Catalog scoping ──────────────────────────────────────────────────────

test('catalog: generic method names are scoped by receiver', () => {
  const member = (o, p) => ({ kind: 'member', object: { kind: 'ident', name: o }, prop: p });
  const hasSink = (callee, file, id) => (matchSinkOrSanitizer(callee, file) || []).some((e) => e.kind === 'sink' && (!id || e.id === id));
  assert.ok(hasSink(member('axios', 'post'), 'a.js', 'js-axios-post'));
  assert.ok(!hasSink(member('router', 'post'), 'a.js', 'js-axios-post'), 'router.post is route registration');
  assert.ok(hasSink('requests.put', 'a.py', 'py-http-verb-put'));
  assert.ok(!hasSink('cache.put', 'a.py', 'py-http-verb-put'));
  assert.ok(hasSink('os.remove', 'a.py', 'py-os-path-remove'));
  assert.ok(!hasSink('items.remove', 'a.py', 'py-os-path-remove'), 'list.remove is not a file operation');
  assert.ok(!hasSink('re.compile.match', 'a.py', 'py-re-pattern-match'), 'in re.compile(p).match(s) the argument is the subject');
  assert.ok(!hasSink('Pattern.compile', 'A.java', 'java-xpath-compile'), 'Pattern.compile is a regex, not an XPath expression');
  assert.ok(!hasSink('Regexp.new', 'a.rb', 'rb-erb-new'), 'only ERB.new compiles a template');
  assert.ok(!hasSink('user.send', 'a.js', 'rb-send-send'), 'Ruby send is scoped to Ruby');
  // `req.url` is not a source: outbound request objects are named `req` too.
  assert.equal(matchSource(member('req', 'url'), 'a.js'), null);
  assert.ok(matchSource(member('request', 'query'), 'a.js'));
});

test('catalog: every model is API-named, carries a CWE, and its id is unique', () => {
  const ids = new Set();
  for (const e of FRAMEWORK_MODELS) {
    assert.ok(!ids.has(e.id.toLowerCase()), `duplicate id ${e.id}`);
    ids.add(e.id.toLowerCase());
    if (e.kind === 'sink') assert.match(e.vuln.cwe, /^CWE-\d+$/, e.id);
    assert.ok(['js', 'py', 'java', 'kt', 'go', 'php', 'rb', 'cs'].includes(e.language), e.id);
  }
});
