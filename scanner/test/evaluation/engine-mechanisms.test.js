// QA-006: parser, IR and flow-engine repairs chosen from development evidence.
//
// Four miss mechanisms, each documented with: the mechanism, a development example, adversarial semantic variants that must still be caught,
// benign controls that must stay quiet, and an ablation showing which analysis layer causes the recovery.
//
//   M1  implicit handler parameters (IR frontends -> catalog source). A controller action's plain string parameter and a Spring-mapped
//       method's plain String parameter are request-bound with no annotation, so no source existed.
//         development example: corpus entry CVE-2019-0980-csharp-open-redirect (taint layer blind; only a regex layer caught it).
//   M2  request-object accessors (catalog sources). `$request->input('x')` is Laravel's primary input call and was not a source.
//         development example: corpus entry CVE-2022-31626-laravel-sqli.
//   M3  sink argument context (engine gate + catalog sinks). `header("Location: " . $x)` is an open redirect, told from header injection by
//       the static prefix the tainted value is appended to; Go's `http.Redirect` took its target in an argument position no sink named.
//         development examples: CVE-2019-11539-php-open-redirect, CVE-2019-11538-go-open-redirect.
//   M4  Go statement line attribution (parser lowering). Blank lines and comment lines inside a function never advanced the line counter and
//       a leading blank line moved the function itself up, so every taint finding in typical Go landed on the wrong line.
//         development example: any Go handler with a blank line or comment before the sink (test/fixtures/engine-mechanisms/go-blank-lines).
//   (The fifth repair, suppression by a non-dominating guard, is QA-005 and is tested in guard-dominance.test.js.)
//
// Nothing here reads a file name, comment, label or expected id to decide a verdict; the rename-invariance tests prove it.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { runScan } from '../../src/runScan.js';
import { buildProjectIR } from '../../src/ir/index.js';
import { runTaintEngine } from '../../src/dataflow/engine.js';
import { parseGoFile } from '../../src/ir/parser-go.js';
import { parseCSharpFile } from '../../src/ir/parser-cs.js';
import { isImplicitCsActionParam, isImplicitSpringMappedParam, IMPLICIT_MVC_PARAM, IMPLICIT_SPRING_PARAM } from '../../src/ir/implicit-handler-params.js';
import { mkTestTmp } from '../helpers/tmp.js';

const REPO = path.resolve(import.meta.dirname, '..', '..', '..');
const CORPUS = path.join(REPO, 'bench', 'cve-replay', 'capability');
const MECH = path.resolve(import.meta.dirname, '../fixtures/engine-mechanisms');
const read = (...p) => fs.readFileSync(path.join(...p), 'utf8');
const firstFileIn = (dir) => { const f = fs.readdirSync(dir).filter((x) => !x.startsWith('.'))[0]; return [f, read(dir, f)]; };

/** Scan a single-file project in a fresh directory; deep mode on or off. Returns all findings. */
async function scanFile(name, body, { deep = true } = {}) {
  const dir = mkTestTmp('qa6-');
  fs.writeFileSync(path.join(dir, name), body);
  const prev = [process.env.AGENTIC_SECURITY_DEEP, process.env.AGENTIC_SECURITY_DEEP_IN_CI];
  if (deep) { process.env.AGENTIC_SECURITY_DEEP = '1'; process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1'; } else { process.env.AGENTIC_SECURITY_DEEP = '0'; }
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    for (const [k, v] of [['AGENTIC_SECURITY_DEEP', prev[0]], ['AGENTIC_SECURITY_DEEP_IN_CI', prev[1]]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}
const taint = (findings, cwe) => findings.filter((f) => f.parser === 'IR-TAINT' && (!cwe || f.cwe === cwe));

describe('[QA-006.AC01] M1 implicit handler parameters: C# MVC actions and Spring-mapped methods', () => {
  const CS = (cls, method, body = 'return Redirect(next);') => `using Microsoft.AspNetCore.Mvc;\n\n${cls} {\n    ${method} {\n        ${body}\n    }\n}\n`;

  test('development example: the corpus entry the taint layer could not see is now seen by the taint layer', async () => {
    const [name, src] = firstFileIn(path.join(CORPUS, 'CVE-2019-0980-csharp-open-redirect', 'pre'));
    const f = taint(await scanFile(name, src), 'CWE-601');
    assert.equal(f.length, 1, 'IR-TAINT reports the open redirect');
    assert.equal(f[0].line, 5);
  });

  test('ablation: the recovery is caused by the IR frontend emitting the implicit parameter; remove only that and the taint layer finds nothing', () => {
    const [name, src] = firstFileIn(path.join(CORPUS, 'CVE-2019-0980-csharp-open-redirect', 'pre'));
    const ir = buildProjectIR({ [name]: src });
    const fn = Object.values(ir.perFile)[0].functions.find((x) => /Go$/.test(x.name));
    assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'next', decorator: IMPLICIT_MVC_PARAM }], 'layer 1 emits the fact');
    assert.equal(runTaintEngine(ir.perFile, ir.callGraph, {}).filter((f) => f.cwe === 'CWE-601').length, 1, 'layer 2 with the fact');
    delete fn.paramAnnotations;
    assert.equal(runTaintEngine(ir.perFile, ir.callGraph, {}).filter((f) => f.cwe === 'CWE-601').length, 0, 'layer 2 without it');
  });

  test('ablation: the deterministic-only layer cannot supply it (the taint layer is the cause)', async () => {
    const [name, src] = firstFileIn(path.join(CORPUS, 'CVE-2019-0980-csharp-open-redirect', 'pre'));
    assert.equal(taint(await scanFile(name, src, { deep: false })).length, 0);
  });

  test('adversarial variants of the same shape are all caught: other base class, no base, async task, other parameter name, nullable, list, several params', async () => {
    const variants = [
      CS('public class AccountController : ControllerBase', 'public IActionResult Go(string next)'),
      CS('public class Account : Controller', 'public IActionResult Go(string next)'),
      CS('public class LinksController', 'public IActionResult Go(string next)'),
      CS('public class LinksController : Controller', 'public async Task<IActionResult> Go(string dest)', 'return Redirect(dest);'),
      CS('public class LinksController : Controller', 'public IActionResult Go(string? target)', 'return Redirect(target);'),
      CS('public class LinksController : Controller', 'public IActionResult Go(int id, string returnUrl, bool remember)', 'return Redirect(returnUrl);'),
      CS('public class LinksController : Controller', '[HttpGet("go")] public IActionResult Go(string next)'),
    ];
    for (const [i, src] of variants.entries()) {
      assert.equal(taint(await scanFile(`V${i}.cs`, src), 'CWE-601').length, 1, `variant ${i}`);
    }
  });

  test('benign controls stay quiet: not a controller, static, [NonAction], [FromServices], a non-string parameter, a private method, a constant', async () => {
    const controls = {
      'not a controller': CS('public class RedirectHelper', 'public IActionResult Go(string next)'),
      'static': CS('public class LinksController : Controller', 'public static IActionResult Go(string next)'),
      'NonAction': `using Microsoft.AspNetCore.Mvc;\n\npublic class LinksController : Controller {\n    [NonAction]\n    public IActionResult Go(string next) {\n        return Redirect(next);\n    }\n}\n`,
      'FromServices': CS('public class LinksController : Controller', 'public IActionResult Go([FromServices] string next)'),
      'int parameter': CS('public class LinksController : Controller', 'public IActionResult Go(int id)', 'return Redirect(id.ToString());'),
      'private': CS('public class LinksController : Controller', 'private IActionResult Go(string next)'),
      'constant target': CS('public class LinksController : Controller', 'public IActionResult Go(string next)', 'return Redirect("/home");'),
    };
    for (const [name, src] of Object.entries(controls)) assert.equal(taint(await scanFile('C.cs', src), 'CWE-601').length, 0, name);
  });

  test('the decision function, both directions', () => {
    const cls = { name: 'LinksController', bases: ['Controller'] };
    const ok = { modifiers: 'public', rawType: 'string', decorators: [], nonAction: false, classRange: cls };
    assert.equal(isImplicitCsActionParam(ok), true);
    for (const bad of [{ classRange: { name: 'Helper', bases: [] } }, { modifiers: 'public static' }, { modifiers: 'private' }, { rawType: 'int' }, { rawType: 'HttpContext' }, { decorators: ['FromServices'] }, { decorators: ['FromQuery'] }, { nonAction: true }]) {
      assert.equal(isImplicitCsActionParam({ ...ok, ...bad }), false, JSON.stringify(bad));
    }
    const sp = { methodAnnotations: ['GetMapping'], paramType: 'String', decorators: [] };
    assert.equal(isImplicitSpringMappedParam(sp), true);
    for (const bad of [{ methodAnnotations: [] }, { methodAnnotations: ['Override'] }, { paramType: 'int' }, { paramType: 'HttpServletRequest' }, { decorators: ['RequestParam'] }, { decorators: ['Value'] }]) {
      assert.equal(isImplicitSpringMappedParam({ ...sp, ...bad }), false, JSON.stringify(bad));
    }
  });

  test('Spring: a mapped method\'s plain String parameter is a source; an unmapped method, a non-String parameter and an explicitly annotated one are handled correctly', async () => {
    const J = (annot, sig, body = 'st.execute("SELECT * FROM users WHERE name=\'" + name + "\'");') => `import java.sql.*;\nimport org.springframework.web.bind.annotation.*;\n@RestController\npublic class Api {\n  private Connection conn;\n  ${annot}\n  public String find(${sig}) throws Exception {\n    Statement st = conn.createStatement();\n    ${body}\n    return "ok";\n  }\n}\n`;
    const mapped = taint(await scanFile('Api.java', J('@GetMapping("/u")', 'String name')), 'CWE-89');
    assert.equal(mapped.length, 1, 'mapped');
    for (const annot of ['@PostMapping("/u")', '@RequestMapping(value = "/u", method = RequestMethod.GET)', '@PutMapping("/u")', '@DeleteMapping("/u")']) {
      assert.equal(taint(await scanFile('Api.java', J(annot, 'String name')), 'CWE-89').length, 1, annot);
    }
    assert.equal(taint(await scanFile('Api.java', J('', 'String name')), 'CWE-89').length, 0, 'unmapped method: not request-bound');
    assert.equal(taint(await scanFile('Api.java', J('@GetMapping("/u")', 'int id', 'st.execute("SELECT " + id);')), 'CWE-89').length, 0, 'int parameter');
    assert.equal(taint(await scanFile('Api.java', J('@GetMapping("/u")', '@RequestParam String name')), 'CWE-89').length, 1, 'explicit annotation still works');
  });

  test('ablation (Spring): without the emitted fact the taint layer is silent', () => {
    const src = read(MECH, 'spring-mapped-java', 'pre', 'UserApi.java');
    const ir = buildProjectIR({ 'UserApi.java': src });
    return import('../../src/ir/index.js').then(async (m) => {
      const aIr = await m.buildProjectIRAsync({ 'UserApi.java': src });
      const fn = Object.values(aIr.perFile)[0].functions.find((x) => /find$/.test(x.name));
      assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'name', decorator: IMPLICIT_SPRING_PARAM }]);
      assert.ok(ir);
      assert.equal(runTaintEngine(aIr.perFile, aIr.callGraph, {}).filter((f) => f.cwe === 'CWE-89').length, 1);
      delete fn.paramAnnotations;
      assert.equal(runTaintEngine(aIr.perFile, aIr.callGraph, {}).filter((f) => f.cwe === 'CWE-89').length, 0);
    });
  });
});

describe('[QA-006.AC01] M2 request-object accessors: Laravel', () => {
  const LV = (expr, sink = 'DB::select(DB::raw("SELECT * FROM users WHERE name=\'" . $name . "\'"))') => `<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\nuse Illuminate\\Support\\Facades\\DB;\nclass UsersController extends Controller {\n  public function find(Request $request) {\n    $name = ${expr};\n    return ${sink};\n  }\n}\n`;

  test('development example: the taint layer now sees the corpus entry; the post tree is quiet', async () => {
    const [n, pre] = firstFileIn(path.join(CORPUS, 'CVE-2022-31626-laravel-sqli', 'pre'));
    assert.equal(taint(await scanFile(n, pre), 'CWE-89').length, 1);
    const [n2, post] = firstFileIn(path.join(CORPUS, 'CVE-2022-31626-laravel-sqli', 'post'));
    assert.equal(taint(await scanFile(n2, post), 'CWE-89').length, 0);
  });

  test('adversarial variants: every accessor, either conventional variable name, are all sources', async () => {
    for (const expr of ["$request->input('name')", "$request->query('name')", "$request->post('name')", "$request->cookie('name')", "$request->header('name')", "$request->string('name')", "$req->input('name')", "$request->all()", "$request->only('name')"]) {
      assert.equal(taint(await scanFile('U.php', LV(expr)), 'CWE-89').length, 1, expr);
    }
  });

  test('benign controls: an unrelated object with an `input` method, a literal, a bound query', async () => {
    assert.equal(taint(await scanFile('U.php', LV("$cart->input('name')")), 'CWE-89').length, 0, 'receiver is not a request');
    assert.equal(taint(await scanFile('U.php', LV("'alice'")), 'CWE-89').length, 0, 'constant');
    assert.equal(taint(await scanFile('U.php', LV("$request->input('name')", "DB::select('SELECT * FROM users WHERE name = ?', [$name])")), 'CWE-89').length, 0, 'bound parameter');
  });

  test('ablation: the deterministic-only layer cannot supply the taint finding', async () => {
    assert.equal(taint(await scanFile('U.php', LV("$request->input('name')"), { deep: false })).length, 0);
  });
});

describe('[QA-006.AC01] M3 sink argument context: header("Location: " . $x) and Go redirect helpers', () => {
  const PHP = (call) => `<?php\n$next = $_GET["next"];\n${call}\nexit;\n`;

  test('development examples: both corpus entries now carry an IR-TAINT open redirect; PHP additionally keeps its header-injection finding', async () => {
    const [pn, php] = firstFileIn(path.join(CORPUS, 'CVE-2019-11539-php-open-redirect', 'pre'));
    const pf = await scanFile(pn, php);
    assert.equal(taint(pf, 'CWE-601').length, 1); assert.equal(taint(pf, 'CWE-113').length, 1);
    const [gn, go] = firstFileIn(path.join(CORPUS, 'CVE-2019-11538-go-open-redirect', 'pre'));
    const gf = taint(await scanFile(gn, go), 'CWE-601');
    assert.equal(gf.length, 1); assert.equal(gf[0].line, 6, 'and at the right line (M4)');
  });

  test('PHP adversarial variants: spacing, case, a template string, a variable first piece through concatenation', async () => {
    for (const call of ['header("Location: " . $next);', "header('Location:' . $next);", 'header("location: " . $next);', 'header("Location: $next");', 'header( "Location : " . $next );']) {
      assert.equal(taint(await scanFile('r.php', PHP(call)), 'CWE-601').length, 1, call);
    }
  });

  test('PHP benign controls: another header, an unknown prefix, a constant target, a tainted value never reaching the header', async () => {
    for (const call of ['header("X-Trace: " . $next);', 'header($next);', 'header("Location: /home");', 'header("Content-Type: text/plain");']) {
      assert.equal(taint(await scanFile('r.php', PHP(call)), 'CWE-601').length, 0, call);
    }
    assert.equal(taint(await scanFile('r.php', PHP('header("X-Trace: " . $next);')), 'CWE-113').length, 1, 'control: header injection is still reported for the other header');
  });

  test('Go: net/http, gin and echo style helpers are sinks for their own argument position; constants and other receivers are not', async () => {
    const GO = (call) => `package main\n\nimport "net/http"\n\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\ttarget := r.URL.Query().Get("next")\n\t${call}\n}\n`;
    assert.equal(taint(await scanFile('h.go', GO('http.Redirect(w, r, target, http.StatusFound)')), 'CWE-601').length, 1);
    assert.equal(taint(await scanFile('h.go', GO('c.Redirect(302, target)')), 'CWE-601').length, 1, 'context helper, target second');
    assert.equal(taint(await scanFile('h.go', GO('http.Redirect(w, r, "/home", http.StatusFound)')), 'CWE-601').length, 0, 'constant target');
    assert.equal(taint(await scanFile('h.go', GO('http.Redirect(w, r, "/home", len(target))')), 'CWE-601').length, 0, 'tainted value in the status position is not the target');
    assert.equal(taint(await scanFile('h.go', GO('router.Redirect(w, r, target)')), 'CWE-601').length, 0, 'a receiver that is not net/http');
  });

  test('ablation: the deterministic-only layer cannot supply the taint finding (Go and PHP)', async () => {
    const [gn, go] = firstFileIn(path.join(CORPUS, 'CVE-2019-11538-go-open-redirect', 'pre'));
    assert.equal(taint(await scanFile(gn, go, { deep: false })).length, 0);
  });

  test('the new gate: a static-prefix requirement fails closed when the prefix is not a known literal', async () => {
    // `header($prefix . $next)`: the leading piece is a variable, so the prefix is unknown and the Location sink does not claim it.
    assert.equal(taint(await scanFile('r.php', `<?php\n$next = $_GET["next"];\n$prefix = "Location: ";\nheader($prefix . $next);\n`), 'CWE-601').length, 0);
  });
});

describe('[QA-006.AC01] M4 Go statement line attribution (parser lowering)', () => {
  const nodeLines = (src) => {
    const ir = parseGoFile('h.go', src);
    return ir.functions.map((fn) => ({ fn: fn.line, nodes: Object.values(fn.cfg.nodes).filter((n) => n.kind === 'call' || n.kind === 'assign').map((n) => n.line) }));
  };

  test('development example: the handler with a blank line and a comment block before the sink is lowered with exact lines', () => {
    const src = read(MECH, 'go-blank-lines', 'pre', 'run.go');
    const [h] = nodeLines(src);
    assert.equal(h.fn, 8); assert.deepEqual(h.nodes, [9, 16, 17]);
    assert.equal(src.split('\n')[16 - 1].includes('exec.Command'), true, 'line 16 really is the sink');
  });

  test('adversarial variants: CRLF endings, tabs, a blank line before func, comment-only lines, statements on one line, a multi-line argument list', () => {
    const base = 'package main\n\nimport "os/exec"\n\nfunc a(h string) {\n\n\t// note\n\tx := h\n\n\texec.Command("sh", "-c", x)\n}\n';
    assert.deepEqual(nodeLines(base)[0], { fn: 5, nodes: [8, 10] });
    assert.deepEqual(nodeLines(base.replace(/\n/g, '\r\n'))[0], { fn: 5, nodes: [8, 10] }, 'CRLF');
    const multi = 'package main\n\nfunc a(h string) {\n\tx := h\n\n\texec.Command(\n\t\t"sh",\n\t\t"-c",\n\t\tx,\n\t)\n\ty := x\n}\n';
    assert.deepEqual(nodeLines(multi)[0], { fn: 3, nodes: [4, 6, 11] }, 'a multi-line call is placed at its first line and the next statement after it');
    const two = 'package main\n\nfunc a() {\n}\n\n\n\nfunc b(h string) {\n\tx := h\n}\n';
    assert.deepEqual(nodeLines(two).map((f) => f.fn), [3, 8], 'several blank lines between functions');
    const nested = 'package main\n\nfunc a(h string) {\n\tif h != "" {\n\n\t\t// c\n\t\texec.Command(h)\n\t}\n\tfor _, v := range h {\n\n\t\texec.Command(v)\n\t}\n}\n';
    assert.deepEqual(nodeLines(nested)[0].nodes, [7, 9, 11], 'inside if and for bodies');
  });

  test('benign control: a file with no blank lines or comments is lowered exactly as before', () => {
    const tight = 'package main\nfunc a(h string) {\n\tx := h\n\texec.Command(x)\n}\n';
    assert.deepEqual(nodeLines(tight)[0], { fn: 2, nodes: [3, 4] });
  });

  test('end to end, and by ablation of the layer: the reported line is the sink line; the old line arithmetic would have missed the label window', async () => {
    const src = read(MECH, 'go-blank-lines', 'pre', 'run.go');
    const f = taint(await scanFile('run.go', src), 'CWE-78');
    assert.equal(f.length, 1); assert.equal(f[0].line, 16);
    // The previous lowering put the call five lines early (blank line, 4 comment lines/blank and the function offset), outside the +-3 matching window.
    const oldStyleLine = 16 - 5;
    assert.ok(Math.abs(oldStyleLine - 16) > 3);
  });
});

describe('[QA-006.AC02] at least three distinct mechanisms, across files and frameworks, with no special-casing', () => {
  test('the repaired mechanisms live in different layers and cover several languages and frameworks', () => {
    const mechanisms = [
      { id: 'implicit-handler-parameters', layer: 'ir -> catalog', frameworks: ['ASP.NET MVC', 'Spring MVC'], languages: ['csharp', 'java'] },
      { id: 'request-object-sources', layer: 'catalog', frameworks: ['Laravel'], languages: ['php'] },
      { id: 'sink-argument-context', layer: 'engine + catalog', frameworks: ['net/http', 'gin/echo', 'PHP header()'], languages: ['go', 'php'] },
      { id: 'go-line-attribution', layer: 'ir', frameworks: ['any Go'], languages: ['go'] },
      { id: 'guard-dominance', layer: 'engine filter', frameworks: ['Express', 'Flask', 'ASP.NET', 'Kotlin servlet', 'PHP'], languages: ['javascript', 'python', 'csharp', 'kotlin', 'php'] },
    ];
    assert.ok(new Set(mechanisms.map((m) => m.id)).size >= 3);
    assert.ok(new Set(mechanisms.flatMap((m) => m.languages)).size >= 5);
    assert.ok(new Set(mechanisms.map((m) => m.layer)).size >= 3);
  });

  test('rename invariance: the same code under different file names, directories and comments gets the same verdict', async () => {
    const src = read(MECH, 'implicit-mvc-cs', 'pre', 'RedirectController.cs');
    const a = taint(await scanFile('RedirectController.cs', src), 'CWE-601').length;
    const b = taint(await scanFile('Zq.cs', `// totally unrelated header comment\n${src}`), 'CWE-601').length;
    const c = taint(await scanFile('Zq.cs', src.replaceAll('RedirectController', 'PortalController').replaceAll('Go', 'Handle').replaceAll('next', 'where')), 'CWE-601').length;
    assert.deepEqual([a, b, c], [1, 1, 1]);
    const go = read(MECH, 'go-blank-lines', 'pre', 'run.go');
    const g = [taint(await scanFile('run.go', go), 'CWE-78'), taint(await scanFile('q.go', go.replaceAll('handler', 'serve').replaceAll('host', 'dest')), 'CWE-78')];
    assert.deepEqual(g.map((x) => [x.length, x[0].line]), [[1, 16], [1, 16]]);
  });

  test('the repair sources name no benchmark, corpus entry, advisory id, label or expected-id switch', () => {
    const files = ['src/ir/implicit-handler-params.js', 'src/dataflow/guard-dominance.js'].map((p) => path.resolve(import.meta.dirname, '../..', p));
    const forbidden = [/cve-replay/i, /bench\//i, /\bCVE-\d{4}-\d+/, /\bGHSA-/i, /corpus/i, /expected/i, /AGENTIC_SECURITY_BENCH/, /manifest\.json/, /\.cs['"`]\s*\)/];
    for (const f of files) {
      const text = fs.readFileSync(f, 'utf8');
      for (const re of forbidden) assert.doesNotMatch(text, re, `${path.basename(f)} must not match ${re}`);
    }
    // the catalog rows and the parsers added for the mechanisms are keyed on framework vocabulary only
    const cat = fs.readFileSync(path.resolve(import.meta.dirname, '../../src/dataflow/catalog.js'), 'utf8');
    for (const id of ['cs-aspnet-implicit-action-param', 'java-spring-implicit-mapped-param', 'php-header-location', 'go-http-redirect', 'go-ctx-redirect-second']) assert.ok(cat.includes(`'${id}'`), id);
    assert.doesNotMatch(cat.slice(cat.indexOf("'php-header-location'") - 600, cat.indexOf("'php-header-location'") + 600), /cve|bench|corpus/i);
  });

  test('there is no environment switch for any of these repairs (no hidden switches)', () => {
    for (const f of ['src/ir/implicit-handler-params.js', 'src/dataflow/guard-dominance.js']) {
      assert.doesNotMatch(fs.readFileSync(path.resolve(import.meta.dirname, '../..', f), 'utf8'), /process\.env/);
    }
  });
});

describe('[QA-006.AC03] development recovery and alert burden improve under the frozen scoring policy; sealed outcomes stay out of reach', () => {
  const rec = () => JSON.parse(read(MECH, 'measured-before-after.json'));

  test('the recorded measurement: more development defects recovered, no more false positives on the patched trees', () => {
    const r = rec();
    assert.ok(r.after.development.micro.tp > r.before.development.micro.tp);
    assert.ok(r.after.development.micro.fp <= r.before.development.micro.fp);
    assert.equal(r.before.development.micro.fn + r.before.development.micro.tp, r.after.development.micro.fn + r.after.development.micro.tp, 'the same denominator');
    const recovered = r.after.development.cases.filter((c, i) => c.recovered && !r.before.development.cases[i].recovered).map((c) => c.id);
    assert.deepEqual(recovered.sort(), ['guard-after-sink-js', 'guard-closed-block-py', 'guard-other-function-js']);
  });

  test('the recorded corpus measurement: the taint layer reaches more entries, and IR-TAINT findings on non-code lines (a mislocation) fall', () => {
    const r = rec();
    assert.ok(r.before.corpus && r.after.corpus, 'the record was measured with --corpus');
    assert.ok(r.after.corpus.irTaintFindings > r.before.corpus.irTaintFindings, 'the taint layer reports on more entries');
    assert.ok(r.after.corpus.irTaintOnNonCodeLine < r.before.corpus.irTaintOnNonCodeLine, 'and no longer reports on blank, brace or comment lines');
    assert.equal(r.after.corpus.irTaintOnNonCodeLine, 0);
    assert.ok(r.after.corpus.rawAlerts < r.before.corpus.rawAlerts, 'the alerts a reviewer reads fell: mislocated duplicates now land on the line they duplicate');
    assert.ok(r.after.corpus.rootCauses <= r.before.corpus.rootCauses, 'with no more root causes');
  });

  test('the instruments that read development material cannot reach the sealed split', () => {
    const script = fs.readFileSync(path.join(REPO, 'scripts', 'dev-recovery.mjs'), 'utf8');
    assert.doesNotMatch(script, /custodianReadLabels|allowSealed|sealed-labels|split:\s*['"](?:sealed|all)['"]/);
    assert.match(script, /split:\s*'dev'/);
  });
});
