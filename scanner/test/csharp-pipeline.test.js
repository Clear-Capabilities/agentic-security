// C# SAST pipeline — Layers 1-4 + Option 4 (LLM validator).
//
// Verifies the IR-based pipeline: tokenizer correctly handles C# string
// idioms, IR captures decls/calls/assignments/attributes, type-flow
// propagates taint, attribute analysis identifies routes, and the detector
// layer fires on Juliet-shaped vulnerable code without firing on the safe
// counterpart.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tokenize } from '../src/sast/csharp-tokenizer.js';
import { buildCSharpIR } from '../src/ir/csharp-ir.js';
import { analyzeCSharpIR, expressionIsTainted } from '../src/posture/csharp-analysis.js';
import { scanCSharp } from '../src/sast/csharp.js';

// ── Layer 1: tokenizer ─────────────────────────────────────────────────────

test('tokenizer: regular vs verbatim vs interpolated strings', () => {
  const tokens = tokenize('var a = "x"; var b = @"\\path"; var c = $"hi {name}";');
  const strings = tokens.filter(t => ['string', 'verbatim', 'interp'].includes(t.kind));
  assert.equal(strings.length, 3);
  assert.equal(strings[0].kind, 'string');
  assert.equal(strings[0].value, 'x');
  assert.equal(strings[1].kind, 'verbatim');
  assert.equal(strings[1].value, '\\path');
  assert.equal(strings[2].kind, 'interp');
  const parts = strings[2].parts;
  assert.equal(parts.find(p => p.kind === 'lit').text, 'hi ');
  assert.equal(parts.find(p => p.kind === 'expr').text, 'name');
});

test('tokenizer: line comments do not produce tokens', () => {
  const tokens = tokenize('var a = 1; // var b = "uncommented";\nvar c = 2;');
  const idents = tokens.filter(t => t.kind === 'ident').map(t => t.value);
  assert.deepEqual(idents, ['a', 'c']);
});

test('tokenizer: block comments span newlines', () => {
  const tokens = tokenize('var a = 1; /* var b = 2;\n */ var c = 3;');
  const idents = tokens.filter(t => t.kind === 'ident').map(t => t.value);
  assert.deepEqual(idents, ['a', 'c']);
});

test('tokenizer: attributes get distinct attr-open / attr-close kinds', () => {
  const tokens = tokenize('[HttpGet] public void M() {}');
  assert.equal(tokens[0].kind, 'attr-open');
  const close = tokens.find(t => t.kind === 'attr-close');
  assert.ok(close);
});

test('tokenizer: indexer brackets stay lbracket / rbracket', () => {
  const tokens = tokenize('var x = arr[0];');
  assert.ok(tokens.some(t => t.kind === 'lbracket'));
  assert.ok(tokens.some(t => t.kind === 'rbracket'));
  assert.ok(!tokens.some(t => t.kind === 'attr-open'));
});

// ── Layer 2: IR ────────────────────────────────────────────────────────────

test('IR: captures class with attributes + base types', () => {
  const ir = buildCSharpIR('[Authorize]\npublic class UsersController : ControllerBase { }');
  assert.equal(ir.classes.length, 1);
  assert.equal(ir.classes[0].name, 'UsersController');
  assert.deepEqual(ir.classes[0].attrs.map(a => a.name), ['Authorize']);
  assert.ok(ir.classes[0].baseTypes.includes('ControllerBase'));
});

test('IR: captures typed declarations with types preserved', () => {
  const ir = buildCSharpIR('class T { void M() { SqlCommand cmd = new SqlCommand("x"); int n = 5; } }');
  const decls = ir.decls;
  assert.equal(decls.find(d => d.name === 'cmd').type, 'SqlCommand');
  assert.equal(decls.find(d => d.name === 'n').type, 'int');
});

test('IR: nested calls inside decl rhs are extracted', () => {
  const ir = buildCSharpIR('class T { void M() { var p = Path.Combine(a, b); } }');
  const call = ir.calls.find(c => c.method === 'Combine');
  assert.ok(call, 'Path.Combine extracted from decl rhs');
  assert.equal(call.receiver, 'Path');
});

test('IR: member assignment captures memberPath', () => {
  const ir = buildCSharpIR('class T { void M() { cmd.CommandText = "x"; } }');
  const a = ir.assignments.find(x => x.target === 'cmd');
  assert.ok(a);
  assert.equal(a.memberPath, 'CommandText');
  assert.equal(a.isMember, true);
});

// ── Layer 3: type-flow + taint ─────────────────────────────────────────────

test('analysis: Request.Query taints the lhs', () => {
  const ir = buildCSharpIR('class T { void M() { var id = Request.Query["id"]; } }');
  const an = analyzeCSharpIR(ir);
  const flow = an.methodFlow.get(ir.methods[0]);
  assert.equal(flow.taintMap.get('id'), true);
});

test('analysis: taint propagates through assignment chains', () => {
  const ir = buildCSharpIR('class T { void M() { var a = Request.Query["x"]; var b = a + "y"; var c = b; } }');
  const an = analyzeCSharpIR(ir);
  const flow = an.methodFlow.get(ir.methods[0]);
  assert.equal(flow.taintMap.get('a'), true);
  assert.equal(flow.taintMap.get('b'), true);
  assert.equal(flow.taintMap.get('c'), true);
});

test('analysis: sanitizer clears taint', () => {
  const ir = buildCSharpIR('class T { void M() { var x = Request.Query["x"]; var safe = HttpUtility.HtmlEncode(x); } }');
  const an = analyzeCSharpIR(ir);
  const flow = an.methodFlow.get(ir.methods[0]);
  assert.equal(flow.taintMap.get('x'), true);
  // The expression check considers the sanitizer.
  assert.equal(expressionIsTainted(flow, 'HttpUtility.HtmlEncode(x)'), false);
});

// Stage 1 correctness audit: argIsTainted/expressionIsTainted checked
// isSanitizedExpr() against the WHOLE argument text before ever looking at
// which identifiers are tainted — a common .NET idiom that combines a
// tainted value with an unrelated validity check (`string.IsNullOrEmpty`,
// `int.TryParse`, etc.) in the same expression short-circuited taint to
// false, because the sanitizer pattern matched somewhere in the text even
// though it had nothing to do with the tainted sub-expression.
test('analysis: an unrelated IsNullOrEmpty check elsewhere in the expression does not clear taint', () => {
  const ir = buildCSharpIR('class T { void M(string flag) { var comment = Request.QueryString["comment"]; Html.Raw(comment + (string.IsNullOrEmpty(flag) ? "[flag]" : "")); } }');
  const an = analyzeCSharpIR(ir);
  const flow = an.methodFlow.get(ir.methods[0]);
  assert.equal(flow.taintMap.get('comment'), true);
  assert.equal(expressionIsTainted(flow, 'comment + (string.IsNullOrEmpty(flag) ? "[flag]" : "")'), true);
});

test('detectXss: Html.Raw still fires when the tainted arg also contains an unrelated IsNullOrEmpty check', () => {
  const src = 'public class T : Controller { public void M(string flag) { var comment = Request.QueryString["comment"]; Html.Raw(comment + (string.IsNullOrEmpty(flag) ? "[flag]" : "")); } }';
  const findings = scanCSharp('T.cs', src);
  assert.ok(findings.some(f => /htmlraw|Html\.Raw/i.test(f.id) || /XSS/i.test(f.vuln)),
    `expected an XSS finding for Html.Raw(tainted), got: ${JSON.stringify(findings)}`);
});

test('analysis: Controller-derived class auto-taints public params', () => {
  const ir = buildCSharpIR('public class UsersController : Controller { public void Get(string id) { } }');
  const an = analyzeCSharpIR(ir);
  const flow = an.methodFlow.get(ir.methods[0]);
  assert.equal(flow.taintMap.get('id'), true);
});

test('analysis: non-controller class does NOT auto-taint params', () => {
  const ir = buildCSharpIR('public class Helper { public void DoSomething(string id) { } }');
  const an = analyzeCSharpIR(ir);
  const flow = an.methodFlow.get(ir.methods[0]);
  assert.notEqual(flow.taintMap.get('id'), true);
});

// ── Layer 4: attribute-driven routes ───────────────────────────────────────

test('routes: [HttpGet("/api/users")] becomes a GET route', () => {
  const ir = buildCSharpIR('public class UsersController : Controller { [HttpGet("/api/users")] public string Get() { return ""; } }');
  const an = analyzeCSharpIR(ir);
  assert.equal(an.routes.length, 1);
  assert.equal(an.routes[0].http, 'GET');
  assert.equal(an.routes[0].path, '/api/users');
});

test('routes: class-level [Authorize] propagates to method routes', () => {
  const ir = buildCSharpIR('[Authorize] public class UsersController { [HttpGet] public string Get() { return ""; } }');
  const an = analyzeCSharpIR(ir);
  assert.equal(an.routes[0].requiresAuth, true);
});

test('routes: method-level [AllowAnonymous] overrides class-level [Authorize]', () => {
  const ir = buildCSharpIR('[Authorize] public class C : Controller { [HttpGet][AllowAnonymous] public string Get() { return ""; } }');
  const an = analyzeCSharpIR(ir);
  assert.equal(an.routes[0].requiresAuth, false);
});

// ── End-to-end detectors ───────────────────────────────────────────────────

test('detector: SQL injection via SqlCommand ctor concatenation (with tainted source)', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public string Q() {
        var id = Request.Query["id"];
        var cmd = new SqlCommand("SELECT * FROM users WHERE id=" + id, conn);
        return cmd.ExecuteReader().ToString();
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'sql-injection'), 'SQL injection detected');
});

test('detector: clean SQL with parameterized query does NOT fire', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public string Q(int id) {
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        return cmd.ExecuteReader().ToString();
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(f => f.family === 'sql-injection'), 'parameterized SQL ignored');
});

test('detector: BinaryFormatter is always critical', () => {
  const src = 'class T { void M() { var bf = new BinaryFormatter(); } }';
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'insecure-deserialization' && f.severity === 'critical'));
});

test('detector: weak crypto MD5CryptoServiceProvider', () => {
  const src = 'class T { void M() { var h = new MD5CryptoServiceProvider(); } }';
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'weak-crypto'));
});

test('detector: hardcoded secret with crypto-naming + non-trivial literal', () => {
  const src = 'class T { void M() { var password = "hunter2longenough"; } }';
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'hardcoded-secret'));
});

test('detector: weak rng in crypto context', () => {
  const src = 'class T { void M() { var token = new Random().Next(); var password = "x12345678901"; } }';
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'weak-rng'));
});

test('detector: path traversal via Path.Combine with tainted segment', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public string Get(string fileName) {
        var p = Path.Combine("/uploads", fileName);
        return p;
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'path-traversal'));
});

test('detector: Html.Raw with tainted input is XSS', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public string Get(string user) {
        return Html.Raw(user);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'xss'));
});

test('detector: route-rooted unauth findings get severity bump', () => {
  const src = `
    public class C : Controller {
      [HttpPost("/run")][AllowAnonymous] public void Run(string args) {
        Process.Start("cmd.exe", args);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  const ci = findings.find(f => f.family === 'command-injection');
  assert.ok(ci);
  assert.equal(ci._inRoute && ci._inRoute.requiresAuth, false);
});

test('detector: idempotent — same source produces same finding ids', () => {
  const src = 'public class C : Controller { [HttpGet] public string Get(string id) { var cmd = new SqlCommand("x" + id); return cmd.ExecuteReader(); } }';
  const a = scanCSharp('t.cs', src).map(f => f.id).sort();
  const b = scanCSharp('t.cs', src).map(f => f.id).sort();
  assert.deepEqual(a, b);
});

test('detector: malformed C# does not throw', () => {
  const src = 'class { void M() { /* unclosed';
  assert.doesNotThrow(() => scanCSharp('t.cs', src));
});

// ── Expanded detectors: XSS / header / open-redirect / format / code-injection / path ─

test('detector: Response.Write with tainted input', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public void Get(string name) {
        Response.Write(name);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'xss' && /Response\.Write/.test(f.vuln)));
});

test('detector: Response.AddHeader with tainted input = header injection', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public void Get(string ua) {
        Response.AddHeader("X-User-Agent", ua);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'header-hardening' && f.cwe === 'CWE-113'));
});

test('detector: Response.Redirect with tainted URL = open redirect', () => {
  // [Authorize] keeps the route authenticated so the severity bump for
  // unauth routes doesn't fire — we get the detector's native 'high'.
  const src = `
    [Authorize]
    public class C : Controller {
      [HttpGet] public void Get(string url) {
        Response.Redirect(url);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.family === 'open-redirect');
  assert.ok(f);
  assert.equal(f.severity, 'high');
});

test('detector: LocalRedirect with tainted URL fires at medium severity', () => {
  const src = `
    [Authorize]
    public class C : Controller {
      [HttpGet] public IActionResult Get(string url) {
        return LocalRedirect(url);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.family === 'open-redirect');
  assert.ok(f);
  assert.equal(f.severity, 'medium');
});

test('detector: string.Format with tainted format string', () => {
  const src = `
    [Authorize]
    public class C : Controller {
      [HttpGet] public string Get(string fmt) {
        return string.Format(fmt, "hello");
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'format-string' && f.cwe === 'CWE-134'));
});

test('detector: string.Format with constant format + tainted ARG does NOT fire', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public string Get(string user) {
        return string.Format("hello {0}", user);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(f => f.family === 'format-string'));
});

test('detector: Assembly.Load with tainted assembly name = code injection', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public void Get(string asm) {
        System.Reflection.Assembly.Load(asm);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  // fullPath is "System.Reflection.Assembly.Load" but my regex matches "Assembly.Load" too
  assert.ok(findings.some(f => f.family === 'code-injection'));
});

test('detector: Activator.CreateInstance with tainted type name', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public object Get(string typeName) {
        return Activator.CreateInstance(typeName);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'code-injection'));
});

test('detector: File.OpenRead with tainted path = traversal', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public void Get(string file) {
        File.OpenRead(file);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'path-traversal' && /File\.OpenRead/.test(f.vuln)));
});

test('detector: new StreamReader(tainted) = traversal via ctor', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public string Get(string file) {
        var r = new StreamReader(file);
        return r.ReadToEnd();
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'path-traversal' && /StreamReader/.test(f.vuln)));
});

// ── Bench-shape gated Juliet-IO sources ────────────────────────────────────

test('analysis: IO.readLine() taints when BENCH_SHAPE=1', () => {
  process.env.AGENTIC_SECURITY_BENCH_SHAPE = '1';
  delete process.env.AGENTIC_SECURITY_BLIND_BENCH;
  try {
    const src = `
      class T {
        public void M() {
          string data = IO.readLine();
          var cmd = new SqlCommand("SELECT * WHERE id=" + data);
          cmd.ExecuteReader();
        }
      }`;
    const findings = scanCSharp('t.cs', src);
    assert.ok(findings.some(f => f.family === 'sql-injection'), 'IO.readLine taint propagates to SQL sink under BENCH_SHAPE=1');
  } finally {
    delete process.env.AGENTIC_SECURITY_BENCH_SHAPE;
  }
});

test('analysis: IO.readLine() does NOT taint under blind mode', () => {
  process.env.AGENTIC_SECURITY_BENCH_SHAPE = '1';
  process.env.AGENTIC_SECURITY_BLIND_BENCH = '1';
  try {
    const src = `
      class T {
        public void M() {
          string data = IO.readLine();
          var cmd = new SqlCommand("SELECT * WHERE id=" + data);
        }
      }`;
    const findings = scanCSharp('t.cs', src);
    assert.ok(!findings.some(f => f.family === 'sql-injection'), 'IO.readLine is NOT a source in blind mode');
  } finally {
    delete process.env.AGENTIC_SECURITY_BENCH_SHAPE;
    delete process.env.AGENTIC_SECURITY_BLIND_BENCH;
  }
});
