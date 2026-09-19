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

test('detector: BinaryFormatter.Deserialize of tainted data is critical', () => {
  const src = `
    public class C {
      [HttpGet] public object M(HttpRequest req) {
        var stream = req.Body;
        var bf = new BinaryFormatter();
        return bf.Deserialize(stream);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'insecure-deserialization' && f.severity === 'critical'));
});

// A bare `new BinaryFormatter()` with no `.Deserialize()` call at all
// (common shared network/file helper boilerplate reused across many
// unrelated files) must not fire — flagging usage alone, independent of
// what it actually deserializes, was measured causing 417 false positives
// on the SARD/Juliet C# corpus, almost all in directories unrelated to
// CWE-502. See detectInsecureDeserialization's own comment.
test('detector: a bare BinaryFormatter declaration with no Deserialize call does NOT fire', () => {
  const src = 'class T { void M() { var bf = new BinaryFormatter(); } }';
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(f => f.family === 'insecure-deserialization'));
});

// Deserializing a LOCAL/hardcoded stream (never touched by network, file,
// or request input) is not the exploitable shape this rule targets.
test('detector: BinaryFormatter.Deserialize of an untainted local stream does NOT fire', () => {
  const src = `
    class T {
      void M() {
        var stream = new MemoryStream(new byte[] { 1, 2, 3 });
        var bf = new BinaryFormatter();
        var obj = bf.Deserialize(stream);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(f => f.family === 'insecure-deserialization'));
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
  // the declared form is caught exactly once, not double-counted by the
  // new inline-chain scan added for W4.C25 below.
  assert.equal(findings.filter(f => f.family === 'weak-rng').length, 1);
});

// SARD_80_F1 W4.C25 — Juliet's own CWE-338 (Weak PRNG) convention never
// declares the Random object at all: `new Random()` is constructed and
// chained off INLINE, directly as a call argument
// (`IO.WriteLine("" + new Random().NextDouble());`) — confirmed against the
// public C# mirror (CWE338_Weak_PRNG__random_01.cs). The old code only ever
// scanned `ir.decls`, a total blackout for this whole descriptor family.
test('detector: weak rng via an INLINE new Random() chained call (no declaration at all)', () => {
  const src = 'using System.Security.Cryptography;\nclass T { void Bad() { IO.WriteLine("" + new Random().NextDouble()); } }';
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'weak-rng' && f.cwe === 'CWE-330'));
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

// SARD_80_F1 W4.C41 bonus fix — a sibling of the precision case directly
// above, but where the constant-format `string.Format(...)` call is itself
// NESTED as another sink's own argument (`Console.Write(string.Format(
// "{0}{1}", data, ...))`, the real Juliet Good() shape). The outer sink
// check previously saw ANY identifier anywhere in its own argument's
// flattened text as disqualifying — including one used safely as a VALUE
// deep inside a nested, literal-first `string.Format` call — so this exact
// safe idiom was misclassified as vulnerable.
test('detector: Console.Write(string.Format(constant, tainted-VALUE)) does NOT fire — nested literal-first format is safe', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public void Get(string user) {
        Console.Write(string.Format("hello {0}", user));
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(f => f.family === 'format-string'), `expected no format-string finding, got: ${findings.map(f => f.vuln).join(',')}`);
});

test('detector: Console.Write(string.Format(tainted)) still fires — the tainted value IS the format string, just nested one level deeper', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public void Get(string fmt) {
        Console.Write(string.Format(fmt));
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'format-string' && f.cwe === 'CWE-134'), `expected a format-string finding, got: ${findings.map(f => f.vuln).join(',')}`);
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

// ── Cleartext storage of sensitive data — CWE-313/314/315 ──────────────────

test('detector: CWE-313 File.WriteAllText with a sensitive-named value', () => {
  const src = 'class T { void M() { string password = "hunter2longenough"; File.WriteAllText("/tmp/out.txt", password); } }';
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.id.startsWith('csharp-cleartext-file:'));
  assert.ok(f, 'expected csharp-cleartext-file finding');
  assert.equal(f.family, 'data-exposure');
  assert.equal(f.cwe, 'CWE-313');
});

test('detector: CWE-313 File.WriteAllText with a non-sensitive value does NOT fire', () => {
  const src = 'class T { void M() { string greeting = "hello"; File.WriteAllText("/tmp/out.txt", greeting); } }';
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(x => x.id.startsWith('csharp-cleartext-file:')));
});

test('detector: CWE-313 File.WriteAllText with a SecureString-wrapped value and no prior hashing (Juliet shape)', () => {
  const src = `
    class T {
      void Bad() {
        char[] data = System.Console.ReadLine().ToCharArray();
        SecureString secureData = new SecureString();
        for (int i = 0; i < data.Length; i++) {
          secureData.AppendChar(data[i]);
        }
        File.WriteAllText(@"C:\\Users\\Public\\WriteText.txt", secureData.ToString());
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.id.startsWith('csharp-cleartext-file:'));
  assert.ok(f, 'expected csharp-cleartext-file finding for an un-hashed SecureString-wrapped sink value');
  assert.equal(f.cwe, 'CWE-313');
});

test('detector: CWE-313 does NOT fire when the value is hashed before the SecureString wrap (Juliet Good() shape)', () => {
  const src = `
    class T {
      void Good() {
        char[] data = System.Console.ReadLine().ToCharArray();
        byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(new string(data));
        SHA512CryptoServiceProvider provider = new SHA512CryptoServiceProvider();
        byte[] resultBytes = provider.ComputeHash(dataBytes);
        SecureString secureData = new SecureString();
        for (int i = 0; i < resultBytes.Length; i++) {
          secureData.AppendChar((char)resultBytes[i]);
        }
        File.WriteAllText(@"C:\\Users\\Public\\WriteText.txt", secureData.ToString());
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(x => x.id.startsWith('csharp-cleartext-file:')));
});

test('detector: a bare .ToString() reaching a cleartext-storage sink does NOT fire when the receiver is not declared SecureString', () => {
  const src = `
    class T {
      void M() {
        object other = new object();
        File.WriteAllText("/tmp/out.txt", other.ToString());
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(x => x.id.startsWith('csharp-cleartext-file:')));
});

test('detector: CWE-313 StreamWriter.Write with a sensitive-named value', () => {
  const src = `
    class T {
      void M() {
        string password = "hunter2longenough";
        StreamWriter sw = new StreamWriter("/tmp/out.txt");
        sw.Write(password);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.id.startsWith('csharp-cleartext-file-writer:'));
  assert.ok(f, 'expected csharp-cleartext-file-writer finding');
  assert.equal(f.cwe, 'CWE-313');
});

test('detector: CWE-313 does NOT fire on Response writer (that is XSS territory, not file storage)', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public void Get() {
        string password = "hunter2longenough";
        Response.Output.Write(password);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(x => x.id.startsWith('csharp-cleartext-file-writer:')));
});

test('detector: CWE-314 Registry.SetValue with a sensitive-named value', () => {
  const src = 'class T { void M() { string password = "hunter2longenough"; Registry.SetValue(@"HKEY_CURRENT_USER\\\\Software\\\\App", "pw", password); } }';
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.id.startsWith('csharp-cleartext-registry:'));
  assert.ok(f, 'expected csharp-cleartext-registry finding');
  assert.equal(f.cwe, 'CWE-314');
});

test('detector: CWE-314 RegistryKey.SetValue with a bare SecureString-wrapped value, no prior hashing (Juliet shape)', () => {
  const src = `
    class T {
      void Bad() {
        string data = System.Console.ReadLine();
        using (SecureString secureData = new SecureString()) {
          for (int i = 0; i < data.Length; i++) {
            secureData.AppendChar(data[i]);
          }
          RegistryKey key = Registry.CurrentUser.OpenSubKey("Software", true);
          key.CreateSubKey("CWEparent");
          key = key.OpenSubKey("CWEparent", true);
          key.SetValue("CWE", secureData);
        }
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.id.startsWith('csharp-cleartext-registry:'));
  assert.ok(f, 'expected csharp-cleartext-registry finding for a bare SecureString-wrapped sink value');
  assert.equal(f.cwe, 'CWE-314');
});

test('detector: CWE-314 does NOT fire when the value is hashed before the SecureString wrap (Juliet GoodB2G shape)', () => {
  const src = `
    class T {
      void GoodB2G() {
        string data = System.Console.ReadLine();
        string salt = "ThisIsMySalt";
        using (SHA512CryptoServiceProvider sha512 = new SHA512CryptoServiceProvider()) {
          byte[] buffer = System.Text.Encoding.UTF8.GetBytes(string.Concat(salt, data));
          byte[] hashedCredsAsBytes = sha512.ComputeHash(buffer);
          data = IO.ToHex(hashedCredsAsBytes);
        }
        using (SecureString secureData = new SecureString()) {
          for (int i = 0; i < data.Length; i++) {
            secureData.AppendChar(data[i]);
          }
          RegistryKey key = Registry.CurrentUser.OpenSubKey("Software", true);
          key.SetValue("CWE", secureData);
        }
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(x => x.id.startsWith('csharp-cleartext-registry:')));
});

test('detector: CWE-315 new HttpCookie with a sensitive-named value', () => {
  const src = 'class T { void M() { string password = "hunter2longenough"; HttpCookie c = new HttpCookie("auth", password); } }';
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.id.startsWith('csharp-cleartext-cookie:'));
  assert.ok(f, 'expected csharp-cleartext-cookie finding');
  assert.equal(f.cwe, 'CWE-315');
});

test('detector: CWE-315 Response.Cookies[...].Value = sensitive value', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public void Get() {
        string password = "hunter2longenough";
        Response.Cookies["auth"].Value = password;
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.id.startsWith('csharp-cleartext-cookie-assign:'));
  assert.ok(f, 'expected csharp-cleartext-cookie-assign finding');
  assert.equal(f.cwe, 'CWE-315');
});

test('detector: CWE-315 new HttpCookie with a non-sensitive value does NOT fire', () => {
  const src = 'class T { void M() { string label = "welcome-banner-seen"; HttpCookie c = new HttpCookie("ui", label); } }';
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(x => x.id.startsWith('csharp-cleartext-cookie:')));
});

// CWE-523 (Unprotected Transport of Credentials) — a "point flaw", not a
// taint-flow vulnerability: Juliet's real shape (confirmed via the public
// Juliet C# mirror this project's manifest pins,
// CWE523_Unprotected_Cred_Transport__Web_01.cs) is a hardcoded HTML
// <form> whose action='http://...' submits a password field, split
// across several resp.Write(...) calls with no data flow at all. This is
// a genuinely new, scramble-safe capability (string literal content is
// unaffected by --scramble-identifiers).
test('detector: CWE-523 a login form action using http:// fires', () => {
  const src = `
    public class C {
      public void Bad(HttpRequest req, HttpResponse resp) {
        resp.Write("<form action='http://hostname.com/j_security_check' method='post'>");
        resp.Write("<table>");
        resp.Write("<tr><td>Password:</td>");
        resp.Write("<td><input type='password' name='j_password' size='8'></td>");
        resp.Write("</form>");
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.id.startsWith('csharp-unprotected-cred-transport:'));
  assert.ok(f, 'expected csharp-unprotected-cred-transport finding');
  assert.equal(f.cwe, 'CWE-523');
});

test('detector: CWE-523 the same form over https:// does NOT fire', () => {
  const src = `
    public class C {
      public void Good(HttpRequest req, HttpResponse resp) {
        resp.Write("<form action='https://hostname.com/j_security_check' method='post'>");
        resp.Write("<tr><td>Password:</td>");
        resp.Write("<td><input type='password' name='j_password' size='8'></td>");
        resp.Write("</form>");
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(x => x.id.startsWith('csharp-unprotected-cred-transport:')));
});

test('detector: CWE-523 a non-credential http:// form does NOT fire (requires a password field too)', () => {
  const src = `
    public class C {
      public void M(HttpRequest req, HttpResponse resp) {
        resp.Write("<form action='http://hostname.com/search' method='get'>");
        resp.Write("<input type='text' name='q'>");
        resp.Write("</form>");
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(x => x.id.startsWith('csharp-unprotected-cred-transport:')));
});

// CWE-539 (Information Exposure Through Persistent Cookie) — another
// "point flaw", same shape class as CWE-523: Juliet's real C# example
// (confirmed via the public Juliet mirror this project's manifest pins,
// CWE539_..._Web_01.cs) sets a future/computed expiration (persistent)
// vs. DateTime.MinValue (session-only, safe). No taint at all.
test('detector: CWE-539 cookie.Expires set to a future date fires', () => {
  const src = `
    public class C {
      public void Bad(HttpRequest req, HttpResponse resp) {
        HttpCookie cookie = new HttpCookie("SecretMessage", "test");
        cookie.Expires = DateTime.Now.AddDays(1825.00);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.id.startsWith('csharp-persistent-cookie:'));
  assert.ok(f, 'expected csharp-persistent-cookie finding');
  assert.equal(f.cwe, 'CWE-539');
});

test('detector: CWE-539 cookie.Expires = DateTime.MinValue does NOT fire', () => {
  const src = `
    public class C {
      public void Good(HttpRequest req, HttpResponse resp) {
        HttpCookie cookie = new HttpCookie("SecretMessage", "test");
        cookie.Expires = DateTime.MinValue;
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(x => x.id.startsWith('csharp-persistent-cookie:')));
});

// SARD_80_F1 W4.C14 — same-file callee return-taint resolution (fixes
// `argIsTainted`'s over-tainting bug: a call like `GoodG2BSource(req, resp)`
// used to taint its assignment target purely because `req`/`resp` are
// unconditionally-tainted HTTP-typed params, textually present in the call,
// regardless of whether the callee's return actually derives from them).
test('detector: a helper that returns a hardcoded literal does NOT taint its caller, even though it receives already-tainted HTTP params', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public void Get(HttpRequest req, HttpResponse resp) {
        string data = GoodG2BSource(req, resp);
        var cmd = new SqlCommand("SELECT * FROM t WHERE x='" + data + "'");
      }
      private string GoodG2BSource(HttpRequest req, HttpResponse resp) {
        return "hardcoded-safe-value";
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(f => f.family === 'sql-injection'), `expected no SQLi finding, got: ${findings.map(f => f.family).join(',')}`);
});

test('detector: a helper that genuinely reads from the request still taints its caller', () => {
  const src = `
    public class C : Controller {
      [HttpGet] public void Get(HttpRequest req, HttpResponse resp) {
        string data = BadSource(req, resp);
        var cmd = new SqlCommand("SELECT * FROM t WHERE x='" + data + "'");
      }
      private string BadSource(HttpRequest req, HttpResponse resp) {
        return req.QueryString["x"];
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'sql-injection'), `expected a SQLi finding, got: ${findings.map(f => f.family).join(',')}`);
});

// SARD_80_F1 W4.C14 — a declaration/assignment/return with no `;` of its
// own, nested inside an enclosing `using (Type x = expr)` clause. Found
// while verifying the fix above: `using (StreamReader sr = new
// StreamReader("f")) { data = sr.ReadLine(); }` used to have its `data =
// sr.ReadLine()` assignment silently swallowed into `sr`'s own decl
// rhsText (the depth-tracking RHS scanner mistook the using-clause's own
// closing paren for one it needed to balance itself, then kept scanning
// for a `;` clear through the following statement).
test('a value read via an instance of StreamReader inside `using (...)` still carries taint through a same-file callee', () => {
  const src = `
    public class C : Controller {
      private bool badPrivate = false;
      [HttpGet] public void Bad(HttpRequest req, HttpResponse resp) {
        badPrivate = true;
        string data = Bad_source(req, resp);
        var cmd = new SqlCommand("SELECT * FROM t WHERE x='" + data + "'");
      }
      private string Bad_source(HttpRequest req, HttpResponse resp) {
        string data;
        if (badPrivate) {
          data = "";
          using (StreamReader sr = new StreamReader("data.txt")) {
            data = sr.ReadLine();
          }
        } else {
          data = null;
        }
        return data;
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'sql-injection'), `expected a SQLi finding via the file-read source, got: ${findings.map(f => f.family).join(',')}`);
});

// SARD_80_F1 W4.C34 — a sibling gap to the StreamReader one above: a database
// row read via `SqlDataReader.GetString()`/`GetValue()`/etc. is every bit as
// untrusted a source as a file/stream read, but had no entry at all in
// `DATAREADER_SOURCE_TYPES`. Confirmed via the public C# Juliet mirror,
// `CWE23_Relative_Path_Traversal__Database_01.cs`: `SqlDataReader dr =
// command.ExecuteReader(); data = dr.GetString(1);` — Juliet's own idiomatic
// variable name (`dr`) contains no "reader" substring, but this detector's
// type-based lookup doesn't depend on the variable's name at all.
test('a value read via SqlDataReader.GetString() is a taint source, independent of the variable name', () => {
  const src = `
    public class C {
      public void Bad() {
        string data;
        using (SqlDataReader dr = command.ExecuteReader()) {
          data = dr.GetString(1);
        }
        string root = "/home/user/uploads/";
        if (File.Exists(root + data)) {
          using (StreamReader sr = new StreamReader(root + data)) {
          }
        }
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'path-traversal'), `expected a path-traversal finding via the SqlDataReader source, got: ${findings.map(f => f.family).join(',')}`);
});

test('a value read via SqlDataReader.GetString() from a variable whose declared type is NOT a DataReader does not fire', () => {
  const src = `
    public class C {
      public void Good() {
        string data;
        using (SomeUnrelatedType dr = GetSomething()) {
          data = dr.GetString(1);
        }
        string root = "/home/user/uploads/";
        if (File.Exists(root + data)) {
          using (StreamReader sr = new StreamReader(root + data)) {
          }
        }
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(f => f.family === 'path-traversal'), `expected no path-traversal finding for a non-DataReader GetString() call, got: ${findings.map(f => f.family).join(',')}`);
});

// SARD_80_F1 W4.C41 — same-file, single-hop caller-argument taint. This
// analyzer's `taintMap` seeding previously only ever considered a method's
// OWN declared params (route-handler convention / HTTP-typed param), never
// what a CALLER actually passed it — the file's own top-level comment
// listed "aliased sources via method indirection" as a known miss.
// Confirmed via the public C# Juliet mirror's own
// `CWE36_Absolute_Path_Traversal__Params_Get_Web_41.cs` (Flow Variant 41:
// "data passed as an argument from one method to another in the same
// class"): a route handler reads `req.Params.Get("name")`, then calls a
// PRIVATE STATIC sink-wrapper helper with it — the direct single-method
// form of this exact sink already fired; the moment the value crossed a
// same-file method-call boundary, it vanished entirely (confirmed: zero
// findings from any detector, structural or deep-engine).
test('a tainted value passed as an argument to a same-file private helper method reaches the helper\'s own sink', () => {
  const src = `
    public class C : AbstractTestCaseWeb {
      private static void BadSink(string data, HttpRequest req, HttpResponse resp) {
        if (data != null) {
          if (File.Exists(data)) {
            using (StreamReader sr = new StreamReader(data)) {
            }
          }
        }
      }
      public override void Bad(HttpRequest req, HttpResponse resp) {
        string data;
        data = req.Params.Get("name");
        BadSink(data, req, resp);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'path-traversal'), `expected a path-traversal finding via the same-file argument-passed source, got: ${findings.map(f => f.family).join(',')}`);
});

test('a hardcoded (non-tainted) value passed as an argument to a same-file private helper method does not fire', () => {
  const src = `
    public class C : AbstractTestCaseWeb {
      private static void GoodSink(string data, HttpRequest req, HttpResponse resp) {
        if (data != null) {
          if (File.Exists(data)) {
            using (StreamReader sr = new StreamReader(data)) {
            }
          }
        }
      }
      public override void Good(HttpRequest req, HttpResponse resp) {
        string data;
        data = "foo";
        GoodSink(data, req, resp);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(f => f.family === 'path-traversal'), `expected no path-traversal finding for a hardcoded argument, got: ${findings.map(f => f.family).join(',')}`);
});

test('an ambiguous same-named helper method (2+ candidates project-wide) is left unresolved, not guessed', () => {
  const src = `
    public class Bad1 : AbstractTestCaseWeb {
      private static void Sink(string data, HttpRequest req, HttpResponse resp) {
        if (data != null) {
          if (File.Exists(data)) {
            using (StreamReader sr = new StreamReader(data)) {
            }
          }
        }
      }
      public override void Run(HttpRequest req, HttpResponse resp) {
        string data;
        data = "foo";
        Sink(data, req, resp);
      }
    }
    public class Bad2 : AbstractTestCaseWeb {
      private static void Sink(string data, HttpRequest req, HttpResponse resp) {
        if (data != null) {
          if (File.Exists(data)) {
            using (StreamReader sr = new StreamReader(data)) {
            }
          }
        }
      }
      public override void Run(HttpRequest req, HttpResponse resp) {
        string data;
        data = req.Params.Get("name");
        Sink(data, req, resp);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(f => f.family === 'path-traversal'), `expected no path-traversal finding when the callee name is ambiguous across classes, got: ${findings.map(f => f.family).join(',')}`);
});

// SARD_80_F1 W5.30 — Juliet's own cross-class "Flow Variant 51: data passed
// as an argument from one method to another in different classes in the
// same package" idiom (confirmed via the public C# mirror's own
// CWE36_..._Params_Get_Web_51a.cs/_51b.cs pair) was invisible even in the
// SAME FILE before this fix: the taint-seeding loop unconditionally skipped
// ANY receiver-qualified call (`call.receiver` truthy), with no exception
// for a static cross-class call. Resolvable only when the receiver text
// names a REAL class declared in the SAME file AND the matched candidate is
// itself `static` (C# cannot compile `ClassName.InstanceMethod()`, so a
// non-static match means the receiver was very likely a coincidentally
// same-named instance variable, not a genuine class qualifier).
test('a tainted value passed to a DIFFERENT class\'s static method (same file) reaches that method\'s own sink', () => {
  const src = `
    public class Caller : AbstractTestCaseWeb {
      public override void Bad(HttpRequest req, HttpResponse resp) {
        string data;
        data = req.Params.Get("name");
        Sink.BadSink(data, req, resp);
      }
    }
    public class Sink {
      public static void BadSink(string data, HttpRequest req, HttpResponse resp) {
        if (data != null) {
          if (File.Exists(data)) {
            using (StreamReader sr = new StreamReader(data)) {
            }
          }
        }
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(findings.some(f => f.family === 'path-traversal'), `expected a path-traversal finding via the cross-class argument-passed source, got: ${findings.map(f => f.family).join(',')}`);
});

test('a hardcoded value passed to a DIFFERENT class\'s static method (same file) does not fire', () => {
  const src = `
    public class Caller : AbstractTestCaseWeb {
      public override void Good(HttpRequest req, HttpResponse resp) {
        string data;
        data = "foo";
        Sink.GoodSink(data, req, resp);
      }
    }
    public class Sink {
      public static void GoodSink(string data, HttpRequest req, HttpResponse resp) {
        if (data != null) {
          if (File.Exists(data)) {
            using (StreamReader sr = new StreamReader(data)) {
            }
          }
        }
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(f => f.family === 'path-traversal'), `expected no path-traversal finding for a hardcoded cross-class argument, got: ${findings.map(f => f.family).join(',')}`);
});

test('a receiver that names a class but resolves only to a NON-STATIC method is left unresolved (likely a same-named instance variable, not a class qualifier)', () => {
  const src = `
    public class Helper : AbstractTestCaseWeb {
      public override void Bad(HttpRequest req, HttpResponse resp) {
        string data;
        data = req.Params.Get("name");
        Helper.BadSink(data, req, resp);
      }
      private void BadSink(string data, HttpRequest req, HttpResponse resp) {
        if (data != null) {
          if (File.Exists(data)) {
            using (StreamReader sr = new StreamReader(data)) {
            }
          }
        }
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(f => f.family === 'path-traversal'), `a non-static candidate must not be resolved via the class-name receiver path, got: ${findings.map(f => f.family).join(',')}`);
});

test('IR: a `using (Type x = expr)` declaration is not corrupted by the enclosing clause\'s own closing paren', () => {
  const src = 'class C { void M() { using (StreamReader sr = new StreamReader("f")) { data = sr.ReadLine(); } } }';
  const ir = buildCSharpIR(src);
  const m = ir.methods.find(x => x.name === 'M');
  const sr = m.decls.find(d => d.name === 'sr');
  assert.equal(sr.rhsText, 'new StreamReader("f")', `expected clean rhsText, got: ${JSON.stringify(sr.rhsText)}`);
  assert.ok(m.assignments.some(a => a.target === 'data' && a.rhsText === 'sr.ReadLine()'), `expected data=sr.ReadLine() as its own assignment, got: ${m.assignments.map(a => `${a.target}=${a.rhsText}`).join(' | ')}`);
});

// SARD_80_F1 W2.8 — CWE-261 (Weak Cryptography for Passwords), a "point
// flaw" like CWE-523/539: no taint needed. The corpus's real shape
// (confirmed via the public C# mirror,
// CWE261_Weak_Cryptography_for_Passwords__NetworkCredential_01.cs) uses
// Convert.FromBase64String AS IF it were decryption of a stored password.
test('detector: CWE-261 Convert.FromBase64String on a password-shaped variable fires', () => {
  const src = `
    public class C {
      public void Bad() {
        string password = "";
        password = sr.ReadLine();
        string decPass = Encoding.UTF8.GetString(Convert.FromBase64String(password));
        NetworkCredential netCred = new NetworkCredential("x", decPass, "");
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  const f = findings.find(x => x.cwe === 'CWE-261');
  assert.ok(f, 'expected a CWE-261 finding');
  assert.equal(f.family, 'weak-crypto');
});

test('detector: CWE-261 does NOT fire when real encryption (AesCryptoServiceProvider) is used instead', () => {
  const src = `
    public class C {
      private void Good1() {
        byte[] encryptedPassword = File.ReadAllBytes("f.bin");
        string decPass = null;
        using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider()) {
          aesAlg.Key = Encoding.UTF8.GetBytes("ABCDEFGHABCDEFGH");
        }
        NetworkCredential netCred = new NetworkCredential("x", decPass, "");
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(x => x.cwe === 'CWE-261'), 'expected no CWE-261 finding when Base64 decoding is never used');
});

test('detector: CWE-261 does NOT fire on Convert.FromBase64String applied to an unrelated (non-password-shaped) variable', () => {
  const src = `
    public class C {
      public void M() {
        string payload = GetPayload();
        byte[] bytes = Convert.FromBase64String(payload);
      }
    }`;
  const findings = scanCSharp('t.cs', src);
  assert.ok(!findings.some(x => x.cwe === 'CWE-261'), 'expected no CWE-261 finding for an unrelated Base64 decode');
});
