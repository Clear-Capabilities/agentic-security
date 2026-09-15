// Taint-engine PRD P1 — C# catalog additions found missing during the
// investigation: Redirect/LocalRedirect (open redirect), Response.Write
// (XSS), Response.AddHeader (header injection), XmlDocument.Load/LoadXml
// (XXE), DirectorySearcher (LDAP injection). None of these CWEs (601, 79,
// 113, 611, 90) could be IR-TAINT-caught without a sink entry, regardless
// of engine quality. Each test proves the entry fires end-to-end on a
// genuinely tainted example.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-cs-catalog-p1-${name}-`));
  fs.writeFileSync(path.join(dir, 'C.cs'), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('cs-redirect: Controller.Redirect(userInput) fires Open Redirect via IR-TAINT', async () => {
  const dir = mkTmp('redirect', `
public class C : Controller {
    public IActionResult Go([FromQuery] string next) {
        return Redirect(next);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /redirect/i.test(`${f.vuln} ${f.cwe}`)),
    `expected Open Redirect, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-localredirect: Controller.LocalRedirect(userInput) fires Open Redirect via IR-TAINT', async () => {
  const dir = mkTmp('localredirect', `
public class C : Controller {
    public IActionResult Go([FromQuery] string next) {
        return LocalRedirect(next);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /redirect/i.test(`${f.vuln} ${f.cwe}`)),
    `expected Open Redirect, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-response-write: Response.Write(userInput) fires XSS via IR-TAINT', async () => {
  const dir = mkTmp('response-write', `
public class C {
    public void Handler([FromQuery] string name, HttpResponse Response) {
        Response.Write(name);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss|cross.site/i.test(`${f.vuln} ${f.cwe}`)),
    `expected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-response-write precision: a differently-receivered .Write(...) does not fire this sink', async () => {
  const dir = mkTmp('response-write-clean', `
public class C {
    public void Handler([FromQuery] string name) {
        Console.Write(name);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /xss|cross.site/i.test(`${f.vuln} ${f.cwe}`)).length, 0,
    `Console.Write must not trigger the Response.Write sink, got: ${taint.map(f => f.vuln).join(', ')}`);
});

// SARD_80_F1 W4: `HtmlTextWriter` (ASP.NET Web Forms' dominant XSS-sink
// shape, 495 dev cases per the PRD) had NO catalog coverage at all before
// this. Declared-type resolution (`class-hierarchy.js`'s `typeOfVar`,
// seeded by `parser-cs.js`'s new `declaredType` field) lets this fire
// even on a NON-conventionally-named variable, via `receiverTypeIn` —
// the `htw` name below deliberately does NOT match the entry's
// name-based `receiver` fallback, isolating the type-based path.
test('cs-htmltextwriter-write: a declared-type HtmlTextWriter (non-conventional name) fires XSS via IR-TAINT', async () => {
  const dir = mkTmp('htmltextwriter', `
public class C {
    public void Handler([FromQuery] string data) {
        HtmlTextWriter htw = new HtmlTextWriter(Console.Out);
        htw.Write(data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss|cross.site/i.test(`${f.vuln} ${f.cwe}`)),
    `expected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// ASP.NET Web Forms' DOMINANT HtmlTextWriter idiom: a PARAMETER, not a
// local declaration (`protected override void Render(HtmlTextWriter w)`).
// parser-cs.js now also extracts `fn.paramTypes` (mirroring parser-java.js),
// consumed by the SAME `class-hierarchy.js` `typeOfVar` mechanism as the
// declared-local-variable case above. Non-conventional param name (`htw`)
// isolates the type-based path from the name-based `receiver` fallback.
test('cs-htmltextwriter-write (parameter form): Render(HtmlTextWriter htw) fires XSS via IR-TAINT', async () => {
  const dir = mkTmp('htmltextwriter-param', `
public class MyControl {
    protected override void Render(HtmlTextWriter htw) {
        string data = Request.QueryString["name"];
        htw.Write(data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss|cross.site/i.test(`${f.vuln} ${f.cwe}`)),
    `expected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-htmltextwriter-write precision: an unrelated .Write(...) (Console) does not fire this sink', async () => {
  const dir = mkTmp('htmltextwriter-clean', `
public class C {
    public void Handler([FromQuery] string data) {
        Console.Write(data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /HtmlTextWriter/i.test(f.vuln)).length, 0,
    `Console.Write must not trigger the HtmlTextWriter sink, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('cs-response-addheader: Response.AddHeader(name, userInput) fires header injection via IR-TAINT', async () => {
  const dir = mkTmp('addheader', `
public class C {
    public void Handler([FromQuery] string val, HttpResponse Response) {
        Response.AddHeader("X-Custom", val);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /header|splitting/i.test(`${f.vuln} ${f.cwe}`)),
    `expected Header Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-xmldoc-load: XmlDocument.Load(userInput) fires XXE via IR-TAINT', async () => {
  const dir = mkTmp('xmlload', `
public class C {
    public void Handler([FromQuery] string path) {
        var xmlDoc = new XmlDocument();
        xmlDoc.Load(path);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xxe|xml/i.test(`${f.vuln} ${f.cwe}`)),
    `expected XXE, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-xmldoc-loadxml: XmlDocument.LoadXml(userInput) fires XXE via IR-TAINT', async () => {
  const dir = mkTmp('loadxml', `
public class C {
    public void Handler([FromQuery] string xml) {
        var doc = new XmlDocument();
        doc.LoadXml(xml);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xxe|xml/i.test(`${f.vuln} ${f.cwe}`)),
    `expected XXE, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-directorysearcher: new DirectorySearcher(concatenated filter) fires LDAP injection via IR-TAINT', async () => {
  const dir = mkTmp('ldap', `
public class C {
    public void Handler([FromQuery] string uid) {
        var filter = "(uid=" + uid + ")";
        var searcher = new DirectorySearcher(filter);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(`${f.vuln} ${f.cwe}`)),
    `expected LDAP Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// Taint-recall PRD (80%): the idiomatic real-world shape — property
// assignment, not a constructor argument. Verified against the real corpus
// fixture (bench/cve-replay/capability/CVE-2020-1722-csharp-ldap) that the
// entry above does NOT fire on this shape; that fixture itself additionally
// lacks a recognized source (bare unannotated param), so it needs Tier 2
// fixture enrichment on top of this sink before it flips in the corpus.
test('cs-directorysearcher-filter: searcher.Filter = concatenated value fires LDAP injection via IR-TAINT (property-assignment shape)', async () => {
  const dir = mkTmp('ldap-filter', `
public class C {
    public void Handler([FromQuery] string uid) {
        var searcher = new DirectorySearcher();
        searcher.Filter = "(uid=" + uid + ")";
        searcher.FindAll();
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(`${f.vuln} ${f.cwe}`)),
    `expected LDAP Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-directorysearcher-filter precision: an unrelated .Filter assignment on a non-search-named receiver does not fire', async () => {
  const dir = mkTmp('ldap-filter-clean', `
public class C {
    public void Handler([FromQuery] string mode) {
        var imageOptions = new ImageOptions();
        imageOptions.Filter = mode;
    }
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /ldap/i.test(`${f.vuln} ${f.cwe}`)).length, 0,
    `an unrelated .Filter= must not trigger the LDAP sink, got: ${taint.map(f => f.vuln).join(', ')}`);
});

// SARD_80_F1_SCANNER_PRD.md §9/§15.1: the name regex above is a real
// precision heuristic (see the precision test just above), but it is also
// exactly what identifier scrambling defeats — and what an ordinary
// codebase that just doesn't name the variable "searcher" would defeat too.
// `receiverTypeIn: ['^DirectorySearcher$']` on the catalog entry lets the
// CHA-resolved allocation type carry the same signal independent of naming.
test('cs-directorysearcher-filter: fires via CHA-resolved allocation type even when the receiver is NOT named search-like', async () => {
  const dir = mkTmp('ldap-filter-renamed', `
public class C {
    public void Handler([FromQuery] string uid) {
        var _q7f = new DirectorySearcher();
        _q7f.Filter = "(uid=" + uid + ")";
        _q7f.FindAll();
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(`${f.vuln} ${f.cwe}`)),
    `expected LDAP Injection via allocation-type resolution, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// The type-based path must stay just as precise as the name-based path: a
// receiver confidently typed as something OTHER than DirectorySearcher must
// not fire merely because its (irrelevant) name also fails the regex.
test('cs-directorysearcher-filter precision: a non-search-named receiver whose CHA type is NOT DirectorySearcher still does not fire', async () => {
  const dir = mkTmp('ldap-filter-typed-clean', `
public class C {
    public void Handler([FromQuery] string mode) {
        var _q7f = new ImageOptions();
        _q7f.Filter = mode;
    }
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /ldap/i.test(`${f.vuln} ${f.cwe}`)).length, 0,
    `a differently-typed receiver must not trigger the LDAP sink, got: ${taint.map(f => f.vuln).join(', ')}`);
});

// ── Interprocedural regression proof (SARD_AGENTIC_SECURITY_PRD.md
//    adversarial-premortem remediation, Round 1 F5/F17) — nothing in this
//    file previously covered cross-method C# taint flow at all.
//
// This proof exists because of a real, self-caught mistake worth recording
// so it isn't quietly repeated: a first investigation pass concluded C#'s
// interprocedural taint engine was broken, based on a two-method fixture
// using `request.Params["cmd"]` (LOWERCASE `request`) producing 0 findings
// against a single-method version of the same fixture producing 1. Before
// that conclusion was written down as fact, the SINGLE-method finding's
// `parser` field was checked and turned out to be `CSHARP` — a single-
// function-scoped SAST STRUCTURAL detector, not `IR-TAINT`. `catalog.js`'s
// `MEMBER_INDEX` lookup for `cs-request-params` (`{object: 'Request', prop:
// 'Params'}`) is a case-SENSITIVE exact-string key, so lowercase
// `request.Params[...]` never matched any real taint source in EITHER
// fixture — the "single-method success" was a coincidental structural-
// detector hit that doesn't span function boundaries, not evidence of
// working taint, and the "two-method failure" was just the continued
// absence of any real source. With the casing fixed to match the real
// catalog entry (`Request.Params[...]`), BOTH shapes correctly produce an
// `IR-TAINT` finding — proven below with two independent sinks. See
// bench/sard/IMPLEMENTATION_STATUS.md's C# detector-coverage-gap row for
// the full account of the retraction and what remains genuinely open.
test('cs-interproc-basic: taint from Request.Params propagates through a private helper method (Bad()/BadSink() split, Juliet\'s own convention)', async () => {
  const dir = mkTmp('ldap-interproc', `
public class C {
    public void Bad(HttpRequest Request) {
        string data = Request.Params["uid"];
        BadSink(data);
    }
    private void BadSink(string data) {
        var searcher = new DirectorySearcher();
        searcher.Filter = "(uid=" + data + ")";
        searcher.FindAll();
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(`${f.vuln} ${f.cwe}`)),
    `expected LDAP Injection to propagate across the method call, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-interproc-basic: taint from Request.Params propagates through a private helper method (command injection via Process.Start)', async () => {
  const dir = mkTmp('cmdi-interproc', `
using System.Diagnostics;
public class D {
    public void Bad(HttpRequest Request) {
        string data = Request.Params["cmd"];
        BadSink(data);
    }
    private void BadSink(string data) {
        Process.Start("cmd.exe", data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln}`)),
    `expected Command Injection to propagate across the method call, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-interproc-basic: lowercase "request"/"req" (SARD_80_F1: the dominant real-world naming convention, mirroring JS\'s own req/request sources) now propagates through IR-TAINT too', async () => {
  // The retraction above documents that lowercase `request` matched no
  // real catalog source AT THE TIME — a fact this test used to pin as a
  // precision guarantee, not a permanent design decision. Real-world (and
  // Juliet's own) C# overwhelmingly parameter-names an HttpRequest `req`/
  // `request`, exactly like JS's `req.query`/`request.body`; the SARD 80%
  // F1 push added `cs-req-*`/`cs-request-lc-*` catalog entries for that
  // convention, so this fixture now correctly fires via IR-TAINT — a
  // deliberate recall widening, not a regression of the lesson above.
  const dir = mkTmp('cmdi-interproc-lowercase-control', `
using System.Diagnostics;
public class E {
    public void Bad(HttpRequest request) {
        string data = request.Params["cmd"];
        BadSink(data);
    }
    private void BadSink(string data) {
        Process.Start("cmd.exe", data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln}`)),
    `expected lowercase "request" to match the cs-req-params catalog source via IR-TAINT, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// Found via the SARD C# benchmark investigation (macro-F1 8.4%, 26/32 CWEs
// at zero detector coverage): the two tests above use `BadSink(data)` — a
// BARE same-class call. `this.BadSink(data)` — equally idiomatic, and the
// form a private helper call is MORE often written in — silently failed to
// resolve at all (`src/ir/callgraph.js`'s call-site resolution never
// stripped the `this.` prefix before matching against `fn.name`, which
// `parser-cs.js` registers bare), blocking interprocedural taint into every
// sink behind a `this.`-qualified helper call, for every CWE. Fixed in
// `callgraph.js` (see `test/callgraph-resolve.test.js` for the resolver-
// level tests); these four cases pin the SAME fix end-to-end through a real
// scan, for the two sink families the pre-existing tests above already
// cover via the bare-call form.
test('cs-interproc-basic (this.-qualified): LDAP injection propagates through a `this.badSink(data)` call', async () => {
  const dir = mkTmp('ldap-interproc-this', `
public class F {
    public void Bad(HttpRequest Request) {
        string data = Request.Params["uid"];
        this.BadSink(data);
    }
    private void BadSink(string data) {
        var searcher = new DirectorySearcher();
        searcher.Filter = "(uid=" + data + ")";
        searcher.FindAll();
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(`${f.vuln} ${f.cwe}`)),
    `expected LDAP Injection to propagate across a this.-qualified method call, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-interproc-basic (this.-qualified): command injection propagates through a `this.badSink(data)` call', async () => {
  const dir = mkTmp('cmdi-interproc-this', `
using System.Diagnostics;
public class G {
    public void Bad(HttpRequest Request) {
        string data = Request.Params["cmd"];
        this.BadSink(data);
    }
    private void BadSink(string data) {
        Process.Start("cmd.exe", data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln}`)),
    `expected Command Injection to propagate across a this.-qualified method call, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-process-start-args: a NON-shell-literal filename with tainted arguments still fires (UseShellExecute defaults to true on .NET Framework)', async () => {
  const dir = mkTmp('cmdi-process-start-args', `
using System.Diagnostics;
public class H {
    public void Bad(HttpRequest Request) {
        string data = Request.Params["host"];
        Process.Start("ping", data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln}`)),
    `expected Process.Start("ping", data) (non-shell filename) to still fire as command injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-process-start-args precision control: a tainted FILENAME with literal arguments does not fire this sink (argIndex is 1 only)', async () => {
  const dir = mkTmp('cmdi-process-start-args-control', `
using System.Diagnostics;
public class I {
    public void Bad(HttpRequest Request) {
        string data = Request.Params["exe"];
        Process.Start(data, "-la");
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(!taint.some(f => /cs-process-start-args|Process\.Start arguments/i.test(`${f.vuln} ${f.id || ''}`)),
    `cs-process-start-args must only check argIndex 1 (arguments), not arg 0 (filename), got: ${taint.map(f => f.vuln).join(', ')}`);
});

// Found via the SAME SARD investigation as the this.-qualified tests above,
// but a bigger, separate bug: `parser-cs.js`'s `_qid()` never recorded
// which CLASS a method belongs to at all, so `callgraph.js`'s classMethods
// index (which resolves ANY cross-class call — `new Helper().Sink(x)`,
// `Helper h = new Helper(); h.Sink(x)`, or a bare `Helper.Sink(x)`) was
// PERMANENTLY EMPTY for C#, independent of same-file vs. cross-file. This
// blocked Juliet's other dominant helper-class idiom (alongside the
// `this.`-qualified same-class case fixed above) for every CWE whose sink
// sits inside a separate helper class. Fixed by having parser-cs.js track
// each method's enclosing class (`_findClassRanges`/`_enclosingClassName`)
// and thread it into `fn.name`/`fn.qid`, matching parser-java.js's/
// parser-js.js's existing `"ClassName.method"` convention exactly — plus a
// companion local-variable-type rewrite (`_applyVarTypeRewrite`) for the
// `Helper h = new Helper(); h.Sink(x)` shape, since `h.Sink` as a raw
// callee string can never match `classMethods` (keyed by the REAL class
// name, not a local variable name).
test('cs-cross-class: LDAP injection propagates through `new Helper().BadSink(data)` (inline instantiate-and-call, same file)', async () => {
  const dir = mkTmp('ldap-cross-class-inline', `
public class Helper1 {
    public void BadSink(string data) {
        var searcher = new DirectorySearcher();
        searcher.Filter = "(uid=" + data + ")";
        searcher.FindAll();
    }
}
public class J {
    public void Bad(HttpRequest Request) {
        string data = Request.Params["uid"];
        new Helper1().BadSink(data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(`${f.vuln} ${f.cwe}`)),
    `expected LDAP Injection to propagate through new Helper1().BadSink(data), got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-cross-class: LDAP injection propagates through `Helper h = new Helper(); h.BadSink(data);` (variable-held instance, same file)', async () => {
  const dir = mkTmp('ldap-cross-class-var', `
public class Helper2 {
    public void BadSink(string data) {
        var searcher = new DirectorySearcher();
        searcher.Filter = "(cn=" + data + ")";
        searcher.FindAll();
    }
}
public class K {
    public void Bad(HttpRequest Request) {
        string data = Request.Params["cn"];
        Helper2 h = new Helper2();
        h.BadSink(data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(`${f.vuln} ${f.cwe}`)),
    `expected LDAP Injection to propagate through a variable-held Helper2 instance, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-cross-class precision control: a variable assigned TWO DIFFERENT constructed types in one function is not rewritten (refuses to guess on ambiguity)', async () => {
  // If `h` is reassigned from `new HelperA()` to `new HelperB()` within the
  // same function, `h.BadSink(data)` could mean either class's method —
  // genuinely ambiguous. The rewrite must refuse (leave the callee as the
  // bare `h.BadSink`, matching this codebase's "never fabricate an edge"
  // convention elsewhere) rather than guess wrong and silently misattribute
  // a real flow to the wrong class's method.
  const dir = mkTmp('cross-class-var-ambiguous', `
public class HelperA2 {
    public void BadSink(string data) { }
}
public class HelperB2 {
    public void BadSink(string data) {
        var searcher = new DirectorySearcher();
        searcher.Filter = "(uid=" + data + ")";
        searcher.FindAll();
    }
}
public class L {
    public void Bad(HttpRequest Request, bool flag) {
        string data = Request.Params["uid"];
        HelperA2 h = new HelperA2();
        h = new HelperB2();
        h.BadSink(data);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.length, 0,
    `an ambiguously-typed variable must not resolve to either class's method (no guessed edge), got: ${taint.map(f => f.vuln).join(', ')}`);
});

// SARD_80_F1 W2.3 — ported from the identical Java bug/fix (see
// parser-java.js's own comment): the class-qualification rewrite was
// class-qualifying `list.Add(data)` to `ArrayList.Add(data)`, desyncing
// engine.js's mutator taint rule (keyed on the fake receiver "ArrayList")
// from a `foreach` read over the container itself (`s = list`, a bare
// identifier the rewrite never touches, staying keyed on "list"). Fixed
// by exempting BCL collection types from the rewrite — they are never
// entries in callgraph.js's classMethods index, so the rewrite bought
// dispatch resolution nothing for them.
test('cs-collection-foreach: taint survives ArrayList.Add() -> foreach over the container itself', async () => {
  const dir = mkTmp('collection-foreach', `
using System.Collections;
public class C {
    public void Bad(HttpRequest Request) {
        string data = Request.QueryString["name"];
        ArrayList list = new ArrayList();
        list.Add(data);
        foreach (string s in list) {
            Process.Start("cmd.exe", "/c " + s);
        }
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln} ${f.cwe}`)),
    `a bare foreach over a tainted ArrayList must still see the taint, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// SARD_80_F1 W2.3 follow-up: `List<T>` — C#'s dominant MODERN collection
// idiom (unlike the non-generic `ArrayList` above) — previously lowered
// its constructor call to `{kind:'unknown'}` entirely (see
// `parser-cs-kt.test.js`'s IR-level test for the exact cause), so
// `list.Add(data)` never even reached the collection-taint mutator rule.
// Fixed by teaching `matchBalancedCall` (shared by all four hand-rolled
// regex IR parsers) to optionally skip a balanced `<...>` generic
// type-argument list before requiring the constructor's own `(`.
test('cs-collection-foreach (generic List<T>): taint survives List<string>.Add() -> foreach over the container itself', async () => {
  const dir = mkTmp('collection-foreach-generic', `
using System.Collections.Generic;
public class C {
    public void Bad(HttpRequest Request) {
        string data = Request.QueryString["name"];
        List<string> list = new List<string>();
        list.Add(data);
        foreach (string s in list) {
            Process.Start("cmd.exe", "/c " + s);
        }
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(`${f.vuln} ${f.cwe}`)),
    `a bare foreach over a tainted List<string> must still see the taint, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-collection-foreach (generic List<T>) precision: a constant value does not fire', async () => {
  const dir = mkTmp('collection-foreach-generic-clean', `
using System.Collections.Generic;
public class C {
    public void Good() {
        List<string> list = new List<string>();
        list.Add("safe-constant-value");
        foreach (string s in list) {
            Process.Start("cmd.exe", "/c " + s);
        }
    }
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /command injection/i.test(`${f.vuln} ${f.cwe}`)).length, 0,
    `a constant value passed through List<T> must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});
