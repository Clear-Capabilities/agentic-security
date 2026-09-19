// Cross-language reflected-XSS structural detector — PRD Tier 1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanXssReflectedMultilang as x } from '../src/sast/xss-reflected-multilang.js';

const fires = (f) => x(...f).some((r) => r.cwe === 'CWE-79');
const clean = (f) => x(...f).every((r) => r.cwe !== 'CWE-79');

test('Go — HTML response built by concat fires; escaped/literal clean', () => {
  assert.ok(fires(['h.go', 'fmt.Fprintf(w, "<h1>"+r.URL.Query().Get("q")+"</h1>")']));
  assert.ok(clean(['h.go', 'fmt.Fprintf(w, "<h1>"+template.HTMLEscapeString(r.URL.Query().Get("q"))+"</h1>")']));
  assert.ok(clean(['h.go', 'fmt.Fprintf(w, "<h1>static</h1>")']));
});

test('PHP — echo of $_GET fires; htmlspecialchars / static clean', () => {
  assert.ok(fires(['p.php', '<?php echo "<div>" . $_GET["x"];']));
  assert.ok(fires(['p.php', '<?php echo $_GET["x"];']));
  assert.ok(clean(['p.php', '<?php echo "<div>" . htmlspecialchars($_GET["x"]);']));
  assert.ok(clean(['p.php', '<?php echo "<div>static</div>";']));
});

// Stage 1 correctness audit: PHP was routed through blankComments' 'py'
// mode, which strips only `#` comments — PHP's much more common `//` and
// `/* */` comment styles were left completely unstripped, so commented-out
// vulnerable PHP code still matched the sink regex.
test('PHP — commented-out echo does not fire (// and /* */ are real PHP comment forms)', () => {
  assert.ok(clean(['p.php', '<?php\n// echo "<div>" . $_GET["x"];\necho "safe";']));
  assert.ok(clean(['p.php', '<?php\n/* echo "<div>" . $_GET["x"]; */\necho "safe";']));
  // still fires on the real, uncommented line
  assert.ok(fires(['p.php', '<?php\n// old code\necho "<div>" . $_GET["x"];']));
});

test('Ruby — render inline interpolation / raw(params) fires; ERB tag / plain clean', () => {
  assert.ok(fires(['c.rb', 'def show; render inline: "<h1>#{params[:q]}</h1>"; end']));
  assert.ok(fires(['c.rb', 'def show; render html: raw(params[:q]); end']));
  assert.ok(clean(['c.rb', 'def show; render inline: "<h1><%= params[:q] %></h1>"; end']));
  assert.ok(clean(['c.rb', 'def show; render plain: params[:q]; end']));
});

test('C# — Response.Write of Request fires; HtmlEncode clean', () => {
  assert.ok(fires(['P.cs', 'Response.Write("<div>" + Request.QueryString["x"]);']));
  assert.ok(fires(['P.cs', 'Response.Write(Request["x"]);']));
  assert.ok(clean(['P.cs', 'Response.Write("<div>" + HttpUtility.HtmlEncode(Request.QueryString["x"]));']));
});

test('Kotlin — Ktor respondText interpolation fires; htmlEscape clean', () => {
  assert.ok(fires(['A.kt', 'call.respondText("<h1>${call.parameters["q"]}</h1>", ContentType.Text.Html)']));
  assert.ok(clean(['A.kt', 'call.respondText("<h1>${htmlEscape(call.parameters["q"])}</h1>", ContentType.Text.Html)']));
});

test('Java — servlet getWriter/out concat fires; literal / OWASP-encoded clean', () => {
  assert.ok(fires(['S.java', 'class S { void h(String q, javax.servlet.http.HttpServletResponse resp) throws Exception { resp.getWriter().write("<h1>" + q + "</h1>"); } }']));
  assert.ok(fires(['S.java', 'class S { void h(String q, java.io.PrintWriter out){ out.println("<div>" + q + "</div>"); } }']));
  assert.ok(clean(['S.java', 'class S { void h(javax.servlet.http.HttpServletResponse resp) throws Exception { resp.getWriter().write("<h1>static</h1>"); } }']));
  assert.ok(clean(['S.java', 'import org.owasp.encoder.Encode;\nclass S { void h(String q, javax.servlet.http.HttpServletResponse resp) throws Exception { resp.getWriter().write("<h1>" + Encode.forHtml(q) + "</h1>"); } }']));
});

// SARD_80_F1 W3.x — Java's real corpus (Juliet CWE80_XSS__CWE182_Servlet)
// keeps the IDENTICAL sink line in bad()/goodG2B(), only swapping the
// local variable's SOURCE — this taint-independent detector had no way to
// tell them apart until now. See the LANGS.java sink regex's own header
// comment for the full incident writeup.
test('Java — a hardcoded-literal local var reaching the sink does NOT fire (bare identifier)', () => {
  assert.ok(clean(['S.java', 'class S { void h(javax.servlet.http.HttpServletResponse resp) throws Exception { String data; data = "foo"; resp.getWriter().println("<br>" + data); } }']));
});
test('Java — a hardcoded-literal local var reaching the sink does NOT fire, even through a chained method call', () => {
  assert.ok(clean(['S.java', 'class S { void h(javax.servlet.http.HttpServletResponse resp) throws Exception { String data; data = "foo"; resp.getWriter().println("<br>" + data.replaceAll("(<script>)", "")); } }']));
});
test('Java — the SAME shape with a genuinely tainted local var still fires', () => {
  assert.ok(fires(['S.java', 'class S { void h(java.io.BufferedReader r, javax.servlet.http.HttpServletResponse resp) throws Exception { String data; data = r.readLine(); resp.getWriter().println("<br>" + data.replaceAll("(<script>)", "")); } }']));
});
test('Java — a param (no local assignment to find) still fires through a chained method call', () => {
  assert.ok(fires(['S.java', 'class S { void h(String data, javax.servlet.http.HttpServletResponse resp) throws Exception { resp.getWriter().println("<br>" + data.replaceAll("(<script>)", "")); } }']));
});

// SARD_80_F1 W4.J28 — Juliet's own "Control flow: if(true) and if(false)"
// flow variant (confirmed against the public mirror,
// CWE80_XSS__CWE182_Servlet_getCookies_Servlet_02.java): the literal
// assignment sits in the ALWAYS-reachable branch of a CONSTANT-CONDITION
// if/else, but the textually-LAST assignment is the branch's own
// deliberately-dead "CWE 561 Dead Code" counterpart — a plain nearest-
// assignment scan sees only the dead branch and wrongly concludes the
// value isn't provably a literal.
// SARD_80_F1 W5.32 — `deadBranchRanges` (java-ast-folding.js) computes dead
// ranges from REAL parsed line numbers, so these fixtures (unlike this
// file's other single-line ones) must be realistic multi-line Java source —
// a whole class crammed onto one line puts the "dead" and "live" branches on
// the SAME line, which a line-range mechanism cannot distinguish.
test('Java — if(true)/else dead-branch: the literal in the reachable if-branch suppresses the finding', () => {
  const src = `
    class S {
      void h(javax.servlet.http.HttpServletResponse resp) throws Exception {
        String data;
        if (true) {
          data = "foo";
        } else {
          data = null;
        }
        if (data != null) {
          resp.getWriter().println("<br>" + data.replaceAll("(<script>)", ""));
        }
      }
    }`;
  assert.ok(clean(['S.java', src]), 'the else branch is provably dead; data is always "foo"');
});
test('Java — if(false)/else dead-branch (the mirror image): the literal in the reachable else-branch suppresses the finding', () => {
  const src = `
    class S {
      void h(javax.servlet.http.HttpServletResponse resp) throws Exception {
        String data;
        if (false) {
          data = null;
        } else {
          data = "foo";
        }
        if (data != null) {
          resp.getWriter().println("<br>" + data.replaceAll("(<script>)", ""));
        }
      }
    }`;
  assert.ok(clean(['S.java', src]), 'the if branch is provably dead; data is always "foo"');
});
test('Java — if(true)/else where the REACHABLE branch is genuinely tainted still fires', () => {
  const src = `
    class S {
      void h(java.io.BufferedReader r, javax.servlet.http.HttpServletResponse resp) throws Exception {
        String data;
        if (true) {
          data = r.readLine();
        } else {
          data = "foo";
        }
        if (data != null) {
          resp.getWriter().println("<br>" + data.replaceAll("(<script>)", ""));
        }
      }
    }`;
  assert.ok(fires(['S.java', src]), 'the reachable if-branch is tainted; the dead else-branch literal must not suppress it');
});

// SARD_80_F1 W5.32 — the sibling Juliet flow variant to W4.J28's own
// "if(true)/if(false)" idiom: "Control flow: if(5==5) and if(5!=5)" (Flow
// Variant 03) is the same provably-constant-condition dead-code shape spelled
// as an integer-literal comparison instead of a bare boolean literal.
// `deadBranchRanges`'s AST evaluator already resolves a literal-vs-literal
// int comparison for free (it recurses into both operands regardless of
// whether either is a known identifier) — no new production code was needed
// for this specific shape once the switch to the shared mechanism landed.
test('Java — if(5==5)/else dead-branch: the literal in the reachable if-branch suppresses the finding', () => {
  const src = `
    class S {
      void h(javax.servlet.http.HttpServletResponse resp) throws Exception {
        String data;
        if (5 == 5) {
          data = "foo";
        } else {
          data = null;
        }
        if (data != null) {
          resp.getWriter().println("<br>" + data.replaceAll("(<script>)", ""));
        }
      }
    }`;
  assert.ok(clean(['S.java', src]), 'the else branch is provably dead; data is always "foo"');
});
test('Java — if(5!=5)/else dead-branch (the mirror image): the literal in the reachable else-branch suppresses the finding', () => {
  const src = `
    class S {
      void h(javax.servlet.http.HttpServletResponse resp) throws Exception {
        String data;
        if (5 != 5) {
          data = null;
        } else {
          data = "foo";
        }
        if (data != null) {
          resp.getWriter().println("<br>" + data.replaceAll("(<script>)", ""));
        }
      }
    }`;
  assert.ok(clean(['S.java', src]), 'the if branch is provably dead; data is always "foo"');
});
test('Java — if(5==5)/else where the REACHABLE branch is genuinely tainted still fires', () => {
  const src = `
    class S {
      void h(java.io.BufferedReader r, javax.servlet.http.HttpServletResponse resp) throws Exception {
        String data;
        if (5 == 5) {
          data = r.readLine();
        } else {
          data = "foo";
        }
        if (data != null) {
          resp.getWriter().println("<br>" + data.replaceAll("(<script>)", ""));
        }
      }
    }`;
  assert.ok(fires(['S.java', src]), 'the reachable if-branch is tainted; the dead else-branch literal must not suppress it');
});
test('Java — if(5==6)/else (a genuine, non-equal-literal comparison) is never guessed as constant, fails closed', () => {
  const src = `
    class S {
      void h(javax.servlet.http.HttpServletResponse resp) throws Exception {
        String data;
        if (5 == 6) {
          data = "foo";
        } else {
          data = null;
        }
        if (data != null) {
          resp.getWriter().println("<br>" + data.replaceAll("(<script>)", ""));
        }
      }
    }`;
  assert.ok(fires(['S.java', src]),
    'a comparison between two DIFFERENT literals must not be treated as provably constant; the textually-nearest assignment (the else branch\'s "null") is not a literal, so this must fail closed and still fire');
});

test('non-matching languages / files produce nothing', () => {
  assert.deepEqual(x('a.js', 'res.send("<h1>" + req.query.q + "</h1>")'), []);
  assert.deepEqual(x('ok.go', 'func add(a, b int) int { return a + b }'), []);
});
