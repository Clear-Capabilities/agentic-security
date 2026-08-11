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

test('non-matching languages / files produce nothing', () => {
  assert.deepEqual(x('a.js', 'res.send("<h1>" + req.query.q + "</h1>")'), []);
  assert.deepEqual(x('ok.go', 'func add(a, b int) int { return a + b }'), []);
});
