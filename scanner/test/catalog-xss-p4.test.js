// Taint-recall PRD (80%), P4 (Tier 3 XSS audit): xss sat at 3/11 (27.3%).
// java/php/kotlin/python carried ZERO XSS sink entries in the catalog at
// all; Express/Koa's own response-write idioms were also uncataloged for
// JS. Root causes and fixes, one per test below:
//
// - PHP: echo/print are language CONSTRUCTS, not function calls — parser-
//   php.js now lowers them to a synthetic __php_echo__ call.
// - Java: resp.getWriter().write(...) (Servlet's canonical response-write
//   idiom) had no sink at all.
// - Python: Flask's render_template_string(tainted) compiles user input AS
//   a Jinja2 template.
// - Kotlin: Ktor's call.respondText(...) had no sink; AND Kotlin's
//   _lowerExpr had NO subscript/bracket-access support at all
//   (`call.parameters["q"]`), a general gap far bigger than just XSS.
// - JS/Express: res.send(...) had no XSS sink.
// - JS/Koa: ctx.body = ... had no sink, AND ctx.query/params/headers/
//   cookies (Koa's direct-on-context shortcuts) had no SOURCE at all
//   (only the ctx.request umbrella did).
// - JS/React: JSX had ZERO IR modeling — dangerouslySetInnerHTML as a JSX
//   ATTRIBUTE (as opposed to a plain member write) silently dropped taint
//   entirely. parser-js.js now extracts it into a synthetic call.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, filename, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-xss-p4-${name}-`));
  fs.writeFileSync(path.join(dir, filename), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('php-echo-xss: echo "..." . $_GET[...] . "..." fires Reflected XSS via IR-TAINT', async () => {
  const dir = mkTmp('php', 'search.php', `<?php
echo "<div>You searched for: " . $_GET['q'] . "</div>";
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected Reflected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('java-writer-write: resp.getWriter().write(...) fires Reflected XSS via IR-TAINT', async () => {
  const dir = mkTmp('java', 'SearchServlet.java', `
import java.io.IOException;
import javax.servlet.http.*;
public class SearchServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String q = req.getParameter("q");
        resp.getWriter().write("<h1>Results for " + q + "</h1>");
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected Reflected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// SARD_80_F1 W4: the two-step form (`PrintWriter out = response.getWriter();
// out.println(x);`) is Java's more common servlet idiom in practice, and a
// COMPLETELY different receiver shape than the chained one-liner above (a
// local variable name, not the literal `getWriter` call). Requires
// `parser-java.js` to resolve `out`'s DECLARED type (not just an `isNew`
// constructor call) so `out.println` rewrites to the class-qualified
// `PrintWriter.println`, which these catalog entries also now match.
test('java-writer-println (two-step, declared-type PrintWriter): out.println(tainted) fires Reflected XSS via IR-TAINT', async () => {
  const dir = mkTmp('java', 'SearchServlet2.java', `
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.*;
public class SearchServlet2 extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String q = req.getParameter("q");
        PrintWriter out = resp.getWriter();
        out.println("<h1>Results for " + q + "</h1>");
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected Reflected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('java-writer-println: a PrintWriter over an ordinary file does NOT fire on an untainted literal', async () => {
  const dir = mkTmp('java', 'FileLogger.java', `
import java.io.PrintWriter;
import java.io.FileWriter;
import java.io.IOException;
public class FileLogger {
    public void log() throws IOException {
        PrintWriter out = new PrintWriter(new FileWriter("log.txt"));
        out.println("server started");
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(!taint.some(f => /xss/i.test(f.vuln)),
    `expected no XSS finding on an untainted literal, got: ${taint.map(f => f.vuln).join(', ')}`);
});

// SARD_80_F1 W4 (CWE-81, "XSS Error Message"): Juliet's error-message
// reflection idiom throws a `new Exception(tainted)` inside a `try`, then
// reflects it back via `catch (Exception e) { ...e.getMessage()... }` — was
// completely invisible (0 findings) since `throw`/`catch` carried no data
// link between the thrown constructor argument and the caught variable.
// `parser-java.js` now binds the catch parameter to the try body's thrown
// expression(s) as a synthetic assign, so the existing generic
// tainted-call-argument / receiver-taint mechanism (no catalog/engine
// change) sees `e.getMessage()` as tainted.
test('exception-message taint (CWE-81 shape): catch(e).getMessage() of a tainted throw fires XSS', async () => {
  const dir = mkTmp('java', 'ErrorServlet.java', `
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.*;
public class ErrorServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String data = req.getParameter("q");
        PrintWriter out = resp.getWriter();
        try {
            if (data != null) {
                throw new Exception(data);
            }
        } catch (Exception exceptCWE81) {
            out.println(exceptCWE81.getMessage());
        }
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected Reflected XSS from the caught exception's message, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('exception-message taint: catch(e).getMessage() of an UNTAINTED throw does not fire', async () => {
  const dir = mkTmp('java', 'SafeErrorServlet.java', `
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.*;
public class SafeErrorServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        PrintWriter out = resp.getWriter();
        try {
            throw new Exception("a constant, non-attacker-controlled message");
        } catch (Exception e) {
            out.println(e.getMessage());
        }
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(!taint.some(f => /xss/i.test(f.vuln)),
    `expected no XSS finding for a constant exception message, got: ${taint.map(f => f.vuln).join(', ')}`);
});

// SARD_80_F1 W4.J4 follow-up: the earlier exception-message fix above,
// while a real and correctly-tested capability, turned out to solve a
// DIFFERENT shape than Juliet's actual CWE-81 corpus tests. Confirmed via
// the public Juliet Java mirror (CWE81_XSS_Error_Message, 545 files, every
// one using this exact `response.sendError(404, "..." + data)` shape) that
// "Error Message" in the CWE's name refers to `sendError`'s HTTP error
// message ARGUMENT (index 1), not a caught exception's `getMessage()` —
// a sink this catalog had zero coverage for under any name.
test('java-response-senderror: response.sendError(code, tainted) fires Reflected XSS via IR-TAINT', async () => {
  const dir = mkTmp('java', 'ErrorPage.java', `
import javax.servlet.http.*;
public class ErrorPage extends HttpServlet {
    public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        String data = request.getParameter("name");
        if (data != null) {
            response.sendError(404, "<br>bad() - Parameter name has value " + data);
        }
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected Reflected XSS from sendError's message argument, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('java-response-senderror precision: response.sendError(code, hardcodedLiteral) does not fire', async () => {
  const dir = mkTmp('java-clean', 'ErrorPageGood.java', `
import javax.servlet.http.*;
public class ErrorPageGood extends HttpServlet {
    public void goodG2B(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        String data = "foo";
        if (data != null) {
            response.sendError(404, "<br>bad() - Parameter name has value " + data);
        }
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(!taint.some(f => /xss/i.test(f.vuln)),
    `expected no XSS finding for a hardcoded sendError message, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('py-flask-render-template-string: render_template_string(tainted) fires Reflected XSS via IR-TAINT', async () => {
  const dir = mkTmp('py', 'app.py', `
from flask import Flask, request, render_template_string
app = Flask(__name__)
@app.route('/hi')
def hi():
    name = request.args.get('name', '')
    return render_template_string('<h1>Hi ' + name + '</h1>')
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected Reflected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('kt-ktor-respondtext + subscript access: call.respondText("...${call.parameters["q"]}...") fires Reflected XSS via IR-TAINT', async () => {
  const dir = mkTmp('kt', 'Routes.kt', `
import io.ktor.application.*
import io.ktor.http.*
import io.ktor.response.*
suspend fun handle(call: ApplicationCall) {
    call.respondText("<h1>\${call.parameters["q"]}</h1>", ContentType.Text.Html)
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected Reflected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('kt-ktor-respondtext precision: htmlEscape(...)-wrapped value is marked sanitized', async () => {
  const dir = mkTmp('kt-clean', 'Routes.kt', `
import io.ktor.application.*
import io.ktor.http.*
import io.ktor.response.*
import org.springframework.web.util.HtmlUtils.htmlEscape
suspend fun handle(call: ApplicationCall) {
    call.respondText("<h1>\${htmlEscape(call.parameters["q"])}</h1>", ContentType.Text.Html)
}
`);
  const taint = await taintFindings(dir);
  const xss = taint.filter(f => /xss/i.test(f.vuln));
  assert.ok(xss.length === 0 || xss.every(f => f.sanitized),
    `an htmlEscape-wrapped value must be marked sanitized (or not fire at all), got: ${JSON.stringify(xss.map(f => ({ vuln: f.vuln, sanitized: f.sanitized })))}`);
});

test('js-express-res-send: res.send with tainted req.query fires Reflected XSS via IR-TAINT', async () => {
  const dir = mkTmp('js-express', 'app.js', `
const express = require('express');
const app = express();
app.get('/p', (req, res) => {
  res.send('<html><div>' + req.query.msg + '</div></html>');
});
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected Reflected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('js-koa-ctx-body + ctx.query source: ctx.body = tainted fires Reflected XSS via IR-TAINT', async () => {
  const dir = mkTmp('js-koa', 'app.js', `
const Koa = require('koa');
const app = new Koa();
app.use(async ctx => {
  ctx.body = '<h1>Hi ' + ctx.query.name + '</h1>';
});
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected Reflected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('js-koa-ctx-body precision: escape-html-wrapped value is marked sanitized', async () => {
  const dir = mkTmp('js-koa-clean', 'app.js', `
const Koa = require('koa');
const escape = require('escape-html');
const app = new Koa();
app.use(async ctx => {
  ctx.body = '<h1>Hi ' + escape(ctx.query.name || '') + '</h1>';
});
`);
  const taint = await taintFindings(dir);
  const xss = taint.filter(f => /xss/i.test(f.vuln));
  assert.equal(xss.length, 0, `an escape()-wrapped value must not fire, got: ${xss.map(f => f.vuln).join(', ')}`);
});

test('react-jsx-dangerouslySetInnerHTML: a JSX attribute with tainted __html fires XSS via IR-TAINT', async () => {
  const dir = mkTmp('react', 'Comment.jsx', `
import React from 'react';
export function Comment() {
  const html = location.hash.slice(1);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected XSS via dangerouslySetInnerHTML, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('react-jsx-dangerouslySetInnerHTML precision: DOMPurify.sanitize(...)-wrapped value is marked sanitized', async () => {
  const dir = mkTmp('react-clean', 'Comment.jsx', `
import React from 'react';
import DOMPurify from 'dompurify';
export function Comment() {
  const html = location.hash.slice(1);
  const clean = DOMPurify.sanitize(html);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
`);
  const taint = await taintFindings(dir);
  const xss = taint.filter(f => /xss/i.test(f.vuln));
  assert.ok(xss.length === 0 || xss.every(f => f.sanitized),
    `a DOMPurify.sanitize-wrapped value must be marked sanitized (or not fire at all), got: ${JSON.stringify(xss.map(f => ({ vuln: f.vuln, sanitized: f.sanitized })))}`);
});
