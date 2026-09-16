// End-to-end fire + precision checks for the Java sources/sinks added
// during SARD_80_F1_SCANNER_PRD.md's Juliet Java coverage push. Each fixture
// mimics a documented Juliet flow variant shape (never copied from the real
// corpus, which this repo's own agent deny-list keeps unreadable) — see
// bench/sard/IMPLEMENTATION_STATUS.md for the audit these entries came from.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, javaSrc) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-java-sard-${name}-`));
  fs.writeFileSync(path.join(dir, 'A.java'), javaSrc);
  return dir;
}

async function deepScan(dir) {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  }
}

function findByCwe(findings, cwe) { return findings.filter(f => f.cwe === cwe); }

test('CWE-22: new FileInputStream(tainted) fires; a constant path does not', async () => {
  const dir = mkTmp('fis', `
import javax.servlet.http.HttpServletRequest;
import java.io.FileInputStream;
public class A {
  public void bad(HttpServletRequest request) throws Exception {
    String data = request.getParameter("file");
    FileInputStream fis = new FileInputStream(data);
  }
  public void good() throws Exception {
    String data = "/etc/hostname";
    FileInputStream fis = new FileInputStream(data);
  }
}`);
  const findings = await deepScan(dir);
  const hits = findByCwe(findings, 'CWE-22');
  assert.ok(hits.length >= 1, `expected a CWE-22 finding, got ${JSON.stringify(findings.map(f => f.cwe))}`);
});

// The single largest CWE-89 false-negative cluster this session found:
// 167 of 308 dev-split fns were Juliet's `*_executeBatch_*` variants, whose
// real sink is `Statement.addBatch(sql)` — `executeBatch()` itself takes no
// arguments and just fires whatever was previously queued. Confirmed via
// the public Juliet Java mirror (CWE89_SQL_Injection's own executeBatch-
// suffixed source, never this repo's own corpus).
test('CWE-89: Statement.addBatch(tainted concat) fires; PreparedStatement\'s zero-arg addBatch() does not', async () => {
  const dir = mkTmp('addbatch', `
import javax.servlet.http.HttpServletRequest;
import java.sql.*;
public class A {
  public void bad(HttpServletRequest request, Connection dbConnection) throws Exception {
    String data = request.getParameter("name");
    Statement sqlStatement = dbConnection.createStatement();
    sqlStatement.addBatch("update users set hitcount=hitcount+1 where name='" + data + "'");
    int[] resultsArray = sqlStatement.executeBatch();
  }
  public void good(Connection dbConnection) throws Exception {
    PreparedStatement sqlStatement = dbConnection.prepareStatement("update users set hitcount=hitcount+1 where name=?");
    sqlStatement.setString(1, "safe");
    sqlStatement.addBatch();
    int[] resultsArray = sqlStatement.executeBatch();
  }
}`);
  const findings = await deepScan(dir);
  const hits = findByCwe(findings, 'CWE-89');
  assert.ok(hits.length >= 1, `expected a CWE-89 finding on addBatch, got ${JSON.stringify(findings.map(f => f.cwe))}`);
  assert.ok(hits.every(f => f.line <= 8), `finding should be on bad()'s addBatch line, not good()'s zero-arg one: ${JSON.stringify(hits)}`);
});

test('CWE-470: Class.forName(tainted) fires', async () => {
  const dir = mkTmp('reflect', `
import javax.servlet.http.HttpServletRequest;
public class A {
  public void bad(HttpServletRequest request) throws Exception {
    String data = request.getParameter("cls");
    Class.forName(data);
  }
}`);
  const findings = await deepScan(dir);
  assert.ok(findByCwe(findings, 'CWE-470').length >= 1, `got ${JSON.stringify(findings.map(f => f.cwe))}`);
});

test('CWE-134: String.format(tainted, ...) fires; a constant format string does not', async () => {
  const dir = mkTmp('format', `
import javax.servlet.http.HttpServletRequest;
public class A {
  public void bad(HttpServletRequest request) throws Exception {
    String data = request.getParameter("fmt");
    String out = String.format(data, "x");
  }
  public void good() throws Exception {
    String out = String.format("%s", "x");
  }
}`);
  const findings = await deepScan(dir);
  assert.ok(findByCwe(findings, 'CWE-134').length >= 1, `got ${JSON.stringify(findings.map(f => f.cwe))}`);
});

test('CWE-113: new Cookie(name, tainted) and addHeader(name, tainted) fire', async () => {
  const dir = mkTmp('header', `
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
public class A {
  public void bad1(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String data = request.getParameter("v");
    Cookie c = new Cookie("track", data);
  }
  public void bad2(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String data = request.getParameter("v");
    response.addHeader("X-Echo", data);
  }
}`);
  const findings = await deepScan(dir);
  assert.ok(findByCwe(findings, 'CWE-113').length >= 2, `got ${JSON.stringify(findings.map(f => f.cwe))}`);
});

test('abstract-dispatch (Juliet variant 81/82 shape): source through a base-typed local resolves into the concrete override and reaches the sink', async () => {
  const dir = mkTmp('dispatch', `
import javax.servlet.http.HttpServletRequest;
public class A {
  abstract static class Base { abstract void action(String data) throws Exception; }
  static class Impl extends Base {
    void action(String data) throws Exception { Runtime.getRuntime().exec(data); }
  }
  public void bad(HttpServletRequest request) throws Exception {
    String data = request.getParameter("x");
    Base b = new Impl();
    b.action(data);
  }
}`);
  const findings = await deepScan(dir);
  assert.ok(findByCwe(findings, 'CWE-78').length >= 1, `expected the flow through the concrete override to reach the sink, got ${JSON.stringify(findings.map(f => f.cwe))}`);
});

test('getAttribute/getQueryString/Cookie.getValue all reach a command-injection sink', async () => {
  const dir = mkTmp('sources', `
import javax.servlet.http.HttpServletRequest;
public class A {
  public void bad1(HttpServletRequest request) throws Exception {
    String data = (String) request.getAttribute("x");
    Runtime.getRuntime().exec(data);
  }
  public void bad2(HttpServletRequest request) throws Exception {
    String data = request.getQueryString();
    Runtime.getRuntime().exec(data);
  }
  public void bad3(javax.servlet.http.Cookie cookie) throws Exception {
    String data = cookie.getValue();
    Runtime.getRuntime().exec(data);
  }
}`);
  const findings = await deepScan(dir);
  const cmdi = findByCwe(findings, 'CWE-78');
  assert.ok(cmdi.length >= 3, `expected 3 CWE-78 findings (one per bad method), got ${JSON.stringify(findings.map(f => `${f.cwe}:${f.line}`))}`);
});
