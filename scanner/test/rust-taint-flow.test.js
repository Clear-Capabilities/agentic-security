// Rust end-to-end taint recall: request-derived data flowing through the
// new IR (parser-rust.js) and catalog (dataflow/catalog.js) into a real
// sink, and the matching precision cases that must NOT fire.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-rs-taint-${name}-`));
  fs.writeFileSync(path.join(dir, 'main.rs'), code);
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

function taintOf(findings) { return findings.filter(f => f.parser === 'IR-TAINT'); }

// ── SQL injection ────────────────────────────────────────────────────────────

test('IR-TAINT: axum Query extractor into sqlx::query(&format!) is SQL injection', async () => {
  const dir = mkTmp('sqli', `
use axum::extract::Query;
use std::collections::HashMap;

async fn search(Query(params): Query<HashMap<String, String>>, pool: &sqlx::PgPool) {
    let q = params.get("q").unwrap().to_string();
    let sql = format!("SELECT * FROM books WHERE title = '{}'", q);
    sqlx::query(&sql).fetch_all(pool).await.unwrap();
}
`);
  const findings = await deepScan(dir);
  const taint = taintOf(findings);
  assert.ok(taint.some(f => /CWE-89/.test(f.cwe)), `expected SQLi, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('IR-TAINT: the parameterized .bind() form does not fire', async () => {
  const dir = mkTmp('sqli-safe', `
use axum::extract::Query;
use std::collections::HashMap;

async fn search(Query(params): Query<HashMap<String, String>>, pool: &sqlx::PgPool) {
    let q = params.get("q").unwrap().to_string();
    sqlx::query("SELECT * FROM books WHERE title = $1").bind(q).fetch_all(pool).await.unwrap();
}
`);
  const findings = await deepScan(dir);
  const taint = taintOf(findings);
  assert.equal(taint.filter(f => /CWE-89/.test(f.cwe)).length, 0,
    `bound query must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('IR-TAINT: sqlx::query! (compile-checked macro) never fires, even with the same shape', async () => {
  const dir = mkTmp('sqli-bang', `
use axum::extract::Query;
use std::collections::HashMap;

async fn search(Query(params): Query<HashMap<String, String>>, pool: &sqlx::PgPool) {
    let q = params.get("q").unwrap().to_string();
    sqlx::query!("SELECT * FROM books WHERE title = $1", q).fetch_all(pool).await.unwrap();
}
`);
  const findings = await deepScan(dir);
  const taint = taintOf(findings);
  assert.equal(taint.filter(f => /CWE-89/.test(f.cwe)).length, 0,
    `sqlx::query! must never match the query sink, got: ${taint.map(f => f.vuln).join(', ')}`);
});

// ── Command injection ────────────────────────────────────────────────────────

test('IR-TAINT: Command::new("sh").arg("-c").arg(input) is command injection', async () => {
  const dir = mkTmp('cmdi', `
use std::process::Command;
use axum::extract::Query;
use std::collections::HashMap;

fn run(Query(params): Query<HashMap<String, String>>) {
    let host = params.get("host").unwrap().to_string();
    Command::new("sh").arg("-c").arg(format!("ping -c 1 {}", host)).output().unwrap();
}
`);
  const findings = await deepScan(dir);
  const taint = taintOf(findings);
  assert.ok(taint.some(f => /CWE-78/.test(f.cwe)), `expected command injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('IR-TAINT: Command::new("ping").arg(input) without a shell does not fire', async () => {
  const dir = mkTmp('cmdi-safe', `
use std::process::Command;
use axum::extract::Query;
use std::collections::HashMap;

fn run(Query(params): Query<HashMap<String, String>>) {
    let host = params.get("host").unwrap().to_string();
    Command::new("ping").arg("-c").arg("1").arg(&host).output().unwrap();
}
`);
  const findings = await deepScan(dir);
  const taint = taintOf(findings);
  assert.equal(taint.filter(f => /CWE-78/.test(f.cwe)).length, 0,
    `array-execve form (no shell) must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});

// ── Path traversal ───────────────────────────────────────────────────────────

test('IR-TAINT: fs::read_to_string with an unchecked joined path is path traversal', async () => {
  const dir = mkTmp('path', `
use axum::extract::Path;
use std::fs;

async fn get_review(Path(filename): Path<String>) -> String {
    let full = format!("/var/reviews/{}", filename);
    fs::read_to_string(&full).unwrap()
}
`);
  const findings = await deepScan(dir);
  const taint = taintOf(findings);
  assert.ok(taint.some(f => /CWE-22/.test(f.cwe)), `expected path traversal, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('IR-TAINT: canonicalize + starts_with containment guard suppresses the finding', async () => {
  const dir = mkTmp('path-safe', `
use axum::extract::Path;
use std::fs;
use std::path::PathBuf;

async fn get_review(Path(filename): Path<String>) -> String {
    let base = PathBuf::from("/var/reviews");
    let candidate = base.join(&filename).canonicalize().unwrap();
    if !candidate.starts_with(&base) {
        return "forbidden".to_string();
    }
    fs::read_to_string(&candidate).unwrap()
}
`);
  const findings = await deepScan(dir);
  const taint = taintOf(findings);
  assert.equal(taint.filter(f => /CWE-22/.test(f.cwe)).length, 0,
    `canonicalize+starts_with guard must suppress, got: ${taint.map(f => f.vuln).join(', ')}`);
});

// ── SSRF ─────────────────────────────────────────────────────────────────────

test('IR-TAINT: reqwest::get with an input-derived URL is SSRF', async () => {
  const dir = mkTmp('ssrf', `
use axum::extract::Query;
use std::collections::HashMap;

async fn fetch(Query(params): Query<HashMap<String, String>>) {
    let url = params.get("url").unwrap().to_string();
    reqwest::get(&url).await.unwrap();
}
`);
  const findings = await deepScan(dir);
  const taint = taintOf(findings);
  assert.ok(taint.some(f => /CWE-918/.test(f.cwe)), `expected SSRF, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// ── XSS ──────────────────────────────────────────────────────────────────────

test('IR-TAINT: axum Html(format!) built from a Query param is XSS', async () => {
  const dir = mkTmp('xss', `
use axum::extract::Query;
use axum::response::Html;
use std::collections::HashMap;

async fn greet(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let name = params.get("name").unwrap().to_string();
    Html(format!("<h1>Welcome, {}!</h1>", name))
}
`);
  const findings = await deepScan(dir);
  const taint = taintOf(findings);
  assert.ok(taint.some(f => /CWE-79/.test(f.cwe)), `expected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('IR-TAINT: html_escape::encode_text before the response body suppresses the XSS', async () => {
  const dir = mkTmp('xss-safe', `
use axum::extract::Query;
use axum::response::Html;
use std::collections::HashMap;

async fn greet(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let name = params.get("name").unwrap().to_string();
    let safe = html_escape::encode_text(&name).to_string();
    Html(format!("<h1>Welcome, {}!</h1>", safe))
}
`);
  const findings = await deepScan(dir);
  const taint = taintOf(findings);
  const xss = taint.filter(f => /CWE-79/.test(f.cwe));
  assert.ok(xss.every(f => f.sanitized === true || (f.proof && f.proof.verdict !== 'vulnerable')),
    `escaped value should be labeled sanitized/proven-clean, got: ${JSON.stringify(xss.map(f => ({ sanitized: f.sanitized, proof: f.proof })))}`);
});

// ── interprocedural ──────────────────────────────────────────────────────────

test('IR-TAINT: taint flows through a helper return value across an impl method', async () => {
  const dir = mkTmp('interproc', `
use axum::extract::Query;
use std::collections::HashMap;

struct Repo;
impl Repo {
    fn build_query(&self, id: &str) -> String {
        format!("SELECT * FROM t WHERE id = '{}'", id)
    }
}

async fn handler(Query(params): Query<HashMap<String, String>>, pool: &sqlx::PgPool) {
    let id = params.get("id").unwrap().to_string();
    let repo = Repo;
    let sql = repo.build_query(&id);
    sqlx::query(&sql).fetch_all(pool).await.unwrap();
}
`);
  const findings = await deepScan(dir);
  const taint = taintOf(findings);
  assert.ok(taint.some(f => /CWE-89/.test(f.cwe)), `expected interprocedural SQLi, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});
