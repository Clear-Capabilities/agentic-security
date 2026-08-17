// Taint-recall PRD (80%), P3/P6: path-traversal (7/15 -> 15/15) and SSRF
// (4/10 -> 10/10) audits. Root causes and fixes, one per test below:
//
// - Engine: a sink call NESTED inside another call's own argument
//   (`render(File.read(tainted))`, Rails' idiomatic wrap-and-render
//   pattern) was invisible to sink-matching entirely — neither `case
//   'call'`, `case 'assign'`, nor `case 'return'` ever recursed into an
//   argument that was itself a call expression. New `_nestedSinkFindings`
//   closes this for the general case.
// - Python: parser-py.helper.py's `_flatten_callee` COMPLETELY DISCARDED
//   an inner call's own arguments for any 2+-level chain
//   (`open(tainted).read()` lost `tainted` entirely, not just
//   misattributed) — the single most consequential Python parser bug
//   found in this PRD.
// - Java: a `new X(args)` constructor STARTING a chain
//   (`new URL(url).openStream()`) had BOTH its class name and its own
//   constructor arguments silently dropped — a strictly worse failure
//   than a terminal-segment shift (no catalog fix is possible for taint
//   the IR never represents at all).
// - Uncataloged sinks: Go os.ReadFile, Java Files.readAllBytes, PHP
//   readfile/curl_init, Koa send (koa-send), JS axios/http.get.
// - Kotlin: readText() is a generic "read everything" extension function
//   shared by File and URL — two catalog entries collided on every call
//   regardless of receiver type until both were receiver-scoped.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, filename, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-path-ssrf-p3-${name}-`));
  fs.writeFileSync(path.join(dir, filename), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('nested sink: render(File.read(tainted)) fires — a sink call nested inside another call\'s own argument', async () => {
  const dir = mkTmp('rb-nested', 'files_controller.rb', `
def show
  name = params[:file]
  render plain: File.read("/var/data/" + name)
end
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /path traversal/i.test(f.vuln)),
    `expected Path Traversal, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('nested sink precision: render(File.read("literal")) does not fire on a hardcoded path', async () => {
  const dir = mkTmp('rb-nested-clean', 'files_controller.rb', `
def show
  render plain: File.read("/etc/motd")
end
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /path traversal/i.test(f.vuln)).length, 0,
    `a literal path must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('py-open-read-chained: open(tainted).read() fires — the inner call\'s own argument must survive the chain', async () => {
  const dir = mkTmp('py', 'srv.py', `
from flask import request

def download():
    name = request.args.get('f')
    return open('/var/data/' + name).read()
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /path traversal/i.test(f.vuln)),
    `expected Path Traversal, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('java-url-openstream: new URL(tainted).openStream() fires — the constructor\'s own class name and args must survive the chain', async () => {
  const dir = mkTmp('java', 'Proxy.java', `
import java.net.URL;
import java.io.*;
import org.springframework.web.bind.annotation.RequestParam;
public class Proxy {
  public String fetch(@RequestParam String url) throws Exception {
    InputStream in = new URL(url).openStream();
    return new String(in.readAllBytes());
  }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ssrf/i.test(f.vuln)),
    `expected SSRF, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('java-files-readallbytes: Files.readAllBytes(Paths.get(tainted)) fires', async () => {
  const dir = mkTmp('java-files', 'FileService.java', `
import java.nio.file.*;
import org.springframework.web.bind.annotation.RequestParam;
class FileService {
    byte[] read(@RequestParam String name) throws Exception {
        return Files.readAllBytes(Paths.get("/var/data/" + name));
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /path traversal/i.test(f.vuln)),
    `expected Path Traversal, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('go-os-readfile: os.ReadFile(tainted) fires', async () => {
  const dir = mkTmp('go', 'serve.go', `
package main
import (
	"net/http"
	"os"
)
func handler(w http.ResponseWriter, r *http.Request) {
	b, _ := os.ReadFile("/var/data/" + r.URL.Query().Get("f"))
	w.Write(b)
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /path traversal/i.test(f.vuln)),
    `expected Path Traversal, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('php-readfile: readfile(tainted) fires', async () => {
  const dir = mkTmp('php', 'download.php', `<?php
$file = $_GET['file'];
readfile("/var/data/" . $file);
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /path traversal/i.test(f.vuln)),
    `expected Path Traversal, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('php-curl-init: curl_init(tainted) fires SSRF', async () => {
  const dir = mkTmp('php-curl', 'fetch.php', `<?php
function fetch() {
    $ch = curl_init($_GET["url"]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    return curl_exec($ch);
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ssrf/i.test(f.vuln)),
    `expected SSRF, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('js-koa-send: koa-send with a tainted path fires Path Traversal', async () => {
  const dir = mkTmp('js-koa', 'app.js', `
const Koa = require('koa');
const send = require('koa-send');
const app = new Koa();
app.use(async ctx => {
  await send(ctx, ctx.query.f, { root: '/var/data' });
});
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /path traversal/i.test(f.vuln)),
    `expected Path Traversal, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('js-axios-http-get: axios.get(tainted) fires SSRF', async () => {
  const dir = mkTmp('js-axios', 'app.js', `
const axios = require('axios');
const express = require('express');
const app = express();
app.get('/fetch', async (req, res) => {
  const r = await axios.get(req.query.url);
  res.send(r.data);
});
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ssrf/i.test(f.vuln)),
    `expected SSRF, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('js-axios-http-get precision: an unrelated .get(...) call (e.g. a Map) does not fire', async () => {
  const dir = mkTmp('js-axios-clean', 'app.js', `
const m = new Map();
function lookup(key) {
  return m.get(key);
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /ssrf/i.test(f.vuln)).length, 0,
    `an unrelated bare .get() call must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('kt-file-readtext / kt-url-readtext precision: readText() on File vs URL do not cross-match each other\'s sink', async () => {
  const dir = mkTmp('kt', 'Mixed.kt', `
import java.io.File
import java.net.URL

fun readLocal(name: String): String {
  return File("/var/data/" + name).readText()
}

fun fetchRemote(url: String): String {
  return URL(url).readText()
}
`);
  const taint = await taintFindings(dir);
  const pathFindings = taint.filter(f => /path traversal/i.test(f.vuln));
  const ssrfFindings = taint.filter(f => /ssrf/i.test(f.vuln));
  assert.equal(pathFindings.length, 0, `neither function has a real source; readLocal must not spuriously fire, got: ${pathFindings.map(f => f.vuln)}`);
  assert.equal(ssrfFindings.length, 0, `neither function has a real source; fetchRemote must not spuriously fire, got: ${ssrfFindings.map(f => f.vuln)}`);
});
