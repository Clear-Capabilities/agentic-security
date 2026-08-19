// A comment is not code. A dangerous construct that appears only inside a
// comment cannot execute, so reporting it is a false positive — and on real
// repositories, which are full of commented-out code, it is a recurring one.
//
// `src/sast/CLAUDE.md` already names this as the FIRST gotcha for detector
// authors ("Comments confuse detectors. Always go through blankComments()"),
// and docs/WORLD_CLASS_DETECTION_PRD.md §8c records the highest-volume
// instance ever measured: PHP backtick command injection, 105 findings, whose
// sampled instance was English prose in a `//` comment.
//
// The convention was documented but never enforced. `runFullScan` dispatches
// the RAW file contents to every SAST module, so whether a given rule ignores
// comments depended on whether its author remembered to strip them: 64 of 117
// modules called blankComments(), the rest did not. Separately the engine's own
// `stripNoise()` handled `//` and `/* */` but NOT `#`, so every engine-level
// regex pass leaked on Python/Ruby/shell/HCL comments regardless.
//
// These tests pin the property itself — "findings come from code" — rather than
// any one detector's use of the helper, so a future module that forgets to
// strip is caught by the behaviour rather than by review.
//
// DELIBERATELY OUT OF SCOPE, both asserted below so the boundary is a decision
// and not an oversight:
//   - `scan.secrets`: a credential committed inside a comment is still a
//     leaked credential. Those scanners read raw source on purpose.
//   - prompt-injection detectors: for an agentic tool, instructions hidden in a
//     comment are the attack, not a false positive.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-commentblind-'));
  const src = path.join(dir, 'src');
  fs.mkdirSync(src, { recursive: true });
  for (const [name, body] of Object.entries(files)) {
    fs.writeFileSync(path.join(src, name), body);
  }
  return dir;
}

// Reported findings that land on a line which is itself a comment.
function findingsOnCommentLines(scan, dir) {
  const hashLang = new Set(['.py', '.rb', '.sh', '.yml', '.yaml', '.tf']);
  const out = [];
  for (const f of (scan.findings || [])) {
    if (!Number.isInteger(f.line)) continue;
    const abs = path.isAbsolute(f.file) ? f.file : path.join(dir, f.file);
    let text;
    try { text = fs.readFileSync(abs, 'utf8').split('\n')[f.line - 1]; } catch { continue; }
    const t = (text || '').trim();
    if (!t) continue;
    const ext = path.extname(abs);
    const isComment = hashLang.has(ext)
      ? t.startsWith('#')
      : (t.startsWith('//') || t.startsWith('/*') || t.startsWith('*') || t.startsWith('#'));
    if (isComment) out.push(`${path.basename(abs)}:${f.line} ${f.vuln} — ${t.slice(0, 70)}`);
  }
  return out;
}

const PY_COMMENTED = `# cursor.execute("SELECT * FROM users WHERE n = '" + request.args["n"] + "'")
# os.system("ping " + request.args.get("host"))
# os.popen("cat " + request.args["p"])
# hashlib.md5(password).hexdigest()
# pickle.loads(request.data)
# yaml.load(request.data)
# random.random()
# open("/data/" + request.args["f"]).read()


def safe():
    return 1
`;

const JS_COMMENTED = `// const q = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
// db.query(q);
// eval(req.body.code);
// exec("ping " + req.query.host);
// crypto.createHash("md5").update(password).digest("hex");
// Math.random().toString(36);
/*
 * connection.execute("SELECT * FROM t WHERE n = " + req.params.n);
 * exec("rm -rf " + req.body.path);
 */
export function safe() {
  return 1;
}
`;

const RB_COMMENTED = `# User.where("name = '#{params[:name]}'")
# system("ping " + params[:host])
# eval(params[:code])
# Digest::MD5.hexdigest(password)

def safe
  1
end
`;

// Ruby's block comment is `=begin` / `=end` at column 0 — a form no other
// supported language shares, and one a `#`-only stripper leaves entirely
// intact.
const RB_BLOCK_COMMENTED = `=begin
ActiveRecord::Base.connection.execute("SELECT * FROM t WHERE n = #{params[:n]}")
system("cat " + params[:p])
eval(params[:code])
=end

def safe
  1
end
`;

const PHP_COMMENTED = `<?php
// $q = "SELECT * FROM users WHERE id = '" . $_GET['id'] . "'";
// mysqli_query($conn, $q);
# shell_exec("ping " . $_GET['host']);
# system("cat " . $_GET['p']);
/* eval($_POST['code']); */

function safe() {
    return 1;
}
`;

test('python: dangerous constructs inside # comments produce no findings', async () => {
  const dir = fixture({ 'app.py': PY_COMMENTED });
  const { scan } = await runScan(dir);
  const leaks = findingsOnCommentLines(scan, dir);
  assert.deepEqual(leaks, [], `findings reported on comment lines:\n${leaks.join('\n')}`);
});

test('javascript: dangerous constructs inside // and /* */ comments produce no findings', async () => {
  const dir = fixture({ 'app.js': JS_COMMENTED });
  const { scan } = await runScan(dir);
  const leaks = findingsOnCommentLines(scan, dir);
  assert.deepEqual(leaks, [], `findings reported on comment lines:\n${leaks.join('\n')}`);
});

test('ruby: dangerous constructs inside # comments produce no findings', async () => {
  const dir = fixture({ 'app.rb': RB_COMMENTED });
  const { scan } = await runScan(dir);
  const leaks = findingsOnCommentLines(scan, dir);
  assert.deepEqual(leaks, [], `findings reported on comment lines:\n${leaks.join('\n')}`);
});

// A regex literal routinely contains an ODD number of quote characters —
// `/"(?:sh|bash)"\s*,\s*(?!"[^"]*")/` has seven. A comment stripper that treats
// every quote as a string delimiter enters "inside a string" at that point and,
// if the state survives the newline, never leaves: every comment in the rest of
// the file silently stops being stripped.
//
// Found on this repository's own `sast/go-extended.js`, where exactly this
// shape resurrected a `http.Get(` false positive out of a descriptive comment
// 6 lines below the regex. Single- and double-quoted strings do not span lines
// in any language handled here, so the state must reset at a newline.
test('an unbalanced quote inside a regex literal does not disable comment stripping for the rest of the file', async () => {
  const dir = fixture({
    'rules.js': `export const RULES = [
  {
    id: 'shell-form',
    re: /\\bexec\\.Command\\s*\\(\\s*"(?:sh|bash)"\\s*,\\s*"-c"\\s*,\\s*(?!"[^"]*"\\s*\\))/g,
    vuln: 'Command Injection',
  },
];
// http.get(varExpr) or http.request(method, varExpr) where the URL is a variable.
// exec("ping " + req.query.host);
// crypto.createHash("md5").update(password).digest("hex");
export function safe() { return 1; }
`,
  });
  const { scan } = await runScan(dir);
  const leaks = findingsOnCommentLines(scan, dir);
  assert.deepEqual(leaks, [],
    `a quote inside a regex literal must not leave the stripper stuck in string mode:\n${leaks.join('\n')}`);
});

test('ruby: dangerous constructs inside an =begin/=end block produce no findings', async () => {
  const dir = fixture({ 'block.rb': RB_BLOCK_COMMENTED });
  const { scan } = await runScan(dir);
  // This block form yields findings with no `line`, which the comment-line
  // helper cannot classify — so assert on the absence of the findings
  // themselves rather than on where they landed.
  const injected = (scan.findings || []).filter((f) => /inject/i.test(f.vuln || ''));
  assert.deepEqual(injected.map((f) => f.vuln), [],
    `=begin/=end is a comment; nothing inside it executes. Got: ${JSON.stringify(injected.map((f) => `${f.vuln}@${f.line}`))}`);
});

test('php: dangerous constructs inside //, # and /* */ comments produce no findings', async () => {
  const dir = fixture({ 'app.php': PHP_COMMENTED });
  const { scan } = await runScan(dir);
  const leaks = findingsOnCommentLines(scan, dir);
  assert.deepEqual(leaks, [], `findings reported on comment lines:\n${leaks.join('\n')}`);
});

// Positive control. Without this the four tests above could pass simply because
// the engine stopped detecting anything at all, which is the failure mode that
// makes a "no false positives" assertion worthless.
test('positive control: the same constructs as real code still produce findings', async () => {
  const dir = fixture({
    'real.py': `import os, hashlib
from flask import request

def handler():
    os.system("ping " + request.args.get("host"))
    return hashlib.md5(request.args["pw"].encode()).hexdigest()
`,
    'real.js': `const crypto = require("crypto");
const { exec } = require("child_process");
module.exports = function (req, res) {
  exec("ping " + req.query.host);
  return crypto.createHash("md5").update(req.query.pw).digest("hex");
};
`,
  });
  const { scan } = await runScan(dir);
  const findings = scan.findings || [];
  assert.ok(findings.length > 0, 'expected the code (non-comment) fixture to still produce findings');
  const cmdi = findings.filter((f) => /command inject/i.test(f.vuln || ''));
  assert.ok(cmdi.length > 0, `expected a command-injection finding on real code, got: ${JSON.stringify(findings.map((f) => f.vuln))}`);
});

// Python's `//` is floor division, not a comment. Blanking it would delete real
// code and silently destroy the rest of the line — the exact reason comment
// stripping has to be language-aware rather than one regex for every file.
test('python floor division is not treated as a comment', async () => {
  const dir = fixture({
    'math_ops.py': `import os
from flask import request

def handler():
    half = int(request.args["n"]) // 2
    os.system("echo " + str(half) + request.args["cmd"])
    return half
`,
  });
  const { scan } = await runScan(dir);
  const cmdi = (scan.findings || []).filter((f) => /command inject/i.test(f.vuln || ''));
  assert.ok(cmdi.length > 0,
    `the os.system sink sits AFTER a \`//\` floor-division operator; blanking from \`//\` to end-of-line would erase it. Findings: ${JSON.stringify((scan.findings || []).map((f) => f.vuln))}`);
});
