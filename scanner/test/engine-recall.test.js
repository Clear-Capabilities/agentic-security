// Regression tests for the two engine recall gaps.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { CATALOG, matchSource } from '../src/dataflow/catalog.js';
import { parsePhpFile, parseRubyFile, parseJsFile } from '../src/ir/index.js';

async function scanJs(src) {
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'recall-test-'));
  try {
    fs.writeFileSync(path.join(dir, 'app.js'), src);
    const { scan } = await runScan(dir);
    const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
    return all.filter(f => /^IR-TAINT/.test(f.parser || ''));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const HEAD = `const { exec } = require('child_process');\nfunction h(req) { return req.query.c; }\n`;

test('assign-sink: a sink call in statement position is found (control)', async () => {
  const hits = await scanJs(HEAD + `function f(req) { const c = h(req); exec(c); }\nmodule.exports={f};\n`);
  assert.ok(hits.length >= 1, 'the control case must still be detected');
});

test('assign-sink: the same sink call on an assignment RHS is found', async () => {
  const hits = await scanJs(HEAD + `function f(req) { const c = h(req); const out = exec(c); return out; }\nmodule.exports={f};\n`);
  assert.ok(hits.length >= 1,
    `an assignment-position sink must be detected; got ${hits.length} IR-TAINT findings`);
});

test('assign-sink: a clean assignment RHS produces no finding', async () => {
  const hits = await scanJs(`const { exec } = require('child_process');\nfunction f() { const out = exec('ls -la'); return out; }\nmodule.exports={f};\n`);
  assert.equal(hits.length, 0, 'a literal argument must not be reported as tainted');
});

// Round 2 (fix round 1/5): the PHP IR frontend keeps the `$` sigil on
// variable idents (`$_GET['cmd']` lowers to an ident named `$_GET`, not
// `_GET`), but the catalog keys global entries without it. The round-1
// synthetic-ident tests below built their own sigil-free `{ kind: 'ident',
// name: '_GET' }` nodes by hand, so they could never exercise — let alone
// catch — that mismatch. These cases now drive real source through the
// real per-language parser and feed the actual IR node `matchSource`
// receives in production, so a regression here can only pass if the whole
// parse -> lower -> lookup path works end to end.
function _firstAssignSource(ir) {
  const fn = ir && ir.functions && ir.functions[0];
  if (!fn) return null;
  const node = Object.values(fn.cfg.nodes).find(n => n.kind === 'assign');
  return node ? node.source : null;
}

// One real snippet per catalog `global` entry id — every entry below is
// asserted present so a future global entry added without a matching probe
// fails loudly instead of silently not being covered.
const REAL_GLOBAL_PROBES = {
  'php-request': { file: 'a.php', parse: () => _firstAssignSource(parsePhpFile('a.php',
    `<?php\nfunction h() {\n  $u = $_REQUEST['cmd'];\n  return $u;\n}\n`)) },
  'php-get': { file: 'a.php', parse: () => _firstAssignSource(parsePhpFile('a.php',
    `<?php\nfunction h() {\n  $u = $_GET['cmd'];\n  return $u;\n}\n`)) },
  'php-post': { file: 'a.php', parse: () => _firstAssignSource(parsePhpFile('a.php',
    `<?php\nfunction h() {\n  $u = $_POST['cmd'];\n  return $u;\n}\n`)) },
  'php-cookie': { file: 'a.php', parse: () => _firstAssignSource(parsePhpFile('a.php',
    `<?php\nfunction h() {\n  $u = $_COOKIE['cmd'];\n  return $u;\n}\n`)) },
  'php-server': { file: 'a.php', parse: () => _firstAssignSource(parsePhpFile('a.php',
    `<?php\nfunction h() {\n  $u = $_SERVER['REQUEST_METHOD'];\n  return $u;\n}\n`)) },
  'rb-rails-params': { file: 'a.rb', parse: () => _firstAssignSource(parseRubyFile('a.rb',
    `def h(req)\n  u = params[:cmd]\n  system(u)\nend\n`)) },
  'rb-rails-cookies': { file: 'a.rb', parse: () => _firstAssignSource(parseRubyFile('a.rb',
    `def h(req)\n  u = cookies[:cmd]\n  system(u)\nend\n`)) },
  'rb-rails-session': { file: 'a.rb', parse: () => _firstAssignSource(parseRubyFile('a.rb',
    `def h(req)\n  u = session[:cmd]\n  system(u)\nend\n`)) },
  'rb-env': { file: 'a.rb', parse: () => _firstAssignSource(parseRubyFile('a.rb',
    `def h(req)\n  u = ENV['CMD']\n  system(u)\nend\n`)) },
  'js-location': { file: 'a.js', parse: () => _firstAssignSource(parseJsFile('a.js',
    `function h() {\n  const u = location.href;\n  eval(u);\n}\n`)) },
};

test('global sources: every global entry is reachable from real parser output', () => {
  const globals = CATALOG.filter(e => e && e.match && e.match.type === 'global');
  assert.ok(globals.length >= 10, `expected at least 10 global entries, got ${globals.length}`);
  const unreachable = [];
  for (const e of globals) {
    const probe = REAL_GLOBAL_PROBES[e.id];
    assert.ok(probe, `no real-parser probe wired for catalog entry ${e.id} — add one to REAL_GLOBAL_PROBES`);
    const expr = probe.parse();
    assert.ok(expr, `real parser produced no assign-source expr to probe ${e.id} with`);
    const hit = matchSource(expr, probe.file);
    if (!hit || hit.id !== e.id) unreachable.push(`${e.id}(${JSON.stringify(expr)})`);
  }
  assert.deepEqual(unreachable, [], `these global sources are unreachable from real parser output: ${unreachable.join(', ')}`);
});

test('global sources: a real PHP superglobal is language-scoped, not just name-scoped', () => {
  const expr = REAL_GLOBAL_PROBES['php-get'].parse();
  const phpOnJs = matchSource(expr, 'a.js');
  assert.ok(!phpOnJs || phpOnJs.language !== 'php',
    'a php superglobal, parsed for real (with its $ sigil), must not match a .js file');
  const phpOnPhp = matchSource(expr, 'a.php');
  assert.equal(phpOnPhp && phpOnPhp.id, 'php-get', 'the same expr must still match on a .php file');
});

test('global sources: an unrelated identifier does not match', () => {
  assert.equal(matchSource({ kind: 'ident', name: 'notAGlobalAnywhere' }, 'a.php'), null);
});
