// Taint-recall PRD (80%): two engine bugs found while debugging why several
// interprocedural corpus fixtures produced zero findings despite a correctly
// cataloged sink and a correctly recognized source.
//
// 1. exprTaint's `case 'call'` short-circuited on "an argument is already
//    tainted" and returned early — skipping _nestedCallReturnTainted
//    entirely, which is the ONLY place that resolves the callee, computes
//    its summary, and MERGES its internal findings into the caller. A
//    tainted argument is the overwhelmingly common interprocedural shape
//    (`return helper(taintedArg)`), so this silently dropped exactly the
//    findings the mechanism exists to surface.
// 2. entryStateFromCall (summaries.js) used an if/else-if chain keyed on
//    argument SHAPE (ident vs. member) rather than on whether that shape's
//    own membership check succeeded — so a source used directly inline as
//    an argument (`helper(request.getParameter("id"))`, never first
//    assigned to a local) took the member branch, found nothing in
//    callerTaintedVars (which tracks ASSIGNED locals, not raw expressions),
//    and — being an else-if — never reached the exprTaint fallback at all.
//
// Both are exercised together here (real-world code virtually always
// combines them) via PHP, the language the corpus fixture that surfaced
// this used. Neither is PHP-specific — both live in language-agnostic
// engine code (engine.js / summaries.js).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-interproc-nested-${name}-`));
  for (const [file, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, file), content);
  }
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('a source used inline as a call argument (never assigned to a local) propagates into the callee', async () => {
  const dir = mkTmp('inline-arg', {
    'lookup.php': `<?php
function find_user($doc, $name) {
    $xp = new DOMXPath($doc);
    return $xp->query("//user[@name='" . $name . "']");
}
function handler($doc) {
    return find_user($doc, $_GET['name']);
}
`,
  });
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath/i.test(f.vuln)),
    `expected an interprocedural XPath Injection finding, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('a tainted local variable (via an intermediate assign) still propagates into the callee (regression check)', async () => {
  const dir = mkTmp('via-local', {
    'lookup.php': `<?php
function get_name() {
    return $_GET['name'];
}
function find_user($doc, $name) {
    $xp = new DOMXPath($doc);
    return $xp->query("//user[@name='" . $name . "']");
}
function handler($doc) {
    $name = get_name();
    return find_user($doc, $name);
}
`,
  });
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath/i.test(f.vuln)),
    `expected an interprocedural XPath Injection finding via a local var, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('an untainted argument does not spuriously trigger the callee\'s internal sink (precision check)', async () => {
  const dir = mkTmp('clean', {
    'lookup.php': `<?php
function find_user($doc, $name) {
    $xp = new DOMXPath($doc);
    return $xp->query("//user[@name='" . $name . "']");
}
function handler($doc) {
    return find_user($doc, "admin");
}
`,
  });
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /xpath/i.test(f.vuln)).length, 0,
    `a hardcoded literal argument must not fire the XPath sink, got: ${taint.map(f => f.vuln).join(', ')}`);
});
