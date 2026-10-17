// E1-06: controls that the verdict follows the code, not the words, names, paths or comments around it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO } from './helpers.js';
import { CASES, E1_CASES, allCases, commentPrefixFor, deriveLabelCases, judge, withComment } from '../../../bench/mutation/cases.mjs';

const hand = [...CASES, ...E1_CASES];

test('case ids are unique and every case says why it expects what it expects', () => {
  const all = allCases();
  assert.equal(new Set(all.map((c) => c.id)).size, all.length);
  for (const c of all) assert.ok(c.why && c.why.length > 15, c.id);
  for (const c of all) assert.ok(typeof c.code === 'string' && c.code.length > 10, c.id);
});

test('the new controls cover frameworks, languages, lookalikes, misleading words and recorded gaps', () => {
  const byClass = {};
  for (const c of E1_CASES) byClass[c.class] = (byClass[c.class] || 0) + 1;
  assert.ok(byClass.baseline >= 18, JSON.stringify(byClass));
  assert.ok(byClass.adversarial >= 12);
  assert.ok(byClass.metamorphic >= 8);
  assert.equal(byClass['known-gap'], 5);
  const files = new Set(E1_CASES.map((c) => path.extname(c.file || 'app.js')));
  for (const ext of ['.js', '.ts', '.py', '.java', '.go', '.php', '.rb']) assert.ok(files.has(ext), `no case in ${ext}`);
  const ids = E1_CASES.map((c) => c.id).join(' ');
  for (const fw of ['koa', 'fastify', 'hapi', 'nest', 'flask', 'django', 'fastapi', 'gin', 'laravel', 'rails', 'sinatra']) assert.match(ids, new RegExp(fw), fw);
  assert.ok(E1_CASES.some((c) => /comment-claims-safe/.test(c.id)) && E1_CASES.some((c) => /comment-claims-vuln/.test(c.id)), 'both directions of misleading words');
  assert.ok(E1_CASES.some((c) => /description-constant/.test(c.id)), 'a malicious description inside the code');
});

test('a known gap records what the engine does today and what it should do, and the two differ', () => {
  const gaps = E1_CASES.filter((c) => c.class === 'known-gap');
  for (const g of gaps) {
    assert.ok(['false positive', 'false negative'].includes(g.gap.kind), g.id);
    assert.notEqual(g.gap.observedDetected, g.expectDetected, `${g.id}: a gap is a difference between behaviour and expectation`);
    assert.equal(g.gap.kind === 'false positive', g.gap.observedDetected === true && g.expectDetected === false);
  }
});

// ---- the verdict logic --------------------------------------------------------------------------------------------------------

test('detection cases pass when the engine concludes what the case expects, and fail otherwise', () => {
  const c = { class: 'adversarial', dimension: 'detection', expectDetected: false };
  assert.equal(judge(c, { detected: false, sanitized: false }).verdictOk, true);
  assert.equal(judge(c, { detected: true, sanitized: false }).verdictOk, false);
  const d = { class: 'baseline', dimension: 'detection', expectDetected: true };
  assert.equal(judge(d, { detected: true }).verdictOk, true);
  assert.equal(judge(d, { detected: false }).verdictOk, false);
});

test('a sanitization case needs the finding to fire: a blind engine cannot pass it', () => {
  const c = { class: 'metamorphic', expectSanitized: false };
  assert.equal(judge(c, { detected: true, sanitized: false }).verdictOk, true);
  assert.equal(judge(c, { detected: false, sanitized: false }).verdictOk, false, 'no finding is not "not sanitized"');
  const s = { class: 'metamorphic', expectSanitized: true };
  assert.equal(judge(s, { detected: true, sanitized: true }).verdictOk, true);
  assert.equal(judge(s, { detected: false, sanitized: true }).verdictOk, false);
});

test('a known gap holds only while the engine behaves as recorded; a closed gap and a changed gap both fail the gate', () => {
  const fp = { class: 'known-gap', dimension: 'detection', expectDetected: false, gap: { observedDetected: true } };
  assert.deepEqual([judge(fp, { detected: true }).verdictOk, judge(fp, { detected: true }).gapClosed], [true, false], 'still wrong in the recorded way');
  assert.deepEqual([judge(fp, { detected: false }).verdictOk, judge(fp, { detected: false }).gapClosed], [false, true], 'fixed: promote the case');
  const fn = { class: 'known-gap', dimension: 'detection', expectDetected: true, gap: { observedDetected: false } };
  assert.equal(judge(fn, { detected: false }).verdictOk, true);
  assert.equal(judge(fn, { detected: true }).gapClosed, true);
});

// ---- mechanically derived label-invariance ------------------------------------------------------------------------------------

test('comment syntax is chosen by file type and unknown types are skipped rather than corrupted', () => {
  assert.equal(commentPrefixFor('app.js'), '//');
  assert.equal(commentPrefixFor('C.java'), '//');
  assert.equal(commentPrefixFor('app.py'), '#');
  assert.equal(commentPrefixFor('a.rb'), '#');
  assert.equal(commentPrefixFor('data.json'), null);
  assert.equal(withComment('{}', 'data.json', 'x'), null);
});

test('a comment never lands before <?php or a shebang, and never changes the code beneath it', () => {
  assert.equal(withComment('<?php\n$a = 1;\n', 'a.php', 'note'), '<?php\n// note\n$a = 1;\n');
  assert.equal(withComment('#!/bin/sh\nls\n', 'a.sh', 'note'), '#!/bin/sh\n# note\nls\n');
  assert.equal(withComment('x = 1\n', 'a.py', 'note'), '# note\nx = 1\n');
  const src = 'db.query(a + b);\n';
  assert.equal(withComment(src, 'app.js', 'n').split('\n').slice(1).join('\n'), src);
});

test('every case with a comment syntax gets a vulnerable-style and a safe-style variant with the same expectation; gaps are not derived', () => {
  const derived = deriveLabelCases(hand);
  const eligible = hand.filter((c) => c.class !== 'known-gap' && commentPrefixFor(c.file));
  assert.equal(derived.length, eligible.length * 2);
  for (const c of eligible) {
    const v = derived.filter((d) => d.derivedFrom === c.id);
    assert.deepEqual(v.map((d) => d.id).sort(), [`${c.id}~safe-label`, `${c.id}~vuln-label`]);
    for (const d of v) {
      assert.equal(d.class, 'label-invariance');
      assert.equal(d.expectDetected, c.expectDetected);
      assert.equal(d.expectSanitized, c.expectSanitized);
      assert.equal(d.dimension, c.dimension);
      assert.notEqual(d.code, c.code);
    }
    assert.match(v.find((d) => d.id.endsWith('vuln-label')).code, /VULNERABLE: this is the FLAW/);
    assert.match(v.find((d) => d.id.endsWith('safe-label')).code, /SAFE: input is sanitized/);
  }
  assert.equal(derived.some((d) => d.derivedFrom && d.derivedFrom.startsWith('gap-')), false);
  assert.ok(derived.length >= 100);
});

// ---- independence from the regression corpus ----------------------------------------------------------------------------------------

test('no new case is a copy of a corpus or fixture file, and the little shared idiom is reported', () => {
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (['node_modules', '.git'].includes(e.name) ? [] : e.isDirectory() ? walk(path.join(d, e.name)) : /\.(js|ts|py|java|go|php|rb|cs|kt|rs|jsx|tsx)$/.test(e.name) ? [path.join(d, e.name)] : []));
  const norm = (s) => s.replace(/\s+/g, ' ').trim();
  const whole = new Set(); const lines = new Set();
  for (const root of ['bench/cve-replay', 'scanner/test/fixtures']) for (const f of walk(path.join(REPO, root))) {
    const text = fs.readFileSync(f, 'utf8');
    whole.add(norm(text));
    for (const l of text.split('\n')) { const n = norm(l); if (n.length >= 40) lines.add(n); }
  }
  assert.ok(lines.size > 1000, 'the corpus was actually read');
  let overlapping = 0;
  for (const c of E1_CASES) {
    assert.equal(whole.has(norm(c.code)), false, `${c.id} is a verbatim copy of a corpus file`);
    const own = c.code.split('\n').map(norm).filter((l) => l.length >= 40);
    if (own.some((l) => lines.has(l))) overlapping++;
  }
  assert.ok(overlapping <= 12, `${overlapping} of ${E1_CASES.length} cases share a long idiomatic line with the corpus`);
});

// ---- the gate itself ----------------------------------------------------------------------------------------------------------------

test('the gate runs end to end: every verdict correct, label invariance holds on every derived case, and the gaps are held', () => {
  const r = spawnSync(process.execPath, [path.join(REPO, 'bench/mutation/runner.mjs')], { cwd: path.join(REPO, 'scanner'), encoding: 'utf8', timeout: 240000 });
  assert.equal(r.status, 0, r.stdout.slice(-1500) + r.stderr.slice(-500));
  const m = (re) => new RegExp(re, 'm').exec(r.stdout);
  const frac = (label) => { const x = m(`^${label}[^\\n:]*: (\\d+)/(\\d+)`); return x ? [Number(x[1]), Number(x[2])] : null; };
  const li = frac('label-invariance'); const meta = frac('metamorphic'); const adv = frac('adversarial'); const gaps = frac('known gaps');
  for (const [name, f] of [['label-invariance', li], ['metamorphic', meta], ['adversarial', adv], ['known gaps', gaps]]) { assert.ok(f, name); assert.equal(f[0], f[1], `${name} ${f}`); }
  assert.ok(li[1] >= 100, `label-invariance covers ${li[1]} derived cases`);
  assert.equal(gaps[1], 5);
  assert.match(r.stdout, /every mutant verdict correct/);
});
