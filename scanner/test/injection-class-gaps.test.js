// Injection-class gaps: each rule fires on its vulnerable fixture and stays silent on the clean one (which carries the fix and,
// where it matters, a near miss the rule must not confuse with the defect).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanLiteralEscaping } from '../src/sast/literal-escaping.js';
import { scanXXE } from '../src/sast/xxe.js';
import { scanRubyKernelOpen } from '../src/sast/ruby.js';
import { scanWeakLocalPathGuard, scanOpenRedirect } from '../src/sast/open-redirect.js';
import { scanPhpStreamRedirect } from '../src/sast/redirect-toctou.js';
import { scanFrontmatterEngine } from '../src/sast/frontmatter-engine.js';
import { scanGitOptionInjection } from '../src/sast/git-option-injection.js';
import { scanPrototypePollutionStructural } from '../src/sast/prototype-pollution-structural.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const run = (scan, rule, side, file) => scan(file, fs.readFileSync(path.join(FIX, rule, side, file), 'utf8'));
const lc = (fs_) => fs_.map((f) => [f.line, f.cwe]);

test('literal escaping: quote escaped without the backslash, and a quoted interpolation in generated code', () => {
  assert.deepEqual(lc(run(scanLiteralEscaping, 'literal-escaping', 'vulnerable', 'emit.py')), [[2, 'CWE-94']]);
  assert.deepEqual(lc(run(scanLiteralEscaping, 'literal-escaping', 'vulnerable', 'quote.php')), [[3, 'CWE-94']]);
  assert.deepEqual(lc(run(scanLiteralEscaping, 'literal-escaping', 'vulnerable', 'scaffold.ts')).sort(), [[2, 'CWE-94'], [6, 'CWE-94']]);
  for (const f of ['emit.py', 'quote.php', 'scaffold.ts']) assert.deepEqual(run(scanLiteralEscaping, 'literal-escaping', 'clean', f), [], f);
  // SQL text gets CWE-89
  assert.equal(scanLiteralEscaping('q.py', 'def q(n):\n    return cursor.execute("SELECT * FROM t WHERE n = \'" + n.replace("\'", "\\\\\'") + "\'")\n')[0]?.cwe, 'CWE-89');
  // an encoder on the other branch of a ternary does not escape this value
  assert.equal(scanLiteralEscaping('x.ts', 'export const f = (s: string, u: boolean) => u ? `"${s.replace(/"/g, \'\\\\"\')}"` : JSON.stringify(s);\n').length, 1);
});

test('XXE: a factory implementation constructed directly', () => {
  assert.deepEqual(lc(run(scanXXE, 'xxe-factory-impl', 'vulnerable', 'Render.java')), [[8, 'CWE-611']]);
  assert.deepEqual(run(scanXXE, 'xxe-factory-impl', 'clean', 'Render.java'), []);
});

test('Ruby Kernel#open with a non-literal path', () => {
  assert.deepEqual(lc(run(scanRubyKernelOpen, 'ruby-kernel-open', 'vulnerable', 'tags.rb')), [[4, 'CWE-78']]);
  assert.deepEqual(run(scanRubyKernelOpen, 'ruby-kernel-open', 'clean', 'tags.rb'), []);
  assert.deepEqual(scanRubyKernelOpen('a.rb', 'class A\n  def open(x); end\n  def b(p); open(p); end\nend\n'), [], 'a class defining open calls its own method');
});

test('open redirect: a local-path guard that accepts //host', () => {
  assert.deepEqual(lc(run(scanWeakLocalPathGuard, 'open-redirect-weak-local-path', 'vulnerable', 'return_guard.rb')), [[5, 'CWE-601']]);
  assert.deepEqual(lc(run(scanWeakLocalPathGuard, 'open-redirect-weak-local-path', 'vulnerable', 'next.js')), [[2, 'CWE-601']]);
  assert.deepEqual(run(scanWeakLocalPathGuard, 'open-redirect-weak-local-path', 'clean', 'return_guard.rb'), []);
  assert.deepEqual(run(scanWeakLocalPathGuard, 'open-redirect-weak-local-path', 'clean', 'next.js'), []);
  // the redirect rule no longer takes startsWith('/') alone as a guard, but still takes it with a // rejection or a fixed prefix
  const r = (guard) => scanOpenRedirect('a.js', `app.get('/x', (req, res) => {\n  const n = req.query.next;\n  if (${guard}) return res.redirect(req.query.next);\n});\n`);
  assert.equal(r("n.startsWith('/')").length, 1);
  assert.equal(r("n.startsWith('/') && !n.startsWith('//')").length, 0);
  assert.equal(r("n.startsWith('/app/')").length, 0);
});

test('PHP stream fetch after a host allow-list follows redirects unless follow_location is 0', () => {
  assert.deepEqual(lc(run(scanPhpStreamRedirect, 'php-stream-redirect', 'vulnerable', 'Fetcher.php')), [[11, 'CWE-918']]);
  assert.deepEqual(run(scanPhpStreamRedirect, 'php-stream-redirect', 'clean', 'Fetcher.php'), []);
});

test('gray-matter with its JavaScript engine left on', () => {
  assert.deepEqual(lc(run(scanFrontmatterEngine, 'frontmatter-engine', 'vulnerable', 'notes.ts')), [[4, 'CWE-94']]);
  assert.deepEqual(run(scanFrontmatterEngine, 'frontmatter-engine', 'clean', 'notes.ts'), []);
  assert.deepEqual(scanFrontmatterEngine('a.ts', 'import matter from "front-matter";\nmatter(raw);\n'), [], 'another package');
});

test('caller keyword arguments forwarded as git options', () => {
  assert.deepEqual(lc(run(scanGitOptionInjection, 'git-option-injection', 'vulnerable', 'history.py')), [[5, 'CWE-88']]);
  assert.deepEqual(run(scanGitOptionInjection, 'git-option-injection', 'clean', 'history.py'), []);
});

test('prototype pollution: regex-capture keys with method recursion, and a delete after a split-path walk', () => {
  assert.deepEqual(lc(run(scanPrototypePollutionStructural, 'prototype-pollution-walk', 'vulnerable', 'bracket-keys.js')), [[7, 'CWE-1321'], [22, 'CWE-1321']]);
  assert.deepEqual(run(scanPrototypePollutionStructural, 'prototype-pollution-walk', 'clean', 'bracket-keys.js'), []);
});
