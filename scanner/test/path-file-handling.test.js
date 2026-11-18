// Path and file handling rules (src/sast/path-file-handling.js) plus the
// verified-then-read-by-path TOCTOU shape in src/sast/toctou.js.
//
// Each rule is pinned in both directions on a synthetic fixture pair: the
// vulnerable file must produce exactly the rules listed below, and the clean
// file (the same code with the correct guard) must produce none of them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanPathFileHandling } from '../src/sast/path-file-handling.js';
import { scanTOCTOU } from '../src/sast/toctou.js';
import { blankComments } from '../src/sast/_comment-strip.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, 'fixtures', 'path-file-handling');
const langOf = (f) => (/\.py$/.test(f) ? 'py' : /\.rb$/.test(f) ? 'rb' : /\.php$/.test(f) ? 'php' : undefined);

function run(kind, file) {
  const p = path.join(FIX, kind, file);
  const code = blankComments(fs.readFileSync(p, 'utf8'), langOf(p));
  return [...scanPathFileHandling(p, code), ...scanTOCTOU(p, code).filter((f) => f.id.startsWith('toctou-verified-path-read'))]
    .map((f) => ({ rule: f.id.split(':')[0], line: f.line, cwe: f.cwe }));
}
const rules = (fs_) => [...new Set(fs_.map((f) => f.rule))].sort();

const EXPECT = {
  'schema_loader.py': ['bare-prefix-containment', 'path-ref-join-read', 'weak-clean-guard'],
  'store.go': ['bare-prefix-containment', 'path-ref-join-read', 'unmasked-file-mode', 'weak-clean-guard'],
  'TemplateIncludes.cs': ['path-ref-join-read'],
  'upload.php': ['bare-prefix-containment', 'php-upload-client-name', 'suffix-extension-denylist'],
  'static_server.rb': ['ruby-request-path-serve'],
  'mount-reader.ts': ['toctou-verified-path-read'],
};

for (const [file, want] of Object.entries(EXPECT)) {
  test(`vulnerable ${file} fires ${want.join(', ')}`, () => {
    assert.deepEqual(rules(run('vulnerable', file)), want);
  });
  test(`clean ${file} is silent`, () => {
    assert.deepEqual(run('clean', file), []);
  });
}

test('findings carry the class CWE and point at the defect line', () => {
  const php = run('vulnerable', 'upload.php');
  assert.ok(php.some((f) => f.rule === 'php-upload-client-name' && f.cwe === 'CWE-22' && f.line === 24), 'concatenation of the client name');
  assert.ok(php.some((f) => f.rule === 'suffix-extension-denylist' && f.cwe === 'CWE-434'));
  const rb = run('vulnerable', 'static_server.rb');
  assert.deepEqual(rb.map((f) => f.line), [17], 'reported at the call that serves the request path, not inside the reader');
  const go = run('vulnerable', 'store.go');
  assert.ok(go.some((f) => f.rule === 'unmasked-file-mode' && f.cwe === 'CWE-732'));
  const ts = run('vulnerable', 'mount-reader.ts');
  assert.deepEqual(ts, [{ rule: 'toctou-verified-path-read', line: 10, cwe: 'CWE-367' }]);
});

test('reference naming is case-sensitive: href and words containing "ref" are not references', () => {
  const code = [
    'import fs from "node:fs";',
    'import path from "node:path";',
    'export const fixtureFileData = (filename) => fs.readFileSync(path.join(__dirname, filename));',
    'export function loadHref(href) { return fs.readFileSync(path.join(ROOT, href)); }',
  ].join('\n');
  assert.deepEqual(scanPathFileHandling('a.js', code), []);
});

test('a document reference read without containment fires; the same join with is_relative_to does not', () => {
  const bad = 'def resolve_include(self, include_path):\n    p = self.root_dir / include_path\n    return p.read_text()\n';
  const good = 'def resolve_include(self, include_path):\n    p = (self.root_dir / include_path).resolve()\n    if not p.is_relative_to(self.root_dir):\n        raise ValueError()\n    return p.read_text()\n';
  assert.equal(scanPathFileHandling('x.py', bad).length, 1);
  assert.equal(scanPathFileHandling('x.py', good).length, 0);
});

test('Go: a decoded name joined with the slash `path` package (remote names) is not a local file path', () => {
  const code = 'package x\nfunc (f *Fs) remotePath(n string) string {\n\treturn path.Join(f.root, url.PathUnescape(n))\n}\n';
  assert.deepEqual(scanPathFileHandling('x.go', code), []);
});

test('suffix denylist ignores lists that are not file extensions checked against a file name', () => {
  const code = 'const BLOCKED_ENV_SUFFIXES = ["_KEY"];\nfunction ok(key) { for (const s of BLOCKED_ENV_SUFFIXES) { if (key.endsWith(s)) return false; } return true; }\n';
  assert.deepEqual(scanPathFileHandling('x.js', code), []);
});
