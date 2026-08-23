// PRD F1.3 — `File.join(<root>, …, <untrusted>)`, the dominant Ruby CWE-22
// shape on real code.
//
// Measured baseline before this rule, over the cached Ruby CWE-22/CWE-79
// entries in `bench/independent`: **0 localized hits**, with roughly
// three-quarters of entries producing no finding of any kind. The existing
// `pathTraversalStructural` rule cannot reach this shape — it requires a STRING
// LITERAL as the first component (`File.read("/data/" + name)`) and the real
// advisories join variables:
//
//   File.join(adapter.document_root, request.path.sub(/\.html$/,'') + '.html')
//     lsegal/yard, GHSA-pxcc-8665-phx8 — the fix rejects `..` segments
//   File.join(root, tenant, folder_for(key), key)
//     basecamp/activerecord-tenanted, GHSA-pmwx-rm49-xv39
//
// PRECISION IS THE DESIGN. The earlier Ruby resource-exhaustion attempt was
// reverted because it fired on `File.read(File.join(__dir__, "…/data.json"))` —
// a path built entirely from constants. Every refusal below encodes one of the
// ways that could happen again.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRubyPathJoin } from '../src/sast/ruby.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, 'fixtures', 'ruby-path-join');
const hits = (body, file = 'lib/app.rb') => scanRubyPathJoin(file, body);

test('the fixture pair: vulnerable fires, clean is silent', () => {
  for (const [variant, expected] of [['vulnerable', 1], ['clean', 0]]) {
    const p = path.join(FIXTURES, variant, 'cache.rb');
    assert.equal(scanRubyPathJoin(p, fs.readFileSync(p, 'utf8')).length, expected, variant);
  }
});

test('FIX-DISCRIMINATION: the traversal check upstream shipped silences it', () => {
  // Both real advisories fixed this by rejecting `..` segments. The rule has to
  // go quiet on exactly that, or it reports a bug that is no longer there.
  const vulnerable = [
    'def serve(request)',
    '  cache_path = File.join(document_root, request.path)',
    '  File.read(cache_path)',
    'end',
  ].join('\n');
  assert.equal(hits(vulnerable).length, 1);

  for (const guard of [
    '  return nil if request.path.split("/").intersect?(%w[. ..])',
    '  raise if request.path.include?("..")',
    '  request.path = File.basename(request.path)',
    '  full = File.expand_path(File.join(document_root, request.path)); raise unless full.start_with?(document_root)',
  ]) {
    const guarded = [
      'def serve(request)', guard,
      '  cache_path = File.join(document_root, request.path)',
      '  File.read(cache_path)',
      'end',
    ].join('\n');
    assert.equal(hits(guarded).length, 0, `guard not recognised: ${guard.trim()}`);
  }
});

test('a constant-rooted join is not a finding', () => {
  // The exact false positive that got the previous Ruby rule reverted: a path
  // assembled from the project's own layout is not attacker-reachable.
  for (const root of ['__dir__', 'Rails.root', 'File.dirname(__FILE__)', 'Dir.pwd']) {
    const body = `def load_fixture(name)\n  File.read(File.join(${root}, "fixtures", name))\nend`;
    assert.equal(hits(body).length, 0, root);
  }
});

test('a join whose last component is a literal is not a finding', () => {
  const body = 'def index\n  File.read(File.join(document_root, "index.html"))\nend';
  assert.equal(hits(body).length, 0);
});

test('a join that never reaches the filesystem is not a finding', () => {
  // Building a path is not using one. `path_for` returning a string is the
  // cross-file case this rule deliberately declines rather than guessing —
  // basecamp/activerecord-tenanted is exactly that shape and stays missed.
  const body = 'def path_for(key)\n  File.join(root, folder_for(key), key)\nend';
  assert.equal(hits(body).length, 0);
});

test('Ruby predicate methods count as filesystem operations', () => {
  // `File.file?(x)` did not count, because the sink pattern ended in `\\b` and a
  // word boundary after `?` can never match. The rule looked correct and found
  // nothing on one of the two advisories it was written from — one character of
  // regex. Pinned so it cannot come back.
  for (const op of ['File.file?(cache_path)', 'File.exist?(cache_path)', 'File.directory?(cache_path)']) {
    const body = `def serve(request)\n  cache_path = File.join(document_root, request.path)\n  return nil unless ${op}\n  cache_path\nend`;
    assert.equal(hits(body).length, 1, op);
  }
});

test('the finding is actionable: it names the line and carries a remediation', () => {
  const [f] = hits('def serve(request)\n  cache_path = File.join(document_root, request.path)\n  File.read(cache_path)\nend');
  assert.equal(f.line, 2);
  assert.equal(f.cwe, 'CWE-22');
  assert.equal(f.family, 'path-traversal');
  assert.match(f.remediation, /intersect\?|expand_path/);
});
