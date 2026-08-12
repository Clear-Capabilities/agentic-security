// SSRF / path guard recognition (PRD #1, precision). Drops CWE-918 / CWE-22
// findings on code hardened by a host allow/deny check or a path containment
// guard, regardless of which detector emitted them — without dropping a
// genuinely-unguarded sink.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dropGuardedFindings } from '../src/engine.js';
import { scanSSRFCloudMetadata } from '../src/sast/ssrf-cloud-metadata.js';

const F = (cwe, file, line) => ({ id: `${cwe}:${file}:${line}`, cwe, file, line, vuln: cwe === 'CWE-918' ? 'SSRF' : 'Path Traversal', severity: 'high' });

test('SSRF finding dropped when a host allow/deny guard is in scope', () => {
  const fc = { 'p.java': 'URL u = new URL(url);\nif (DENY.contains(u.getHost()) || u.getHost().startsWith("10.")) throw new Exception();\nu.openStream();' };
  const kept = dropGuardedFindings([F('CWE-918', 'p.java', 3)], fc);
  assert.equal(kept.length, 0);
});

test('SSRF finding KEPT when there is no guard (real vuln)', () => {
  const fc = { 'p.py': 'url = request.args.get("url")\nr = requests.get(url, timeout=5)\nreturn r.text' };
  assert.equal(dropGuardedFindings([F('CWE-918', 'p.py', 2)], fc).length, 1);
});

test('a vuln-describing comment must NOT read as a guard', () => {
  const fc = { 'p.py': '# no host allow-list or metadata filter; attacker hits 169.254.169.254\nr = requests.get(url)' };
  assert.equal(dropGuardedFindings([F('CWE-918', 'p.py', 2)], fc).length, 1);
});

test('path finding dropped on basename / containment guard, kept otherwise', () => {
  const guarded = { 'a.js': "const want = path.resolve(base, path.basename(req.query.file));\nif(!want.startsWith(base)) return res.status(400).end();\nfs.readFile(want, cb);" };
  assert.equal(dropGuardedFindings([F('CWE-22', 'a.js', 3)], guarded).length, 0);
  const vuln = { 'a.js': "fs.readFile('/var/data/' + req.query.file, cb);" };
  assert.equal(dropGuardedFindings([F('CWE-22', 'a.js', 1)], vuln).length, 1);
});

test('non-SSRF/path findings are untouched', () => {
  const fc = { 'a.js': 'DENY.has(x)\nbasename(y)' };
  assert.equal(dropGuardedFindings([F('CWE-89', 'a.js', 1), F('CWE-79', 'a.js', 2)], fc).length, 2);
});

test('reflected-XSS dropped when the value is HTML-escaped; raw reflection kept', () => {
  // escaped via a prior `const safe = escape(req.query.x)` then reflected.
  // The flow-pair finding carries its line on sink/source, not at top level.
  const safe = { 'app.js': "const safe = escape(req.query.msg || '');\nres.send('<div>' + safe + '</div>');" };
  const escaped = { id: 'app.js:1:Reflected_XSS', cwe: 'CWE-79', file: 'app.js', vuln: 'Reflected XSS', severity: 'medium', source: { line: 1 }, sink: { line: 2 } };
  assert.equal(dropGuardedFindings([escaped], safe).length, 0);
  // raw source concatenated straight into the sink → kept
  const vuln = { 'app.js': "res.send('<div>' + req.query.msg + '</div>');" };
  const raw = { id: 'app.js:1:Reflected_XSS', cwe: 'CWE-79', file: 'app.js', vuln: 'Reflected XSS', severity: 'medium', sink: { line: 1 } };
  assert.equal(dropGuardedFindings([raw], vuln).length, 1);
});

test('ssrf-cloud-metadata: metadata IP in a deny-list is not flagged; a real fetch is', () => {
  const n = (c) => scanSSRFCloudMetadata('x.js', c).filter(f => f.id.includes('hardcoded')).length;
  assert.equal(n('const DENY = new Set(["169.254.169.254"]); if (DENY.has(host)) throw new Error();'), 0);
  assert.ok(n('fetch("http://169.254.169.254/latest/meta-data/iam/")') >= 1);
});

// Stage 4 correctness audit: rule 2 (user-controlled URL into an HTTP
// client) checks `fileHasMetadataGuard = METADATA_GUARD_RE.test(code)` over
// the WHOLE FILE, then suppresses via `if (... || fileHasMetadataGuard)
// continue;` — a metadata guard ANYWHERE in the file suppresses EVERY
// unguarded call site in that file, not just ones actually near the guard.
// The correct, already-present check is the localized ±10-line window
// (`METADATA_GUARD_RE.test(window)`); `fileHasMetadataGuard` makes that
// check redundant in the safe direction and dangerous in the unsafe one.
// Pre-existing tests didn't catch this because they compare separate FILES
// (a guarded fixture vs. an unguarded one) — this needs both call sites in
// the SAME file to reproduce.
test('ssrf-cloud-metadata: a guard near one fetch does not blanket-suppress an unrelated, unguarded fetch far below it in the same file', () => {
  const filler = Array.from({ length: 20 }, (_, i) => `console.log("filler ${i}");`).join('\n');
  const src = [
    'function guardedFetch(req) {',
    '  if (req.url.host === "169.254.169.254") throw new SecurityException("blocked");',
    '  return fetch(req.query.url);',
    '}',
    filler,
    'function unguardedFetch(req) {',
    '  return fetch(req.query.url);',
    '}',
  ].join('\n');
  const out = scanSSRFCloudMetadata('app.js', src).filter(f => f.id.includes('usercontrolled'));
  // The near-guard fetch is correctly suppressed by its own local ±10-line
  // window; the far-away fetch has no guard anywhere near it and must fire.
  assert.equal(out.length, 1, `expected exactly the far, unguarded fetch to fire (near-guard one correctly suppressed locally); got ${out.length} findings: ${JSON.stringify(out.map(f => f.line))}`);
});
