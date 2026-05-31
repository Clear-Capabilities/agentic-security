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
