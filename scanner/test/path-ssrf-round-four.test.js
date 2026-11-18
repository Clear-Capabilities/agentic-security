// Path traversal, SSRF and DNS-rebinding shapes added together:
//   go-request-path-join        (path-file-handling.js)  CWE-22
//   go-decoded-path-forwarded   (path-file-handling.js)  CWE-22
//   bare-prefix-containment with a member root resolved in the constructor
//                               (path-file-handling.js)  CWE-22
//   validated host re-fetched by name (redirect-toctou.js, toctou-resolve) CWE-367
//   Laravel fetch rule after an SSRF guard without 'bail' (laravel-hardening.js) CWE-918
//
// Each is pinned in both directions on a synthetic vulnerable / clean pair.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanPathFileHandling } from '../src/sast/path-file-handling.js';
import { scanRedirectToctou } from '../src/sast/redirect-toctou.js';
import { scanLaravelFetchRuleWithoutBail } from '../src/sast/laravel-hardening.js';
import { blankComments } from '../src/sast/_comment-strip.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, 'fixtures');
const read = (...p) => fs.readFileSync(path.join(FIX, ...p), 'utf8');

function pfh(dir, kind, file) {
  const p = path.join(FIX, dir, kind, file);
  return scanPathFileHandling(p, blankComments(fs.readFileSync(p, 'utf8'))).map((f) => ({ rule: f.id.split(':')[0], line: f.line, cwe: f.cwe }));
}

test('go-request-path-join fires on a query value joined into a path', () => {
  const v = pfh('go-request-path-join', 'vulnerable', 'notes.go').filter((f) => f.rule === 'go-request-path-join');
  assert.equal(v.length, 1);
  assert.equal(v[0].cwe, 'CWE-22');
  assert.equal(v[0].line, 17);
});

test('go-request-path-join is silent when the value must be local', () => {
  assert.deepEqual(pfh('go-request-path-join', 'clean', 'notes.go').filter((f) => f.rule === 'go-request-path-join'), []);
});

test('go-decoded-path-forwarded fires on a decoded rewrite forwarded as is', () => {
  const v = pfh('go-decoded-path-forwarded', 'vulnerable', 'rewrite.go').filter((f) => f.rule === 'go-decoded-path-forwarded');
  assert.equal(v.length, 1);
  assert.equal(v[0].line, 26);
});

test('go-decoded-path-forwarded is silent when the decoded path is normalized and compared', () => {
  assert.deepEqual(pfh('go-decoded-path-forwarded', 'clean', 'rewrite.go').filter((f) => f.rule === 'go-decoded-path-forwarded'), []);
});

test('bare-prefix-containment sees a member root resolved where it is set', () => {
  const v = pfh('bare-prefix-member-root', 'vulnerable', 'workspace.ts').filter((f) => f.rule === 'bare-prefix-containment');
  assert.equal(v.length, 1);
  assert.equal(v[0].line, 12);
});

test('bare-prefix-containment is silent with a separator-anchored prefix', () => {
  assert.deepEqual(pfh('bare-prefix-member-root', 'clean', 'workspace.ts').filter((f) => f.rule === 'bare-prefix-containment'), []);
});

const rebinding = (kind) => {
  const p = path.join(FIX, 'validated-host-refetch', kind, 'feed_fetch.py');
  return scanRedirectToctou(p, fs.readFileSync(p, 'utf8')).filter((f) => f.subfamily === 'toctou-resolve');
};

test('a host validated by a resolving helper and then fetched by name is a TOCTOU', () => {
  const v = rebinding('vulnerable');
  assert.equal(v.length, 1);
  assert.equal(v[0].cwe, 'CWE-367');
  assert.equal(v[0].line, 19);
});

test('a helper that returns the checked address and a pinned request is silent', () => {
  assert.deepEqual(rebinding('clean'), []);
});

function laravel(kind) {
  const base = path.join('laravel-fetch-rule-without-bail', kind, 'app');
  const fc = {};
  for (const rel of ['Rules/PublicDestination.php', 'Rules/ServesImage.php', 'Http/Requests/StoreAvatarRequest.php']) {
    fc[`app/${rel}`] = read(base, rel);
  }
  return scanLaravelFetchRuleWithoutBail(fc);
}

test('a fetching rule after an SSRF guard rule without bail is reported at the list', () => {
  const v = laravel('vulnerable');
  assert.equal(v.length, 1);
  assert.equal(v[0].cwe, 'CWE-918');
  assert.equal(v[0].file, 'app/Http/Requests/StoreAvatarRequest.php');
  assert.equal(v[0].line, 14);
});

test('the same list starting with bail is silent', () => {
  assert.deepEqual(laravel('clean'), []);
});
