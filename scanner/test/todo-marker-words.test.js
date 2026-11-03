// The known-broken-marker detector matches its security vocabulary as whole words (identifiers split on camelCase and underscores), not as
// substrings. Pinned in both directions with sources written for this file.

import test from 'node:test';
import assert from 'node:assert/strict';
import { scanTodosNearSecurity } from '../src/engine.js';

const hits = (src, file = 'x.txt') => scanTodosNearSecurity(file, src).length;

test('todo-marker: a marker next to a word that only CONTAINS a security word is not reported', () => {
  assert.equal(hits('-- TODO: credit the author\nmodule Foo where\n', 'Foo.hs'), 0);
  assert.equal(hits('-- FIXME later\nimport Data.Hashable\n', 'Foo.hs'), 0);
  assert.equal(hits('// TODO tidy\nconst tokenizerStream = 1\n', 'a.js'), 0);
});

test('todo-marker: a marker next to security logic is still reported, in comment text and in identifiers', () => {
  assert.equal(hits('// TODO validate the JWT signature here\nfoo()\n', 'a.js'), 1);
  assert.equal(hits('-- TODO tighten\ncheckAuthToken :: Token -> Bool\n', 'Foo.hs'), 1);
  assert.equal(hits('# TODO fix\ndef check_password(p):\n', 'a.py'), 1);
  assert.equal(hits('// HACK skip\nfunction verifySession(req) {}\n', 'a.js'), 1);
});

test('todo-marker: a marker with no security word in its window is not reported', () => {
  assert.equal(hits('// TODO rename\nconst total = 1\n', 'a.js'), 0);
});
