// The JavaScript parser refused any file over 500,000 characters, silently: a 520 KB editor bundle lowered
// to no function at all and nothing recorded it. The cap now matches the module resolver's 1.5 MB and a skip
// is recorded.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile, JS_MAX_CHARS, jsOversizeSkips, _resetJsOversizeSkips } from '../src/ir/parser-js.js';

function bundle(chars) {
  // Distinct names: a module may not declare the same function twice, and a parse error is a different skip.
  let s = '';
  for (let i = 0; s.length < chars; i++) s += `function f${i}(x) { return document.write(x); }\n`;
  return s;
}

test('a 700 KB file is lowered', () => {
  _resetJsOversizeSkips();
  const ir = parseJsFile('big.js', bundle(700_000));
  assert.ok(ir && ir.functions && ir.functions.length > 1000, 'functions lowered from a 700 KB file');
  assert.deepEqual(jsOversizeSkips(), []);
});

test('a file over the cap is skipped and the skip is recorded with its size', () => {
  _resetJsOversizeSkips();
  const code = bundle(JS_MAX_CHARS + 10);
  assert.equal(parseJsFile('huge.js', code), null);
  const skips = jsOversizeSkips();
  assert.equal(skips.length, 1);
  assert.equal(skips[0].file, 'huge.js');
  assert.equal(skips[0].chars, code.length);
  assert.equal(JS_MAX_CHARS, 1_500_000);
});
