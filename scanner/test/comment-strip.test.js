// blankComments' 'php' mode — added alongside the Stage 1 fix to
// xxe.js/xss-reflected-multilang.js, which were both routed through 'py'
// mode (strips only `#`), leaving PHP's much more common `//`/`/* */`
// comment forms completely unstripped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { blankComments } from '../src/sast/_comment-strip.js';

test('blankComments php mode strips //, /* */, and # comments', () => {
  const src = '<?php\n// line comment\n/* block\n comment */\n# hash comment\necho "real code";\n';
  const out = blankComments(src, 'php');
  assert.doesNotMatch(out, /line comment/);
  assert.doesNotMatch(out, /block/);
  assert.doesNotMatch(out, /hash comment/);
  assert.match(out, /echo "real code";/);
});

test('blankComments php mode preserves line count (indices stay aligned)', () => {
  const src = '<?php\n// c1\necho 1;\n/* c2\nc3 */\necho 2;\n';
  const out = blankComments(src, 'php');
  assert.equal(out.split('\n').length, src.split('\n').length);
});

test('blankComments php mode does not blank a #[Attribute] (PHP 8 syntax, not a comment)', () => {
  const src = '#[Route("/x", methods: ["POST"])]\nfunction handle() {}\n';
  const out = blankComments(src, 'php');
  assert.match(out, /#\[Route/);
});

test('blankComments py mode is unaffected by the php addition', () => {
  const src = '# python comment\nx = 1  // not a comment in python, left alone\n';
  const out = blankComments(src, 'py');
  assert.doesNotMatch(out, /python comment/);
  assert.match(out, /not a comment in python/);
});
