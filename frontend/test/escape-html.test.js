import { test } from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml } from '../src/lib/escape-html.js';

test('escapes all five HTML-significant characters', () => {
  assert.equal(
    escapeHtml(`<script>alert('&"x"')</script>`),
    '&lt;script&gt;alert(&#39;&amp;&quot;x&quot;&#39;)&lt;/script&gt;',
  );
});

test('handles null and undefined as empty string', () => {
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
});

test('passes through ordinary text unchanged', () => {
  assert.equal(escapeHtml('card_number'), 'card_number');
  assert.equal(escapeHtml('Payments Service'), 'Payments Service');
});

test('coerces non-string values (numbers, booleans) via String()', () => {
  assert.equal(escapeHtml(42), '42');
  assert.equal(escapeHtml(true), 'true');
});

test('a long adversarial payload with mixed HTML/JS never leaves a live tag boundary', () => {
  const payload = `"><img src=x onerror=alert(1)>&<svg/onload=alert(2)>`;
  const escaped = escapeHtml(payload);
  assert.ok(!escaped.includes('<img'));
  assert.ok(!escaped.includes('<svg'));
  assert.ok(!/(?<!&(amp|lt|gt|quot|#39);)[<>]/.test(escaped.replace(/&(amp|lt|gt|quot|#39);/g, '')), 'no raw angle bracket should survive outside an entity');
});
