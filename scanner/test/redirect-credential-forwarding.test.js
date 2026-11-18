// Credentials re-sent across a hand-written redirect follow (CWE-200), src/sast/redirect-credential-forwarding.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRedirectCredentialForwarding as scan } from '../src/sast/redirect-credential-forwarding.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'redirect-credential-forwarding');
const read = (side, f) => fs.readFileSync(path.join(FIX, side, f), 'utf8');
const lineOf = (code, needle) => code.split('\n').findIndex((l) => l.includes(needle)) + 1;

for (const [file, needle] of [['http_client.rb', 'return call(verb, next_url, opts)'], ['fetcher.py', 'headers=headers,']]) {
  test(`${file}: the re-issued request that forwards the same options is reported`, () => {
    const code = read('vulnerable', file);
    const out = scan(file, code);
    assert.deepEqual(out.map((f) => f.line), [lineOf(code, needle)]);
    assert.equal(out[0].cwe, 'CWE-200');
    for (const k of ['id', 'severity', 'file', 'line', 'vuln', 'cwe', 'description', 'remediation', 'parser', 'family']) assert.ok(out[0][k] !== undefined, k);
  });
  test(`${file}: the fixed version, which narrows the options per hop, is silent`, () => {
    assert.deepEqual(scan(file, read('clean', file)), []);
  });
}

test('a strip gated on the host name alone still reports; one gated on the origin does not', () => {
  const base = read('vulnerable', 'http_client.rb');
  const hostOnly = base.replace('    response = perform(verb, url, opts)\n',
    '    response = perform(verb, url, opts)\n    opts[:headers].delete("Authorization") if url.host != prev.host\n');
  assert.equal(scan('c.rb', hostOnly).length, 1);
  const origin = base.replace('    response = perform(verb, url, opts)\n',
    '    response = perform(verb, url, opts)\n    opts[:headers].delete("Authorization") if url.origin != prev.origin\n');
  assert.equal(scan('c.rb', origin).length, 0);
});

test('a validated location, a non-bag argument, and test code are silent', () => {
  const validated = read('vulnerable', 'http_client.rb').replace('      next_url = URI.join(url.to_s, target)\n',
    '      ensure_same_origin!(url, target)\n      next_url = URI.join(url.to_s, target)\n');
  assert.deepEqual(scan('c.rb', validated), []);
  const noBag = read('vulnerable', 'http_client.rb').replace('call(verb, next_url, opts)', 'call(verb, next_url, {})');
  assert.deepEqual(scan('c.rb', noBag), []);
  assert.deepEqual(scan('spec/client_spec.rb', read('vulnerable', 'http_client.rb')), []);
});
