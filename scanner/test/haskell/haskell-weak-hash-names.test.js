// Development cases for the extra pure-md5 / SHA package entry points in the weak-hash rule. Not an accuracy measurement.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';

const mk = (imp, body) => `module Main where\nimport qualified ${imp} as H\nimport qualified Data.ByteString.Lazy as L\n\nd :: L.ByteString -> L.ByteString\nd x = ${body}\n`;
const run = (src) => analyzeHaskellRules({ 'Main.hs': src });
const rules = (src) => { const r = run(src); return (r.findings || r).map((f) => f.rule); };

test('pureMD5 md5DigestBytes is a weak hash', () => assert.ok(rules(mk('Data.Digest.Pure.MD5', 'H.md5DigestBytes undefined')).includes('hs-weak-hash')));
test('SHA sha1Incremental is a weak hash', () => assert.ok(rules(mk('Data.Digest.Pure.SHA', 'H.sha1Incremental x')).includes('hs-weak-hash')));
test('sha256 is not flagged', () => assert.ok(!rules(mk('Data.Digest.Pure.SHA', 'H.sha256 x')).includes('hs-weak-hash')));
