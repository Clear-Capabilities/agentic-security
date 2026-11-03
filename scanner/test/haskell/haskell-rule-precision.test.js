// Rule precision from semantics (plan Phase 3, items 10 and 11). A self-written probe of 13 partial-function idioms (2026-11-02, before any
// change) had the rule report five: two TOTAL calls (`head (x : xs)`, `last (xs ++ [x])`), a `when (length xs > 2)` guard written as a
// combinator, a `case length xs of 3` size test, and the two unguarded calls it should report. The weak-hash rule did not see a digest
// chosen by a type annotation (`hash x :: Digest MD5`). Pinned both ways; the dev-set site that motivated the totality rule is xmonad's
// `last (["Root"] ++ ..)` (labelled FP in 0.195.11), the rule itself is general.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';

const partial = (body) => analyzeHaskellRules({ 'Lib.hs': `module Lib (p) where\nimport Data.Maybe (fromJust, isJust)\nimport Control.Monad (when)\n\n${body}` }).findings.filter((f) => f.rule === 'hs-partial-function-on-input');

test('a partial list function on a list with a literal element prepended or appended is total', () => {
  assert.equal(partial('p :: String -> String\np input = head (input : words input)\n').length, 0, 'head (x : xs)');
  assert.equal(partial('p :: String -> String\np input = last (words input ++ [input])\n').length, 0, 'last (xs ++ [x])');
  assert.equal(partial('p :: String -> String\np input = head ([input] ++ words input)\n').length, 0, 'head ([x] ++ xs)');
  assert.equal(partial('p :: String -> String\np input = head (words input)\n').length, 1, 'head of the split alone is still partial');
  assert.equal(partial('p :: String -> String\np input = last (words input ++ words input)\n').length, 1, 'two possibly empty lists are not a non-empty list');
});

test('a guard written as when / unless, and a case or equality on the length, cover the partial call', () => {
  assert.equal(partial('p :: String -> IO ()\np input = let xs = words input in when (length xs > 2) (putStrLn (xs !! 2))\n').length, 0, 'when (length xs > 2)');
  assert.equal(partial('p :: String -> IO ()\np input = let xs = words input in unless (null xs) (putStrLn (head xs))\n').length, 0, 'unless (null xs)');
  assert.equal(partial('p :: String -> String\np input = let xs = words input in case length xs of 3 -> xs !! 1; _ -> ""\n').length, 0, 'case length xs of 3');
  assert.equal(partial('p :: String -> String\np input = let xs = words input in if length xs == 2 then head xs else ""\n').length, 0, 'length xs == 2');
  assert.equal(partial('p :: String -> String\np input = let xs = words input in if length input == 2 then head xs else ""\n').length, 1, 'a length test of ANOTHER value does not cover xs');
  assert.equal(partial('p :: String -> IO ()\np input = let xs = words input in when (null (words "x")) (putStrLn (xs !! 2))\n').length, 1, 'a when on an unrelated value does not cover xs');
});

test('a digest chosen by a type annotation is the weak hash it names', () => {
  const src = (ann, use) => `{-# LANGUAGE OverloadedStrings #-}\nmodule Lib (check) where\nimport Crypto.Hash (hash, hashlazy, Digest, MD5, SHA1, SHA256)\nimport qualified Data.ByteString as B\n\ncheck :: B.ByteString -> B.ByteString -> Bool\ncheck stored secret = ${use.replace('ANN', ann)}\n`;
  const weak = (s) => analyzeHaskellRules({ 'Lib.hs': s }).findings.filter((f) => f.rule === 'hs-weak-hash');
  const md5 = weak(src('Digest MD5', 'stored == B.pack (show (hash secret :: ANN))'));
  assert.equal(md5.length, 1, 'hash :: Digest MD5 compared with a stored value');
  assert.equal(md5[0].severity, 'medium');
  const sha1 = weak(src('Digest SHA1', 'stored == B.pack (show (hashlazy (B.fromStrict secret) :: ANN))'));
  assert.equal(sha1.length, 1, 'hashlazy :: Digest SHA1');
  assert.equal(weak(src('Digest SHA256', 'stored == B.pack (show (hash secret :: ANN))')).length, 0, 'a strong digest is silent');
  // No comparison, no credential name, nothing signed: reported at info (the digest may only name or key something).
  const noUse = weak('{-# LANGUAGE OverloadedStrings #-}\nmodule Lib (tag) where\nimport Crypto.Hash (hash, Digest, MD5)\nimport qualified Data.ByteString as B\n\ntag :: B.ByteString -> B.ByteString\ntag payload = B.pack (show (hash payload :: Digest MD5))\n');
  assert.equal(noUse.length, 1);
  assert.equal(noUse[0].severity, 'info', 'at info when no use depends on collision resistance');
});
