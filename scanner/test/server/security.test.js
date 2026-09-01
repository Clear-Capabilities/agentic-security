import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateSessionToken, constantTimeEqual, isValidHost, CSP_HEADER_VALUE } from '../../src/server/security.js';

test('generateSessionToken: 64 hex chars, unique per call', () => {
  const a = generateSessionToken();
  const b = generateSessionToken();
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.match(b, /^[0-9a-f]{64}$/);
  assert.notEqual(a, b);
});

test('constantTimeEqual: equal strings', () => {
  assert.equal(constantTimeEqual('abc123', 'abc123'), true);
});

test('constantTimeEqual: unequal, same length', () => {
  assert.equal(constantTimeEqual('abc123', 'abc124'), false);
});

test('constantTimeEqual: unequal, different length never throws', () => {
  assert.doesNotThrow(() => constantTimeEqual('short', 'a-much-longer-string'));
  assert.equal(constantTimeEqual('short', 'a-much-longer-string'), false);
  assert.equal(constantTimeEqual('a-much-longer-string', 'short'), false);
});

test('constantTimeEqual: malformed/non-string input returns false, never throws', () => {
  assert.equal(constantTimeEqual(null, 'abc'), false);
  assert.equal(constantTimeEqual('abc', null), false);
  assert.equal(constantTimeEqual(undefined, undefined), false);
  assert.equal(constantTimeEqual(123, '123'), false);
  assert.equal(constantTimeEqual({}, {}), false);
});

test('isValidHost: accepts loopback forms with the expected port', () => {
  assert.equal(isValidHost('127.0.0.1:4321', 4321), true);
  assert.equal(isValidHost('localhost:4321', 4321), true);
  assert.equal(isValidHost('LOCALHOST:4321', 4321), true, 'hostname comparison is case-insensitive');
  assert.equal(isValidHost('[::1]:4321', 4321), true);
});

test('isValidHost: rejects a spoofed/arbitrary Host header (T2 — this is the pure-function half of the regression guard)', () => {
  assert.equal(isValidHost('evil.example.com:4321', 4321), false);
  assert.equal(isValidHost('evil.example.com', 4321), false);
  assert.equal(isValidHost('127.0.0.1.evil.example.com:4321', 4321), false);
  assert.equal(isValidHost('attacker.test', 4321), false);
});

test('isValidHost: rejects the right hostname with the wrong port', () => {
  assert.equal(isValidHost('127.0.0.1:1111', 4321), false);
  assert.equal(isValidHost('localhost:1', 4321), false);
});

test('isValidHost: bare loopback host with no port is only valid for the default HTTP port', () => {
  assert.equal(isValidHost('localhost', 80), true);
  assert.equal(isValidHost('127.0.0.1', 80), true);
  assert.equal(isValidHost('localhost', 4321), false);
});

test('isValidHost: rejects malformed input without throwing', () => {
  assert.doesNotThrow(() => isValidHost(undefined, 4321));
  assert.equal(isValidHost(undefined, 4321), false);
  assert.equal(isValidHost('', 4321), false);
  assert.equal(isValidHost('127.0.0.1:abc', 4321), false);
  assert.equal(isValidHost(' 127.0.0.1:4321', 4321), false);
  assert.equal(isValidHost('127.0.0.1:4321 ', 4321), false);
  assert.equal(isValidHost('2001:db8::1', 4321), false, 'unbracketed IPv6 literal is invalid Host syntax');
  assert.equal(isValidHost('127.0.0.1:4321', NaN), false);
  assert.equal(isValidHost('127.0.0.1:4321', -1), false);
});

test('CSP_HEADER_VALUE is maximally restrictive for a JSON-only API server', () => {
  assert.match(CSP_HEADER_VALUE, /default-src 'none'/);
});
