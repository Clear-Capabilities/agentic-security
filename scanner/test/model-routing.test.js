import { test } from 'node:test';
import assert from 'node:assert';

import {
  routeModelForFinding,
  routeModelForFindings,
  summarizeRouting,
  parseCwe,
} from '../src/posture/model-routing.js';

const OPUS = 'claude-opus-4-8';
const SONNET = 'claude-sonnet-4-6';
const HAIKU = 'claude-haiku-4-5';

test('critical SQLi routes to the strongest model (opus, high effort)', () => {
  const r = routeModelForFinding({ severity: 'critical', cwe: 'CWE-89: SQL Injection' });
  assert.equal(r.model, OPUS);
  assert.equal(r.effort, 'high');
  assert.equal(typeof r.reason, 'string');
  assert.ok(r.reason.length > 0);
});

test('hard-set crypto CWE-327 at high severity routes to opus', () => {
  const r = routeModelForFinding({ severity: 'high', cwe: 'CWE-327' });
  assert.equal(r.model, OPUS);
  assert.equal(r.effort, 'high');
});

test('mid-set CWE-89 at high routes to sonnet (CWE-89 is mid, not hard)', () => {
  const r = routeModelForFinding({ severity: 'high', cwe: 'CWE-89' });
  assert.equal(r.model, SONNET);
  assert.equal(r.effort, 'medium');
});

test('low-severity hardening CWE-532 routes to the cheapest model (haiku, low effort)', () => {
  const r = routeModelForFinding({ severity: 'low', cwe: 'CWE-532' });
  assert.equal(r.model, HAIKU);
  assert.equal(r.effort, 'low');
});

test('multi-file finding routes to opus even at medium severity', () => {
  const r = routeModelForFinding({ severity: 'medium', cwe: 'CWE-79', multiFile: true });
  assert.equal(r.model, OPUS);
  assert.equal(r.effort, 'high');
});

test('isCrossFile is treated the same as multiFile', () => {
  const r = routeModelForFinding({ severity: 'medium', cwe: 'CWE-200', isCrossFile: true });
  assert.equal(r.model, OPUS);
  assert.equal(r.effort, 'high');
});

test('parses the CWE id out of a "CWE-79: XSS" descriptive string', () => {
  assert.equal(parseCwe('CWE-79: XSS'), 'CWE-79');
  assert.equal(parseCwe('CWE-89'), 'CWE-89');
  assert.equal(parseCwe('cwe-611: XXE'), 'CWE-611');
  assert.equal(parseCwe(undefined), null);
  const r = routeModelForFinding({ severity: 'medium', cwe: 'CWE-79: Cross-site Scripting' });
  assert.equal(r.model, SONNET);
  assert.equal(r.effort, 'medium');
});

test('a hard-set CWE BELOW high severity is not forced to opus', () => {
  // CWE-330 is in the hard set but only escalates at high/critical.
  const r = routeModelForFinding({ severity: 'medium', cwe: 'CWE-330' });
  assert.notEqual(r.model, OPUS);
});

test('bare high severity with an unlisted CWE routes to sonnet', () => {
  const r = routeModelForFinding({ severity: 'high', cwe: 'CWE-1021' });
  assert.equal(r.model, SONNET);
  assert.equal(r.effort, 'medium');
});

test('routeModelForFindings returns the finding plus its routing per entry', () => {
  const findings = [
    { severity: 'critical', cwe: 'CWE-89' },
    { severity: 'low', cwe: 'CWE-532' },
  ];
  const routed = routeModelForFindings(findings);
  assert.equal(routed.length, 2);
  assert.equal(routed[0].finding, findings[0]);
  assert.equal(routed[0].model, OPUS);
  assert.equal(routed[1].finding, findings[1]);
  assert.equal(routed[1].model, HAIKU);
});

test('summarizeRouting tallies counts per model', () => {
  const findings = [
    { severity: 'critical', cwe: 'CWE-502' }, // opus  (critical)
    { severity: 'high', cwe: 'CWE-327' },     // opus  (hard-set at high)
    { severity: 'high', cwe: 'CWE-89' },      // sonnet (mid-set)
    { severity: 'medium', cwe: 'CWE-601' },   // sonnet (mid-set)
    { severity: 'low', cwe: 'CWE-532' },      // haiku
  ];
  assert.deepEqual(summarizeRouting(findings), {
    'claude-opus-4-8': 2,
    'claude-sonnet-4-6': 2,
    'claude-haiku-4-5': 1,
  });
});

test('empty / missing input degrades gracefully', () => {
  assert.deepEqual(summarizeRouting([]), {
    'claude-opus-4-8': 0,
    'claude-sonnet-4-6': 0,
    'claude-haiku-4-5': 0,
  });
  assert.deepEqual(routeModelForFindings(undefined), []);
  const r = routeModelForFinding({});
  assert.equal(r.model, HAIKU); // safe default when nothing is known
  assert.equal(r.effort, 'low');
});
