// Threat-model PRD FR-07 (TM-09): authentication truth survives a credential header, an authenticated actor receiving another tenant's
// object is detected, and the target counter counts only the target route. Every case goes through the same reader, matcher and hunt
// the CLI uses.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { parseLine } from '../../src/posture/dnr/log-reader.js';
import { evaluateEvent, authenticationOf } from '../../src/posture/dnr/matchers.js';
import { buildDetectionIR } from '../../src/posture/dnr/detection-ir.js';
import { huntLogs } from '../../src/posture/dnr/hunt.js';
import { validateDetection } from '../../src/posture/dnr/validate.js';
import { renderAll } from '../../src/posture/dnr/outputs.js';

const proven = (payloadClass, cwe) => buildDetectionIR({ finding: { id: `F-${payloadClass}`, cwe }, proof: { state: 'EXPLOIT_CONFIRMED', reproducer: { attack: { method: 'GET', path: '/records/:id', payloadClass } } } }).ir;
const BYPASS = proven('auth-bypass', 'CWE-306');
const OBJECT = proven('object-authz', 'CWE-639');
const line = (o) => JSON.stringify({ '@timestamp': '2026-11-08T10:00:00Z', method: 'GET', path: '/records/r-b-1', status: 200, ...o });
const ev = (o) => parseLine(line(o));

test('AC-07A: an explicit rejection survives a credential header; a header alone is undecidable; legacy events keep their reading', () => {
  const rejected = ev({ headers: { authorization: '[redacted]' }, authenticated: false });
  assert.equal(rejected.credentialPresent, true); assert.equal(rejected.authOutcome, 'unauthenticated');
  assert.equal(rejected.authPresent, true, 'the legacy field is unchanged');
  const r = evaluateEvent(BYPASS, rejected);
  assert.equal(r.match, true); assert.equal(r.matchedOn, 'unauthenticated-success'); assert.equal(r.signal, 'response-indication');
  for (const outcome of ['rejected', 'failure', 'expired']) assert.equal(evaluateEvent(BYPASS, ev({ headers: { authorization: 'x' }, auth: { result: outcome } })).match, true, outcome);
  const headerOnly = evaluateEvent(BYPASS, ev({ headers: { authorization: 'Bearer x' } }));
  assert.equal(headerOnly.match, false); assert.equal(headerOnly.undecidable, true); assert.deepEqual(headerOnly.missing, ['auth']);
  assert.equal(evaluateEvent(BYPASS, ev({ headers: { accept: '*/*' } })).match, true, 'no credential at all is unauthenticated');
  assert.equal(evaluateEvent(BYPASS, ev({ headers: { authorization: 'x' }, authenticated: true })).match, false, 'an accepted credential');
  const conflict = ev({ authenticated: true, auth: { outcome: 'rejected' } });
  assert.equal(conflict.authOutcome, 'conflict'); assert.equal(evaluateEvent(BYPASS, conflict).undecidable, true, 'conflicting facts leave it unknown');
  // an event built by an older caller, with only authPresent
  assert.equal(authenticationOf({ authPresent: false }), 'unauthenticated');
  assert.equal(authenticationOf({ authPresent: true }), 'authenticated');
  assert.equal(authenticationOf({ authPresent: null }), 'unknown');
  const clf = parseLine('203.0.113.9 - - [08/Nov/2026:10:00:00 +0000] "GET /records/r-b-1 HTTP/1.1" 200 12');
  assert.equal(clf.authOutcome, 'unknown'); assert.equal(evaluateEvent(BYPASS, clf).undecidable, true);
});

test('AC-07B: tenant A receiving tenant B\'s object is detected; the rightful read, a delegation and a denial are distinguishable', () => {
  const t = (actor, object, extra = {}) => ev({ authenticated: true, identity: { tenant: actor }, object: { tenant: object }, ...extra });
  const cross = evaluateEvent(OBJECT, t('tenant-a', 'tenant-b'));
  assert.equal(cross.match, true); assert.equal(cross.matchedOn, 'cross-tenant-success');
  assert.equal(evaluateEvent(OBJECT, t('tenant-b', 'tenant-b')).match, false, 'the rightful tenant');
  const delegated = evaluateEvent(OBJECT, t('tenant-a', 'tenant-b', { authz: { cross_tenant_grant: true } }));
  assert.equal(delegated.match, false); assert.equal(delegated.attempt, 'authorized-delegation');
  const denied = evaluateEvent(OBJECT, t('tenant-a', 'tenant-b', { status: 403, authz: { decision: 'deny' } }));
  assert.equal(denied.match, false); assert.equal(denied.attempt, 'denied', 'a denied attempt is not a delivery');
  assert.equal(evaluateEvent(OBJECT, t('tenant-a', null)).undecidable, true, 'a missing object tenant');
  // identity comes only from mapped fields: a client-supplied header or query value is not a tenant
  const spoof = parseLine(line({ authenticated: true, headers: { 'x-tenant': 'tenant-b' }, query: 'tenant=tenant-b', object: { tenant: 'tenant-b' } }));
  assert.equal(spoof.actorTenant, null); assert.equal(evaluateEvent(OBJECT, spoof).undecidable, true);
  // the rejected-credential case is the bypass rule's, not this one's
  assert.equal(evaluateEvent(OBJECT, t('tenant-a', 'tenant-b', { authenticated: false })).match, false);
  const anon = evaluateEvent(OBJECT, ev({ authenticated: false }));
  assert.equal(anon.undecidable, false, 'an unauthenticated request has no actor tenant to compare: decided, not undecidable');
  assert.equal(anon.match, false);
});

test('AC-07C: another route with the same method counts zero; template and missing fields are visible and block a clear result', async () => {
  const dir = mkTestTmp('dnr-target-');
  const lines = [
    line({ path: '/records/r-b-1', authenticated: true, identity: { tenant: 'tenant-b' }, object: { tenant: 'tenant-b' } }),
    line({ path: '/records/r-b-2', authenticated: true, identity: { tenant: 'tenant-b' }, object: { tenant: 'tenant-b' } }),
    line({ path: '/health', authenticated: true, identity: { tenant: 'tenant-a' }, object: { tenant: 'tenant-b' } }),
    line({ path: '/records', authenticated: true, identity: { tenant: 'tenant-a' }, object: { tenant: 'tenant-b' } }),
  ];
  fs.writeFileSync(path.join(dir, 'access.log'), `${lines.join('\n')}\n`);
  const clean = await huntLogs({ ir: OBJECT, logsPath: dir });
  assert.equal(clean.coverage.target.relevant, 2, 'only GET /records/:id is the target; /health and /records are not');
  assert.equal(clean.coverage.target.adjudicable, 2); assert.equal(clean.coverage.endpointEvents, 2);
  assert.equal(clean.verdict, 'NOT_OBSERVED'); assert.equal(clean.notExploitedClaim, false);

  fs.appendFileSync(path.join(dir, 'access.log'), `${line({ path: '/records/r-b-3', authenticated: true, identity: { tenant: 'tenant-a' } })}\n`);
  const missing = await huntLogs({ ir: OBJECT, logsPath: dir });
  assert.equal(missing.coverage.target.missingRequired, 1);
  assert.equal(missing.verdict, 'INCONCLUSIVE', 'a target event without its object tenant cannot support a clear result');
  assert.match(missing.caveats.join(' '), /tenant/);

  const late = await huntLogs({ ir: OBJECT, logsPath: dir, since: '2026-11-07T00:00:00Z', until: '2026-11-09T00:00:00Z' });
  assert.equal(late.coverage.windowGaps.length, 2, 'the logs reach neither edge of the requested window');
  assert.equal(late.verdict, 'INCONCLUSIVE');
});

test('AC-07B/C through the hunt: a cross-tenant delivery is OBSERVED as a signal, not as a corroborated effect', async () => {
  const dir = mkTestTmp('dnr-obs-');
  fs.writeFileSync(path.join(dir, 'access.log'), `${[
    line({ authenticated: true, identity: { tenant: 'tenant-a' }, object: { tenant: 'tenant-b' } }),
    line({ status: 403, authenticated: true, identity: { tenant: 'tenant-a' }, object: { tenant: 'tenant-b' }, authz: { decision: 'deny' } }),
  ].join('\n')}\n`);
  const r = await huntLogs({ ir: OBJECT, logsPath: dir });
  assert.equal(r.verdict, 'OBSERVED'); assert.equal(r.matches.count, 1);
  assert.equal(r.matches.samples[0].signal, 'response-indication');
  assert.equal(r.coverage.target.deniedAttempts, 1);
  assert.equal(r.effect.corroborated, false, 'a log line never corroborates delivery');
  assert.ok(!JSON.stringify(r).includes('tenant-a'), 'tenant identifiers are not copied into the result');
});

test('AC-07D: built-in validation passes with independent controls, and unsupported renderers say so', () => {
  for (const ir of [BYPASS, OBJECT]) {
    const v = validateDetection(ir);
    assert.equal(v.status, 'VALIDATED', `${ir.payloadClass}: ${JSON.stringify(v.failures)}`);
    assert.ok(v.cases.some((c) => c.kind === 'undecidable' && c.ok), `${ir.payloadClass}: an undecidable control`);
  }
  assert.ok(validateDetection(BYPASS).cases.some((c) => /rejected/.test(c.name) && c.kind === 'positive' && c.ok));
  const objOut = renderAll(OBJECT);
  for (const f of ['sigma', 'waf', 'spl', 'kql', 'cloudwatch', 'elastic', 'yaral', 'datadog']) {
    assert.equal(objOut[f].applicable, false, f); assert.match(objOut[f].reason, /tenant/, f);
  }
  assert.equal(objOut.http.applicable, true); assert.equal(objOut['log-query'].applicable, true);
  assert.match(objOut['log-query'].content, /ne-field/);
  const byOut = renderAll(BYPASS);
  assert.match(byOut.sigma.coverage.notCovered, /rejected/, 'a header-based rule states that a rejected credential is not covered');
  // repeatability: the same input renders the same text
  assert.deepEqual(renderAll(OBJECT), objOut);
});
