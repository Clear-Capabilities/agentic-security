// Contract test for detection and response (docs/reference/dnr-contract.md): builds a detection, validates it, hunts a log and computes
// an exposure window, then holds each record to the page's tables in both directions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { buildDetectionIR } from '../../src/posture/dnr/detection-ir.js';
import { validateDetection } from '../../src/posture/dnr/validate.js';
import { huntLogs, HUNT_VERDICTS } from '../../src/posture/dnr/hunt.js';
import { computeExposureWindow } from '../../src/posture/dnr/exposure-window.js';
import { FORMATS } from '../../src/posture/dnr/outputs.js';
import { PAYLOAD_CLASS_NAMES } from '../../src/posture/dnr/payload-classes.js';
import { HUNT_EXIT } from '../../src/posture/dnr/cli.js';

const PAGE = readPage('docs/reference/dnr-contract.md');
const FINDING = { id: 'F1', stableId: 'F1', cwe: 'CWE-78', file: 'app.js', line: 9 };
const PROOF = { state: 'EXPLOIT_CONFIRMED', recordDigest: 'abc123', oracle: 'command_execution', reproducer: { attack: { method: 'POST', path: '/api/export', parameter: 'filename', location: 'body', payloadClass: 'command-injection', sink: 'exec()' } } };
const built = buildDetectionIR({ finding: FINDING, proof: PROOF });
const ir = built.ir;
const validation = validateDetection(ir);

const logs = mkTestTmp('agsec-dnr-contract-');
fs.writeFileSync(path.join(logs, 'a.log'), '{"@timestamp":"2024-03-14T02:13:44Z","http":{"request":{"method":"post"},"response":{"status_code":200}},"url":{"path":"/api/export"},"body":"{\\"filename\\":\\"a;id\\"}"}\n');
const hunt = await huntLogs({ ir, logsPath: logs });
const A = 'a'.repeat(40);
const windowFor = (over = {}) => computeExposureWindow({
  finding: { stableId: 'F1', findingProvenance: { findingOrigin: { commit: A, authorDate: '2024-01-01T00:00:00Z' } } }, repo: '.',
  deployments: [{ commit: A, commitSource: 'deployment-record', deployedAt: '2024-02-01T00:00:00Z', environment: 'prod', artifactDigest: null }],
  fixCommit: 'b'.repeat(40), telemetry: { start: '2024-01-15T00:00:00Z', end: '2024-04-01T00:00:00Z' },
  deps: { isAncestor: (a, d) => a === d, commitDate: () => '2024-03-01T00:00:00.000Z' }, ...over,
});
const win = windowFor();

test('contract: the detection and its validation have exactly the documented fields', () => {
  assert.equal(built.ok, true);
  sameFields(ir, fieldsUnder(PAGE, 'Detection'), 'detection');
  sameFields(validation, fieldsUnder(PAGE, 'Validation'), 'validation');
  sameFields(validation.counts, ['positives', 'negatives', 'passed', 'failed'], 'validation counts');
  for (const k of ['positives', 'negatives', 'passed', 'failed']) assert.ok(PAGE.includes(`\`${k}\``));
  assert.equal(ir.schema, 'agentic-security/detection-ir');
  assert.equal(ir.version, 1);
  assert.match(ir.id, /^det-[0-9a-f]{12}$/);
  assert.equal(validation.schema, 'agentic-security/detection-validation');
  assert.equal(validation.status, 'VALIDATED');
  assert.deepEqual(Object.keys(ir.endpoint), ['method', 'path']);
  assert.deepEqual(Object.keys(ir.facts).sort(), ['endpoint', 'parameter', 'payloadClass', 'sink']);
});

test('contract: a detection without a confirmed exploit is refused unless allowed, and the allowed one is labelled static-only', () => {
  assert.equal(buildDetectionIR({ finding: FINDING, proof: null }).ok, false);
  const weak = buildDetectionIR({ finding: FINDING, proof: null, allowUnproven: true });
  if (weak.ok) { assert.equal(weak.ir.grounding, 'static-only'); assert.ok(weak.ir.limitations.length > 0); }
  assert.ok(PAGE.includes('`exploit-confirmed`') && PAGE.includes('`static-only`'));
});

test('contract: the hunt result has exactly the documented fields at every level', () => {
  sameFields(hunt, fieldsUnder(PAGE, 'Hunt result'), 'hunt result');
  sameFields(hunt.logs, fieldsUnder(PAGE, 'Logs'), 'logs');
  sameFields(hunt.window, fieldsUnder(PAGE, 'Window'), 'window');
  sameFields(hunt.coverage, fieldsUnder(PAGE, 'Coverage'), 'coverage');
  sameFields(hunt.matches, fieldsUnder(PAGE, 'Matches'), 'matches');
  assert.equal(hunt.schema, 'agentic-security/hunt-result');
  assert.equal(hunt.notExploitedClaim, false, 'a hunt never claims the vulnerability was not exploited');
  assert.equal(hunt.egress, 'none');
  assert.equal(hunt.verdict, 'OBSERVED');
});

test('contract: the verdicts and their exit codes are the documented ones, and every verdict has its own code', () => {
  assert.deepEqual([...HUNT_VERDICTS].sort(), ['INCONCLUSIVE', 'NOT_OBSERVED', 'OBSERVED', 'TELEMETRY_UNAVAILABLE']);
  assert.deepEqual(HUNT_EXIT, { NOT_OBSERVED: 0, OBSERVED: 10, INCONCLUSIVE: 11, TELEMETRY_UNAVAILABLE: 12 });
  for (const v of HUNT_VERDICTS) assert.ok(PAGE.includes(`\`${v}\``), `${v} is on the page`);
  for (const code of Object.values(HUNT_EXIT).filter(c => c > 0)) assert.ok(PAGE.includes(`| \`${code}\` |`), `exit ${code} is on the page`);
  assert.equal(new Set(Object.values(HUNT_EXIT)).size, 4, 'no two verdicts share a code');
});

test('contract: an empty or unreadable log set is TELEMETRY_UNAVAILABLE, never NOT_OBSERVED', async () => {
  const empty = mkTestTmp('agsec-dnr-empty-');
  const r = await huntLogs({ ir, logsPath: empty });
  assert.equal(r.verdict, 'TELEMETRY_UNAVAILABLE');
  const missing = await huntLogs({ ir, logsPath: path.join(empty, 'nope') });
  assert.notEqual(missing.verdict, 'NOT_OBSERVED');
});

test('contract: the exposure window has exactly the documented fields, and the deployments carry their source', () => {
  sameFields(win, fieldsUnder(PAGE, 'Exposure window'), 'exposure window');
  assert.equal(win.schema, 'agentic-security/exposure-window');
  assert.equal(win.version, 1);
  assert.ok(['complete', 'partial', 'unavailable'].includes(win.status));
  sameFields(win.firstVulnerableDeployment, ['at', 'commit', 'commitSource', 'environment', 'artifactDigest'], 'first vulnerable deployment');
  sameFields(win.fixCommitted, ['at', 'commit'], 'fix committed');
  for (const k of ['commitSource', 'artifactDigest']) assert.ok(PAGE.includes(`\`${k}\``));
});

test('contract: a date with no source is unknown, and the window is not complete', () => {
  const w = windowFor({ fixCommit: null, telemetry: null });
  assert.notEqual(w.status, 'complete');
  assert.ok(w.unknowns.length > 0);
  assert.equal(windowFor({ deployments: [] }).status, 'unavailable');
});

test('contract: the output formats and payload classes are the documented ones', () => {
  for (const f of FORMATS) assert.ok(PAGE.includes(`\`${f}\``), `${f} is on the page`);
  assert.equal(PAYLOAD_CLASS_NAMES.length, 8, 'the page says eight payload classes');
  assert.ok(PAGE.includes('Eight payload classes'));
});

test('contract: the comparison itself fails when a field is added or dropped', () => {
  const doc = fieldsUnder(PAGE, 'Hunt result');
  assert.throws(() => sameFields({ ...hunt, extra: 1 }, doc, 'hunt'));
  const { statement, ...rest } = hunt;
  assert.throws(() => sameFields(rest, doc, 'hunt'));
  assert.ok(statement);
});
