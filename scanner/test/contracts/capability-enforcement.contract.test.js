// Contract test for runner-level capability enforcement (docs/reference/capability-enforcement-contract.md): the manifest shape and its
// validation refusals, the binding, the policy decision and its closed reason codes, the decision record and its enforcement rule, the
// operator-only feature switch, the platform statements (macOS never `enforced`, mediated network unsupported on Linux), the runner's
// refusal results and the capability report, each against the page's tables in both directions.
//
// Nothing here needs a sandbox backend or spawns a confined process tree: the runner refusals exercised below all return before the
// backend is selected, and the report is built from a stated probe report. It passes the same on macOS and on a plain Linux runner.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  validateManifest, bindManifest, deriveChild, manifestDigest, ARG_MODES, NETWORK_SCHEMES, RESOURCE_RANGES,
  MANIFEST_SCHEMA, MANIFEST_SCHEMA_VERSION, MAX_DELEGATION_DEPTH,
} from '../../src/capabilities/manifest.js';
import { decide } from '../../src/capabilities/decide.js';
import { REASONS, REASON_CODES } from '../../src/capabilities/reasons.js';
import { toCapabilityDecisionRecord, advise } from '../../src/capabilities/records.js';
import { platformStatements, isAdvertisedBackend, requiredControlsFor, unmetControls } from '../../src/capabilities/probes.js';
import { buildCapabilityReport, REPORT_LIMITATIONS } from '../../src/capabilities/report.js';
import { runCapabilityTask } from '../../src/capabilities/runner.js';
import { resolveAssuranceConfig, featureStatus, FEATURES, RESULT_STATUSES, RESULT_CODES } from '../../src/posture/assurance/config.js';
import {
  CAPABILITY_KINDS, CAPABILITY_DECISIONS, CAPABILITY_MEDIATIONS, validateCapabilityDecision,
} from '../../src/posture/assurance/contracts.js';
import { readPage, fieldsUnder, sameFields, REPO } from '../helpers/contract-page.js';

const PAGE = readPage('docs/reference/capability-enforcement-contract.md');
const FEATURE = 'capability-enforcement';
const ON = 'AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT';
const REV = 'a'.repeat(40);
const src = (rel) => fs.readFileSync(path.join(REPO, 'scanner', 'src', rel), 'utf8');

/** Cells of every data row of the table under the bold heading that starts with `heading`. */
function rowsUnder(page, heading) {
  const lines = page.split('\n');
  const at = lines.findIndex(l => l.startsWith(`**${heading}`));
  assert.ok(at >= 0, `the page has no "${heading}" table`);
  const rows = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (lines[i].startsWith('**') || lines[i].startsWith('#')) break;
    if (!lines[i].startsWith('| ') || /^\|[-| ]+\|$/.test(lines[i])) continue;
    const cells = lines[i].slice(1, -1).split(' | ').map(c => c.trim());
    if (rows.length === 0 && !cells[0].startsWith('`') && lines[i + 1]?.startsWith('|---')) continue; // header row
    rows.push(cells);
  }
  assert.ok(rows.length, `the "${heading}" table has no rows`);
  return rows;
}
const tick = (cell) => { const m = /^`([^`]+)`/.exec(cell); return m ? m[1] : null; };

/** The string-array literal bound to `name` in a source file (the shape the code enforces, read from the code itself). */
function arrayLiteral(text, name) {
  const m = new RegExp(`const ${name} = \\[([^\\]]*)\\]`).exec(text);
  assert.ok(m, `no ${name} literal`);
  return [...m[1].matchAll(/'([^']+)'/g)].map(x => x[1]);
}

const base = (over = {}) => ({
  schema: 'agentic-security/capability-manifest', schemaVersion: '1.0.0', taskId: 'task-1',
  repository: { revision: REV }, policyVersion: 1, ...over,
});
const full = () => base({
  parentTaskId: 'task-0', createdAt: '2026-11-13T00:00:00Z',
  filesystem: { read: ['/opt/r'], write: ['/opt/w'] },
  commands: [{ executable: '/usr/bin/true', args: { mode: 'prefix', values: ['-x'] }, interpreter: null }],
  network: [{ host: '*.example.com', port: 443, schemes: ['https'], allowPrivateResolution: false, addresses: ['203.0.113.7'] }],
  tools: ['read_scratchpad'],
  resources: { timeoutMs: 1000, maxOutputBytes: 1000, maxFileSizeKb: 10, maxProcesses: 10, maxMemoryMiB: 128 },
  delegation: { allow: true, maxDepth: 2 },
});
const codes = (v) => v.errors.map(e => e.code);

// ---------------------------------------------------------------- feature switch

test('contract: the feature is off by default, Linux-only, high-risk execution, and the gate answers each documented code with its status', () => {
  assert.deepEqual(FEATURES[FEATURE].platforms, ['linux']);
  assert.equal(FEATURES[FEATURE].risk, 'high-risk-execution');
  for (const platform of ['linux', 'darwin', 'win32']) {
    const c = resolveAssuranceConfig({ env: {}, platform });
    assert.equal(c.features[FEATURE].enabled, false);
    assert.equal(c.features[FEATURE].source, 'default');
  }
  const produce = {
    disabled: () => resolveAssuranceConfig({ env: {}, platform: 'linux' }),
    'kill-switch': () => resolveAssuranceConfig({ env: { [ON]: '1', AGENTIC_SECURITY_NO_CAPABILITY_ENFORCEMENT: '1' }, platform: 'linux' }),
    'invalid-config': () => resolveAssuranceConfig({ env: { [ON]: 'yes' }, platform: 'linux' }),
    'platform-unsupported': () => resolveAssuranceConfig({ env: { [ON]: '1' }, platform: 'darwin' }),
  };
  const rows = rowsUnder(PAGE, 'Feature gate results');
  assert.deepEqual(rows.map(r => tick(r[0])).sort(), Object.keys(produce).sort());
  for (const [code, status] of rows.map(r => [tick(r[0]), tick(r[1])])) {
    const g = featureStatus(produce[code](), FEATURE);
    assert.equal(g.code, code); assert.equal(g.status, status, code);
  }
  assert.equal(featureStatus(resolveAssuranceConfig({ env: { [ON]: '1' }, platform: 'linux' }), FEATURE).status, 'ok');
  assert.notEqual(featureStatus(resolveAssuranceConfig({ env: { [ON]: '1' }, platform: 'win32' }), FEATURE).status, 'ok');
});

test('contract: every documented switch does what the page says, and only those three are listed', () => {
  assert.deepEqual(fieldsUnder(PAGE, 'Feature switches').sort(),
    [ON, 'AGENTIC_SECURITY_NO_ASSURANCE', 'AGENTIC_SECURITY_NO_CAPABILITY_ENFORCEMENT'].sort());
  const en = (env) => resolveAssuranceConfig({ env, platform: 'linux' }).features[FEATURE];
  for (const v of ['1', 'true']) assert.equal(en({ [ON]: v }).enabled, true);
  for (const v of ['0', 'false']) assert.equal(en({ [ON]: v }).enabled, false);
  assert.equal(en({ [ON]: 'on' }).source, 'invalid-config');
  assert.equal(en({ [ON]: '1', AGENTIC_SECURITY_NO_CAPABILITY_ENFORCEMENT: '1' }).enabled, false);
  assert.equal(en({ [ON]: '1', AGENTIC_SECURITY_NO_ASSURANCE: '1' }).enabled, false);
});

test('contract: a project file can never turn the feature on (operator-only), and the refusal is disclosed', () => {
  const file = (enabled) => () => `features:\n  ${FEATURE}:\n    enabled: ${enabled}\n`;
  const refused = resolveAssuranceConfig({ scanRoot: path.join(REPO, 'no-such-dir'), env: {}, platform: 'linux', readFile: file(true) });
  const f = refused.features[FEATURE];
  assert.equal(f.enabled, false);
  assert.equal(f.source, 'project-file-refused');
  assert.ok(f.notes.some(n => /refused/.test(n)));
  assert.equal(featureStatus(refused, FEATURE).status, 'disabled');
  const off = resolveAssuranceConfig({ scanRoot: path.join(REPO, 'no-such-dir'), env: { [ON]: '1' }, platform: 'linux', readFile: file(false) });
  assert.equal(off.features[FEATURE].enabled, true, 'the environment outranks the project file');
});

// ---------------------------------------------------------------- manifest

test('contract: the manifest input fields and required set are the code\'s, in both directions', () => {
  const text = src('capabilities/manifest.js');
  const rows = rowsUnder(PAGE, 'Manifest input');
  assert.deepEqual(rows.map(r => tick(r[0])).sort(), arrayLiteral(text, 'MANIFEST_ALLOWED').sort());
  assert.deepEqual(rows.filter(r => r[1] === 'Yes').map(r => tick(r[0])).sort(), arrayLiteral(text, 'MANIFEST_REQUIRED').sort());
  for (const k of arrayLiteral(text, 'MANIFEST_REQUIRED')) {
    const m = base(); delete m[k];
    assert.equal(validateManifest(m).ok, false, `${k} is required`);
  }
  assert.ok(codes(validateManifest(base({ extra: 1 }))).includes('UNKNOWN_FIELD'));
  assert.equal(MANIFEST_SCHEMA, 'agentic-security/capability-manifest');
  assert.equal(MANIFEST_SCHEMA_VERSION, '1.0.0');
  assert.match(PAGE, /`agentic-security\/capability-manifest`, version `1\.0\.0`/);
});

test('contract: the normalized manifest and every nested shape report exactly the documented fields', () => {
  const v = validateManifest(full());
  assert.equal(v.ok, true, JSON.stringify(v.errors));
  const m = v.manifest;
  sameFields(m, fieldsUnder(PAGE, 'Normalized manifest'), 'normalized manifest');
  assert.equal('createdAt' in m, false, 'createdAt is dropped');
  sameFields(m.filesystem, fieldsUnder(PAGE, 'Filesystem grant'), 'filesystem');
  sameFields(m.commands[0], fieldsUnder(PAGE, 'Command entry'), 'command entry');
  sameFields(m.commands[0].args, fieldsUnder(PAGE, 'Command arguments'), 'command arguments');
  sameFields(m.network[0], fieldsUnder(PAGE, 'Network destination'), 'network destination');
  sameFields(m.delegation, fieldsUnder(PAGE, 'Delegation'), 'delegation');
  assert.ok(Object.isFrozen(m) && Object.isFrozen(m.commands[0].args), 'deeply frozen');
  // documented defaults of an absent section
  const empty = validateManifest(base()).manifest;
  assert.deepEqual(empty.filesystem, { read: [], write: [] });
  assert.deepEqual([empty.commands, empty.network, empty.tools], [[], [], []]);
  assert.deepEqual(empty.resources, {});
  assert.deepEqual(empty.delegation, { allow: false, maxDepth: 0 });
  assert.equal(empty.parentTaskId, null);
  const cmd = validateManifest(base({ commands: [{ executable: '/usr/bin/true' }] })).manifest.commands[0];
  assert.deepEqual(cmd, { executable: '/usr/bin/true', args: { mode: 'exact', values: [] }, interpreter: null });
  const net = validateManifest(base({ network: [{ host: 'api.example.com', port: 443 }] })).manifest.network[0];
  assert.deepEqual(net.schemes, ['https']); assert.equal(net.allowPrivateResolution, false); assert.equal(net.addresses, null);
  assert.equal(validateManifest(base({ delegation: { allow: true } })).manifest.delegation.maxDepth, 1);
});

test('contract: argument modes, network schemes and resource ranges match the page, in both directions', () => {
  assert.deepEqual(fieldsUnder(PAGE, 'Argument modes').sort(), [...ARG_MODES].sort());
  assert.deepEqual(fieldsUnder(PAGE, 'Network schemes').sort(), [...NETWORK_SCHEMES].sort());
  const rows = rowsUnder(PAGE, 'Resource limits');
  assert.deepEqual(rows.map(r => tick(r[0])).sort(), Object.keys(RESOURCE_RANGES).sort());
  for (const [cell, min, max] of rows) {
    const k = tick(cell);
    assert.equal(Number(min), RESOURCE_RANGES[k].min, `${k} min`);
    assert.equal(Number(max), RESOURCE_RANGES[k].max, `${k} max`);
    assert.equal(validateManifest(base({ resources: { [k]: Number(min) } })).ok, true);
    assert.equal(validateManifest(base({ resources: { [k]: Number(max) } })).ok, true);
    assert.ok(codes(validateManifest(base({ resources: { [k]: Number(min) - 1 } }))).includes('BAD_TYPE'), `${k} below min`);
    assert.ok(codes(validateManifest(base({ resources: { [k]: Number(max) + 1 } }))).includes('BAD_TYPE'), `${k} above max`);
  }
  assert.equal(MAX_DELEGATION_DEPTH, 8);
  assert.equal(validateManifest(base({ delegation: { allow: true, maxDepth: 8 } })).ok, true);
  assert.equal(validateManifest(base({ delegation: { allow: true, maxDepth: 9 } })).ok, false);
});

// Each documented validation error code, produced for real.
const REFUSALS = {
  NOT_AN_OBJECT: () => validateManifest(null),
  SCHEMA_MISMATCH: () => validateManifest(base({ schema: 'other' })),
  BAD_VERSION: () => validateManifest(base({ schemaVersion: '1' })),
  UNSUPPORTED_MAJOR: () => validateManifest(base({ schemaVersion: '2.0.0' })),
  MISSING_FIELD: () => { const m = base(); delete m.taskId; return validateManifest(m); },
  UNKNOWN_FIELD: () => validateManifest(base({ resources: { cpus: 2 } })),
  BAD_TYPE: () => validateManifest(base({ repository: { revision: 'main' } })),
  BAD_PATH: () => validateManifest(base({ filesystem: { read: ['relative/dir'] } })),
  UNKNOWN_ENUM: () => validateManifest(base({ network: [{ host: 'a.example.com', port: 443, schemes: ['ftp'] }] })),
  RULE_VIOLATION: () => validateManifest(base({ commands: [{ executable: '/usr/bin/true', args: { mode: 'any', values: ['x'] } }] })),
  SCOPE_EXPANSION: () => deriveChild(validateManifest(base({ filesystem: { read: ['/opt/a'] } })).manifest, { taskId: 'child', filesystem: { read: ['/etc'] } }),
};

test('contract: the documented validation error codes are exactly the ones the validator can raise, and each is raised for real', () => {
  const documented = fieldsUnder(PAGE, 'Validation error codes').sort();
  // Codes raised in manifest.js itself, plus the ones its shared header, field and type checks raise.
  const inSource = new Set([...src('capabilities/manifest.js').matchAll(/(?:err\(|code: )'([A-Z_]+)'/g)].map(m => m[1]));
  for (const c of ['SCHEMA_MISMATCH', 'BAD_VERSION', 'UNSUPPORTED_MAJOR', 'MISSING_FIELD', 'UNKNOWN_FIELD', 'BAD_TYPE', 'NOT_AN_OBJECT']) inSource.add(c);
  assert.deepEqual(documented, [...inSource].sort());
  assert.deepEqual(documented, Object.keys(REFUSALS).sort());
  for (const [code, fn] of Object.entries(REFUSALS)) {
    const r = fn();
    assert.equal(r.ok, false, code);
    assert.equal(r.manifest, null, `${code}: no manifest on refusal`);
    assert.ok(codes(r).includes(code), `${code}: got ${codes(r).join(', ')}`);
    for (const e of r.errors) sameFields(e, ['code', 'path', 'message'], 'validation error');
  }
});

test('contract: each refusal rule named on the page refuses the whole manifest, and every error is returned together', () => {
  const bad = [
    [{ filesystem: { read: ['/opt/../etc'] } }, 'BAD_PATH'],
    [{ filesystem: { write: ['/'] } }, 'BAD_PATH'],
    [{ commands: [{ executable: 'true' }] }, 'BAD_PATH'],
    [{ commands: [{ executable: '/bin/sh', args: { mode: 'prefix', values: [] }, interpreter: 'scoped' }] }, 'RULE_VIOLATION'],
    [{ commands: [{ executable: '/bin/sh', interpreter: 'yes' }] }, 'UNKNOWN_ENUM'],
    [{ network: [{ host: '*.com', port: 443 }] }, 'RULE_VIOLATION'],
    [{ network: [{ host: '*.10.0.0.1', port: 443 }] }, 'RULE_VIOLATION'],
    [{ network: [{ host: 'a.example.com', port: 0 }] }, 'BAD_TYPE'],
    [{ network: [{ host: 'a.example.com', port: 443, addresses: ['a.example.com'] }] }, 'BAD_TYPE'],
    [{ delegation: { allow: false, maxDepth: 2 } }, 'RULE_VIOLATION'],
    [{ delegation: { allow: true, maxDepth: 0 } }, 'RULE_VIOLATION'],
    [{ tools: ['has space'] }, 'BAD_TYPE'],
    [{ policyVersion: 0 }, 'BAD_TYPE'],
    [{ createdAt: 5 }, 'BAD_TYPE'],
  ];
  for (const [over, code] of bad) {
    const r = validateManifest(base(over));
    assert.equal(r.ok, false, JSON.stringify(over));
    assert.ok(codes(r).includes(code), `${JSON.stringify(over)}: ${codes(r).join(', ')}`);
  }
  const many = validateManifest(base({ policyVersion: 0, tools: 5, extra: true }));
  assert.ok(many.errors.length >= 3, 'all errors are reported, not only the first');
  // Loose, and documented as loose: any 1.x schema version validates and is carried through unchanged.
  assert.equal(validateManifest(base({ schemaVersion: '1.5.0' })).manifest.schemaVersion, '1.5.0');
  assert.match(PAGE, /`schemaVersion` `1\.5\.0` validates/);
});

test('contract: the binding is the documented four fields, and a decision for another identity is binding-mismatch', () => {
  const b = bindManifest(base({ tools: ['t1'] }));
  assert.equal(b.ok, true);
  sameFields(b.bound, ['manifest', 'binding'], 'bound');
  sameFields(b.bound.binding, fieldsUnder(PAGE, 'Binding'), 'binding');
  assert.equal(b.bound.binding.digest, manifestDigest(b.bound.manifest));
  assert.match(b.bound.binding.digest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(Object.isFrozen(b.bound) && Object.isFrozen(b.bound.binding));
  const act = { kind: 'tool', tool: 't1' };
  assert.equal(decide(b.bound, act, { binding: b.bound.binding }).decision, 'allow');
  for (const other of [{ taskId: 'x' }, { revision: 'b'.repeat(40) }, { policyVersion: 2 }]) {
    const d = decide(b.bound, act, { binding: { ...b.bound.binding, ...other } });
    assert.equal(d.decision, 'deny'); assert.equal(d.code, 'binding-mismatch');
  }
  assert.equal(bindManifest(base({ policyVersion: -1 })).bound, null);
});

test('contract: deriveChild yields no manifest on any widening, and a subset child is accepted', () => {
  const parent = validateManifest(base({
    filesystem: { read: ['/opt/a'], write: ['/opt/a/w'] }, tools: ['t1'], resources: { timeoutMs: 1000 },
    network: [{ host: '*.example.com', port: 443 }], delegation: { allow: true, maxDepth: 2 },
  })).manifest;
  const ok = deriveChild(parent, { taskId: 'c', filesystem: { read: ['/opt/a/sub'] }, tools: ['t1'], network: [{ host: 'api.example.com', port: 443 }], delegation: { allow: true, maxDepth: 1 } });
  assert.equal(ok.ok, true, JSON.stringify(ok.errors));
  assert.equal(ok.manifest.parentTaskId, 'task-1');
  for (const widen of [
    { filesystem: { write: ['/opt/a'] } }, { tools: ['t2'] }, { resources: { timeoutMs: 2000 } },
    { network: [{ host: 'api.example.com', port: 8443 }] }, { network: [{ host: 'api.example.com', port: 443, schemes: ['http'] }] },
    { delegation: { allow: true, maxDepth: 2 } }, { policyVersion: 2 }, { repository: { revision: 'b'.repeat(40) } },
    { parentTaskId: 'someone-else' },
  ]) {
    const r = deriveChild(parent, { taskId: 'c', ...widen });
    assert.equal(r.ok, false, JSON.stringify(widen)); assert.equal(r.manifest, null);
    assert.ok(codes(r).includes('SCOPE_EXPANSION'), JSON.stringify(widen));
  }
  assert.ok(codes(deriveChild(parent, { taskId: 'task-1' })).includes('SCOPE_EXPANSION'), 'a child has its own task id');
});

// ---------------------------------------------------------------- decisions

test('contract: a policy decision has exactly the documented fields, and every documented capability kind is the code\'s', () => {
  const b = bindManifest(base()).bound;
  const d = decide(b, { kind: 'tool', tool: 'x' }, { binding: b.binding });
  sameFields(d, fieldsUnder(PAGE, 'Policy decision'), 'policy decision');
  assert.ok(Object.isFrozen(d));
  assert.deepEqual(fieldsUnder(PAGE, 'Capability kinds').sort(), [...CAPABILITY_KINDS].sort());
  assert.equal(decide(b, { kind: 'shell' }, { binding: b.binding }).code, 'unknown-action');
  assert.equal(decide(null, { kind: 'tool' }, {}).code, 'invalid-manifest');
  for (const kind of CAPABILITY_KINDS) assert.equal(decide(b, { kind }, { binding: b.binding }).decision, 'deny', `${kind} with no grant is denied`);
});

test('contract: the reason-code table is the closed set, with the exact sentence for each code', () => {
  const rows = rowsUnder(PAGE, 'Reason codes');
  assert.deepEqual(rows.map(r => tick(r[0])).sort(), [...REASON_CODES].sort());
  for (const [cell, sentence] of rows) assert.equal(sentence, REASONS[tick(cell)], tick(cell));
  // The reason is the fixed sentence even for hostile input; only the subject is request-derived.
  const b = bindManifest(base()).bound;
  const d = decide(b, { kind: 'filesystem-read', path: '/etc/\u0007ghp_' + 'A'.repeat(36) }, { binding: b.binding });
  assert.equal(d.reason, REASONS[d.code]);
  assert.doesNotMatch(d.subject, /\u0007/);
});

test('contract: the decision record has the documented fields, decision and mediation values, and only runner or proxy may claim enforced', () => {
  const text = src('posture/assurance/contracts.js');
  const rows = rowsUnder(PAGE, 'Decision record');
  assert.deepEqual(rows.map(r => tick(r[0])).sort(), arrayLiteral(text, 'CD_ALLOWED').sort());
  assert.deepEqual(rows.filter(r => r[1] === 'Yes').map(r => tick(r[0])).sort(), arrayLiteral(text, 'CD_REQUIRED').sort());
  assert.deepEqual(fieldsUnder(PAGE, 'Decision values').sort(), [...CAPABILITY_DECISIONS].sort());
  const med = rowsUnder(PAGE, 'Mediation values');
  assert.deepEqual(med.map(r => tick(r[0])).sort(), [...CAPABILITY_MEDIATIONS].sort());

  const b = bindManifest(base()).bound;
  const d = decide(b, { kind: 'tool', tool: 'x' }, { binding: b.binding });
  const digest = `sha256:${'0'.repeat(64)}`;
  const advisory = toCapabilityDecisionRecord(d, { mediation: 'hook-advisory', enforced: false, backend: null });
  assert.equal(advisory.ok, true);
  sameFields(advisory.record, rows.map(r => tick(r[0])), 'decision record', ['probeDigest', 'migration', 'createdAt']);
  assert.equal(advisory.record.reason, `${d.code}: ${d.reason}`);
  assert.equal(validateCapabilityDecision(advisory.record).ok, true);
  for (const [cell, may] of med) {
    const mediation = tick(cell);
    const r = toCapabilityDecisionRecord(d, { mediation, enforced: true, backend: 'namespace', probeDigest: digest });
    assert.equal(r.ok, may.startsWith('Yes'), `${mediation} may claim enforced: ${may}`);
    if (may.startsWith('Yes')) {
      assert.equal(toCapabilityDecisionRecord(d, { mediation, enforced: true, backend: null, probeDigest: digest }).ok, false, 'needs a backend');
      assert.equal(toCapabilityDecisionRecord(d, { mediation, enforced: true, backend: 'namespace' }).ok, false, 'needs a probe digest');
      assert.equal(toCapabilityDecisionRecord({ ...d, decision: 'blocked' }, { mediation, enforced: true, backend: 'namespace', probeDigest: digest }).ok, false, 'blocked cannot be enforced');
    }
  }
  assert.equal(validateCapabilityDecision({ ...advisory.record, subject: 'changed' }).ok, false, 'an id that does not match is refused');
  // A hook only advises; a shell string cannot be mediated.
  const a = advise(b, { kind: 'tool', tool: 'x' }, { binding: b.binding });
  assert.equal(a.enforced, false); assert.equal(a.record.mediation, 'hook-advisory'); assert.equal(a.record.enforced, false);
  const sh = advise(b, { kind: 'command', command: 'rm -rf /' }, { binding: b.binding });
  assert.equal(sh.decision, 'unsupported'); assert.equal(sh.record, null);
});

// ---------------------------------------------------------------- platforms

test('contract: the platform statements are the page\'s table, in both directions, and Linux lists exactly the documented controls', () => {
  const p = platformStatements();
  const rows = rowsUnder(PAGE, 'Platform statements');
  assert.deepEqual(rows.map(r => tick(r[0])).sort(), Object.keys(p).sort());
  for (const [plat, backend, status] of rows) {
    const s = p[tick(plat)];
    assert.equal(s.backend, tick(backend), `${tick(plat)} backend`); // `none` cell has no backticks -> null
    assert.equal(s.status, tick(status), `${tick(plat)} status`);
    assert.notEqual(s.status, 'enforced', 'no platform statement claims enforced');
  }
  assert.equal(p.linux.status, 'partially-verified');
  assert.deepEqual(fieldsUnder(PAGE, 'Linux verified controls').sort(), [...p.linux.verifiedControls].sort());
  assert.deepEqual(fieldsUnder(PAGE, 'Linux unsupported controls').sort(), [...p.linux.unsupportedControls].sort());
  assert.ok(p.linux.unsupportedControls.includes('network-mediation'));
  assert.ok(!p.linux.verifiedControls.includes('network-mediation'), 'mediated network is never claimed on Linux');
  assert.match(p.linux.evidence, /sandbox-linux/);
});

test('contract: only the namespace backend on Linux is advertised, so a macOS run can never reach level enforced', () => {
  for (const backend of ['namespace', 'userspace', 'disabled']) {
    assert.equal(isAdvertisedBackend(backend, 'darwin'), false, `darwin/${backend}`);
    assert.equal(isAdvertisedBackend(backend, 'win32'), false, `win32/${backend}`);
    assert.equal(isAdvertisedBackend(backend, 'linux'), backend === 'namespace', `linux/${backend}`);
  }
  // The runner's level is `advertised ? 'enforced' : 'host-proved'`: pinned here so the darwin rule cannot be loosened silently.
  assert.match(src('capabilities/runner.js'), /const level = advertised \? 'enforced' : 'host-proved';/);
  assert.deepEqual(fieldsUnder(PAGE, 'Run levels').sort(), ['enforced', 'host-proved', 'none']);
});

test('contract: a manifest that declares a destination requires network-mediation, which Linux does not prove, so the task is blocked', () => {
  const quiet = validateManifest(base()).manifest;
  const net = validateManifest(base({ network: [{ host: 'api.example.com', port: 443 }] })).manifest;
  assert.ok(!requiredControlsFor(quiet).includes('network-mediation'));
  assert.ok(requiredControlsFor(net).includes('network-mediation'));
  const linuxLike = { controls: Object.fromEntries(platformStatements().linux.verifiedControls.map(c => [c, { state: 'proved' }])) };
  linuxLike.controls['network-mediation'] = { state: 'unsupported', reason: 'not implemented' };
  assert.deepEqual(unmetControls(linuxLike, requiredControlsFor(quiet)), []);
  assert.deepEqual(unmetControls(linuxLike, requiredControlsFor(net)).map(u => u.control), ['network-mediation']);
});

// ---------------------------------------------------------------- report

const ALL_PROVED = (extra = {}) => ({
  platform: 'darwin', backend: 'userspace', probeDigest: `sha256:${'1'.repeat(64)}`,
  controls: Object.fromEntries([...platformStatements().linux.verifiedControls, 'network-mediation'].map(c => [c, { state: 'proved' }])),
  ...extra,
});

test('contract: the capability report has the documented fields; host-proved enforces nothing, and tool, delegation and memory never are', () => {
  const bound = bindManifest(base({
    filesystem: { read: ['/opt/r'], write: ['/opt/w'] }, network: [{ host: 'api.example.com', port: 443 }], tools: ['t'],
    resources: { maxMemoryMiB: 128, maxProcesses: 8 },
  })).bound;
  const required = requiredControlsFor(bound.manifest);
  const host = buildCapabilityReport({ bound, probeReport: ALL_PROVED(), level: 'host-proved', required });
  sameFields(host, fieldsUnder(PAGE, 'Capability report'), 'capability report');
  assert.equal(host.version, 1);
  sameFields(host.resources, fieldsUnder(PAGE, 'Report resources'), 'report resources');
  const entry = fieldsUnder(PAGE, 'Report capability entry');
  assert.deepEqual(host.capabilities.map(c => c.kind).sort(), [...CAPABILITY_KINDS].sort());
  for (const c of host.capabilities) sameFields(c, entry, `report entry ${c.kind}`, ['descendantExec', 'payloadFiltering']);
  assert.equal(host.capabilities.find(c => c.kind === 'command').descendantExec, 'not-allowlisted');
  assert.equal(host.capabilities.find(c => c.kind === 'network').payloadFiltering, 'plaintext-http-only');
  assert.ok(host.capabilities.every(c => c.enforced === false), 'host-proved claims no capability enforced');
  assert.ok(Object.values(host.resources).every(r => r.enforced === false), 'host-proved claims no resource enforced');
  assert.deepEqual(host.limitations, [...REPORT_LIMITATIONS]);

  const enf = buildCapabilityReport({ bound, probeReport: ALL_PROVED({ platform: 'linux', backend: 'namespace' }), level: 'enforced', required });
  const by = Object.fromEntries(enf.capabilities.map(c => [c.kind, c]));
  assert.equal(by['filesystem-read'].enforced, true);
  assert.equal(by.tool.enforced, false); assert.equal(by.tool.enforcedBy, 'in-process-policy');
  assert.equal(by.delegation.enforced, false); assert.equal(by.delegation.enforcedBy, 'in-process-policy');
  assert.equal(enf.resources.maxMemoryMiB.enforced, false); assert.equal(enf.resources.maxMemoryMiB.state, 'not-enforced');
  assert.equal(enf.resources.maxProcesses.enforced, true);
  const noCap = buildCapabilityReport({ bound, probeReport: ALL_PROVED({ controls: { ...ALL_PROVED().controls, 'process-cap': { state: 'unverified' } } }), level: 'enforced', required });
  assert.equal(noCap.resources.maxProcesses.enforced, false); assert.equal(noCap.resources.maxProcesses.state, 'unverified');
  const oneMissing = { ...ALL_PROVED().controls, 'fs-read-confinement': { state: 'not-proved' } };
  const partial = buildCapabilityReport({ bound, probeReport: ALL_PROVED({ controls: oneMissing }), level: 'enforced', required });
  assert.ok(partial.capabilities.every(c => c.enforced === false), 'one unproved required control means nothing is reported enforced');
});

// ---------------------------------------------------------------- runner refusals (no backend reached)

const bound1 = () => bindManifest(base({ commands: [{ executable: '/usr/bin/true' }] })).bound;
const darwinOn = () => resolveAssuranceConfig({ env: { [ON]: '1' }, platform: 'darwin' });

test('contract: the runner refuses with the documented shape before the backend: feature off, kill switch, platform without the opt-in', async () => {
  const base5 = fieldsUnder(PAGE, 'Runner refusal');
  const b = bound1();
  const cases = [
    [resolveAssuranceConfig({ env: {}, platform: 'linux' }), {}, 'disabled', 'disabled'],
    [resolveAssuranceConfig({ env: { [ON]: '1', AGENTIC_SECURITY_NO_CAPABILITY_ENFORCEMENT: '1' }, platform: 'linux' }), {}, 'blocked', 'kill-switch'],
    [darwinOn(), {}, 'unsupported', 'platform-unsupported'],
  ];
  for (const [config, extra, status, code] of cases) {
    const r = await runCapabilityTask(b, { executable: '/usr/bin/true' }, { binding: b.binding, config, ...extra });
    assert.equal(r.status, status, code); assert.equal(r.code, code);
    assert.equal(r.executed, false); assert.equal(r.outcome, 'not-run');
    for (const k of base5) assert.ok(k in r, `${code} result has ${k}`);
    assert.equal(r.level, undefined, 'a refusal claims no level');
  }
  // Default config resolution (no config passed) is off as well, whatever host this runs on, unless the operator set the switch.
  if (process.env[ON] === undefined) {
    const r = await runCapabilityTask(b, { executable: '/usr/bin/true' }, { binding: b.binding, scanRoot: path.join(REPO, 'no-such-dir') });
    assert.equal(r.status, 'disabled'); assert.equal(r.executed, false);
  }
});

test('contract: a policy denial carries exactly the documented fields, and an environment refusal carries policyCode only', async () => {
  const b = bound1();
  const opts = { binding: b.binding, config: darwinOn(), allowUnadvertisedBackend: true };
  const denied = await runCapabilityTask(b, { executable: '/bin/ls', args: [] }, opts);
  assert.equal(denied.status, 'blocked'); assert.equal(denied.code, 'capability-denied');
  assert.equal(denied.policyCode, 'command-not-listed'); assert.equal(denied.executed, false);
  sameFields(denied, [...fieldsUnder(PAGE, 'Runner refusal'), ...fieldsUnder(PAGE, 'Policy denial')], 'policy denial');
  const env = await runCapabilityTask(b, { executable: '/usr/bin/true', env: { GITHUB_TOKEN: 'x' } }, opts);
  assert.equal(env.code, 'capability-denied'); assert.equal(env.policyCode, 'secret-in-argument'); assert.equal(env.executed, false);
  sameFields(env, [...fieldsUnder(PAGE, 'Runner refusal'), 'policyCode'], 'environment refusal');
  const wrongId = await runCapabilityTask(b, { executable: '/usr/bin/true' }, { ...opts, binding: { ...b.binding, taskId: 'other' } });
  assert.equal(wrongId.policyCode, 'binding-mismatch'); assert.equal(wrongId.executed, false);
  // Documented looseness: the runner's code is not in the shared closed list.
  assert.ok(!RESULT_CODES.includes('capability-denied'));
});

test('contract: the documented result statuses are the shared closed set', () => {
  assert.deepEqual(fieldsUnder(PAGE, 'Result statuses').sort(), [...RESULT_STATUSES].sort());
});

// ---------------------------------------------------------------- page hygiene

test('contract: the page states its limits under the fixed heading with a verification date, and has no em-dash', () => {
  assert.match(PAGE, /\n## What this does not do\n\n<!-- limits-verified: \d{4}-\d{2}-\d{2} -->\n\n- /);
  assert.ok(!PAGE.includes(String.fromCharCode(0x2014)), 'no em-dashes');
  assert.match(PAGE, /^# Runner-level capability enforcement: contract\n/);
});
