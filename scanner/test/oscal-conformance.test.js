// OSCAL structural conformance.
//
// SCOPE, STATED PLAINLY: this is STRUCTURAL validation — the fields the
// assessment-results model marks required, the datatypes OSCAL constrains
// (`uuid`, `token`, `dateTime-with-timezone`), the closed value sets, and
// referential integrity between the parts of a document that point at each
// other. It is NOT full JSON-Schema validation against NIST's published schema,
// because fetching that schema at test time breaks the no-network rule and
// vendoring it adds a 3 MB file that rots silently against upstream. Same call,
// same reasoning, as test/sbom-conformance.test.js.
//
// What this DOES catch is the failure mode of every "we support OSCAL" claim
// that was never run through a validator: a document that looks OSCAL-shaped
// and is rejected at the first control because a real-world control identifier
// (`§1798.100`, `Art. 32(1)(a)`) is not a legal OSCAL token.
//
// It also pins the DOCTRINE, which is not a schema property and would otherwise
// be one refactor away from quietly reversing:
//   · a raw scan emits observations and risks and NO findings
//   · a control the engine could not decide emits NO finding
//   · `absent` is a decision, not an absence of one
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  toOSCAL, toOSCALCompliance, complianceRowsFromEvaluation, complianceRowsFromPrivacy,
  oscalToken, OSCAL_NS,
} from '../src/report/oscal.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

// ── the datatypes OSCAL actually constrains ─────────────────────────────────
// `uuid` is v4/v5 only: the version nibble must be 4 or 5 and the variant nibble
// must be 8/9/a/b. A bare sha256 slice passes "looks hex-ish" and fails this.
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
// `token` is an NCName: leading letter or underscore, then letters, digits,
// `.`, `-`, `_`. This is the one that rejects real control ids.
const TOKEN = /^[\p{L}_][\p{L}\p{N}.\-_]*$/u;
// `dateTime-with-timezone`: the offset is mandatory. A bare local timestamp is
// a validation error, and is what `new Date().toString()` would have produced.
const DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

const OBSERVATION_METHODS = new Set(['EXAMINE', 'INTERVIEW', 'TEST']);
const RISK_STATUS = new Set(['open', 'investigating', 'remediating', 'deviation-requested', 'deviation-approved', 'closed']);
const TARGET_TYPES = new Set(['statement-id', 'objective-id']);
const TARGET_STATES = new Set(['satisfied', 'not-satisfied']);
const LIFECYCLES = new Set(['recommendation', 'planned', 'completed']);

const SCAN = {
  filesScanned: 3,
  findings: [
    {
      id: 'f1', stableId: 'sid-1', severity: 'critical', file: 'src/db.js', line: 12,
      vuln: 'SQL Injection', cwe: 'CWE-89', family: 'sql-injection', parser: 'ast',
      description: 'User input reaches a query without parameterisation.',
      remediation: 'Use parameterised queries.', confidenceTier: 'high', exploitabilityTier: 'high',
    },
    {
      id: 'f2', severity: 'medium', file: 'src\\win\\path.js', line: 4,
      vuln: 'Path Traversal', cwe: 'CWE-22', family: 'path-traversal', parser: 'regex',
      description: 'Unvalidated path component.',
    },
  ],
  secrets: [], supplyChain: [], logicVulns: [],
};
const META = { startedAt: '2026-08-23T10:00:00.000Z', scanId: 'test-scan' };

/** Every OSCAL object that is required to carry a `uuid`, found recursively. */
function collectUuidFields(node, out = []) {
  if (Array.isArray(node)) { for (const v of node) collectUuidFields(v, out); return out; }
  if (!node || typeof node !== 'object') return out;
  for (const [k, v] of Object.entries(node)) {
    if (typeof v === 'string' && (k === 'uuid' || k.endsWith('-uuid'))) out.push([k, v]);
    else collectUuidFields(v, out);
  }
  return out;
}

function assertCommonShape(doc, label) {
  assert.match(doc.uuid, UUID, `${label}: document uuid`);
  const m = doc.metadata;
  for (const k of ['title', 'last-modified', 'version', 'oscal-version']) {
    assert.ok(m[k], `${label}: metadata.${k} is required by the model`);
  }
  assert.match(m['last-modified'], DATETIME, `${label}: metadata.last-modified`);
  assert.match(m['oscal-version'], /^\d+\.\d+\.\d+$/, `${label}: oscal-version must name a real release`);

  // import-ap is REQUIRED. A document without it is not assessment-results.
  assert.ok(doc['import-ap'] && typeof doc['import-ap'].href === 'string' && doc['import-ap'].href.length,
    `${label}: import-ap.href is required`);

  assert.ok(Array.isArray(doc.results) && doc.results.length >= 1, `${label}: results must be non-empty`);
  for (const r of doc.results) {
    for (const k of ['uuid', 'title', 'description', 'start', 'reviewed-controls']) {
      assert.ok(r[k], `${label}: result.${k} is required`);
    }
    assert.match(r.start, DATETIME, `${label}: result.start`);
    const sels = r['reviewed-controls']['control-selections'];
    assert.ok(Array.isArray(sels) && sels.length >= 1, `${label}: control-selections must be non-empty`);
  }

  for (const [k, v] of collectUuidFields(doc)) assert.match(v, UUID, `${label}: ${k}`);
}

function assertPropsNamespaced(doc, label) {
  const walk = (node) => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (!node || typeof node !== 'object') return;
    for (const [k, v] of Object.entries(node)) {
      if (k === 'props' && Array.isArray(v)) {
        for (const p of v) {
          assert.ok(p.name && typeof p.value === 'string', `${label}: prop needs name+value`);
          assert.equal(p.ns, OSCAL_NS, `${label}: extension prop "${p.name}" must be namespaced`);
        }
      } else walk(v);
    }
  };
  walk(doc);
}

/** Every internal reference must resolve, or the document is a set of orphans. */
function assertReferentialIntegrity(doc, label) {
  const declared = new Set();
  for (const [k, v] of collectUuidFields(doc)) if (k === 'uuid') declared.add(v);
  for (const [k, v] of collectUuidFields(doc)) {
    if (k === 'uuid') continue;
    assert.ok(declared.has(v), `${label}: ${k} ${v} points at nothing in this document`);
  }
  const hrefs = [];
  const walk = (n) => {
    if (Array.isArray(n)) return n.forEach(walk);
    if (!n || typeof n !== 'object') return;
    for (const [k, v] of Object.entries(n)) {
      if (k === 'links' && Array.isArray(v)) v.forEach(l => hrefs.push(l.href));
      else walk(v);
    }
  };
  walk(doc);
  for (const h of hrefs) {
    if (!h.startsWith('#')) continue;
    assert.ok(declared.has(h.slice(1)), `${label}: link ${h} resolves to nothing`);
  }
}

// ── scan flavour ─────────────────────────────────────────────────────────────

test('a scan emits a structurally valid assessment-results document', () => {
  const doc = toOSCAL(SCAN, META);
  assertCommonShape(doc, 'scan');
  assertPropsNamespaced(doc, 'scan');
  assertReferentialIntegrity(doc, 'scan');

  const r = doc.results[0];
  assert.equal(r.observations.length, 2);
  assert.equal(r.risks.length, 2);
  for (const o of r.observations) {
    assert.ok(o.description, 'observation.description is required');
    assert.ok(Array.isArray(o.methods) && o.methods.length >= 1, 'observation.methods is required');
    for (const meth of o.methods) assert.ok(OBSERVATION_METHODS.has(meth), `bad method ${meth}`);
    assert.match(o.collected, DATETIME, 'observation.collected');
  }
  for (const k of r.risks) {
    for (const f of ['title', 'description', 'statement', 'status']) assert.ok(k[f], `risk.${f} is required`);
    assert.ok(RISK_STATUS.has(k.status), `bad risk status ${k.status}`);
    for (const rem of k.remediations || []) {
      assert.ok(LIFECYCLES.has(rem.lifecycle), `bad lifecycle ${rem.lifecycle}`);
      assert.ok(rem.title && rem.description, 'response needs title+description');
    }
  }
});

test('DOCTRINE: a raw scan asserts nothing about any control', () => {
  // An OSCAL finding is a statement ABOUT A CONTROL, with a binary
  // satisfied/not-satisfied state. A SAST hit is not that, and no catalog is in
  // scope. Emitting findings here would publish a CWE→control mapping nobody
  // wrote. If this ever fails, someone added findings to the scan exporter and
  // the document is now making claims it cannot support.
  const r = toOSCAL(SCAN, META).results[0];
  assert.equal(r.findings, undefined, 'a source-code scan must not emit OSCAL findings');
  // And it must not claim to have reviewed a catalog it never saw.
  const sel = r['reviewed-controls']['control-selections'][0];
  assert.equal(sel['include-all'], undefined, 'include-all would claim every control of an unnamed catalog was reviewed');
  assert.equal(sel['include-controls'], undefined);
  assert.match(r['reviewed-controls'].description, /no control catalog/i);
});

test('the scan document carries the same caveats SARIF does', () => {
  const doc = toOSCAL(SCAN, META);
  const ids = doc['back-matter'].resources
    .flatMap(x => (x.props || []).filter(p => p.name === 'caveat-id').map(p => p.value));
  assert.ok(ids.includes('scores-are-ordinal'), 'the ordinal-score caveat must travel with the artifact');
  assert.ok(ids.includes('owasp-benchmark-tuning'));
});

test('the raw ordinal scores are NOT emitted as bare numbers', () => {
  // A compliance reader is the reader most likely to read a decimal in a
  // NIST-shaped document as a probability. Tiers only.
  const doc = toOSCAL({ ...SCAN, findings: [{ ...SCAN.findings[0], confidence: 0.907, exploitability: 0.42 }] }, META);
  const props = doc.results[0].observations[0].props.map(p => p.name);
  assert.ok(props.includes('confidence-tier'));
  assert.ok(!props.includes('confidence'), 'raw confidence must not be published as a bare value');
  assert.ok(!props.includes('exploitability'));
});

test('Windows-shaped paths are normalised before they become evidence hrefs', () => {
  const doc = toOSCAL(SCAN, META);
  const win = doc.results[0].observations.find(o => o.title === 'Path Traversal');
  assert.equal(win['relevant-evidence'][0].href, 'src/win/path.js');
});

// ── compliance flavour ───────────────────────────────────────────────────────

const FW = { id: 'demo-fw', name: 'Demo Framework', publisher: 'Demo', url: 'https://example.invalid/fw', license: 'CC0' };
const EVAL = [
  { control: { id: 'AC-1', summary: 'Access control policy', codeTestable: 'yes' }, status: 'present', observations: ['cleared'] },
  { control: { id: 'AC-2', summary: 'Account management' }, status: 'partial', observations: ['one signal did not clear'] },
  { control: { id: 'AC-3', summary: 'Least privilege' }, status: 'absent', observations: ['nothing cleared'] },
  { control: { id: 'PM-1', summary: 'Programme management' }, status: 'manual', observations: [] },
];

test('a compliance evaluation emits a structurally valid assessment-results document', () => {
  const doc = toOSCALCompliance(FW, complianceRowsFromEvaluation(EVAL), META);
  assertCommonShape(doc, 'compliance');
  assertPropsNamespaced(doc, 'compliance');
  assertReferentialIntegrity(doc, 'compliance');

  const r = doc.results[0];
  assert.equal(r.observations.length, 4, 'every control is observed, decided or not');
  for (const f of r.findings) {
    for (const k of ['title', 'description', 'target']) assert.ok(f[k], `finding.${k} is required`);
    assert.ok(TARGET_TYPES.has(f.target.type), `bad target type ${f.target.type}`);
    assert.ok(f.target['target-id'], 'target-id is required');
    assert.match(f.target['target-id'], TOKEN, 'target-id must be an OSCAL token');
    assert.ok(TARGET_STATES.has(f.target.status.state), `bad state ${f.target.status.state}`);
  }
  for (const sel of r['reviewed-controls']['control-selections']) {
    for (const c of sel['include-controls'] || []) assert.match(c['control-id'], TOKEN);
  }
});

test('DOCTRINE: `absent` is a decision — it becomes not-satisfied, never unassessed', () => {
  // This is the bug this file was written after: a catch-all mapped every
  // status except present/partial to "requires human judgement", which deleted
  // the evaluator's strongest failure signal from the document and attached a
  // remark that was false.
  const rows = complianceRowsFromEvaluation(EVAL);
  assert.deepEqual(
    rows.map(r => `${r.statusLabel}->${r.decision}`),
    ['present->satisfied', 'partial->not-satisfied', 'absent->not-satisfied', 'manual->unassessed'],
  );
  const doc = toOSCALCompliance(FW, rows, META);
  const byId = Object.fromEntries(doc.results[0].findings.map(f => [f.target['target-id'], f.target.status.state]));
  assert.deepEqual(byId, { 'AC-1': 'satisfied', 'AC-2': 'not-satisfied', 'AC-3': 'not-satisfied' });
});

test('DOCTRINE: a control the engine could not decide gets NO finding', () => {
  const doc = toOSCALCompliance(FW, complianceRowsFromEvaluation(EVAL), META);
  const r = doc.results[0];
  assert.ok(!r.findings.some(f => f.target['target-id'] === 'PM-1'),
    'asserting satisfied OR not-satisfied for an unchecked control is a false claim either way');
  const obs = r.observations.find(o => o.props.some(p => p.name === 'source-control-id' && p.value === 'PM-1'));
  assert.deepEqual(obs.methods, ['EXAMINE'], 'unassessed controls are for a human to examine');
  assert.match(obs.remarks, /not evidence of compliance/i);
  assert.equal(r.props.find(p => p.name === 'count-unassessed').value, '1');
});

test('an unrecognised upstream status is reported as unrecognised, not as human judgement', () => {
  const rows = complianceRowsFromEvaluation([{ control: { id: 'X-1', summary: 's' }, status: 'invented-later' }]);
  assert.equal(rows[0].decision, 'unassessed');
  assert.equal(rows[0].known, false);
  const obs = toOSCALCompliance(FW, rows, META).results[0].observations[0];
  assert.match(obs.remarks, /defect in the exporter/i);
  assert.equal(obs.props.find(p => p.name === 'assessment-status').value, 'invented-later');
});

test('the privacy bucket model keeps engine-gap distinct from a control failure', () => {
  // `engine-gap` means NIST rates the control code-testable and this scanner
  // has no check for it. That is a hole in the tool. Folding it into
  // not-satisfied would blame the assessed system for our coverage.
  const rows = complianceRowsFromPrivacy({
    controls: [
      { id: 'ID.IM-P1', summary: 'a', bucket: 'satisfied' },
      { id: 'ID.IM-P2', summary: 'b', bucket: 'gap' },
      { id: 'ID.IM-P3', summary: 'c', bucket: 'engine-gap' },
      { id: 'ID.IM-P4', summary: 'd', bucket: 'manual' },
    ],
    findings: [{ id: 'privacy-framework:ID.IM-P2', remediation: 'Do the thing.' }],
  });
  assert.deepEqual(rows.map(r => r.decision), ['satisfied', 'not-satisfied', 'unassessed', 'unassessed']);
  const doc = toOSCALCompliance({ id: 'nist-privacy-1-1', name: 'NIST Privacy Framework 1.1' }, rows, META);
  const r = doc.results[0];
  assert.equal(r.findings.length, 2);
  assert.equal(r.risks.length, 1);
  assert.equal(r.risks[0].remediations[0].description, 'Do the thing.');
  const gapObs = r.observations.find(o => o.props.some(p => p.name === 'source-control-id' && p.value === 'ID.IM-P3'));
  assert.match(gapObs.remarks, /coverage gap in the scanner, NOT a defect in the assessed system/);
});

// ── the token problem, against real shipped control ids ──────────────────────

test('real control identifiers survive the OSCAL token datatype', () => {
  // Not a synthetic case: the CCPA catalog bundled with this engine uses
  // `§1798.100`, which is not a legal OSCAL token. A document that emitted it
  // raw would be rejected at the first control by any validator.
  const ccpa = JSON.parse(fs.readFileSync(
    path.join(HERE, '..', 'src', 'posture', 'compliance-frameworks', 'ccpa.json'), 'utf8'));
  const raw = ccpa.controls.map(c => c.id);
  assert.ok(raw.some(id => !TOKEN.test(id)), 'fixture check: CCPA must still contain a non-token id, or this test proves nothing');

  const rows = ccpa.controls.map(c => ({
    id: c.id, title: c.summary, decision: 'satisfied', statusLabel: 'present', known: true, observations: [],
  }));
  const doc = toOSCALCompliance(ccpa, rows, META);
  const r = doc.results[0];
  for (const c of r['reviewed-controls']['control-selections'][0]['include-controls']) {
    assert.match(c['control-id'], TOKEN, `control-id ${c['control-id']} is not an OSCAL token`);
  }
  for (const f of r.findings) assert.match(f.target['target-id'], TOKEN);

  // And the original identifier must still be recoverable — a sanitised id that
  // loses the publisher's identifier makes the document unusable to the auditor
  // holding the actual regulation.
  const originals = new Set(r.observations.flatMap(
    o => o.props.filter(p => p.name === 'source-control-id').map(p => p.value)));
  for (const id of raw) assert.ok(originals.has(id), `original id ${id} was lost`);
});

test('oscalToken is total: it never returns something that is not a token', () => {
  for (const s of ['§1798.100', 'Art. 32(1)(a)', '1.2.3', '', '   ', 'AC-1', 'V2.7', '§§', '—', 'ID.IM-P1']) {
    assert.match(oscalToken(s), TOKEN, `oscalToken(${JSON.stringify(s)})`);
  }
});

test('--deterministic uuids are still legal uuids, and are stable', () => {
  // The deterministic branch mints uuids by SHAPING a sha256 digest. A digest
  // slice is not a uuid: OSCAL's uuid datatype requires the version nibble to
  // be 4 or 5 and the variant nibble to be 8/9/a/b, and roughly 15 of every 16
  // unshaped digests fail on the variant alone. Every test above ran the
  // crypto.randomUUID() branch, so without this the deterministic artifact —
  // the one an attestation is taken over — was the untested one.
  const prev = process.env.AGENTIC_SECURITY_DETERMINISTIC;
  process.env.AGENTIC_SECURITY_DETERMINISTIC = '1';
  try {
    const a = toOSCAL(SCAN, META);
    const b = toOSCAL(SCAN, META);
    assert.equal(JSON.stringify(a), JSON.stringify(b), 'two emits of one scan must be byte-identical');
    for (const [k, v] of collectUuidFields(a)) assert.match(v, UUID, `deterministic ${k}`);
    assertReferentialIntegrity(a, 'deterministic scan');

    const c = toOSCALCompliance(FW, complianceRowsFromEvaluation(EVAL), META);
    for (const [k, v] of collectUuidFields(c)) assert.match(v, UUID, `deterministic ${k}`);
    assertReferentialIntegrity(c, 'deterministic compliance');

    // Distinct objects must get distinct uuids — a seed collision would make
    // two observations the same observation and silently merge two findings.
    const scanUuids = collectUuidFields(a).filter(([k]) => k === 'uuid').map(([, v]) => v);
    assert.equal(new Set(scanUuids).size, scanUuids.length, 'deterministic uuid seeds collided');
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_DETERMINISTIC;
    else process.env.AGENTIC_SECURITY_DETERMINISTIC = prev;
  }
});

test('token sanitisation is injective across every bundled framework', () => {
  // Two controls collapsing to one token would make the document
  // self-contradictory: two findings targeting the same target-id, and a reader
  // with no way to tell which control either one is about. The sanitiser
  // therefore substitutes rather than strips — `§1798.100` becomes
  // `_-1798.100`, not the prettier `_1798.100`, because the pretty form would
  // collide with a control literally named `1798.100`. Readability is not worth
  // an ambiguous document; the publisher's identifier is carried verbatim as a
  // source-control-id property either way.
  const dir = path.join(HERE, '..', 'src', 'posture', 'compliance-frameworks');
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
  assert.ok(files.length >= 5, 'fixture check: expected the bundled frameworks to be present');
  for (const file of files) {
    const fw = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
    const ids = (fw.controls || []).map(c => c.id);
    if (!ids.length) continue;
    const tokens = ids.map(oscalToken);
    assert.equal(new Set(tokens).size, new Set(ids).size,
      `${file}: distinct control ids collapsed to the same OSCAL token`);
    for (const t of tokens) assert.match(t, TOKEN, `${file}: ${t}`);
  }
});

test('assessment-assets sits on the RESULT, and names an assessment platform', () => {
  // Two placement facts the model fixes and an emitter can get wrong silently:
  //   · `assessment-results/local-definitions` carries objectives-and-methods
  //     and activities — NOT assessment-assets, which is result-scoped.
  //   · `assessment-assets` requires at least one `assessment-platforms` entry.
  // Both were wrong in the first draft. Neither costs anything at emit time and
  // both cost the whole document at validation time.
  for (const [label, doc] of [
    ['scan', toOSCAL(SCAN, META)],
    ['compliance', toOSCALCompliance(FW, complianceRowsFromEvaluation(EVAL), META)],
  ]) {
    assert.equal(doc['local-definitions'], undefined,
      `${label}: assessment-assets must not hang off the document's local-definitions`);
    const assets = doc.results[0]['local-definitions']['assessment-assets'];
    assert.ok(Array.isArray(assets['assessment-platforms']) && assets['assessment-platforms'].length >= 1,
      `${label}: assessment-assets requires a non-empty assessment-platforms`);
    const component = assets.components[0];
    assert.equal(component.type, 'software');
    assert.ok(component.status && component.status.state, 'a component requires a status.state');
    assert.equal(assets['assessment-platforms'][0]['uses-components'][0]['component-uuid'], component.uuid);
    // And every observation's origin must point at that component, or the
    // document does not say a machine produced these.
    for (const o of doc.results[0].observations) {
      assert.equal(o.origins[0].actors[0].type, 'tool');
      assert.equal(o.origins[0].actors[0]['actor-uuid'], component.uuid);
    }
  }
});
