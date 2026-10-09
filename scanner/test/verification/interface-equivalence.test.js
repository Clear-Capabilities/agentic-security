// X-206: equivalent verification in every interface. The CLI JSON report, the MCP tools, the human-readable reports and the
// autopilot response all present the same verification of the same finding, because they all call one projection. Each
// criterion is tested in both directions: the surfaces agree, AND a disagreement or a generic label is detected.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { toJSON, toCLI, toMarkdown, normalizeFindings } from '../../src/report/index.js';
import { createServer } from '../../src/mcp/server.js';
import { signLastScan } from '../../src/posture/integrity.js';
import { runAutopilot, serializeAutopilotResult } from '../../src/posture/autopilot.js';
import { projectVerification, verificationFields, verificationCoverage, VIEW_SCHEMA } from '../../src/posture/verification/projection.js';
import { emitVerification } from '../../src/posture/verification/emit.js';
import { buildVerificationRecord, VERIFICATION_OUTCOMES, REPAIR_STATUSES } from '../../src/posture/assurance/verification-record.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { COMMIT, META, FINDING, scanInput, autopilotStages } from '../fixtures/verification-compat/inputs.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const REPO = path.resolve(SCANNER, '..');
const compat = (name) => JSON.parse(fs.readFileSync(path.join(SCANNER, 'test', 'fixtures', 'verification-compat', name), 'utf8'));
const clone = (o) => JSON.parse(JSON.stringify(o));

// ---------------------------------------------------------------- records in every state

const trustedEvidence = [{ id: 'oracle-observation', kind: 'trusted-runtime-proof', producer: 'trusted-runner', digest: digestOf('observed'), source: 'oracle:injection-execution@1' }];
const observedOnly = [{ id: 'run-observation', kind: 'observation', producer: 'trusted-runner', digest: digestOf('run'), source: 'oracle:injection-execution@1' }];

function record(outcome, over = {}) {
  const decided = outcome === 'confirmed' || outcome === 'refuted';
  const ran = !['not-run', 'unsupported'].includes(outcome);
  return buildVerificationRecord({
    hypothesisId: FINDING.stableId, commit: COMMIT, detectorOrigin: { detector: 'Command injection', family: 'injection', parser: 'SAST' },
    oracle: ran || decided ? { id: 'injection-execution', kind: 'runtime-replay', version: '1' } : null,
    attempt: ran ? 1 : 0, outcome, reason: `fixture reason for ${outcome}`,
    evidence: decided ? trustedEvidence : (ran ? observedOnly : []),
    scope: { description: 'injection-execution oracle in the trust boundary', platform: process.platform, backend: 'userspace' },
    preconditions: { valid: decided || outcome === 'inconclusive' ? outcome !== 'inconclusive' : false },
    repair: { status: 'none' }, ...over,
  });
}

const REPLAY = [{ kind: 'toolchain', id: 'node-24', state: 'met', resumable: false, reason: 'the pinned runtime is present' }, { kind: 'network', id: 'denied', state: 'unmet', resumable: false, reason: 'acquisition is never attempted' }];

// ---------------------------------------------------------------- the four interfaces

function cliJson(rec, replay) {
  const scan = scanInput();
  scan.findings[0].verificationRecord = rec; if (replay) scan.findings[0].verificationReplay = replay;
  const out = clone(toJSON(scan, META));
  return { json: out, finding: out.findings[0], scan };
}

async function mcpExplain(jsonOut) {
  const root = mkTestTmp('as-x206-');
  const state = path.join(root, '.agentic-security');
  fs.mkdirSync(state, { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"x206"}');
  const body = JSON.stringify(jsonOut);
  fs.writeFileSync(path.join(state, 'last-scan.json'), body);
  fs.writeFileSync(path.join(state, 'last-scan.json.sig'), signLastScan(body));
  const { handleRequest } = createServer({ sessionRoot: root });
  const r = await handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'explain_finding', arguments: { finding_id: FINDING.id } } });
  return JSON.parse(r.result.content[0].text);
}

const autopilotOut = (rec, replay) => clone(serializeAutopilotResult({ ok: true, results: [{ key: FINDING.stableId, outcome: 'NEEDS_REVIEW', verificationRecord: rec, ...(replay ? { verificationReplay: replay } : {}) }] }).results[0]);

/** The verification text block as the CLI report prints it: the lines after the finding, indented. */
function cliBlock(scan, n) {
  const lines = toCLI(scan, { color: false }).split('\n');
  const i = lines.findIndex((l) => l.startsWith('        Verification:'));
  return i === -1 ? null : lines.slice(i, i + n).map((l) => l.replace(/^ {8}/, ''));
}
function markdownBlock(scan, n) {
  const lines = toMarkdown(scan, META).split('\n');
  const i = lines.findIndex((l) => l.startsWith('Verification:'));
  return i === -1 ? null : lines.slice(i, i + n);
}

const GENERIC = /(^|[^a-z])(safe|fixed|fixes|secure|resolved|remediated|all clear|no issues)([^a-z]|$)/i;
const genericLabels = (lines) => lines.filter((l) => GENERIC.test(l));

// ---------------------------------------------------------------- AC01

describe('[X-206.AC01] identical states, scope, evidence ids and replay prerequisites in every interface', () => {
  for (const outcome of VERIFICATION_OUTCOMES) {
    test(`[X-206.AC01] a '${outcome}' record reads the same in the CLI JSON, MCP, the text reports and the autopilot response`, async () => {
      const rec = record(outcome);
      assert.equal(projectVerification(rec).ok, true, 'the fixture record is valid');
      const { json, finding, scan } = cliJson(rec, REPLAY);
      const mcp = await mcpExplain(json);
      const auto = autopilotOut(rec, REPLAY);
      const reference = projectVerification(rec, { replay: REPLAY }).view;

      for (const [name, v] of [['CLI JSON', finding.verificationView], ['MCP', mcp.verificationView], ['autopilot', auto.verificationView]]) {
        assert.equal(v.schema, VIEW_SCHEMA, name);
        assert.equal(v.state, outcome, `${name}: state`);
        assert.deepEqual(v.scope, rec.scope, `${name}: scope`);
        assert.deepEqual(v.evidenceIds, rec.evidence.map((e) => e.id), `${name}: evidence ids`);
        assert.deepEqual(v.replay, reference.replay, `${name}: replay prerequisites`);
        assert.deepEqual(v, reference, `${name}: the whole projection is identical`);
      }
      // the replay prerequisites the attempt reported are present, not just the derived ones
      assert.ok(finding.verificationView.replay.prerequisites.some((p) => p.id === 'network:denied' && p.state === 'unmet'));

      // the human-readable reports carry the SAME lines, not a re-rendering
      const n = reference.text.length;
      assert.deepEqual(cliBlock(scan, n), reference.text, 'CLI text report');
      assert.deepEqual(markdownBlock(scan, n), reference.text, 'Markdown report');
      // and they state the same state, scope and evidence ids a JSON consumer reads
      const text = reference.text.join('\n');
      assert.ok(text.includes(rec.scope.description));
      for (const id of reference.evidenceIds) assert.ok(text.includes(id), `evidence id ${id} appears in the text`);
    });
  }

  test('[X-206.AC01] the autopilot record sealed by the loop itself reads the same across the interfaces', async () => {
    const res = await runAutopilot({ stages: autopilotStages(), commit: COMMIT });
    const rec = res.results[0].verificationRecord;
    assert.equal(rec.outcome, 'inconclusive', 'the older runner never yields confirmed');
    const ser = serializeAutopilotResult(res).results[0];
    const { json, finding } = cliJson(rec);
    const mcp = await mcpExplain(json);
    assert.deepEqual(ser.verificationView, finding.verificationView);
    assert.deepEqual(ser.verificationView, mcp.verificationView);
    // the native vocabulary is untouched beside the shared projection
    assert.equal(ser.outcome, 'VERIFIED_FIXED');
    assert.equal(ser.verificationView.state, 'inconclusive');
    assert.equal(ser.verificationView.legacy.verified, null, 'a legacy consumer cannot read this as a pass');
  });

  test('[X-206.AC01] a different record reads differently in all four, so the equivalence is not vacuous', async () => {
    const a = record('confirmed'); const b = record('inconclusive');
    const views = [];
    for (const rec of [a, b]) {
      const { json, finding, scan } = cliJson(rec);
      const mcp = await mcpExplain(json);
      views.push({ json: finding.verificationView, mcp: mcp.verificationView, auto: autopilotOut(rec).verificationView, cli: cliBlock(scan, 12).join('\n') });
    }
    for (const k of ['json', 'mcp', 'auto']) assert.notDeepEqual(views[0][k], views[1][k], k);
    assert.notEqual(views[0].cli, views[1].cli);
    assert.notEqual(views[0].json.recordId, views[1].json.recordId);
  });

  test('[X-206.AC01] a finding without a record gains nothing: no field, no block, no summary line', async () => {
    const scan = scanInput();
    const out = clone(toJSON(scan, META));
    assert.equal('verificationView' in out.findings[0], false);
    assert.equal('verificationRecord' in out.findings[0], false);
    assert.equal('verificationCoverage' in out, false);
    const mcp = await mcpExplain(out);
    assert.equal('verificationView' in mcp, false);
    assert.equal(cliBlock(scan, 3), null);
    assert.equal(/Trusted non-taint verification/.test(toCLI(scan, { color: false })), false);
    assert.deepEqual(serializeAutopilotResult({ ok: true, results: [{ key: 'k', outcome: 'UNPROVEN' }] }).results[0], { key: 'k', outcome: 'UNPROVEN' });
    assert.deepEqual(verificationFields(undefined), {});
  });

  test('[X-206.AC01] an invalid record is reported identically as an error, never projected into a guessed state', async () => {
    const forged = { ...record('inconclusive'), confirmationLevel: 'runtime-confirmed' };
    assert.equal(projectVerification(forged).ok, false);
    const { json, finding } = cliJson(forged);
    const mcp = await mcpExplain(json);
    const auto = autopilotOut(forged);
    for (const [name, o] of [['CLI JSON', finding], ['MCP', mcp], ['autopilot', auto]]) {
      assert.equal(o.verificationView, null, name);
      assert.ok(o.verificationViewErrors.some((e) => e.code === 'RULE_VIOLATION'), name);
    }
    assert.equal(cliBlock(cliJson(forged).scan, 3), null, 'no state is printed for a record that does not validate');
  });

  test('[X-206.AC01] trusted-negative accounting is shared: only decided non-taint oracle results count, the rest are listed', () => {
    const decided = buildVerificationRecord({
      hypothesisId: 'h-auth', commit: COMMIT, detectorOrigin: { detector: 'authz' }, oracle: { id: 'authorization-decision', kind: 'runtime-replay', version: '1' }, attempt: 1,
      outcome: 'refuted', reason: 'denied as expected', evidence: trustedEvidence, scope: { description: 'authorization oracle', platform: process.platform },
      preconditions: { valid: true }, repair: { status: 'none' },
    });
    const cov = verificationCoverage([decided, record('unsupported'), record('not-run'), record('inconclusive'), { not: 'a record' }]);
    assert.equal(cov.denominator, 1);
    assert.equal(cov.trustedNegatives, 1);
    assert.equal(cov.total, 5);
    assert.deepEqual(cov.excluded.map((e) => e.reason).sort(), ['inconclusive', 'malformed', 'not-run', 'unsupported']);
    assert.match(cov.lines[0], /1 decided \(1 not reproduced, 0 confirmed\) of 5 record\(s\); 4 not counted/);
    // the same line reaches the JSON report and the CLI report
    const scan = scanInput();
    scan.findings[0].verificationRecord = decided;
    assert.deepEqual(clone(toJSON(scan, META)).verificationCoverage.lines, verificationCoverage([decided]).lines);
    assert.match(verificationCoverage([decided]).lines[0], /1 decided \(1 not reproduced, 0 confirmed\) of 1 record\(s\); 0 not counted$/);
    assert.match(toCLI(scan, { color: false }), /Trusted non-taint verification: 1 decided/);
  });
});

// ---------------------------------------------------------------- AC02

describe('[X-206.AC02] human-readable output says what was verified and what was not, with no generic safe or fixed label', () => {
  test('[X-206.AC02] every state and repair status names what was verified and what remains untested', () => {
    for (const outcome of VERIFICATION_OUTCOMES) {
      for (const status of REPAIR_STATUSES) {
        const repair = status === 'none' ? { status } : status === 'replay-verified' ? { status, patchDigest: digestOf('p'), replayRecordId: 'vrec:0123456789abcdef' } : { status, patchDigest: digestOf('p') };
        const p = projectVerification(record(outcome, { repair }));
        assert.equal(p.ok, true, `${outcome}/${status}: ${JSON.stringify(p.errors)}`);
        const text = p.view.text.join('\n');
        assert.match(text, /^Verification: /m);
        assert.match(text, /^ {2}Verified: .+/m, `${outcome}: says what was verified`);
        assert.match(text, /^ {2}Not verified: .+/m, `${outcome}: says what was not`);
        assert.match(text, /^ {2}Repair: .+/m);
        assert.match(text, /^ {2}Replay prerequisites: .+/m);
        assert.deepEqual(genericLabels(p.view.text), [], `${outcome}/${status}: generic label in ${JSON.stringify(p.view.text)}`);
        if (outcome !== 'confirmed' && outcome !== 'refuted') assert.match(p.view.summary.verified, /nothing was established/);
        // a repair is only ever described as replay-verified for that status, and only against the declared scenario
        if (status !== 'replay-verified') assert.match(p.view.summary.untested.join(' '), /proposed patch under a trusted exploit-negative replay/);
        else assert.match(text, /declared scenario and functional cases only/);
      }
    }
  });

  test('[X-206.AC02] the lint catches a generic label, so a regression in the wording would fail the suite', () => {
    for (const bad of ['Status: safe to deploy', 'Verified: fixed', 'VERIFIED_FIXED', 'This is secure', 'issue resolved', 'No issues found']) {
      assert.deepEqual(genericLabels([bad]), [bad], bad);
    }
    for (const ok of ['Verification: INCONCLUSIVE (nothing was decided)', 'Not verified: the effect of any proposed patch under a trusted exploit-negative replay']) {
      assert.deepEqual(genericLabels([ok]), [], ok);
    }
  });

  test('[X-206.AC02] the wording the real surfaces produce for partial results passes the same lint', () => {
    const finding = { stableId: 'h-real', vuln: 'Command injection', family: 'injection', parser: 'SAST', severity: 'high' };
    const emitted = [
      emitVerification('fix-verify', { rescan: { ok: true }, lint: { ok: true }, tests: { passed: true }, poc: { status: 'not-requested' } }, { finding, commit: COMMIT, files: { 'a.js': 'x' } }),
      emitVerification('fix-verify', { rescan: { ok: true }, lint: { ok: true, skipped: true }, tests: { skipped: true }, poc: { status: 'fixed', tier: 'proof-failed' } }, { finding, commit: COMMIT, files: { 'a.js': 'x' } }),
      emitVerification('fix-verify-loop', { verdict: 'accepted', legs: { scan: { ok: true }, lint: { ok: true }, tests: { ok: true } } }, { finding, commit: COMMIT, files: { 'a.js': 'x' } }),
      emitVerification('execution-proof', { ...finding, proofEvidence: { tier: 'execution-proven', ran: true } }, { commit: COMMIT }),
      emitVerification('execution-proof', { ...finding, proofEvidence: { tier: 'proof-failed', ran: true } }, { commit: COMMIT }),
      emitVerification('verifier', { ...finding, verifier_verdict: 'verified-exploit', verifier_reason: 'exit 0' }, { commit: COMMIT }),
      emitVerification('verifier', { ...finding, verifier_verdict: 'unverified-by-design', verifier_reason: 'no oracle for this family' }, { commit: COMMIT }),
      emitVerification('autopilot', { outcome: 'VERIFIED_FIXED', pocStillFires: false, testsPass: true, applied: false, proofTier: 'execution-proven' }, { finding, commit: COMMIT, patch: { 'a.js': 'x' } }),
      emitVerification('autopilot', { outcome: 'NEEDS_REVIEW', pocStillFires: true, proofTier: 'execution-proven' }, { finding, commit: COMMIT, patch: { 'a.js': 'x' } }),
      emitVerification('hunt', { ...finding, discovery: { lens: 'auth', confirmation: { tier: 'unconfirmed' } } }, { commit: COMMIT }),
      emitVerification('hunt', { ...finding, discovery: { lens: 'auth', confirmation: { tier: 'taint-confirmed' } } }, { commit: COMMIT }),
    ];
    for (const e of emitted) {
      assert.equal(e.ok, true, JSON.stringify(e.errors));
      const p = projectVerification(e.record);
      assert.equal(p.ok, true);
      assert.deepEqual(genericLabels(p.view.text), [], `${e.record.reason}`);
      assert.notEqual(p.view.state, 'confirmed', 'a legacy surface never reaches confirmed');
    }
  });

  test('[X-206.AC02] the printed report, not just the projection, is free of generic labels for a partial result', () => {
    const { scan } = cliJson(record('inconclusive'));
    const printed = toCLI(scan, { color: false }).split('\n').filter((l) => /Verification|Verified|Not verified|Repair|Reason|Evidence|Replay/.test(l));
    assert.ok(printed.length >= 7);
    assert.deepEqual(genericLabels(printed), []);
    assert.deepEqual(genericLabels(markdownBlock(scan, 9)), []);
  });
});

// ---------------------------------------------------------------- AC03

describe('[X-206.AC03] previous output schemas still hold; changes are additive and lose nothing', () => {
  const isSuperset = (prev, cur, at = '') => {
    if (prev !== null && typeof prev === 'object' && !Array.isArray(prev)) {
      assert.ok(cur !== null && typeof cur === 'object', `${at}: object expected`);
      for (const k of Object.keys(prev)) { assert.ok(k in cur, `${at}.${k}: a previous field is gone`); isSuperset(prev[k], cur[k], `${at}.${k}`); }
    } else assert.deepEqual(cur, prev, `${at}: a previous value changed`);
  };

  test('[X-206.AC03] the CLI JSON report keeps every top-level key and every finding field it had, with the same values', () => {
    const prev = compat('report-json.v0.json');
    const cur = clone(toJSON(scanInput(), META));
    for (const k of prev.topLevelKeys) assert.ok(k in cur, `top-level key ${k} is gone`);
    isSuperset(prev.finding, clone(normalizeFindings(scanInput())[0]), 'finding');
    // for an output without a record the shape is exactly the previous one
    assert.deepEqual(Object.keys(cur).sort(), prev.topLevelKeys);
    assert.deepEqual(clone(normalizeFindings(scanInput())[0]), prev.finding);
  });

  test('[X-206.AC03] the MCP explain_finding payload keeps every field it had', async () => {
    const prev = compat('mcp-explain-finding.v0.json').payload;
    const cur = await mcpExplain(clone(toJSON(scanInput(), META)));
    isSuperset(prev, cur, 'explain_finding');
    assert.deepEqual(cur, prev);
  });

  test('[X-206.AC03] the autopilot result keeps every field, the native outcome vocabulary and the record, and only adds `verificationView`', async () => {
    const prev = compat('autopilot-result.v0.json');
    const res = await runAutopilot({ stages: autopilotStages(), commit: COMMIT });
    const ser = serializeAutopilotResult(res);
    const strip = (r) => { const c = clone(r); if (process.platform !== 'darwin') { delete c.verificationRecord.id; delete c.verificationRecord.scope.platform; } return c; };
    const stripPrev = clone(prev.result);
    if (process.platform !== 'darwin') { delete stripPrev.verificationRecord.id; delete stripPrev.verificationRecord.scope.platform; }
    isSuperset(stripPrev, strip(ser.results[0]), 'autopilot result');
    assert.deepEqual(Object.keys(ser.results[0]).filter((k) => !(k in prev.result)), ['verificationView']);
    assert.deepEqual(ser.summary, prev.summary);
    assert.equal(ser.results[0].outcome, prev.result.outcome, 'the native outcome keeps its meaning');
  });

  test('[X-206.AC03] no richer verification field is lost: every record field has a counterpart in the projection', () => {
    const rec = record('confirmed', { repair: { status: 'replay-verified', patchDigest: digestOf('p'), replayRecordId: 'vrec:0123456789abcdef' } });
    const edited = { ...rec, reason: 'edited after the id was computed' };
    const view = projectVerification(rec).view;
    const map = { hypothesisId: 'hypothesisId', commit: 'commit', detectorOrigin: 'detectorOrigin', oracle: 'oracle', attempt: 'attempt', outcome: 'state', reason: 'reason', evidence: 'evidence', evidenceRefs: 'referencedEvidenceIds', scope: 'scope', preconditions: 'preconditions', confirmationLevel: 'confirmationLevel', repair: 'repair', id: 'recordId', schemaVersion: 'recordSchemaVersion' };
    for (const [from, to] of Object.entries(map)) {
      assert.ok(from in rec && to in view, `${from} -> ${to}`);
      if (from === 'evidence') assert.deepEqual(view[to].map((e) => e.id), rec[from].map((e) => e.id));
      else assert.deepEqual(view[to], rec[from], `${from} is carried unchanged`);
    }
    // every field the schema allows is either mapped above or one of the two optional bookkeeping fields, also carried
    for (const k of Object.keys(rec)) assert.ok(k === 'schema' || k in map, `record field '${k}' has no counterpart`);
    assert.equal(projectVerification(edited).ok, false, 'a record whose content moved off its id is refused, not projected');
    assert.ok('migration' in view && 'createdAt' in view);
    // the whole record also rides along in the report JSON, so a richer consumer reads the original
    const { finding } = cliJson(rec);
    assert.deepEqual(finding.verificationRecord, rec);
    // a legacy consumer's view is kept, with a skipped check never reading as a pass
    assert.equal(view.legacy.verified, true);
    assert.equal(projectVerification(record('not-run')).view.legacy.verified, null);
    assert.equal(projectVerification(record('refuted')).view.legacy.verified, false);
  });

  test('[X-206.AC03] the projection is deterministic and survives a JSON round trip', () => {
    const rec = record('refuted');
    const a = projectVerification(rec, { replay: REPLAY }).view;
    const b = projectVerification(clone(rec), { replay: clone(REPLAY) }).view;
    assert.deepEqual(a, b);
    assert.deepEqual(clone(a), a);
    assert.equal(JSON.stringify(a), JSON.stringify(b));
  });

  test('[X-206.AC03] the versioned migration documentation exists and names the version, every added field and the previous fixtures', () => {
    const doc = fs.readFileSync(path.join(REPO, 'docs', 'guides', 'verification-schema-migration.md'), 'utf8');
    assert.match(doc, new RegExp(VIEW_SCHEMA.replace(/\//g, '\\/')));
    assert.match(doc, /1\.0\.0/);
    for (const field of ['verificationView', 'verificationViewErrors', 'verificationRecord', 'verificationReplay', 'verificationCoverage', 'advisoryExcluded', 'promotions']) assert.ok(doc.includes(field), `the migration page names ${field}`);
    for (const f of ['report-json.v0.json', 'mcp-explain-finding.v0.json', 'autopilot-result.v0.json']) {
      assert.ok(doc.includes(f), `the migration page names the fixture ${f}`);
      assert.ok(fs.existsSync(path.join(SCANNER, 'test', 'fixtures', 'verification-compat', f)));
    }
    assert.match(doc, /additive/i);
  });
});
