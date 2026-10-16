#!/usr/bin/env node
// Existing behaviour contract (E0-03): a structural snapshot of the public surfaces other tools depend on.
//   node contract.mjs --check               capture now and compare with the committed snapshot; exit 1 on a breaking change
//   node contract.mjs --update              rewrite the snapshot (refuses a breaking change)
//   node contract.mjs --update --accept-breaking "reason"   rewrite it anyway, recording the reason in the snapshot's history
//   node contract.mjs --print               print the current capture
//
// The snapshot records SHAPES (key names and value types) and the small closed vocabularies that consumers switch on (assurance modes,
// scan-health statuses, exit codes), never values that change from run to run. A removed key, a changed type or a changed vocabulary
// entry is BREAKING and fails the check. A new key is ADDITIVE: it passes, and is folded in by `--update`.
//
// Surfaces: scan JSON, scanHealth, assurance modes, CLI exit codes (scan and ci --assurance strict), MCP tool schemas, verify_fix,
// findingProvenance, the signed evidence bundle, OSCAL.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as os from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { atomicWriteJson } from '../loop-engineering/lib/util.mjs';
import { REPO_ROOT } from './lib/model.mjs';

export const SNAPSHOT_REL = 'scanner/test/fixtures/engineering-excellence/contract.snapshot.json';

// ---- shapes ---------------------------------------------------------------------------------------------------------------

/** Merge two shapes: equal shapes stay, objects merge key by key (a key missing on one side becomes optional), anything else is a union. */
export function mergeShapes(a, b) {
  if (a === undefined) return b;
  if (b === undefined) return a;
  if (JSON.stringify(a) === JSON.stringify(b)) return a;
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    if ('array' in a && 'array' in b) return { array: mergeShapes(a.array, b.array) };
    if ('object' in a && 'object' in b) {
      const out = {};
      const keys = new Set([...Object.keys(a.object), ...Object.keys(b.object)]);
      for (const k of [...keys].sort()) {
        const inA = k in a.object; const inB = k in b.object;
        const base = mergeShapes(a.object[k], b.object[k]);
        out[k] = inA && inB ? base : { optional: base };
      }
      return { object: out };
    }
  }
  const parts = (x) => (typeof x === 'string' ? x.split('|') : [JSON.stringify(x)]);
  return [...new Set([...parts(a), ...parts(b)])].sort().join('|');
}

export function shapeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return { array: v.length ? v.map(shapeOf).reduce((acc, s) => mergeShapes(acc, s)) : 'empty' };
  if (typeof v === 'object') {
    const o = {};
    for (const k of Object.keys(v).sort()) if (v[k] !== undefined) o[k] = shapeOf(v[k]);
    return { object: o };
  }
  return typeof v;
}

const unwrapOptional = (s) => (s && typeof s === 'object' && 'optional' in s ? s.optional : s);

/** Differences between a recorded shape and the current one, as {path, kind: 'removed'|'type-changed'|'added', ...}. */
export function diffShapes(before, after, path = '$') {
  const out = [];
  const a = unwrapOptional(before); const b = unwrapOptional(after);
  if (JSON.stringify(a) === JSON.stringify(b)) return out;
  const isObj = (x) => x && typeof x === 'object' && 'object' in x;
  const isArr = (x) => x && typeof x === 'object' && 'array' in x;
  if (isObj(a) && isObj(b)) {
    for (const k of Object.keys(a.object)) {
      if (!(k in b.object)) out.push({ path: `${path}.${k}`, kind: 'removed' });
      else out.push(...diffShapes(a.object[k], b.object[k], `${path}.${k}`));
    }
    for (const k of Object.keys(b.object)) if (!(k in a.object)) out.push({ path: `${path}.${k}`, kind: 'added' });
    return out;
  }
  if (isArr(a) && isArr(b)) return diffShapes(a.array, b.array, `${path}[]`);
  // a value that was one type and is now a superset of it is additive; anything that drops a recorded type is breaking
  if (typeof a === 'string' && typeof b === 'string') {
    const before2 = new Set(a.split('|')); const after2 = new Set(b.split('|'));
    const dropped = [...before2].filter((t) => !after2.has(t));
    if (!dropped.length) return [{ path, kind: 'added', detail: `type widened from ${a} to ${b}` }];
    if (a === 'empty' || b === 'empty') return [];
    return [{ path, kind: 'type-changed', before: a, after: b }];
  }
  return [{ path, kind: 'type-changed', before: a, after: b }];
}

// ---- capture ---------------------------------------------------------------------------------------------------------------

const imp = async (root, rel) => import(pathToFileURL(join(root, 'scanner', rel)).href);

function cliExit(root, args) {
  const r = spawnSync(process.execPath, [join(root, 'scanner', 'bin', 'agentic-security.js'), ...args], { cwd: join(root, 'scanner'), encoding: 'utf8', timeout: 5 * 60 * 1000, env: { ...process.env, NO_COLOR: '1', AGENTIC_SECURITY_LLM_ENDPOINT: '' } });
  return r.status;
}

export async function captureContract(root = REPO_ROOT) {
  const fixture = (n) => join(root, 'scanner', 'test', 'fixtures', n);
  const surfaces = {};

  const { runScan } = await imp(root, 'src/runScan.js');
  const report = await imp(root, 'src/report/index.js');
  const { scan } = await runScan(fixture('vulnerable-js'));
  const json = report.toJSON(scan);
  surfaces.scanJson = { shape: shapeOf(json) };
  const findings = report.normalizeFindings(scan);
  surfaces.findingsRequired = ['id', 'severity', 'file', 'line', 'vuln', 'cwe', 'description', 'remediation', 'parser', 'family'].filter((k) => findings.every((f) => f[k] !== undefined));
  surfaces.severityVocabulary = [...new Set(findings.map((f) => f.severity))].sort();

  const sh = await imp(root, 'src/pipeline/scan-health.js');
  const healthIn = { scanMeta: { filesScanned: 10, filesSkipped: 0, filesDenseSkipped: 0, filesTimedOut: 0, checkpoint: { total: 10 } }, annotatorErrors: [], engineErrors: { cppDataflowParseErrors: 0 }, deepStatus: { requested: true, enabled: true, inCi: false, ciOverrideAllowed: false, reason: null, failure: null } };
  const health = sh.computeScanHealth(healthIn);
  surfaces.scanHealth = { schemaVersion: sh.SCAN_HEALTH_SCHEMA_VERSION, shape: shapeOf(health), statusWhenClean: health.status };
  const partial = sh.computeScanHealth({ ...healthIn, scanMeta: { ...healthIn.scanMeta, filesTimedOut: 1 } });
  surfaces.scanHealth.statusWhenAFileTimedOut = partial.status;

  const am = await imp(root, 'src/pipeline/assurance-mode.js');
  const mk = (over) => ({ status: 'complete', conditions: [], analyzers: { expected: 10, completed: 10, failed: 0, timedOut: 0, skippedByPolicy: 0 }, ...over });
  const cases = { clean: mk({}), analyzerFailed: mk({ status: 'partial', analyzers: { expected: 10, completed: 9, failed: 1, timedOut: 0, skippedByPolicy: 0 } }), analyzerTimedOut: mk({ status: 'partial', analyzers: { expected: 10, completed: 9, failed: 0, timedOut: 1, skippedByPolicy: 0 } }), analyzerSkipped: mk({ analyzers: { expected: 10, completed: 9, failed: 0, timedOut: 0, skippedByPolicy: 1 } }) };
  const verdicts = {};
  for (const mode of am.ASSURANCE_MODES) for (const [name, h] of Object.entries(cases)) {
    const v = am.evaluateAssuranceMode(mode, h);
    (verdicts[mode] ||= {})[name] = v.ok;
  }
  surfaces.assuranceModes = { modes: [...am.ASSURANCE_MODES], default: am.DEFAULT_ASSURANCE_MODE, verdictShape: shapeOf(am.evaluateAssuranceMode('strict', cases.analyzerFailed)), okByModeAndCase: verdicts };

  surfaces.cliExitCodes = {
    scanClean: cliExit(root, ['scan', fixture('clean-js')]),
    scanVulnerable: cliExit(root, ['scan', fixture('vulnerable-js')]),
    ciStrictClean: cliExit(root, ['ci', fixture('clean-js'), '--assurance', 'strict']),
    ciStrictVulnerable: cliExit(root, ['ci', fixture('vulnerable-js'), '--assurance', 'strict']),
  };

  const tools = await imp(root, 'src/mcp/tools.js');
  surfaces.mcpTools = tools.ALL_TOOLS.map((t) => ({ name: t.name, required: [...(t.inputSchema?.required || [])].sort(), properties: Object.fromEntries(Object.entries(t.inputSchema?.properties || {}).map(([k, v]) => [k, v.type || 'any']).sort()) })).sort((a, b) => (a.name < b.name ? -1 : 1));

  const fv = await imp(root, 'src/posture/fix-verify.js');
  const tmp = mkdtempSync(join(os.tmpdir(), 'ee-contract-'));
  try {
    writeFileSync(join(tmp, 'package.json'), '{"name":"c","scripts":{"test":"exit 0"}}');
    const verdict = await fv.verifyFix({ scanRoot: tmp, originalFindingStableId: 'no-such-id', files: { 'a.js': 'export const a = 1;\n' } });
    surfaces.verifyFix = { shape: shapeOf(verdict), ok: verdict.ok };
  } finally { rmSync(tmp, { recursive: true, force: true }); }

  const prov = await imp(root, 'src/posture/provenance/schema.js');
  surfaces.findingProvenance = { statuses: Object.values(prov.PROVENANCE_STATUS).sort(), emptyShape: shapeOf(prov.emptyProvenance()) };

  const eb = await imp(root, 'src/posture/evidence-bundle.js');
  const keyDir = mkdtempSync(join(os.tmpdir(), 'ee-contract-key-'));
  try {
    const kp = eb.ensureKeyPair(keyDir);
    const finding = { id: 'f1', stableId: 's1', severity: 'high', file: 'app.js', line: 42, vuln: 'SQL Injection', cwe: 'CWE-89', family: 'injection', parser: 'IR-TAINT', proofTier: 'execution-proven', proofEvidence: { ran: true, observed: 'PROVEN', backend: 'userspace' } };
    const bundle = eb.signEvidenceBundle(eb.buildEvidenceBundle(finding, { engineVersion: '0.0.0', bundleSha: 'abc' }), kp.privateKeyPem);
    const ok = eb.verifyEvidenceBundle(bundle, kp.publicKeyPem);
    const tampered = JSON.parse(JSON.stringify(bundle));
    (tampered.finding || tampered.evidence || tampered).severity = 'critical';
    if (tampered.finding) tampered.finding.severity = 'critical';
    const bad = eb.verifyEvidenceBundle(tampered, kp.publicKeyPem);
    surfaces.evidenceBundle = { schema: eb.BUNDLE_SCHEMA, shape: shapeOf(bundle), verifiesWhenIntact: !!(ok && (ok.valid ?? ok.ok ?? ok)), rejectsWhenTampered: !(bad && (bad.valid ?? bad.ok ?? bad)) };
  } finally { rmSync(keyDir, { recursive: true, force: true }); }

  const oscal = await imp(root, 'src/report/oscal.js');
  surfaces.oscal = { shape: shapeOf(oscal.toOSCAL(scan, { generatedAt: '2026-01-01T00:00:00.000Z' })) };

  const pkg = JSON.parse(readFileSync(join(root, 'scanner', 'package.json'), 'utf8'));
  return { schemaVersion: 1, capturedAtVersion: pkg.version, surfaces };
}

// ---- comparison and storage -------------------------------------------------------------------------------------------------

/** Compare two captured contracts. Returns { breaking: [...], additive: [...] }. */
export function compareContracts(before, after) {
  const breaking = []; const additive = [];
  const note = (surface, d) => (d.kind === 'added' ? additive : breaking).push({ surface, ...d });
  const walk = (path, a, b) => {
    if (JSON.stringify(a) === JSON.stringify(b)) return;
    const isShape = (x) => x && typeof x === 'object' && ('object' in x || 'array' in x);
    if (isShape(a) && isShape(b)) { for (const d of diffShapes(a, b, path)) note(path.split('.')[0], d); return; }
    if (Array.isArray(a) && Array.isArray(b) && a.every((x) => typeof x === 'string') && b.every((x) => typeof x === 'string')) {
      for (const x of a) if (!b.includes(x)) breaking.push({ surface: path, path, kind: 'removed', detail: `vocabulary entry ${JSON.stringify(x)} is gone` });
      for (const x of b) if (!a.includes(x)) additive.push({ surface: path, path, kind: 'added', detail: `vocabulary entry ${JSON.stringify(x)} is new` });
      return;
    }
    if (Array.isArray(a) && Array.isArray(b) && a.every((x) => x && typeof x === 'object' && 'name' in x)) {
      const bn = new Map(b.map((x) => [x.name, x])); const an = new Map(a.map((x) => [x.name, x]));
      for (const [n, x] of an) { if (!bn.has(n)) breaking.push({ surface: path, path: `${path}.${n}`, kind: 'removed', detail: 'tool removed' }); else walk(`${path}.${n}`, x, bn.get(n)); }
      for (const n of bn.keys()) if (!an.has(n)) additive.push({ surface: path, path: `${path}.${n}`, kind: 'added', detail: 'tool added' });
      return;
    }
    if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
      for (const k of Object.keys(a)) { if (!(k in b)) breaking.push({ surface: path.split('.')[0], path: `${path}.${k}`, kind: 'removed' }); else walk(`${path}.${k}`, a[k], b[k]); }
      for (const k of Object.keys(b)) if (!(k in a)) additive.push({ surface: path.split('.')[0], path: `${path}.${k}`, kind: 'added' });
      return;
    }
    breaking.push({ surface: path.split('.')[0], path, kind: 'value-changed', before: a, after: b });
  };
  for (const k of new Set([...Object.keys(before.surfaces), ...Object.keys(after.surfaces)])) {
    if (!(k in after.surfaces)) breaking.push({ surface: k, path: k, kind: 'removed', detail: 'surface no longer captured' });
    else if (!(k in before.surfaces)) additive.push({ surface: k, path: k, kind: 'added' });
    else walk(k, before.surfaces[k], after.surfaces[k]);
  }
  return { breaking, additive };
}

export function loadSnapshot(root = REPO_ROOT) {
  const p = join(root, SNAPSHOT_REL);
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, 'utf8'));
}

export function writeSnapshot(root, capture, { acceptBreaking = null, previous = null } = {}) {
  const history = [...(previous?.history || [])];
  if (acceptBreaking) history.push({ at: new Date().toISOString(), version: capture.capturedAtVersion, acceptedBreakingChange: String(acceptBreaking).slice(0, 400) });
  const p = join(root, SNAPSHOT_REL);
  mkdirSync(dirname(p), { recursive: true });
  atomicWriteJson(p, { ...capture, history });
}

const arg = (a, k) => { const i = a.indexOf(k); return i >= 0 ? a[i + 1] : null; };
if (import.meta.url === `file://${process.argv[1]}`) {
  const a = process.argv.slice(2);
  const root = a.includes('--root') ? resolve(arg(a, '--root')) : REPO_ROOT;
  (async () => {
    const cap = await captureContract(root);
    if (a.includes('--print')) { console.log(JSON.stringify(cap, null, 2)); return 0; }
    const snap = loadSnapshot(root);
    const diff = snap ? compareContracts(snap, cap) : { breaking: [], additive: [] };
    if (a.includes('--update')) {
      if (diff.breaking.length && !a.includes('--accept-breaking')) { console.error(`refusing to update: ${diff.breaking.length} breaking change(s):\n${diff.breaking.map((d) => `  ${d.path} ${d.kind}`).join('\n')}\nre-run with --accept-breaking "reason" if this is intended and versioned`); return 1; }
      writeSnapshot(root, cap, { acceptBreaking: arg(a, '--accept-breaking'), previous: snap });
      console.log(`contract snapshot written (${diff.additive.length} additive change(s) folded in)`);
      return 0;
    }
    if (!snap) { console.error('no contract snapshot; run with --update'); return 1; }
    for (const d of diff.additive) console.log(`additive: ${d.path} ${d.detail || ''}`);
    for (const d of diff.breaking) console.error(`BREAKING: ${d.path} ${d.kind} ${d.detail || ''}`);
    if (!diff.breaking.length) console.log(`contract holds (${diff.additive.length} additive change(s) not yet in the snapshot)`);
    return diff.breaking.length ? 1 : 0;
  })().then((c) => process.exit(c)).catch((e) => { console.error(`contract failed: ${e.stack || e.message}`); process.exit(2); });
}
