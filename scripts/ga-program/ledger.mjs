#!/usr/bin/env node
// The GA programme's acceptance ledger (AGENTIC_SECURITY_CURRENT_CAPABILITIES_GA_PLAN.PRD, sections 4, 5 and 8): one machine-readable record per
// capability, generated into a readable status page. Nothing here promotes a capability; docs/capabilities.yaml stays the only maturity source.
//
//   node scripts/ga-program/ledger.mjs --check       validate the ledger, the inventory and the status page; exit 1 on any finding
//   node scripts/ga-program/ledger.mjs --render      write docs/ga-program/status.json and docs/ga-program/STATUS.md
//   node scripts/ga-program/ledger.mjs --milestone   print the all-GA milestone verdict and every unmet reason; exit 1 unless met
//   node scripts/ga-program/ledger.mjs --json        print the evaluated model
//
// Two record kinds. A MECHANICAL record's status is computed here from committed artifacts (the registry, the scorecard, the independent
// record, the source tree) and is never typed by hand. A MANUAL record keeps the status the ledger declares, and `passed` is accepted only
// with a source commit, a command and an evidence path that exists; one older than program.evidenceReviewDays is reported stale and is not
// counted as passed. Skipped, stale, unavailable, insufficient and unmeasured are never counted as passed for required scope.
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRegistry, checkGaBar } from '../check-positioning-docs.mjs';
import { buildInventory, surfaceKey, INVENTORY_FILE } from './inventory.mjs';
import { checkClaims, collectFacts } from '../engineering-excellence/inventory.mjs';
import { evaluate as realcodeEvaluate, loadBaseline, latestRunId } from '../../bench/independent/realcode.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(HERE, '..', '..');
export const LEDGER_FILE = 'docs/ga-program/ledger.json';
export const STATUS_JSON = 'docs/ga-program/status.json';
export const STATUS_MD = 'docs/ga-program/STATUS.md';
const ALLOWED = ['not-started', 'in-progress', 'blocked', 'failed', 'passed', 'not-applicable'];
const read = (repo, rel) => readFileSync(path.join(repo, rel), 'utf8');
const readJson = (repo, rel) => (existsSync(path.join(repo, rel)) ? JSON.parse(read(repo, rel)) : null);
const readJsonAbs = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : null);

export function loadLedger(repo = REPO) { return JSON.parse(read(repo, LEDGER_FILE)); }

// ── mechanical checks ──────────────────────────────────────────────────────────────────────────────────────────────────────
// Each returns { status, detail, evidence } for one capability; status is one of ALLOWED.

function registryGaBar(ctx, cap) {
  const row = ctx.registry.capabilities.find((c) => c.id === cap.capabilityId);
  if (!row) return { status: 'failed', detail: 'not in docs/capabilities.yaml' };
  const findings = ctx.barFindings.filter((f) => String(f.message || '').startsWith(`${cap.capabilityId}:`)).map((f) => f.message);
  if (row.maturity === 'GA') return findings.length ? { status: 'failed', detail: findings.join('; ') } : { status: 'passed', detail: `GA bar met (since ${row.since}, gate ${row.gate})`, evidence: 'docs/capabilities.yaml' };
  const missing = ['contract', 'contractTest', 'gate', 'limits', 'since', 'platforms'].filter((k) => !row[k]);
  return { status: 'not-started', detail: `${row.maturity} row; the GA bar still needs ${missing.join(', ') || 'nothing but the promotion itself'}${findings.length ? `; ${findings.join('; ')}` : ''}` };
}

function evidenceIdentity(ctx) {
  const sc = ctx.scorecard;
  if (!sc) return { status: 'blocked', detail: 'docs/scorecard.json is missing' };
  const prov = sc.provenance || {}; const meas = sc.measurement || {};
  const problems = [];
  if (prov.worktreeClean !== true) problems.push('the scorecard was measured on a dirty worktree');
  if (meas.cleanMeasurement !== true) problems.push('the scorecard does not record a clean measurement');
  if (meas.engineVersion !== ctx.version) problems.push(`the scorecard describes engine ${meas.engineVersion}, the tree is ${ctx.version}`);
  if (!/^[0-9a-f]{40}$/.test(String(prov.commit || ''))) problems.push('no source commit recorded');
  if (!/^[0-9a-f]{64}$/.test(String(prov.bundleSha256 || ''))) problems.push('no bundle digest recorded');
  return problems.length ? { status: 'failed', detail: problems.join('; ') } : { status: 'passed', detail: `clean measurement of ${meas.engineVersion} at ${String(prov.commit).slice(0, 12)}, bundle ${String(prov.bundleSha256).slice(0, 12)}`, evidence: 'docs/scorecard.json' };
}

function independentAccuracyCurrent(ctx) {
  // The latest finished run in bench/independent/runs/, judged against the APPROVED floors by realcode.mjs's own evaluate(): the verdict is
  // computed here, never read from BASELINE.json (which records the approved run and its floors, not a verdict).
  const { runId, run, verdict } = ctx.realcode || {};
  if (!run) return { status: 'blocked', detail: 'no independent run has been recorded in bench/independent/runs/' };
  const problems = [];
  if (run.engineVersion !== ctx.version) problems.push(`the latest independent run (${runId}) measured engine ${run.engineVersion}, not ${ctx.version} (historical)`);
  const id = run.identity || {};
  if (id.measurementValid !== true) problems.push(`the run's measurement is not valid${(id.invalidReasons || []).length ? `: ${id.invalidReasons.join(', ')}` : ''}`);
  if (!/^[0-9a-f]{40}$/.test(String(id.sourceCommit || ''))) problems.push('no source commit in the run identity');
  if (!/^[0-9a-f]{64}$/.test(String(id.bundleSha256 || ''))) problems.push('no bundle digest in the run identity');
  if (verdict.status !== 'passed') problems.push(`the release-tier real-code verdict is ${verdict.status}: ${verdict.why}`);
  const evidence = `bench/independent/runs/${runId}/RESULT.json`;
  return problems.length ? { status: 'blocked', detail: problems.join('; ') } : { status: 'passed', detail: `independent run ${runId} on ${run.engineVersion} at ${String(id.sourceCommit).slice(0, 12)}; release-tier verdict passed: ${verdict.why}`, evidence };
}

/** The latest finished independent run and its release-tier verdict against the approved floors. */
function realcodeContext(runsDir) {
  const runId = latestRunId(runsDir);
  const run = runId ? readJsonAbs(path.join(runsDir, runId, 'RESULT.json')) : null;
  const base = loadBaseline(runsDir);
  return { runId, run, verdict: realcodeEvaluate({ floors: base ? base.floors : null, current: run, tier: 'release' }) };
}

/**
 * Every file that sends a prompt to a model endpoint must evaluate the egress policy or go through the shared bounded call. A candidate is
 * a file whose CODE lines (comment lines skipped) call `fetch(` and mention a prompt or messages; `program.nonModelFetch` exempts a
 * candidate whose fetch sends no prompt (a dashboard polling itself, a transport invoked only after the caller's policy check), each with
 * a reason the ledger check requires.
 */
export function modelCallSites(repo = REPO, exempt = {}) {
  const out = [];
  const code = (text) => text.split('\n').filter((l) => { const t = l.trim(); return !(t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')); }).join('\n');
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'node_modules' || e.name === 'dist' || e.name === 'vendor' || e.name.startsWith('.')) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(?:m?js|cjs)$/.test(e.name) && !/\.test\.m?js$/.test(e.name)) {
        const text = code(readFileSync(p, 'utf8'));
        if (!/\b(?:fetch|modelFetch|guardedModelCall)\s*\(/.test(text) || !/\b(?:prompt|messages)\b/.test(text)) continue;
        const rel = path.relative(repo, p);
        const guarded = /\bguardedModelCall\s*\(/.test(text) || /\bevaluateEgress\s*\(/.test(text) || /\bresolveLlmInvokeWithDecision\s*\(/.test(text);
        // GA-06.3: a model site also sends through the shared transport (no redirect, capped reply, deadline), never a bare fetch
        const bareFetch = /(?<![.\w])fetch\s*\(/.test(text) && rel !== path.join('scanner', 'src', 'egress', 'transport.js');
        const bounded = /\bmodelFetch\s*\(/.test(text) || /\bguardedModelCall\s*\(/.test(text);
        out.push({ file: rel, guarded, bounded: bounded && !bareFetch, exempt: exempt[rel] || null });
      }
    }
  };
  for (const root of ['scanner/src', 'scanner/bin', 'scripts', 'hooks']) if (existsSync(path.join(repo, root))) walk(path.join(repo, root));
  return out.sort((a, b) => (a.file < b.file ? -1 : 1));
}

function egressAllModelPaths(ctx) {
  const sites = modelCallSites(ctx.repo, ctx.ledger.program.nonModelFetch || {});
  const bad = sites.filter((s) => !s.guarded && !s.exempt);
  const unbounded = sites.filter((s) => s.guarded && !s.bounded && !s.exempt);
  if (bad.length) return { status: 'failed', detail: `${bad.length} model-call site(s) bypass the egress policy: ${bad.map((s) => s.file).join(', ')}`, evidence: null };
  if (unbounded.length) return { status: 'failed', detail: `${unbounded.length} model-call site(s) send through a bare fetch instead of the shared transport: ${unbounded.map((s) => s.file).join(', ')}`, evidence: null };
  return { status: 'passed', detail: `${sites.filter((s) => s.guarded).length} model-call site(s) evaluate the policy and send through the shared transport; ${sites.filter((s) => s.exempt).length} exempt with a reason`, evidence: 'scripts/ga-program/ledger.mjs (modelCallSites)' };
}

const MECHANICAL = { 'registry-ga-bar': registryGaBar, 'evidence-identity': evidenceIdentity, 'independent-accuracy-current': independentAccuracyCurrent, 'egress-all-model-paths': egressAllModelPaths };

// ── evaluation ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

function manualStatus(ctx, rec) {
  if (rec.status === 'passed') {
    const problems = [];
    if (!/^[0-9a-f]{40}$/.test(String(rec.sourceCommit || ''))) problems.push('no source commit');
    if (!rec.command) problems.push('no command');
    if (!rec.evidencePath) problems.push('no evidence path');
    else if (!existsSync(path.join(ctx.repo, rec.evidencePath))) problems.push(`evidence path ${rec.evidencePath} does not exist`);
    if (!rec.recordedAt || Number.isNaN(Date.parse(rec.recordedAt))) problems.push('no recordedAt date');
    if (problems.length) return { status: 'failed', detail: `declared passed without evidence: ${problems.join(', ')}`, invalid: true };
    const ageDays = (ctx.now - Date.parse(rec.recordedAt)) / 86400000;
    if (ageDays > ctx.ledger.program.evidenceReviewDays) return { status: 'in-progress', detail: `evidence recorded ${Math.floor(ageDays)} days ago, past the ${ctx.ledger.program.evidenceReviewDays} day review window: stale, not counted as passed`, stale: true };
    return { status: 'passed', detail: `${rec.command} (exit ${rec.exitCode}) at ${String(rec.sourceCommit).slice(0, 12)}: ${rec.evidencePath}`, evidence: rec.evidencePath };
  }
  if (rec.status === 'not-applicable') return String(rec.reason || '').length >= 30 ? { status: 'not-applicable', detail: rec.reason } : { status: 'failed', detail: 'not-applicable needs a reviewed reason of at least 30 characters', invalid: true };
  return { status: rec.status, detail: rec.blocker || rec.detail || '' };
}

function evaluateRecords(ctx, owner, records) {
  return records.map((rec) => {
    const base = { id: rec.id, kind: rec.kind, workstream: rec.workstream || null, requirement: rec.requirement };
    if (rec.kind === 'mechanical') {
      const fn = MECHANICAL[rec.check];
      if (!fn) return { ...base, status: 'failed', detail: `unknown mechanical check ${rec.check}`, invalid: true };
      const r = fn(ctx, owner);
      return { ...base, check: rec.check, status: r.status, detail: r.detail, evidencePath: r.evidence || null };
    }
    const r = manualStatus(ctx, rec);
    return { ...base, status: r.status, detail: r.detail, evidencePath: r.evidence || null, blocker: rec.blocker || null, ...(r.invalid ? { invalid: true } : {}), ...(r.stale ? { stale: true } : {}) };
  });
}

function rollup(records) {
  const required = records.filter((r) => r.status !== 'not-applicable');
  const passed = required.filter((r) => r.status === 'passed').length;
  let status = 'passed';
  if (passed !== required.length) {
    if (required.some((r) => r.status === 'failed')) status = 'failed';
    else if (required.some((r) => r.status === 'blocked')) status = 'blocked';
    else if (required.every((r) => r.status === 'not-started')) status = 'not-started';
    else status = 'in-progress';
  }
  return { status, passed, required: required.length };
}

/**
 * Evaluate the ledger against the committed artifacts. `overrides.ledger` and `overrides.inventory` replace the committed files (the
 * tests use them to fabricate a defect without touching the tree); everything else is read from `repo`.
 */
export function evaluate(repo = REPO, { now = Date.now(), ledger: ledgerOverride = null, inventory: inventoryOverride = null, runsDir = path.join(repo, 'bench', 'independent', 'runs') } = {}) {
  const ledger = ledgerOverride || loadLedger(repo);
  const registry = loadRegistry(repo);
  const version = JSON.parse(read(repo, 'scanner/package.json')).version;
  const ctx = { repo, ledger, registry, version, now, barFindings: checkGaBar(registry, repo), scorecard: readJson(repo, 'docs/scorecard.json'), realcode: realcodeContext(runsDir) };
  const capabilities = ledger.capabilities.map((cap) => {
    const row = registry.capabilities.find((c) => c.id === cap.capabilityId) || {};
    const records = evaluateRecords(ctx, cap, cap.acceptance);
    const r = rollup(records);
    const next = records.find((x) => x.status !== 'passed' && x.status !== 'not-applicable');
    return { capabilityId: cap.capabilityId, registryMaturity: row.maturity || null, baselineMaturity: cap.baselineMaturity, targetMaturity: cap.targetMaturity, owner: cap.owner, ownerAssigned: !!(cap.owner && cap.owner.person), workstreams: cap.workstreams, ...r, records, nextAction: next ? `${next.id}: ${next.detail || next.requirement}` : 'all required records passed' };
  });
  const subcapabilities = (ledger.subcapabilities || []).map((s) => { const records = evaluateRecords(ctx, s, s.acceptance); return { id: s.id, parent: s.parent, title: s.title, ...rollup(records), records }; });
  const byWorkstream = Object.fromEntries(Object.entries(ledger.program.workstreams).map(([id, w]) => {
    const recs = [...capabilities, ...subcapabilities].flatMap((c) => c.records.filter((r) => r.workstream === id));
    const required = recs.filter((r) => r.status !== 'not-applicable');
    return [id, { title: w.title, accountableRole: w.accountableRole, required: required.length, passed: required.filter((r) => r.status === 'passed').length, blocked: required.filter((r) => r.status === 'blocked' || r.status === 'failed').length }];
  }));
  const ga = capabilities.filter((c) => c.registryMaturity === 'GA');
  const verifiedGa = ga.filter((c) => c.status === 'passed').length;
  const meas = (ctx.scorecard && ctx.scorecard.measurement) || {};
  const run = meas.independentRun || null;
  const realCode = run ? { label: run.historical ? 'historical (not this engine)' : 'current', engineVersion: run.engine || run.engineVersion || null, measuredAt: run.measuredAt || null, sourceCommit: run.identity && run.identity.sourceCommit || null, bundleSha256: run.identity && run.identity.bundleSha256 || null, denominators: run.denominators || null, headline: run.headline || null, currentEngineIndependentAccuracy: meas.currentEngineIndependentAccuracy || null } : null;
  const inventory = inventoryOverride || readJson(repo, INVENTORY_FILE);
  const orphans = inventory ? inventory.surfaces.map(surfaceKey).filter((k) => !ledger.surfaces[k]) : [];
  const model = {
    schema: 'agentic-security/ga-program-status@1',
    engineVersion: version,
    program: { baselineCapabilities: ledger.program.baselineCapabilities, capabilitiesInLedger: capabilities.length, verifiedGa, registryGa: ga.length, promotionCandidatesRemaining: capabilities.filter((c) => c.registryMaturity !== 'GA').length, ownersUnassigned: capabilities.filter((c) => !c.ownerAssigned).length, milestoneDeclared: !!ledger.program.milestone.declared },
    records: { required: capabilities.reduce((n, c) => n + c.required, 0) + subcapabilities.reduce((n, c) => n + c.required, 0), passed: capabilities.reduce((n, c) => n + c.passed, 0) + subcapabilities.reduce((n, c) => n + c.passed, 0) },
    realCodeAccuracy: realCode,
    surfaces: { inventoried: inventory ? inventory.counts.surfaces : null, mapped: Object.keys(ledger.surfaces).length, orphans },
    byWorkstream,
    capabilities,
    subcapabilities,
  };
  model.milestone = milestoneReasons(model, ctx);
  return model;
}

function milestoneReasons(model, ctx) {
  const reasons = [];
  for (const c of model.capabilities) {
    if (c.status !== 'passed') reasons.push(`${c.capabilityId}: ${c.passed}/${c.required} acceptance records passed (${c.status}); next: ${c.nextAction}`);
    if (!c.ownerAssigned) reasons.push(`${c.capabilityId}: owner unassigned (role ${c.owner && c.owner.role})`);
  }
  for (const s of model.subcapabilities) if (s.status !== 'passed') reasons.push(`subcapability ${s.id} (${s.parent}): ${s.passed}/${s.required} passed (${s.status})`);
  for (const k of model.surfaces.orphans) reasons.push(`orphan shipped surface ${k}: no capability owns it`);
  if (model.surfaces.inventoried === null) reasons.push(`${INVENTORY_FILE} is missing`);
  const cs = readJson(ctx.repo, 'docs/completion-status.json');
  if (!cs) reasons.push('docs/completion-status.json is missing');
  else if (cs.requirements && cs.requirements.verified !== cs.requirements.total) reasons.push(`completion status is ${cs.requirements.verified}/${cs.requirements.total}`);
  const rc = model.realCodeAccuracy;
  if (!rc || rc.label !== 'current' || rc.currentEngineIndependentAccuracy === 'unmeasured') reasons.push('no current-engine independent accuracy record (the scorecard says unmeasured; the independent record is historical)');
  return { met: reasons.length === 0, reasons };
}

// ── validation (the ledger itself) ─────────────────────────────────────────────────────────────────────────────────────────

/**
 * Every finding about the ledger, the inventory and the status page, as strings. `overrides` (tests only) replaces the committed ledger
 * or inventory; with an override the committed status page is of course stale, so those findings are reported as usual and the test
 * filters for the defect it fabricated.
 */
export function validateLedger(repo = REPO, { ledger: ledgerOverride = null, inventory: inventoryOverride = null, now = Date.now() } = {}) {
  const out = [];
  const say = (m) => out.push(m);
  let ledger; try { ledger = ledgerOverride || loadLedger(repo); } catch (e) { return [`${LEDGER_FILE}: ${e.message}`]; }
  const registry = loadRegistry(repo);
  if (ledger.schema !== 'agentic-security/ga-program-ledger@1') say('unknown ledger schema');
  const p = ledger.program || {};
  if (!p.workstreams || !p.milestone || typeof p.milestone.declared !== 'boolean' || !(p.evidenceReviewDays > 0)) say('program block needs workstreams, milestone.declared and evidenceReviewDays');
  const shipped = registry.capabilities.filter((c) => c.maturity !== 'Roadmap').map((c) => c.id);
  const ids = (ledger.capabilities || []).map((c) => c.capabilityId);
  for (const id of shipped) if (!ids.includes(id)) say(`registry capability ${id} (${registry.capabilities.find((c) => c.id === id).maturity}) has no ledger entry`);
  for (const id of ids) { if (!shipped.includes(id)) say(`ledger entry ${id} is not a shipped registry capability`); if (ids.filter((x) => x === id).length > 1) say(`duplicate ledger entry ${id}`); }
  if (p.baselineCapabilities !== shipped.length) say(`program.baselineCapabilities is ${p.baselineCapabilities}, the registry ships ${shipped.length}`);
  const recordIds = new Set();
  const checkRecords = (ownerId, records, workstreams) => {
    for (const r of records || []) {
      if (!r.id || recordIds.has(r.id)) say(`${ownerId}: record id ${r.id || '(missing)'} is missing or duplicated`); recordIds.add(r.id);
      if (!r.requirement) say(`${ownerId}/${r.id}: no requirement text`);
      if (r.kind === 'mechanical') { if (!MECHANICAL[r.check]) say(`${ownerId}/${r.id}: unknown mechanical check ${r.check}`); if (r.status) say(`${ownerId}/${r.id}: a mechanical record must not declare a status`); continue; }
      if (r.kind !== 'manual') { say(`${ownerId}/${r.id}: kind must be mechanical or manual`); continue; }
      if (!ALLOWED.includes(r.status)) say(`${ownerId}/${r.id}: status ${r.status} is not one of ${ALLOWED.join(', ')}`);
      if (r.workstream && !p.workstreams[r.workstream]) say(`${ownerId}/${r.id}: unknown workstream ${r.workstream}`);
      if (r.workstream && workstreams && !workstreams.includes(r.workstream)) say(`${ownerId}/${r.id}: workstream ${r.workstream} is not listed on the entry`);
      if ((r.status === 'blocked' || r.status === 'failed') && !r.blocker) say(`${ownerId}/${r.id}: ${r.status} needs a blocker`);
    }
  };
  for (const c of ledger.capabilities || []) {
    const row = registry.capabilities.find((x) => x.id === c.capabilityId);
    if (row && c.baselineMaturity !== row.maturity) say(`${c.capabilityId}: baselineMaturity ${c.baselineMaturity} differs from the registry (${row.maturity}); the ledger never moves maturity, update the baseline when the registry changes`);
    if (c.targetMaturity !== 'GA') say(`${c.capabilityId}: targetMaturity must be GA`);
    if (!c.owner || !c.owner.role) say(`${c.capabilityId}: owner.role is required (person may be null)`);
    for (const w of c.workstreams || []) if (!p.workstreams[w]) say(`${c.capabilityId}: unknown workstream ${w}`);
    checkRecords(c.capabilityId, c.acceptance, c.workstreams);
  }
  for (const s of ledger.subcapabilities || []) { if (!ids.includes(s.parent)) say(`subcapability ${s.id}: parent ${s.parent} is not a ledger capability`); checkRecords(`subcapability ${s.id}`, s.acceptance, null); }
  const targets = new Set([...ids, ...(ledger.subcapabilities || []).map((s) => s.id)]);
  for (const [k, v] of Object.entries(ledger.surfaces || {})) if (!v || !targets.has(v.to)) say(`surface ${k} maps to ${v && v.to}, which is neither a ledger capability nor a subcapability`);
  // the inventory: committed, fresh, and every surface mapped
  const fresh = inventoryOverride || buildInventory(repo);
  const committed = inventoryOverride || readJson(repo, INVENTORY_FILE);
  if (!committed) say(`${INVENTORY_FILE} is missing: run node scripts/ga-program/inventory.mjs --write`);
  else if (JSON.stringify(committed) !== JSON.stringify(fresh)) say(`${INVENTORY_FILE} is stale: run node scripts/ga-program/inventory.mjs --write`);
  const keys = new Set(fresh.surfaces.map(surfaceKey));
  for (const k of keys) if (!(ledger.surfaces || {})[k]) say(`orphan shipped surface ${k}: map it to a capability or a tracked subcapability in ${LEDGER_FILE}`);
  for (const k of Object.keys(ledger.surfaces || {})) if (!keys.has(k)) say(`surface ${k} is mapped but no longer shipped: remove it from ${LEDGER_FILE}`);
  for (const [file, reason] of Object.entries(p.nonModelFetch || {})) { if (!existsSync(path.join(repo, file))) say(`nonModelFetch names ${file}, which does not exist`); if (String(reason).length < 30) say(`nonModelFetch ${file}: the reason must say why this fetch sends no prompt (30+ characters)`); }
  // evaluated records that are invalid (a passed record without evidence) are findings too
  const model = evaluate(repo, { now, ledger: ledgerOverride, inventory: inventoryOverride });
  for (const c of [...model.capabilities, ...model.subcapabilities]) for (const r of c.records) if (r.invalid) say(`${c.capabilityId || c.id}/${r.id}: ${r.detail}`);
  // documented counts that the checkout can be asked about (MCP tools, dispatchers, versions) must match the code
  for (const claim of checkClaims(repo, collectFacts(repo))) if (!claim.ok) say(`${claim.doc}: ${claim.claim} says ${claim.expected}, the checkout has ${claim.actual}`);
  // the status page must be what the ledger renders
  const { json, md } = render(model);
  const curJson = existsSync(path.join(repo, STATUS_JSON)) ? read(repo, STATUS_JSON) : null;
  const curMd = existsSync(path.join(repo, STATUS_MD)) ? read(repo, STATUS_MD) : null;
  if (curJson !== json || curMd !== md) say(`${STATUS_MD} / ${STATUS_JSON} are stale: run node scripts/ga-program/ledger.mjs --render`);
  return out;
}

// ── rendering ──────────────────────────────────────────────────────────────────────────────────────────────────────────────

const cell = (s) => String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function render(model) {
  const json = `${JSON.stringify(model, null, 2)}\n`;
  const L = [];
  L.push('# GA programme status');
  L.push('');
  L.push(`Generated by \`node scripts/ga-program/ledger.mjs --render\` from \`docs/ga-program/ledger.json\` at engine ${model.engineVersion}. Do not edit by hand. The plan is AGENTIC_SECURITY_CURRENT_CAPABILITIES_GA_PLAN.PRD; the registry (\`docs/capabilities.yaml\`) stays the only source of maturity, and this page never promotes anything.`);
  L.push('');
  L.push('## Headline');
  L.push('');
  L.push('| | |');
  L.push('|---|---|');
  L.push(`| Shipped capabilities in the baseline | ${model.program.baselineCapabilities} |`);
  L.push(`| Registry GA today | ${model.program.registryGa} |`);
  L.push(`| Verified GA (every required acceptance record passed) | ${model.program.verifiedGa} of ${model.program.baselineCapabilities} |`);
  L.push(`| Promotion candidates remaining | ${model.program.promotionCandidatesRemaining} |`);
  L.push(`| Acceptance records passed / required | ${model.records.passed} / ${model.records.required} |`);
  L.push(`| Owners unassigned | ${model.program.ownersUnassigned} of ${model.program.capabilitiesInLedger} (roles are named; no person is invented) |`);
  L.push(`| Shipped surfaces inventoried / mapped / orphan | ${model.surfaces.inventoried} / ${model.surfaces.mapped} / ${model.surfaces.orphans.length} |`);
  L.push(`| All-GA milestone | ${model.milestone.met ? 'met' : `not met (${model.milestone.reasons.length} named reasons below)`}${model.program.milestoneDeclared ? '; DECLARED in the ledger, so the release check treats every reason as an error' : '; not declared, so the release check reports the reasons as warnings'} |`);
  L.push('');
  L.push('## Current real-code accuracy');
  L.push('');
  const rc = model.realCodeAccuracy;
  if (!rc) L.push('No independent run is recorded in the scorecard.');
  else {
    L.push(`The scorecard's current-engine independent accuracy is **${rc.currentEngineIndependentAccuracy}**. The latest independent run is ${rc.label}: engine ${rc.engineVersion}, measured ${rc.measuredAt}, source commit ${rc.sourceCommit ? rc.sourceCommit.slice(0, 12) : 'not recorded'}, bundle ${rc.bundleSha256 ? rc.bundleSha256.slice(0, 12) : 'not recorded'}.`);
    if (rc.headline) L.push(`Headline of that run: precision ${cell(rc.headline.precision && rc.headline.precision.display || JSON.stringify(rc.headline.precision))}, recall ${cell(rc.headline.recall && rc.headline.recall.display || JSON.stringify(rc.headline.recall))}, F1 ${cell(rc.headline.f1 && (rc.headline.f1.value ?? rc.headline.f1))}; denominators ${cell(JSON.stringify(rc.denominators))}. A historical run cannot satisfy a current-engine gate.`);
  }
  L.push('');
  L.push('## Capabilities');
  L.push('');
  L.push('Status is the rollup of the acceptance records: `passed` only when every required record passed; `failed` when a mechanical check fails or a declared pass has no evidence; `blocked` when a record names a blocker; otherwise `in-progress` or `not-started`. Maturity is the registry\'s and is reported separately.');
  L.push('');
  L.push('| Capability | Maturity | Owner | Status | Passed / required | Next action |');
  L.push('|---|---|---|---|---|---|');
  for (const c of model.capabilities) L.push(`| \`${c.capabilityId}\` | ${c.registryMaturity} | ${c.owner.person || `unassigned (${c.owner.role})`} | ${c.status} | ${c.passed} / ${c.required} | ${cell(c.nextAction)} |`);
  L.push('');
  L.push('## Workstreams');
  L.push('');
  L.push('| Workstream | Accountable role | Records passed / required | Blocked or failed |');
  L.push('|---|---|---|---|');
  for (const [id, w] of Object.entries(model.byWorkstream)) L.push(`| ${id} ${cell(w.title)} | ${cell(w.accountableRole)} | ${w.passed} / ${w.required} | ${w.blocked} |`);
  L.push('');
  L.push('## Tracked subcapabilities (PRD GA-12 surfaces under a parent capability)');
  L.push('');
  L.push('| Subcapability | Parent | Status | Passed / required |');
  L.push('|---|---|---|---|');
  for (const s of model.subcapabilities) L.push(`| \`${s.id}\` ${cell(s.title)} | \`${s.parent}\` | ${s.status} | ${s.passed} / ${s.required} |`);
  L.push('');
  L.push('## Acceptance records');
  L.push('');
  L.push('Mechanical records are computed from committed artifacts; manual records carry the status the ledger declares and are counted as passed only with a source commit, a command and an evidence path that exists, within the review window.');
  L.push('');
  for (const c of model.capabilities) {
    L.push(`### \`${c.capabilityId}\` (${c.registryMaturity}, workstreams ${c.workstreams.join(', ')})`);
    L.push('');
    L.push('| Record | Kind | Workstream | Status | Detail |');
    L.push('|---|---|---|---|---|');
    for (const r of c.records) L.push(`| ${r.id} | ${r.kind} | ${r.workstream || ''} | ${r.status}${r.stale ? ' (stale)' : ''} | ${cell(r.detail || r.requirement)} |`);
    L.push('');
  }
  for (const s of model.subcapabilities) {
    L.push(`### subcapability \`${s.id}\``);
    L.push('');
    L.push('| Record | Kind | Workstream | Status | Detail |');
    L.push('|---|---|---|---|---|');
    for (const r of s.records) L.push(`| ${r.id} | ${r.kind} | ${r.workstream || ''} | ${r.status} | ${cell(r.detail || r.requirement)} |`);
    L.push('');
  }
  L.push('## Milestone reasons');
  L.push('');
  if (model.milestone.met) L.push('Every required acceptance record passed, every surface is owned, every owner is assigned, and the evidence is current.');
  else for (const r of model.milestone.reasons) L.push(`- ${cell(r)}`);
  L.push('');
  return { json, md: `${L.join('\n')}\n` };
}

export function main(argv = process.argv.slice(2)) {
  if (argv.includes('--render')) {
    const model = evaluate(REPO);
    const { json, md } = render(model);
    writeFileSync(path.join(REPO, STATUS_JSON), json); writeFileSync(path.join(REPO, STATUS_MD), md);
    console.log(`wrote ${STATUS_MD} and ${STATUS_JSON}: verified GA ${model.program.verifiedGa}/${model.program.baselineCapabilities}, records ${model.records.passed}/${model.records.required}, milestone ${model.milestone.met ? 'met' : 'not met'}`);
    return 0;
  }
  if (argv.includes('--json')) { process.stdout.write(`${JSON.stringify(evaluate(REPO), null, 2)}\n`); return 0; }
  if (argv.includes('--milestone')) {
    const model = evaluate(REPO);
    console.log(`all-GA milestone: ${model.milestone.met ? 'MET' : 'NOT MET'} (${model.milestone.reasons.length} reasons; declared: ${model.program.milestoneDeclared})`);
    for (const r of model.milestone.reasons) console.log(`  - ${r}`);
    return model.milestone.met ? 0 : 1;
  }
  const findings = validateLedger(REPO);
  if (!findings.length) { console.log(`ga-program: ledger, inventory and status page are consistent (${LEDGER_FILE})`); return 0; }
  console.error(`ga-program: ${findings.length} finding(s):`);
  for (const f of findings) console.error(`  ${f}`);
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(main());
