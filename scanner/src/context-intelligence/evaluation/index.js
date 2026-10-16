//
// `agentic-security context eval`: the frozen synthetic suite, scored.
//
// Honest by construction:
//   * every scorecard says on its face that the suite and the reader are synthetic and that no accuracy claim follows;
//   * intervals come from the repo's existing grouped bootstrap (a case is one group; fewer than 10 groups is "unmeasured");
//   * the holdout split is scored only through a ledger that counts every use, and non-default prompt variants are refused
//     on it unless the run is declared final;
//   * a label-leakage audit checks that neither the corpus nor any prompt a system saw contains the label vocabulary.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256, canonicalJson, hashOf } from '../canonical.js';
import { writeStoreJson, readStoreFile } from '../store.js';
import { groupedBootstrap, wilsonInterval, f1Of, precisionOf, recallOf } from '../../posture/evaluation/interval.js';
import { runCase, SYSTEMS } from './runner.js';
import { readerIdentity } from './scripted-reader.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// The bundled synthetic suite lives in the source tree's fixtures, found from the package root. Scan code must not
// read evaluation labels, so this is reachable only from the explicit `context eval` command, and `--suite-dir` /
// AGENTIC_SECURITY_DCI_EVAL_SUITE can point at any other suite in the same layout.
function packageRoot(from) {
  let dir = from;
  for (let i = 0; i < 8; i++) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    dir = path.dirname(dir);
  }
  return from;
}
export const DEFAULT_SUITE_DIR = process.env.AGENTIC_SECURITY_DCI_EVAL_SUITE
  ? path.resolve(process.env.AGENTIC_SECURITY_DCI_EVAL_SUITE)
  : path.join(packageRoot(HERE), ['test', 'fixtures', 'context-intelligence', 'eval'].join(path.sep));
export const VARIANTS = Object.freeze(['dci', 'dci-all-packs']);
export const FROZEN_VARIANT = 'dci';
const FLAG = (args, k) => (args && args[k] !== undefined ? args[k] : undefined);
const truthy = (v) => v === true || v === 'true' || v === '1';

const LEAK_TERMS = /\b(?:vulnerable|vulnerability|idor|bola|bfla|exploit|insecure|label|holdout|ground.?truth|expected result)\b/i;

function loadSuite(dir) {
  const read = (f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  const labels = read('labels.json');
  const split = read('split.json');
  return { labels, split, dir };
}

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out); else if (e.isFile()) out.push(p);
  }
  return out.sort();
}

function suiteHash(dir) {
  const files = walk(dir).map(f => ({ f: path.relative(dir, f), h: sha256(fs.readFileSync(f)) }));
  return hashOf(files);
}

/** The corpus and every prompt a system saw must not contain the label vocabulary. Returns hits (empty = clean). */
export function leakageAudit(dir, promptsBySystem) {
  const hits = [];
  for (const f of walk(path.join(dir, 'corpus'))) {
    const text = fs.readFileSync(f, 'utf8');
    const m = LEAK_TERMS.exec(text);
    if (m) hits.push({ where: 'corpus', file: path.relative(dir, f), term: m[0] });
  }
  for (const [system, prompts] of Object.entries(promptsBySystem)) {
    for (const p of prompts) {
      const body = String(p);
      const m = /\bc(?:0[1-9]|1[01])\b/.exec(body) || /\bdci-eval\b/.exec(body);
      if (m) { hits.push({ where: `prompt:${system}`, term: m[0] }); break; }
    }
  }
  return hits;
}

function tally(units) {
  const c = { tp: 0, fp: 0, fn: 0, tn: 0 };
  for (const u of units) { c.tp += u.tp; c.fp += u.fp; c.fn += u.fn; c.tn += u.tn; }
  return c;
}

export function metricsFor(units, protocolHash, name) {
  const c = tally(units);
  const groupOf = Object.fromEntries(units.map(u => [u.id, u.caseId]));
  const f1 = groupedBootstrap({ units, groupOf, statistic: ({ total }) => f1Of(total), name: `${name}:f1`, protocolHash });
  const pn = c.tp + c.fp;
  return {
    counts: c, units: units.length,
    precision: precisionOf(c), recall: recallOf(c), f1: f1Of(c),
    precisionInterval: pn > 0 ? wilsonInterval(c.tp, pn) : { status: 'unmeasured', reason: 'nothing was reported' },
    f1Interval: f1,
    // A point estimate with no interval around it reads as a finding. It is reportable only when the interval is measured.
    reportable: f1 && f1.status === 'measured',
  };
}

/** Nearest-rank percentile of a numeric list (null when empty). */
export function percentile(values, q) {
  if (!values.length) return null;
  const v = [...values].sort((a, b) => a - b);
  return v[Math.min(v.length - 1, Math.max(0, Math.ceil(q * v.length) - 1))];
}

/** Context-size, call and cost accounting for one system. Token figures are chars/4 estimates; no price is assumed. */
export function economicsOf({ promptSizes, calls, wallMs, metrics }) {
  const tokens = promptSizes.map(n => Math.ceil(n / 4));
  const tp = metrics.counts.tp;
  return {
    tokenizer: 'chars/4-estimate',
    promptsPerCase: promptSizes.length,
    contextTokens: { median: percentile(tokens, 0.5), p95: percentile(tokens, 0.95), p99: percentile(tokens, 0.99), total: tokens.reduce((a, b) => a + b, 0) },
    modelCalls: calls,
    callsPerTruePositive: tp > 0 ? calls / tp : null,
    wallMs,
    cost: { usd: null, basis: 'no price supplied; calls and estimated tokens are reported instead' },
  };
}

function ledgerPath() { return 'reports/eval-ledger.json'; }
function readLedger(root) {
  const r = readStoreFile(root, ledgerPath());
  if (!r.ok) return { schemaVersion: 'eval-ledger/1', holdoutScoredRuns: 0, devScoredRuns: 0, runs: [] };
  try { return JSON.parse(r.text); } catch { return { schemaVersion: 'eval-ledger/1', holdoutScoredRuns: 0, devScoredRuns: 0, runs: [], note: 'previous ledger unreadable; counts restart' }; }
}

const pct = (x) => (x === null || x === undefined ? 'n/a' : (x * 100).toFixed(0) + '%');
const interval = (i) => (!i || i.status !== 'measured' ? `unmeasured (${i && i.reason ? i.reason.split(',')[0] : 'no data'})` : `${pct(i.low)} to ${pct(i.high)}`);

// Precision, recall and F1 are printed only when their interval is measured; otherwise the counts stand alone.
const shown = (m, x) => (m.reportable ? pct(x) : 'withheld');

export function renderMarkdown(card) {
  const L = [];
  L.push('# Context Intelligence evaluation scorecard', '');
  L.push('> SYNTHETIC SUITE, SCRIPTED READER. These cases and the reader were written by the same authors, with no independent adjudication and no real-world defect history. The numbers describe the context-building and verification machinery on synthetic cases. They are not evidence about any model, and they make no accuracy claim about real repositories.', '');
  L.push(`- split: ${card.split}   variant: ${card.variant}   cases: ${card.caseCount}`);
  L.push(`- suite hash: ${card.hashes.suite}`);
  L.push(`- protocol hash: ${card.hashes.protocol}`);
  L.push(`- reader: ${card.reader.kind} v${card.reader.version} ${card.reader.digest} (synthetic)`);
  L.push(`- label leakage audit: ${card.leakage.length === 0 ? 'clean' : card.leakage.length + ' hit(s)'}`);
  L.push(`- holdout scored runs so far (this machine's ledger): ${card.ledger.holdoutScoredRuns}`, '');
  L.push('| system | status | TP | FP | FN | TN | precision | recall | F1 | F1 interval | model calls | prompt chars |', '|---|---|---|---|---|---|---|---|---|---|---|---|');
  for (const s of card.systems) {
    if (s.status !== 'measured') { L.push(`| ${s.system} | ${s.status}: ${s.reason} | | | | | | | | | | |`); continue; }
    const m = s.metrics;
    L.push(`| ${s.system} | measured | ${m.counts.tp} | ${m.counts.fp} | ${m.counts.fn} | ${m.counts.tn} | ${shown(m, m.precision)} | ${shown(m, m.recall)} | ${shown(m, m.f1)} | ${interval(m.f1Interval)} | ${s.calls} | ${s.promptChars} |`);
  }
  L.push('', '## Economics (estimated; no price supplied)', '', '| system | median ctx tokens | P95 | P99 | model calls | calls per true positive | wall ms |', '|---|---|---|---|---|---|---|');
  for (const s of card.systems) if (s.economics) { const e = s.economics; L.push(`| ${s.system} | ${e.contextTokens.median ?? 'n/a'} | ${e.contextTokens.p95 ?? 'n/a'} | ${e.contextTokens.p99 ?? 'n/a'} | ${e.modelCalls} | ${e.callsPerTruePositive === null || !s.metrics || !s.metrics.reportable ? 'withheld' : e.callsPerTruePositive.toFixed(1)} | ${e.wallMs} |`); }
  L.push('', 'Precision, recall, F1 and calls per true positive are withheld while their interval is unmeasured (fewer than 10 independent groups). The counts above are what was observed; they are not an estimate of anything.');
  L.push('', `Replay: \`${card.replay}\``, '');
  if (card.leakage.length) { L.push('## Leakage hits', ...card.leakage.map(h => `- ${h.where} ${h.file || ''} ${h.term}`), ''); }
  return L.join('\n');
}

export function renderCsv(card) {
  // The marker is a column, not a banner: a CSV is the format that gets pasted into a spreadsheet without its header text.
  const rows = [['system', 'case', 'variant', 'vulnerable', 'flagged', 'outcome', 'calls', 'promptChars', 'synthetic']];
  for (const s of card.systems) for (const u of (s.units || [])) rows.push([s.system, u.caseId, u.variant, u.vulnerable, u.flagged, u.outcome, u.calls, u.promptChars, card.synthetic === false ? false : true]);
  return rows.map(r => r.join(',')).join('\n') + '\n';
}

export async function evaluateSuite({ suiteDir = DEFAULT_SUITE_DIR, split = 'dev', systems = ['deterministic', 'hunt', 'dci'], variant = FROZEN_VARIANT, root = null, final = false, onProgress = () => {} } = {}) {
  const suite = loadSuite(suiteDir);
  const ids = split === 'all' ? [...suite.split.dev, ...suite.split.holdout] : suite.split[split];
  if (!ids) return { ok: false, reason: `unknown split '${split}' (dev, holdout, all)` };
  if (!VARIANTS.includes(variant)) return { ok: false, reason: `unknown variant '${variant}' (${VARIANTS.join(', ')})` };
  const touchesHoldout = split !== 'dev';
  if (touchesHoldout && variant !== FROZEN_VARIANT && !final) return { ok: false, reason: `variant '${variant}' is not the frozen one; develop variants on the dev split. The holdout may only score the frozen variant unless the run is declared --final.` };

  const protocol = { suite: suiteHash(suiteDir), split, variant, systems, reader: readerIdentity(), tolerance: 5 };
  const protocolHash = hashOf(protocol);
  const promptsBySystem = {};
  const out = [];
  for (const system of systems) {
    if (!SYSTEMS.includes(system)) { out.push({ system, status: 'error', reason: 'unknown system' }); continue; }
    const units = []; let calls = 0; let promptChars = 0; let blocked = null; const errors = []; const promptSizes = []; const t0 = Date.now();
    for (const id of ids) {
      const def = { id, ...suite.labels.cases[id] };
      for (const key of Object.keys(def.variants).sort()) {
        const v = def.variants[key];
        onProgress({ system, case: id, variant: key });
        const r = await runCase({ system, caseDef: def, variant: { key }, suiteDir, variantName: variant });
        if (r.status === 'blocked') { blocked = r.reason; continue; }
        if (r.status === 'error') { errors.push(`${id}/${key}: ${r.reason}`); continue; }
        const flagged = !!r.flagged; const vuln = !!v.vulnerable;
        const u = { id: `${id}/${key}`, caseId: id, variant: key, language: def.language, vulnerable: vuln, flagged, tp: vuln && flagged ? 1 : 0, fn: vuln && !flagged ? 1 : 0, fp: !vuln && flagged ? 1 : 0, tn: !vuln && !flagged ? 1 : 0, calls: r.calls, promptChars: r.promptChars, outcome: vuln ? (flagged ? 'tp' : 'fn') : (flagged ? 'fp' : 'tn'), detail: r.detail };
        units.push(u); calls += r.calls; promptChars += r.promptChars;
        (promptsBySystem[system] = promptsBySystem[system] || []).push(...r.prompts);
        promptSizes.push(...r.prompts.map(x => String(x).length));
      }
    }
    if (blocked && units.length === 0) { out.push({ system, status: 'blocked', reason: blocked }); continue; }
    if (errors.length) { out.push({ system, status: 'error', reason: `${errors.length} case run(s) failed: ${errors.slice(0, 3).join('; ')}` }); continue; }
    const metrics = metricsFor(units, protocolHash, system);
    out.push({ system, status: 'measured', metrics, units, calls, promptChars, economics: economicsOf({ promptSizes, calls, wallMs: Date.now() - t0, metrics }) });
  }
  const leakage = leakageAudit(suiteDir, promptsBySystem);

  let ledger = { holdoutScoredRuns: 0, devScoredRuns: 0 };
  if (root) {
    ledger = readLedger(root);
    if (touchesHoldout) ledger.holdoutScoredRuns += 1; else ledger.devScoredRuns += 1;
    ledger.runs = [...(ledger.runs || []).slice(-49), { protocolHash, split, variant, systems }];
    writeStoreJson(root, ledgerPath(), ledger);
  }
  const replay = `agentic-security context eval --suite fixtures --split ${split} --variant ${variant} --baseline ${systems.join(',')}`;
  const card = { schemaVersion: 'dci-eval-scorecard/1', synthetic: true, claim: 'machinery on synthetic cases only; no accuracy claim about real repositories', split, variant, caseCount: ids.length, hashes: { suite: protocol.suite, protocol: protocolHash }, reader: readerIdentity(), leakage, ledger: { holdoutScoredRuns: ledger.holdoutScoredRuns, devScoredRuns: ledger.devScoredRuns }, systems: out, replay };
  card.hashes.scorecard = hashOf({ ...card, ledger: null, systems: card.systems.map(x => (x.economics ? { ...x, economics: { ...x.economics, wallMs: null } } : x)) });
  return { ok: true, card };
}

export async function cmdEval(root, args, format) {
  const suiteArg = FLAG(args, 'suite');
  if (suiteArg !== undefined && suiteArg !== 'fixtures' && suiteArg !== true) { console.log("context eval: only '--suite fixtures' is available (the bundled synthetic suite)"); return 1; }
  if (!fs.existsSync(path.join(DEFAULT_SUITE_DIR, 'labels.json'))) { console.log('context eval: the synthetic suite is not present in this install (it ships with the source tree)'); return 1; }
  const baseline = FLAG(args, 'baseline') && FLAG(args, 'baseline') !== true ? String(FLAG(args, 'baseline')).split(',').map(s => s.trim()).filter(Boolean) : ['deterministic', 'hunt', 'dci'];
  const variant = FLAG(args, 'variant') && FLAG(args, 'variant') !== true ? String(FLAG(args, 'variant')) : FROZEN_VARIANT;
  const split = FLAG(args, 'split') && FLAG(args, 'split') !== true ? String(FLAG(args, 'split')) : 'dev';
  const r = await evaluateSuite({ split, variant, systems: baseline, root, final: truthy(FLAG(args, 'final')) });
  if (!r.ok) { console.log(`context eval: ${r.reason}`); return 1; }
  const card = r.card;
  const base = `reports/eval-${card.hashes.scorecard.slice(0, 16)}`;
  const w = [writeStoreJson(root, `${base}.json`, card)];
  const md = renderMarkdown(card);
  const fileWrites = [['.md', md], ['.csv', renderCsv(card)]];
  const { writeStoreFile } = await import('../store.js');
  for (const [ext, text] of fileWrites) w.push(writeStoreFile(root, base + ext, text));
  if (format === 'json') console.log(JSON.stringify({ ...card, files: w.map(x => x && x.ok !== false) }, null, 2));
  else console.log(md + `\nWritten: .agentic-security/context-intelligence/${base}.{json,md,csv}`);
  return card.leakage.length || card.systems.some(s => s.status === 'error') ? 1 : 0;
}
