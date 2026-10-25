export const id = 6893;
export const ids = [6893];
export const modules = {

/***/ 26893:
/***/ ((__webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(__webpack_module__, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   cmdEval: () => (/* binding */ cmdEval)
/* harmony export */ });
/* unused harmony exports DEFAULT_SUITE_DIR, VARIANTS, FROZEN_VARIANT, leakageAudit, metricsFor, percentile, economicsOf, renderMarkdown, renderCsv, evaluateSuite */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var node_url__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(73136);
/* harmony import */ var _canonical_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(4844);
/* harmony import */ var _store_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(72351);
/* harmony import */ var _posture_evaluation_interval_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(76159);
/* harmony import */ var _runner_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(62879);
/* harmony import */ var _scripted_reader_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(403);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_runner_js__WEBPACK_IMPORTED_MODULE_6__]);
_runner_js__WEBPACK_IMPORTED_MODULE_6__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];
//
// `agentic-security context eval`: the frozen synthetic suite, scored.
//
// Honest by construction:
//   * every scorecard says on its face that the suite and the reader are synthetic and that no accuracy claim follows;
//   * intervals come from the repo's existing grouped bootstrap (a case is one group; fewer than 10 groups is "unmeasured");
//   * the holdout split is scored only through a ledger that counts every use, and non-default prompt variants are refused
//     on it unless the run is declared final;
//   * a label-leakage audit checks that neither the corpus nor any prompt a system saw contains the label vocabulary.









const HERE = node_path__WEBPACK_IMPORTED_MODULE_1__.dirname((0,node_url__WEBPACK_IMPORTED_MODULE_2__.fileURLToPath)(import.meta.url));
// The bundled synthetic suite lives in the source tree's fixtures, found from the package root. Scan code must not
// read evaluation labels, so this is reachable only from the explicit `context eval` command, and `--suite-dir` /
// AGENTIC_SECURITY_DCI_EVAL_SUITE can point at any other suite in the same layout.
function packageRoot(from) {
  let dir = from;
  for (let i = 0; i < 8; i++) {
    if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, 'package.json'))) return dir;
    dir = node_path__WEBPACK_IMPORTED_MODULE_1__.dirname(dir);
  }
  return from;
}
const DEFAULT_SUITE_DIR = process.env.AGENTIC_SECURITY_DCI_EVAL_SUITE
  ? node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(process.env.AGENTIC_SECURITY_DCI_EVAL_SUITE)
  : node_path__WEBPACK_IMPORTED_MODULE_1__.join(packageRoot(HERE), ['test', 'fixtures', 'context-intelligence', 'eval'].join(node_path__WEBPACK_IMPORTED_MODULE_1__.sep));
const VARIANTS = Object.freeze(['dci', 'dci-all-packs']);
const FROZEN_VARIANT = 'dci';
const FLAG = (args, k) => (args && args[k] !== undefined ? args[k] : undefined);
const truthy = (v) => v === true || v === 'true' || v === '1';

const LEAK_TERMS = /\b(?:vulnerable|vulnerability|idor|bola|bfla|exploit|insecure|label|holdout|ground.?truth|expected result)\b/i;

function loadSuite(dir) {
  const read = (f) => JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, f), 'utf8'));
  const labels = read('labels.json');
  const split = read('split.json');
  return { labels, split, dir };
}

function walk(dir, out = []) {
  for (const e of node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir, { withFileTypes: true })) {
    const p = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, e.name);
    if (e.isDirectory()) walk(p, out); else if (e.isFile()) out.push(p);
  }
  return out.sort();
}

function suiteHash(dir) {
  const files = walk(dir).map(f => ({ f: node_path__WEBPACK_IMPORTED_MODULE_1__.relative(dir, f), h: (0,_canonical_js__WEBPACK_IMPORTED_MODULE_3__/* .sha256 */ .sc)(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(f)) }));
  return (0,_canonical_js__WEBPACK_IMPORTED_MODULE_3__/* .hashOf */ .qQ)(files);
}

/** The corpus and every prompt a system saw must not contain the label vocabulary. Returns hits (empty = clean). */
function leakageAudit(dir, promptsBySystem) {
  const hits = [];
  for (const f of walk(node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, 'corpus'))) {
    const text = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(f, 'utf8');
    const m = LEAK_TERMS.exec(text);
    if (m) hits.push({ where: 'corpus', file: node_path__WEBPACK_IMPORTED_MODULE_1__.relative(dir, f), term: m[0] });
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

function metricsFor(units, protocolHash, name) {
  const c = tally(units);
  const groupOf = Object.fromEntries(units.map(u => [u.id, u.caseId]));
  const f1 = (0,_posture_evaluation_interval_js__WEBPACK_IMPORTED_MODULE_5__/* .groupedBootstrap */ .jN)({ units, groupOf, statistic: ({ total }) => (0,_posture_evaluation_interval_js__WEBPACK_IMPORTED_MODULE_5__/* .f1Of */ .li)(total), name: `${name}:f1`, protocolHash });
  const pn = c.tp + c.fp;
  return {
    counts: c, units: units.length,
    precision: (0,_posture_evaluation_interval_js__WEBPACK_IMPORTED_MODULE_5__/* .precisionOf */ .ij)(c), recall: (0,_posture_evaluation_interval_js__WEBPACK_IMPORTED_MODULE_5__/* .recallOf */ .HR)(c), f1: (0,_posture_evaluation_interval_js__WEBPACK_IMPORTED_MODULE_5__/* .f1Of */ .li)(c),
    precisionInterval: pn > 0 ? (0,_posture_evaluation_interval_js__WEBPACK_IMPORTED_MODULE_5__/* .wilsonInterval */ .YV)(c.tp, pn) : { status: 'unmeasured', reason: 'nothing was reported' },
    f1Interval: f1,
    // A point estimate with no interval around it reads as a finding. It is reportable only when the interval is measured.
    reportable: f1 && f1.status === 'measured',
  };
}

/** Nearest-rank percentile of a numeric list (null when empty). */
function percentile(values, q) {
  if (!values.length) return null;
  const v = [...values].sort((a, b) => a - b);
  return v[Math.min(v.length - 1, Math.max(0, Math.ceil(q * v.length) - 1))];
}

/** Context-size, call and cost accounting for one system. Token figures are chars/4 estimates; no price is assumed. */
function economicsOf({ promptSizes, calls, wallMs, metrics }) {
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
  const r = (0,_store_js__WEBPACK_IMPORTED_MODULE_4__/* .readStoreFile */ .Oq)(root, ledgerPath());
  if (!r.ok) return { schemaVersion: 'eval-ledger/1', holdoutScoredRuns: 0, devScoredRuns: 0, runs: [] };
  try { return JSON.parse(r.text); } catch { return { schemaVersion: 'eval-ledger/1', holdoutScoredRuns: 0, devScoredRuns: 0, runs: [], note: 'previous ledger unreadable; counts restart' }; }
}

const pct = (x) => (x === null || x === undefined ? 'n/a' : (x * 100).toFixed(0) + '%');
const interval = (i) => (!i || i.status !== 'measured' ? `unmeasured (${i && i.reason ? i.reason.split(',')[0] : 'no data'})` : `${pct(i.low)} to ${pct(i.high)}`);

// Precision, recall and F1 are printed only when their interval is measured; otherwise the counts stand alone.
const shown = (m, x) => (m.reportable ? pct(x) : 'withheld');

function renderMarkdown(card) {
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

function renderCsv(card) {
  // The marker is a column, not a banner: a CSV is the format that gets pasted into a spreadsheet without its header text.
  const rows = [['system', 'case', 'variant', 'vulnerable', 'flagged', 'outcome', 'calls', 'promptChars', 'synthetic']];
  for (const s of card.systems) for (const u of (s.units || [])) rows.push([s.system, u.caseId, u.variant, u.vulnerable, u.flagged, u.outcome, u.calls, u.promptChars, card.synthetic === false ? false : true]);
  return rows.map(r => r.join(',')).join('\n') + '\n';
}

async function evaluateSuite({ suiteDir = DEFAULT_SUITE_DIR, split = 'dev', systems = ['deterministic', 'hunt', 'dci'], variant = FROZEN_VARIANT, root = null, final = false, onProgress = () => {} } = {}) {
  const suite = loadSuite(suiteDir);
  const ids = split === 'all' ? [...suite.split.dev, ...suite.split.holdout] : suite.split[split];
  if (!ids) return { ok: false, reason: `unknown split '${split}' (dev, holdout, all)` };
  if (!VARIANTS.includes(variant)) return { ok: false, reason: `unknown variant '${variant}' (${VARIANTS.join(', ')})` };
  const touchesHoldout = split !== 'dev';
  if (touchesHoldout && variant !== FROZEN_VARIANT && !final) return { ok: false, reason: `variant '${variant}' is not the frozen one; develop variants on the dev split. The holdout may only score the frozen variant unless the run is declared --final.` };

  const protocol = { suite: suiteHash(suiteDir), split, variant, systems, reader: (0,_scripted_reader_js__WEBPACK_IMPORTED_MODULE_7__/* .readerIdentity */ .ue)(), tolerance: 5 };
  const protocolHash = (0,_canonical_js__WEBPACK_IMPORTED_MODULE_3__/* .hashOf */ .qQ)(protocol);
  const promptsBySystem = {};
  const out = [];
  for (const system of systems) {
    if (!_runner_js__WEBPACK_IMPORTED_MODULE_6__/* .SYSTEMS */ .LB.includes(system)) { out.push({ system, status: 'error', reason: 'unknown system' }); continue; }
    const units = []; let calls = 0; let promptChars = 0; let blocked = null; const errors = []; const promptSizes = []; const t0 = Date.now();
    for (const id of ids) {
      const def = { id, ...suite.labels.cases[id] };
      for (const key of Object.keys(def.variants).sort()) {
        const v = def.variants[key];
        onProgress({ system, case: id, variant: key });
        const r = await (0,_runner_js__WEBPACK_IMPORTED_MODULE_6__/* .runCase */ .ef)({ system, caseDef: def, variant: { key }, suiteDir, variantName: variant });
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
    (0,_store_js__WEBPACK_IMPORTED_MODULE_4__/* .writeStoreJson */ .DU)(root, ledgerPath(), ledger);
  }
  const replay = `agentic-security context eval --suite fixtures --split ${split} --variant ${variant} --baseline ${systems.join(',')}`;
  const card = { schemaVersion: 'dci-eval-scorecard/1', synthetic: true, claim: 'machinery on synthetic cases only; no accuracy claim about real repositories', split, variant, caseCount: ids.length, hashes: { suite: protocol.suite, protocol: protocolHash }, reader: (0,_scripted_reader_js__WEBPACK_IMPORTED_MODULE_7__/* .readerIdentity */ .ue)(), leakage, ledger: { holdoutScoredRuns: ledger.holdoutScoredRuns, devScoredRuns: ledger.devScoredRuns }, systems: out, replay };
  card.hashes.scorecard = (0,_canonical_js__WEBPACK_IMPORTED_MODULE_3__/* .hashOf */ .qQ)({ ...card, ledger: null, systems: card.systems.map(x => (x.economics ? { ...x, economics: { ...x.economics, wallMs: null } } : x)) });
  return { ok: true, card };
}

async function cmdEval(root, args, format) {
  const suiteArg = FLAG(args, 'suite');
  if (suiteArg !== undefined && suiteArg !== 'fixtures' && suiteArg !== true) { console.log("context eval: only '--suite fixtures' is available (the bundled synthetic suite)"); return 1; }
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(DEFAULT_SUITE_DIR, 'labels.json'))) { console.log('context eval: the synthetic suite is not present in this install (it ships with the source tree)'); return 1; }
  const baseline = FLAG(args, 'baseline') && FLAG(args, 'baseline') !== true ? String(FLAG(args, 'baseline')).split(',').map(s => s.trim()).filter(Boolean) : ['deterministic', 'hunt', 'dci'];
  const variant = FLAG(args, 'variant') && FLAG(args, 'variant') !== true ? String(FLAG(args, 'variant')) : FROZEN_VARIANT;
  const split = FLAG(args, 'split') && FLAG(args, 'split') !== true ? String(FLAG(args, 'split')) : 'dev';
  const r = await evaluateSuite({ split, variant, systems: baseline, root, final: truthy(FLAG(args, 'final')) });
  if (!r.ok) { console.log(`context eval: ${r.reason}`); return 1; }
  const card = r.card;
  const base = `reports/eval-${card.hashes.scorecard.slice(0, 16)}`;
  const w = [(0,_store_js__WEBPACK_IMPORTED_MODULE_4__/* .writeStoreJson */ .DU)(root, `${base}.json`, card)];
  const md = renderMarkdown(card);
  const fileWrites = [['.md', md], ['.csv', renderCsv(card)]];
  const { writeStoreFile } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 72351));
  for (const [ext, text] of fileWrites) w.push(writeStoreFile(root, base + ext, text));
  if (format === 'json') console.log(JSON.stringify({ ...card, files: w.map(x => x && x.ok !== false) }, null, 2));
  else console.log(md + `\nWritten: .agentic-security/context-intelligence/${base}.{json,md,csv}`);
  return card.leakage.length || card.systems.some(s => s.status === 'error') ? 1 : 0;
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 62879:
/***/ ((__webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(__webpack_module__, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LB: () => (/* binding */ SYSTEMS),
/* harmony export */   ef: () => (/* binding */ runCase)
/* harmony export */ });
/* unused harmony exports LINE_TOLERANCE, locate */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var _runScan_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(5950);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(92582);
/* harmony import */ var _ir_index_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(57546);
/* harmony import */ var _discovery_index_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(78992);
/* harmony import */ var _build_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(93260);
/* harmony import */ var _config_js__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(55478);
/* harmony import */ var _queue_js__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(76161);
/* harmony import */ var _prompts_packs_js__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(15592);
/* harmony import */ var _review_js__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(80108);
/* harmony import */ var _candidates_js__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(54898);
/* harmony import */ var _scripted_reader_js__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(403);
/* harmony import */ var _files_js__WEBPACK_IMPORTED_MODULE_14__ = __webpack_require__(37673);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_runScan_js__WEBPACK_IMPORTED_MODULE_3__]);
_runScan_js__WEBPACK_IMPORTED_MODULE_3__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];
//
// Runs the frozen synthetic suite through the compared systems and tallies per-case outcomes.
//
// Systems (each answers one question per case variant: "is a defect reported at the labeled sink?"):
//   deterministic  the default scanner (`runScan`) with state writes disabled; no model, no spend
//   hunt           the existing discovery pipeline (partition, lens hunters, confirm, panel, judge)
//   dci            DCI bundles + governed review + verified citations -> candidates (model hypotheses, pre-confirmation)
//   dci-compiler   dci with imported compiler metadata; BLOCKED unless the case ships a `hie-export.json`
// Both model-backed systems get the SAME injected reader, so the only thing that differs is the text put in front of it.
//
// The reader here is the scripted one, so every number is a statement about the machinery on synthetic cases.

















const SYSTEMS = Object.freeze(['deterministic', 'hunt', 'dci', 'dci-compiler']);
const LINE_TOLERANCE = 5;

/** Line (1-based) of the first line containing `contains`, or null. */
function locate(text, contains) {
  const lines = String(text).split('\n');
  for (let i = 0; i < lines.length; i++) if (lines[i].includes(contains)) return i + 1;
  return null;
}

function copyTree(src, dest) {
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(dest, { recursive: true });
  for (const e of node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(src, { withFileTypes: true })) {
    const s = node_path__WEBPACK_IMPORTED_MODULE_2__.join(src, e.name); const d = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dest, e.name);
    if (e.isDirectory()) copyTree(s, d); else if (e.isFile()) node_fs__WEBPACK_IMPORTED_MODULE_0__.copyFileSync(s, d);
  }
}

function recorder(inner) {
  const prompts = [];
  const fn = async (prompt) => { prompts.push(prompt); return inner(prompt); };
  fn.tokenizerName = inner.tokenizerName;
  return { invoke: fn, prompts };
}

function hit(found, sink) {
  return found.some(f => f.file === sink.file && Number.isInteger(f.line) && Math.abs(f.line - sink.line) <= LINE_TOLERANCE);
}

async function runDeterministic(dir, sink) {
  const { scan } = await (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_4__/* .withStateWritesDisabled */ .Ao)(() => (0,_runScan_js__WEBPACK_IMPORTED_MODULE_3__.runScan)(dir, { deep: true, deepInCi: true }));
  const findings = [...(scan.findings || []), ...(scan.logicVulns || [])].filter(f => f && f.severity !== 'info');
  return { flagged: hit(findings, sink), calls: 0, promptChars: 0, detail: { findings: findings.length }, prompts: [] };
}

async function runHuntSystem(dir, sink, reader) {
  const snap = await (0,_files_js__WEBPACK_IMPORTED_MODULE_14__/* .readSnapshot */ .RA)(dir, { maxFiles: 2000 });
  const fileContents = snap.fileContents;
  const ir = (0,_ir_index_js__WEBPACK_IMPORTED_MODULE_5__.buildProjectIR)(fileContents);
  const rec = recorder(reader);
  const res = await (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_4__/* .withStateWritesDisabled */ .Ao)(() => (0,_discovery_index_js__WEBPACK_IMPORTED_MODULE_6__.runDiscovery)({ perFileIR: ir.perFile, callGraph: ir.callGraph, fileContents }, { llmInvoke: rec.invoke, lenses: ['authz', 'business-logic'], maxAreas: 8 }));
  const reported = [...res.fresh, ...res.duplicates];
  const found = reported.map(f => ({ file: f.file, line: f.line }));
  return { flagged: hit(found, sink), calls: rec.prompts.length, promptChars: rec.prompts.reduce((n, p) => n + p.length, 0), detail: { reported: reported.length, areas: res.focusAreas.length }, prompts: rec.prompts };
}

async function runDciSystem(dir, sink, reader, { packIds, withCompiler }) {
  const { config } = (0,_config_js__WEBPACK_IMPORTED_MODULE_8__/* .loadConfig */ .Z9)(dir);
  if (withCompiler) config.semanticMetadata = { mode: 'import', haskellHieDir: '.' };
  const built = await (0,_build_js__WEBPACK_IMPORTED_MODULE_7__/* .buildContext */ .g)(dir, { config });
  if (!built.ok) return { flagged: false, calls: 0, promptChars: 0, detail: { buildFailed: built.reason }, prompts: [] };
  const packs = packIds.map(_prompts_packs_js__WEBPACK_IMPORTED_MODULE_10__/* .packById */ .Oy).filter(Boolean);
  const model = (0,_review_js__WEBPACK_IMPORTED_MODULE_11__/* .describeModel */ .Vy)();
  const { jobs } = (0,_queue_js__WEBPACK_IMPORTED_MODULE_9__/* .planJobs */ .KR)({ bundles: built.bundles, packs, model });
  const byEp = new Map(built.bundles.map(b => [b.entrypoint.id, b]));
  const packMap = new Map(packs.map(p => [p.id, p]));
  const loadJob = (job) => {
    const bundles = job.entrypointIds.map(id => byEp.get(id));
    if (bundles.some(b => !b || !b.manifest)) return { error: 'no bundle' };
    return { pack: packMap.get(job.packId), entrypoints: bundles.map(b => b.entrypoint), manifests: bundles.map(b => b.manifest), packageTexts: bundles.map((b, i) => (b.pack.packages.find(p => p.index === job.packageIndexes[i]) || b.pack.packages[0]).text) };
  };
  const rec = recorder(reader);
  const result = await (0,_queue_js__WEBPACK_IMPORTED_MODULE_9__/* .runQueue */ .rj)(jobs, { root: built.root, fileContents: built.fileContents, model, invoker: { ok: true, invoke: rec.invoke }, loadJob, retryFailed: false, limits: { concurrency: 1, maxCalls: 500, maxWallSeconds: 300, maxTokensPerJob: 40000, maxRetries: 0, jobTimeoutMs: 30000, maxCostUsd: null, costPerCallUsd: null } });
  const records = [];
  for (const [, res] of result.results) {
    if (res.state === 'succeeded' && res.review) { const lj = loadJob(res.job); if (!lj.error) records.push({ review: res.review, entrypoints: lj.entrypoints.map(e => ({ id: e.id, label: e.label })), pack: lj.pack }); }
  }
  const candidates = (0,_candidates_js__WEBPACK_IMPORTED_MODULE_12__/* .reviewsToCandidates */ .D)(records);
  const adj = await (0,_candidates_js__WEBPACK_IMPORTED_MODULE_12__/* .adjudicate */ .p)(candidates, { taintProbe: (0,_discovery_index_js__WEBPACK_IMPORTED_MODULE_6__.makeTaintProbe)(built.ir.perFile, built.ir.callGraph), scanRoot: built.root });
  const found = candidates.map(c => ({ file: c.file, line: c.line }));
  const tiers = {};
  for (const f of adj.findings) { const t = (f.discovery && f.discovery.confirmation && f.discovery.confirmation.tier) || 'unknown'; tiers[t] = (tiers[t] || 0) + 1; }
  return {
    flagged: hit(found, sink), calls: rec.prompts.length, promptChars: rec.prompts.reduce((n, p) => n + p.length, 0),
    detail: { jobs: jobs.length, candidates: candidates.length, coverage: { eligible: result.coverage.eligible, succeeded: result.coverage.succeeded, missing: result.coverage.missingCoverage }, confirmationTiers: tiers, bundles: { complete: built.summary.complete, partial: built.summary.partialBundles, unavailable: built.summary.unavailable } },
    prompts: rec.prompts,
  };
}

/**
 * Run one system over one case variant in a throwaway copy. Never touches the source fixture.
 * Returns { flagged, calls, promptChars, detail, prompts, status } where status is 'ok' or 'blocked'/'error'.
 */
async function runCase({ system, caseDef, variant, suiteDir, variantName = 'dci' }) {
  const v = caseDef.variants[variant.key];
  const srcDir = node_path__WEBPACK_IMPORTED_MODULE_2__.join(suiteDir, 'corpus', caseDef.id, variant.key);
  if (system === 'dci-compiler' && !node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(srcDir, 'hie-export.json'))) {
    return { status: 'blocked', reason: 'no compiler metadata export is shipped for this case (the exporter needs a build toolchain and is not run by DCI)', flagged: null, calls: 0, promptChars: 0, detail: {}, prompts: [] };
  }
  const tmp = node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdtempSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.tmpdir(), 'dci-eval-'));
  try {
    copyTree(srcDir, tmp);
    const sinkText = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(tmp, v.sink.file), 'utf8');
    const line = locate(sinkText, v.sink.contains);
    if (line === null) return { status: 'error', reason: `sink text not found in ${v.sink.file}`, flagged: null, calls: 0, promptChars: 0, detail: {}, prompts: [] };
    const sink = { file: v.sink.file, line };
    const reader = (0,_scripted_reader_js__WEBPACK_IMPORTED_MODULE_13__/* .scriptedReader */ .Y$)();
    let r;
    if (system === 'deterministic') r = await runDeterministic(tmp, sink);
    else if (system === 'hunt') r = await runHuntSystem(tmp, sink, reader);
    else if (system === 'dci' || system === 'dci-compiler') {
      const packIds = variantName === 'dci-all-packs' ? ['authz-idor', 'authz-function', 'transaction-integrity'] : [caseDef.pack];
      r = await runDciSystem(tmp, sink, reader, { packIds, withCompiler: system === 'dci-compiler' });
    } else return { status: 'error', reason: `unknown system ${system}`, flagged: null, calls: 0, promptChars: 0, detail: {}, prompts: [] };
    return { status: 'ok', sink, ...r };
  } catch (e) {
    return { status: 'error', reason: String(e && e.message || e).slice(0, 200), flagged: null, calls: 0, promptChars: 0, detail: {}, prompts: [] };
  } finally {
    try { node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 403:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Y$: () => (/* binding */ scriptedReader),
/* harmony export */   ue: () => (/* binding */ readerIdentity)
/* harmony export */ });
/* unused harmony exports blocksFromReviewPrompt, blocksFromHuntPrompt, analyseRoute, decide */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
//
// A deterministic, rule-based "reader" that stands in for a model in the SYNTHETIC evaluation suite.
//
// WHAT IT IS. A small text analyser that answers the same two prompt formats a model would see (the DCI review prompt
// and the `hunt` prompt) using only what is literally written in the prompt. Because it is deterministic, a suite run
// is reproducible bit for bit and needs no network, key or spend, which is what lets the evaluation HARNESS be tested.
//
// WHAT IT IS NOT. It is not a language model and its results are not evidence about any model's ability. It was
// written by the same people who wrote the fixtures, so it is good at exactly the shapes those fixtures contain. Any
// score produced with it measures the context-construction and verification machinery on synthetic cases, never
// vulnerability-finding skill. The scorecard says so on its face.
//
// It reads ONLY the prompt. That is the point of the comparison: two systems differ in what text they put in front of
// the same reader, so a difference in outcome is a difference in context.


const ROUTE_CALL = /\b(?:app|router|server|api)\.(get|post|put|patch|delete|all)\s*\(\s*(['"`])([^'"`]+)\2/;
const FLASK_ROUTE = /@\w+\.route\(\s*(['"])([^'"]+)\1/;
const SCOTTY_ROUTE = /^\s*(get|post|put|patch|delete)\s+"([^"]+)"/;
const UNTRUSTED = /\b(?:req|request)\.(?:params|query|body|args|form)\b|\bparam\s+"|<int:\w+>|<\w+>|\bnote_id\b|\bitem_id\b/;
const DATA = /\b(?:db|tx|conn|pool|client|repo)\.(?:query|execute|run)\s*\(|\bquery\s+conn\b|\bexecute\s+conn\b|\bdb\.execute\(/;
const WRITE = /\b(?:UPDATE|DELETE|INSERT)\b/i;
const QUALIFIED_PRINCIPAL = /\b(?:req\.user|request\.user|current_user|session\.user|principal|ctx\.user|userId\s+u)\b/;
const OWNER_COL = /\b(?:owner|owner_id|org_id|tenant_id|user_id|account_id)\b|\bowner\s*=/i;
const ROLE_GUARD = /\b(?:requireAdmin|isAdmin|role\s*!==?\s*['"]admin['"]|hasRole|requireRole)\b/;

function numbered(text) {
  // "  12| code" lines, as the DCI packer renders them
  const out = [];
  for (const raw of text.split('\n')) {
    const m = /^\s*(\d+)\| ?(.*)$/.exec(raw);
    if (m) out.push({ n: +m[1], text: m[2] });
  }
  return out;
}

/** Blocks from a DCI review prompt: [{file, lines:[{n,text}]}] plus metadata the packer wrote into the header. */
function blocksFromReviewPrompt(prompt) {
  const blocks = [];
  const re = /^=== SOURCE (\S+):(\d+)-(\d+) \|[^\n]*===\n/gm;
  const marks = [];
  let m;
  while ((m = re.exec(prompt))) marks.push({ file: m[1], at: m.index, bodyAt: re.lastIndex });
  marks.forEach((mk, i) => {
    const end = i + 1 < marks.length ? marks[i + 1].at : prompt.length;
    blocks.push({ file: mk.file, lines: numbered(prompt.slice(mk.bodyAt, end)) });
  });
  return { blocks, unresolved: /^UNRESOLVED:/m.test(prompt), notIncluded: /^NOT INCLUDED:/m.test(prompt), limit: /^LIMIT:/m.test(prompt) };
}

/** Blocks from a `hunt` prompt: whole files, which the reader numbers itself. */
function blocksFromHuntPrompt(prompt) {
  const blocks = [];
  const re = /--- SOURCE FILE \(untrusted data\): (\S+?)(?: \(truncated\))? ---\n([\s\S]*?)\n--- END SOURCE FILE: /g;
  let m;
  while ((m = re.exec(prompt))) blocks.push({ file: m[1], lines: m[2].split('\n').map((text, i) => ({ n: i + 1, text })) });
  return blocks;
}

function allLines(blocks) { return blocks.flatMap(b => b.lines.map(l => ({ ...l, file: b.file }))); }

/** Lines from a registration to the end of its handler within one block. */
function handlerRange(block, startIdx) {
  const L = block.lines;
  const first = L[startIdx].text;
  if (/^\s*@/.test(first)) { // decorator style: until the next top-level line after the def body
    let i = startIdx + 1;
    while (i < L.length && /^\s*@/.test(L[i].text)) i++;
    const base = /^\s*/.exec(L[i] ? L[i].text : '')[0].length;
    let j = i + 1;
    while (j < L.length && (L[j].text.trim() === '' || /^\s*/.exec(L[j].text)[0].length > base)) j++;
    return L.slice(startIdx, j);
  }
  if (SCOTTY_ROUTE.test(first)) {
    const base = /^\s*/.exec(first)[0].length;
    let j = startIdx + 1;
    while (j < L.length && (L[j].text.trim() === '' || /^\s*/.exec(L[j].text)[0].length > base)) j++;
    return L.slice(startIdx, j);
  }
  let depth = 0; let opened = false; let j = startIdx;
  for (; j < L.length; j++) {
    for (const c of L[j].text) { if (c === '{') { depth++; opened = true; } else if (c === '}') depth--; }
    if (opened && depth <= 0) break;
  }
  return L.slice(startIdx, Math.min(L.length, j + 1));
}

function findRoutes(blocks) {
  const routes = [];
  for (const b of blocks) {
    b.lines.forEach((l, i) => {
      let m = ROUTE_CALL.exec(l.text);
      if (m) { routes.push({ block: b, idx: i, method: m[1].toUpperCase(), path: m[3], file: b.file, line: l.n }); return; }
      m = FLASK_ROUTE.exec(l.text);
      if (m) { routes.push({ block: b, idx: i, method: 'GET', path: m[2], file: b.file, line: l.n }); return; }
      m = SCOTTY_ROUTE.exec(l.text);
      if (m) routes.push({ block: b, idx: i, method: m[1].toUpperCase(), path: m[2], file: b.file, line: l.n });
    });
  }
  return routes;
}

/** Find the body of a function named `name` anywhere in the blocks (one level of helper). */
function functionBody(blocks, name) {
  for (const b of blocks) {
    for (let i = 0; i < b.lines.length; i++) {
      if (new RegExp(`(?:function\\s+${name}\\b|\\b${name}\\s*=\\s*(?:async\\s*)?\\(|^\\s*${name}\\s*::|\\bdef\\s+${name}\\b)`).test(b.lines[i].text)) {
        const range = handlerRange(b, i);
        return range.map(l => ({ ...l, file: b.file }));
      }
    }
  }
  return null;
}

function statement(lines, i) {
  let text = lines[i].text; let depth = 0;
  for (const c of text) { if (c === '(') depth++; else if (c === ')') depth--; }
  let j = i;
  while (depth > 0 && j + 1 < lines.length && j - i < 6) { j++; text += ' ' + lines[j].text; for (const c of lines[j].text) { if (c === '(') depth++; else if (c === ')') depth--; } }
  return text;
}

function stripUntrusted(t) {
  return t.replace(/\b(?:req|request)\.(?:params|query|body|args|form)\b(?:\.\w+)?/g, ' ').replace(/(["'`])(?:\\.|(?!\1).)*\1/g, '""');
}

/**
 * Analyse ONE route: returns the observations a reader can make from the text it was given.
 */
function analyseRoute(route, blocks, { dynamicUnresolved = false } = {}) {
  const handler = handlerRange(route.block, route.idx).map(l => ({ ...l, file: route.file }));
  const all = allLines(blocks);
  const obs = { route, handler, untrusted: false, data: [], writes: [], scoping: [], capability: null, roleGuards: [], roleGuardDefined: false, lateScoping: [], dynamic: false, transaction: false, helperScoping: [] };
  const regLine = handler[0] ? handler[0].text : '';

  obs.untrusted = handler.some(l => UNTRUSTED.test(l.text)) || UNTRUSTED.test(regLine);
  handler.forEach((l, i) => {
    if (DATA.test(l.text)) {
      const st = statement(handler, i);
      obs.data.push({ ...l, stmt: st });
      if (WRITE.test(st)) obs.writes.push({ ...l, stmt: st });
      if (OWNER_COL.test(st) && QUALIFIED_PRINCIPAL.test(stripUntrustedKeepUser(st))) obs.scoping.push({ ...l, kind: 'query-filter' });
    }
    if (/\btoken\s*=\s*\$1/.test(l.text) && /\b(?:req|request)\.params\.token\b/.test(statement(handler, i))) obs.capability = { ...l };
    if (/!==|!=|==/.test(l.text) && OWNER_COL.test(l.text) && QUALIFIED_PRINCIPAL.test(stripUntrustedKeepUser(l.text))) obs.lateScoping.push({ ...l });
    if (/\bactions\[|\[[^\]]*(?:params|query|body)[^\]]*\]/.test(l.text) || /\breturn\s+run\(/.test(l.text)) obs.dynamic = true;
    if (/\btransaction\b/.test(l.text)) obs.transaction = true;
    if (/\bisAdmin\b|\brole\s*!==?\s*['"]admin['"]/.test(l.text)) obs.roleGuards.push({ ...l, where: 'handler' });
  });

  // middleware named on the registration line
  const mwNames = [...regLine.matchAll(/\b(require[A-Z]\w*)\b/g)].map(m => m[1]);
  for (const name of mwNames) {
    if (ROLE_GUARD.test(name)) {
      const body = functionBody(blocks, name);
      if (body) { obs.roleGuardDefined = true; obs.roleGuards.push({ ...body[0], where: 'middleware', name }); }
      else obs.roleGuards.push({ file: route.file, n: route.line, text: regLine, where: 'middleware-undefined', name });
    }
  }
  // router-level / app-level `use` lines in the provided blocks
  for (const l of all) {
    const m = /\b(?:router|app)\.use\(\s*(require[A-Z]\w*)\s*\)/.exec(l.text);
    if (m && ROLE_GUARD.test(m[1]) && l.n < route.line + 0 && l.file === route.file) {
      const body = functionBody(blocks, m[1]);
      obs.roleGuards.push({ ...l, where: 'use', name: m[1], defined: !!body });
      if (body) obs.roleGuardDefined = true;
    }
  }
  // one level of helper: a call whose definition is in the blocks and which scopes by the principal
  for (const l of handler) {
    for (const m of l.text.matchAll(/\b(find\w+|get\w+|load\w+)\s*\(/g)) {
      const body = functionBody(blocks, m[1]);
      if (!body) continue;
      body.forEach((bl, i) => {
        if (DATA.test(bl.text)) {
          const st = statement(body, i);
          obs.helperData = { ...bl, stmt: st };
          if (OWNER_COL.test(st) && /\buser\.id\b|\bcurrent_user\b|\buser\.orgId\b/.test(st)) obs.helperScoping.push({ ...bl });
        }
      });
    }
  }
  void dynamicUnresolved;
  return obs;
}

function stripUntrustedKeepUser(t) { return stripUntrusted(t).replace(/""/g, '""'); }

function cite(l, role, claim) { return { role, file: l.file, startLine: l.n, endLine: l.n, claim }; }

/** A reader that cites a line says what is on it: the claim quotes the cited text, as a careful model would. */
function quoteCited(obj, blocks) {
  const text = (c) => {
    for (const b of blocks) if (b.file === c.file) { const l = b.lines.find(x => x.n === c.startLine); if (l) return l.text.trim().slice(0, 100); }
    return '';
  };
  const fix = (list) => (Array.isArray(list) ? list.map(c => ({ ...c, claim: `${c.claim}: ${text(c)}` })) : list);
  return { ...obj, evidence: fix(obj.evidence), observedMitigations: fix(obj.observedMitigations) };
}

/** The decision for a pack, from the observations. Returns the review JSON object. */
function decide(packId, obs, ctx) {
  const base = { observedMitigations: [], attackerControl: [], uncertainties: [], likelihood: 'low' };
  if (packId === 'authz-idor') {
    if (obs.capability) {
      return { ...base, evidence: [cite(obs.capability, 'data-access', 'looked up by an unguessable token')], observedMitigations: [{ kind: 'other', file: obs.capability.file, startLine: obs.capability.n, endLine: obs.capability.n, claim: 'capability token lookup' }], conclusion: ctx.complete ? 'no_issue_observed' : 'insufficient_evidence', invariant: 'object selected by identifier must be scoped', narrative: 'access is by capability token', uncertainties: ctx.complete ? [] : ['context incomplete'] };
    }
    const data = obs.data[0] || (obs.helperData ? { ...obs.helperData } : null);
    if (!obs.untrusted || !data) return { ...base, evidence: [], conclusion: 'insufficient_evidence', invariant: 'object selected by identifier must be scoped', uncertainties: ['no identifier-to-data path visible'] };
    const scoped = obs.scoping.length || obs.helperScoping.length;
    if (obs.writes.length && obs.lateScoping.length) {
      const w = obs.writes[0]; const g = obs.lateScoping[0];
      if (g.n > w.n) return { ...base, evidence: [cite(w, 'state-change', 'the write happens first'), cite(g, 'guard', 'the ownership check comes after it')], conclusion: 'potential_issue', invariant: 'object selected by identifier must be scoped before it is changed', narrative: 'the change is made before the owner is checked', attackerControl: ['req.params.id'], likelihood: 'high' };
    }
    if (obs.lateScoping.length && !obs.writes.length && obs.lateScoping[0].n >= data.n) {
      return { ...base, evidence: [cite(data, 'data-access', 'fetch'), cite(obs.lateScoping[0], 'guard', 'owner check')], observedMitigations: [{ kind: 'ownership', file: obs.lateScoping[0].file, startLine: obs.lateScoping[0].n, endLine: obs.lateScoping[0].n, claim: 'owner compared with the principal and rejected before use' }], conclusion: ctx.complete ? 'no_issue_observed' : 'insufficient_evidence', invariant: 'object selected by identifier must be scoped', narrative: 'fetched, then checked before use' };
    }
    if (scoped) {
      const s = obs.scoping[0] || obs.helperScoping[0];
      return { ...base, evidence: [cite(data, 'data-access', 'query'), cite(s, 'guard', 'filter by principal')], observedMitigations: [{ kind: 'ownership', file: s.file, startLine: s.n, endLine: s.n, claim: 'query is filtered by the authenticated principal' }], conclusion: ctx.complete ? 'no_issue_observed' : 'insufficient_evidence', invariant: 'object selected by identifier must be scoped', narrative: 'id is combined with the principal in the query', uncertainties: ctx.complete ? [] : ['context incomplete'] };
    }
    if (ctx.unresolved) return { ...base, evidence: [], conclusion: 'insufficient_evidence', invariant: 'object selected by identifier must be scoped', uncertainties: ['an unresolved call could contain the scoping'] };
    return { ...base, evidence: [cite(data, 'data-access', 'object fetched by a caller-controlled identifier')], conclusion: 'potential_issue', invariant: 'object selected by identifier must be scoped to the principal', narrative: 'the identifier flows into the query and nothing ties it to the caller', attackerControl: ['identifier'], likelihood: 'high' };
  }
  if (packId === 'authz-function') {
    if (obs.dynamic && ctx.unresolved) return { ...base, evidence: [], conclusion: 'insufficient_evidence', invariant: 'privileged action needs a role check', uncertainties: ['the action is chosen at runtime'] };
    if (obs.dynamic) return { ...base, evidence: [], conclusion: 'insufficient_evidence', invariant: 'privileged action needs a role check', uncertainties: ['the action is chosen at runtime'] };
    const act = obs.writes[0] || obs.data[0];
    if (!act) return { ...base, evidence: [], conclusion: 'insufficient_evidence', invariant: 'privileged action needs a role check', uncertainties: ['no privileged action visible'] };
    const defined = obs.roleGuards.find(g => g.where === 'handler' || g.where === 'middleware' || (g.where === 'use' && g.defined));
    if (defined) return { ...base, evidence: [cite(act, 'state-change', 'privileged change')], observedMitigations: [{ kind: 'role-check', file: defined.file, startLine: defined.n, endLine: defined.n, claim: 'role check precedes the action' }], conclusion: ctx.complete ? 'no_issue_observed' : 'insufficient_evidence', invariant: 'privileged action needs a role check', narrative: 'role check then action' };
    if (obs.roleGuards.length) return { ...base, evidence: [], conclusion: 'insufficient_evidence', invariant: 'privileged action needs a role check', uncertainties: ['a role guard is named but its body is not shown'] };
    if (ctx.unresolved) return { ...base, evidence: [], conclusion: 'insufficient_evidence', invariant: 'privileged action needs a role check', uncertainties: ['an unresolved call could contain the check'] };
    return { ...base, evidence: [cite(act, 'state-change', 'privileged change with no role check')], conclusion: 'potential_issue', invariant: 'privileged action needs a role check', narrative: 'only authentication stands in front of the action', likelihood: 'high' };
  }
  if (packId === 'transaction-integrity') {
    if (obs.writes.length >= 2 && !obs.transaction) return { ...base, evidence: [cite(obs.writes[0], 'state-change', 'first write'), cite(obs.writes[1], 'state-change', 'second write')], conclusion: 'potential_issue', invariant: 'dependent writes must be atomic', narrative: 'a failure between the two writes leaves them inconsistent' };
    if (obs.writes.length >= 2 && obs.transaction) return { ...base, evidence: [cite(obs.writes[0], 'state-change', 'write')], observedMitigations: [{ kind: 'other', file: obs.writes[0].file, startLine: obs.writes[0].n, endLine: obs.writes[0].n, claim: 'writes run inside a transaction' }], conclusion: ctx.complete ? 'no_issue_observed' : 'insufficient_evidence', invariant: 'dependent writes must be atomic' };
    return { ...base, evidence: [], conclusion: 'insufficient_evidence', invariant: 'dependent writes must be atomic' };
  }
  return { ...base, evidence: [], conclusion: 'insufficient_evidence', invariant: 'unspecified' };
}

/** The reader as an `llmInvoke`: prompt in, JSON text out. Handles both prompt formats. */
function scriptedReader() {
  const invoke = async (prompt) => {
    if (/^QUESTION PACK: /m.test(prompt)) {
      const packId = /^QUESTION PACK: ([\w-]+)\//m.exec(prompt)[1];
      const label = (/^ENTRY POINT LABEL \(data\): (.*)$/m.exec(prompt) || [])[1] || '';
      const { blocks, unresolved, notIncluded, limit } = blocksFromReviewPrompt(prompt);
      const routes = findRoutes(blocks);
      const [method, ...rest] = label.split(' ');
      const wantPath = rest.join(' ');
      const route = routes.find(r => r.path === wantPath && (r.method === method || r.method === 'ALL')) || routes.find(r => r.path === wantPath) || routes[0];
      if (!route) return JSON.stringify({ evidence: [], observedMitigations: [], conclusion: 'insufficient_evidence', invariant: 'unspecified', uncertainties: ['the registration is not in the provided context'] });
      const obs = analyseRoute(route, blocks);
      const complete = !unresolved && !notIncluded && !limit;
      return JSON.stringify(quoteCited(decide(packId, obs, { complete, unresolved }), blocks));
    }
    // hunt prompt: report the candidates for the lens, with a location
    const lens = /Your lens is ([\w ]+)\./.exec(prompt);
    const lensTitle = lens ? lens[1].trim() : '';
    const packId = lensTitle === 'Authorization' ? 'authz-idor' : lensTitle === 'Business logic' ? 'transaction-integrity' : null;
    const blocks = blocksFromHuntPrompt(prompt);
    const candidates = [];
    if (packId) {
      for (const route of findRoutes(blocks)) {
        const obs = analyseRoute(route, blocks);
        let d = decide(packId, obs, { complete: true, unresolved: false });
        if (packId === 'authz-idor' && /(?:role|admin|users\/:id\/role|purge|jobs)/.test(route.path + obs.handler.map(l => l.text).join(' '))) {
          const f = decide('authz-function', obs, { complete: true, unresolved: false });
          if (f.conclusion === 'potential_issue') d = f;
        }
        if (d.conclusion === 'potential_issue' && d.evidence.length) {
          const e = d.evidence[0];
          candidates.push({ title: `${route.method} ${route.path}: ${d.invariant}`, file: e.file, line: e.startLine, rationale: d.narrative || '', entryPoint: `${route.method} ${route.path}`, sink: e.claim });
        }
      }
    }
    return JSON.stringify({ candidates });
  };
  invoke.tokenizerName = 'chars/4-estimate';
  return invoke;
}

function readerIdentity() {
  return { kind: 'scripted-reader', version: 1, digest: node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash('sha256').update(scriptedReader.toString() + decide.toString() + analyseRoute.toString()).digest('hex').slice(0, 16), synthetic: true };
}


/***/ }),

/***/ 76159:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   HR: () => (/* binding */ recallOf),
/* harmony export */   YV: () => (/* binding */ wilsonInterval),
/* harmony export */   ij: () => (/* binding */ precisionOf),
/* harmony export */   jN: () => (/* binding */ groupedBootstrap),
/* harmony export */   li: () => (/* binding */ f1Of)
/* harmony export */ });
/* unused harmony exports INTERVAL_METHODS, seededRng, seedFor */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
// Documented 95% interval methods (QA-004.AC01).
//
// Two methods, each registered by name in the protocol (`thresholds.intervalMethod`) before any result is observed:
//
//   grouped-bootstrap-95   For F1, precision and recall, and for the micro and macro aggregates. Resamples GROUPS, not cases:
//                          targets that share a pair, upstream, advisory, commit or template (grouping.js) are one resampling
//                          unit, because treating near-duplicates as independent draws makes the interval narrower than the
//                          evidence supports. The percentile method over `replicates` resamples (default 2000), driven by a
//                          seeded generator, so the same score and protocol produce the same interval to the last digit.
//                          The seed is derived from the protocol hash: nobody picks a seed after seeing a result.
//   wilson-95              For a single proportion (the completion rate), where there is no group structure to resample.
//
// When there are too few groups for resampling to mean anything (`minGroups`, default 10), the interval is `unmeasured` with the
// reason, never a degenerate zero-width or a made-up range. An undefined statistic in a resample (no positives drawn) is skipped
// and counted, and a method that skips too many resamples is itself reported `unmeasured`.
//
// Pure: no fs, no clock, no Math.random.



const INTERVAL_METHODS = Object.freeze({
  'grouped-bootstrap-95': Object.freeze({
    level: 0.95,
    unit: 'target group (grouping.js union-find over pair, upstream, advisory, commit, template)',
    estimator: 'percentile',
    replicates: 2000,
    minGroups: 10,
    maxUndefinedFraction: 0.1,
    seed: 'first 32 bits of sha256(protocolHash + "|" + statisticName)',
  }),
  'wilson-95': Object.freeze({ level: 0.95, unit: 'case', estimator: 'wilson-score', z: 1.959964 }),
});

/** mulberry32: a small, well-distributed 32-bit generator. Deterministic for a given seed. */
function seededRng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** A 32-bit seed that depends only on the frozen protocol and the statistic's name. */
function seedFor(protocolHash, statisticName) {
  return node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash('sha256').update(`${protocolHash}|${statisticName}`).digest().readUInt32BE(0);
}

const quantile = (sorted, q) => {
  if (!sorted.length) return null;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos); const hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
};

const ZERO = () => ({ tp: 0, fn: 0, fp: 0, tn: 0 });
const add = (a, b) => { a.tp += b.tp; a.fn += b.fn; a.fp += b.fp; a.tn += b.tn; };

const f1Of = (c) => (c.tp + c.fp + c.fn === 0 ? null : (2 * c.tp) / (2 * c.tp + c.fp + c.fn));
const precisionOf = (c) => (c.tp + c.fp > 0 ? c.tp / (c.tp + c.fp) : null);
const recallOf = (c) => (c.tp + c.fn > 0 ? c.tp / (c.tp + c.fn) : null);

/**
 * Grouped percentile bootstrap.
 * @param {object} o
 * @param {{id: string, language: string, tp: number, fn: number, fp: number, tn: number}[]} o.units  per-target tallies
 * @param {Object<string,string>} o.groupOf  target id -> group id (a target with no entry is its own group)
 * @param {(agg: {total: object, byLanguage: Object<string,object>}) => (number|null)} o.statistic
 * @param {string} o.name        the statistic's name (feeds the seed)
 * @param {string} o.protocolHash
 */
function groupedBootstrap({ units, groupOf = {}, statistic, name, protocolHash, replicates = INTERVAL_METHODS['grouped-bootstrap-95'].replicates, minGroups = INTERVAL_METHODS['grouped-bootstrap-95'].minGroups, level = 0.95 }) {
  const method = 'grouped-bootstrap-95';
  const groups = new Map();
  for (const u of units || []) {
    const g = groupOf[u.id] || `solo:${u.id}`;
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(u);
  }
  const G = [...groups.keys()].sort();
  const aggOf = (members) => {
    const total = ZERO(); const byLanguage = {};
    for (const u of members) {
      add(total, u);
      byLanguage[u.language] = byLanguage[u.language] || ZERO();
      add(byLanguage[u.language], u);
    }
    return { total, byLanguage };
  };
  const all = aggOf(units || []);
  const point = statistic(all);
  const base = { method, level, replicates, groups: G.length, units: (units || []).length, point };
  if (G.length < minGroups) {
    return { ...base, status: 'unmeasured', low: null, high: null, reason: `${G.length} independent group${G.length === 1 ? '' : 's'}, fewer than the ${minGroups} needed for a resampling interval to mean anything` };
  }
  const rng = seededRng(seedFor(protocolHash, name));
  const perGroup = G.map((g) => aggOf(groups.get(g)));
  const draws = [];
  let undefinedDraws = 0;
  for (let r = 0; r < replicates; r++) {
    const total = ZERO(); const byLanguage = {};
    for (let i = 0; i < G.length; i++) {
      const pick = perGroup[Math.floor(rng() * G.length)];
      add(total, pick.total);
      for (const [lang, c] of Object.entries(pick.byLanguage)) { byLanguage[lang] = byLanguage[lang] || ZERO(); add(byLanguage[lang], c); }
    }
    const v = statistic({ total, byLanguage });
    if (v === null || v === undefined || Number.isNaN(v)) undefinedDraws++; else draws.push(v);
  }
  const maxUndef = INTERVAL_METHODS[method].maxUndefinedFraction;
  if (undefinedDraws / replicates > maxUndef) {
    return { ...base, status: 'unmeasured', low: null, high: null, undefinedDraws, reason: `the statistic was undefined in ${undefinedDraws} of ${replicates} resamples (more than ${maxUndef * 100}%), so the interval would describe a different population` };
  }
  draws.sort((a, b) => a - b);
  const alpha = (1 - level) / 2;
  return { ...base, status: 'measured', low: quantile(draws, alpha), high: quantile(draws, 1 - alpha), undefinedDraws, seed: seedFor(protocolHash, name) };
}

/** Wilson score interval for a proportion. n = 0 is unmeasured. */
function wilsonInterval(successes, n, z = INTERVAL_METHODS['wilson-95'].z) {
  const method = 'wilson-95';
  if (!Number.isInteger(successes) || !Number.isInteger(n) || n <= 0 || successes < 0 || successes > n) {
    return { method, level: 0.95, status: 'unmeasured', point: null, low: null, high: null, successes, n, reason: 'no cases' };
  }
  const p = successes / n; const z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  return { method, level: 0.95, status: 'measured', point: p, low: Math.max(0, centre - half), high: Math.min(1, centre + half), successes, n };
}


/***/ })

};
