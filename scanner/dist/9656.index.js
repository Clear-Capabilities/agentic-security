export const id = 9656;
export const ids = [9656];
export const modules = {

/***/ 69656:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   cmdDataflowContracts: () => (/* binding */ cmdDataflowContracts),
/* harmony export */   cmdDataflowSinkQuery: () => (/* binding */ cmdDataflowSinkQuery),
/* harmony export */   cmdDataflowView: () => (/* binding */ cmdDataflowView),
/* harmony export */   cmdWitness: () => (/* binding */ cmdWitness),
/* harmony export */   planContract: () => (/* binding */ planContract)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_fs_promises__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(51455);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var _lineage_completion_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(15396);
// dag-commands.js: explicit, opt-in CLI entry points for the DAG-PRD capabilities that used to be library-only.
//
//   dataflow view         typed graph view over the signed DataFlowGraph (DAG-06) plus SCC condensation (DAG-01)
//   dataflow contracts    boundary contracts bound to parser-resolved sites, consumer seeding (DAG-08)
//   dataflow sink-query   demand-driven reverse taint for one sink site (DAG-02)
//   dataflow plan-cuts    its completion contract (the command itself lives in bin/agentic-security.js) (DAG-09)
//   witness build|verify  signed, replayable path witness bundles (DAG-10)
//
// Rules every command here follows:
//   * Nothing runs unless the user types the subcommand. A default scan never imports this module, so a default scan's
//     output is unchanged.
//   * Every report carries a completion record with the shared vocabulary complete | partial | cancelled | unavailable |
//     invalid. "No path found" is never reported as "no vulnerability": `negativeClaimAllowed` is false unless the
//     completion envelope proves an exhausted query over a complete model, and even then it is scoped to the modeled graph.
//   * Exit codes: 0 a report was produced (read its completion status), 1 nothing usable could be produced (unavailable or
//     invalid input data, a failed verification), 2 a usage error.
//
// Everything is read-only with respect to scan state. The only writes are the files the user names with --output / --out.






const err = (m) => process.stderr.write(`${m}\n`);

/** Write a JSON report to --output, or stdout. Returns an exit code on failure, null on success. */
async function emit(who, args, text) {
  const out = args.flags.output;
  if (out !== undefined && (typeof out !== 'string' || !out)) { err(`${who}: --output needs a path.`); return 2; }
  if (!out) { process.stdout.write(text); return null; }
  try {
    await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.mkdir(node_path__WEBPACK_IMPORTED_MODULE_2__.dirname(node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(out)), { recursive: true });
    await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.writeFile(node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(out), text);
  } catch (e) { err(`${who}: could not write --output: ${e.message}`); return 2; }
  return null;
}

function describe(who, completion) {
  if (completion.status === 'complete') return;
  err(`${who}: completion is ${completion.status}${completion.reasons.length ? ` (${completion.reasons.join(', ')})` : ''}. This is a statement about the modeled scope, not about the software.`);
}

const asInt = (v) => (v === undefined ? undefined : (/^\d+$/.test(String(v)) ? Number(v) : NaN));

// ---------------------------------------------------------------------------------------------------------------------
// plan-cuts completion contract (DAG-09)
// ---------------------------------------------------------------------------------------------------------------------

/**
 * Completion contract for a cut plan. A plan is `complete` only when a finite cut exists AND the graph it was computed over is
 * known complete. `no-flow` is `partial`: no modeled path between the selected sources and sinks is a statement about the
 * model, never evidence of safety. A placement is hypothetical, so a negative claim is never allowed here.
 */
function planContract(plan) {
  const reasons = [];
  if (plan.status !== 'complete-cut') reasons.push(`plan-${plan.status}`);
  if (plan.status === 'no-flow') reasons.push('no-modeled-path');
  for (const r of plan.completeness?.reasons ?? []) reasons.push(r.replace(/[^\w ,.:()-]/g, '').slice(0, 120));
  const complete = plan.status === 'complete-cut' && plan.completeness?.complete === true && reasons.length === 0;
  const c = (0,_lineage_completion_js__WEBPACK_IMPORTED_MODULE_3__/* .makeCompletion */ .Lv)({ status: complete ? 'complete' : 'partial', modelCoverage: plan.completeness?.complete ? 'complete' : 'partial', reasons, unit: 'cut-plan' });
  return { ...c, negativeClaimAllowed: false, hypothetical: true, verified: false };
}

// ---------------------------------------------------------------------------------------------------------------------
// shared project loading (source -> IR -> call graph) for the commands that analyse code
// ---------------------------------------------------------------------------------------------------------------------

async function loadProgram(root) {
  const { readTree } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 5950));
  const { buildProjectIR } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 5033));
  const tree = await readTree(root);
  const ir = buildProjectIR(tree.fileContents);
  return { fileContents: tree.fileContents, oversize: tree.oversize || [], perFile: ir.perFile, callGraph: ir.callGraph, cha: ir.cha };
}

// ---------------------------------------------------------------------------------------------------------------------
// dataflow view
// ---------------------------------------------------------------------------------------------------------------------

/**
 * agentic-security dataflow view [path] [--node <id> [--direction in|out|both] [--relations a,b] [--origins a,b]] [--output <file>]
 * Read-only over the signed lineage graph. Without --node it reports the view identity, counts, completion and the SCC
 * condensation of the data-flow relation. With --node it lists the neighbours the filter allows.
 */
async function cmdDataflowView(args) {
  const who = 'agentic-security dataflow view';
  const root = node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(args._[2] || '.');
  const f = args.flags;
  for (const k of ['node', 'direction', 'relations', 'origins']) {
    if (f[k] !== undefined && (typeof f[k] !== 'string' || !f[k])) { err(`${who}: --${k} needs a value.`); return 2; }
  }
  const direction = f.direction || 'both';
  if (!['in', 'out', 'both'].includes(direction)) { err(`${who}: --direction must be in, out or both.`); return 2; }
  if (f.node === undefined && (f.direction || f.relations || f.origins)) { err(`${who}: --direction, --relations and --origins apply to --node.`); return 2; }

  const { loadSignedGraph } = await __webpack_require__.e(/* import() */ 8922).then(__webpack_require__.bind(__webpack_require__, 18922));
  const loaded = loadSignedGraph(root);
  if (!loaded.ok) { err(`${who}: ${loaded.message}`); return 1; }
  const { dataflowView, GraphViewError } = await __webpack_require__.e(/* import() */ 3969).then(__webpack_require__.bind(__webpack_require__, 43969));
  const { computeScc, verifyScc } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 45034));

  let view;
  try { view = dataflowView(loaded.graph); } catch (e) { err(`${who}: the graph could not be viewed: ${e.message}`); return 1; }

  const report = {
    schema: 'agentic-security/graph-view-report@1',
    maturity: 'preview',
    identity: view.identity,
    metadata: view.metadata(),
    viewCompletion: view.completion(),
    note: 'A view is a read-only lens over the signed graph. An absent edge means the model has no such edge, not that the software has none.',
  };
  const completion = (0,_lineage_completion_js__WEBPACK_IMPORTED_MODULE_3__.completionOfGraph)(loaded.graph);

  if (f.node === undefined) {
    const nodeIds = view.entities('node').map((e) => e.localId);
    const edges = view.edges().filter((e) => e.relation === 'data_flow' && e.origin !== 'observed' && e.origin !== 'declared');
    const pairs = edges.map((e) => [e.from.localId, e.to.localId]);
    const known = new Set(nodeIds);
    const scc = computeScc({ nodes: nodeIds, edges: pairs.filter(([a, b]) => known.has(a) && known.has(b)) });
    const verify = verifyScc({ nodes: nodeIds, edges: pairs.filter(([a, b]) => known.has(a) && known.has(b)) }, scc);
    const recursive = scc.components.filter((c) => c.recursive);
    report.condensation = {
      relation: 'data_flow',
      origins: ['code', 'derived', 'schema'],
      nodeCount: nodeIds.length,
      componentCount: scc.components.length,
      cyclicComponentCount: recursive.length,
      cyclicComponents: recursive.slice(0, 20).map((c) => c.members),
      isAcyclic: recursive.length === 0,
      condensationEdgeCount: scc.condensationEdges.length,
      verified: verify.ok === true,
      verificationProblems: verify.problems.slice(0, 5),
      note: 'The raw graph is preserved. The condensation is a derived view, acyclic by construction; a cyclic component is reported, never removed.',
    };
  } else {
    const filter = { relations: f.relations ? f.relations.split(',').map((s) => s.trim()).filter(Boolean) : undefined, origins: f.origins ? f.origins.split(',').map((s) => s.trim()).filter(Boolean) : undefined };
    try {
      const ref = view.ref('node', f.node);
      const lite = (e) => ({ id: e.id, relation: e.relation, origin: e.origin, from: e.from.localId, to: e.to.localId, evidence: e.evidence, unknowns: e.unknowns });
      report.query = {
        node: view.node(ref).summary ?? null, nodeId: f.node, direction, filter,
        incoming: direction === 'out' ? undefined : view.incoming(ref, filter).map(lite),
        outgoing: direction === 'in' ? undefined : view.outgoing(ref, filter).map(lite),
      };
    } catch (e) {
      if (e instanceof GraphViewError) {
        report.completion = (0,_lineage_completion_js__WEBPACK_IMPORTED_MODULE_3__/* .makeCompletion */ .Lv)({ status: 'invalid', reasons: [`graph-view-${String(e.code).toLowerCase()}`], unit: 'graph-view' });
        const code = await emit(who, args, JSON.stringify(report, null, 2) + '\n');
        err(`${who}: ${e.message}`);
        return code ?? 1;
      }
      throw e;
    }
  }
  report.completion = { ...completion, negativeClaimAllowed: false };
  const code = await emit(who, args, JSON.stringify(report, null, 2) + '\n');
  if (code !== null) return code;
  describe(who, completion);
  return 0;
}

// ---------------------------------------------------------------------------------------------------------------------
// dataflow contracts
// ---------------------------------------------------------------------------------------------------------------------

/**
 * agentic-security dataflow contracts [path] [--contracts <file>] [--output <file>]
 * Binds boundary contracts to parser-resolved sites and runs the taint engine with the consumer fields seeded. A declaration
 * is a MODELED input: every attribution carries modeledInput:true, observed:false, exploited:false. A contract that does not
 * bind becomes a coverage gap and never a finding.
 */
async function cmdDataflowContracts(args) {
  const who = 'agentic-security dataflow contracts';
  const root = node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(args._[2] || '.');
  const f = args.flags;
  if (f.contracts !== undefined && (typeof f.contracts !== 'string' || !f.contracts)) { err(`${who}: --contracts needs a path.`); return 2; }
  const { BOUNDARY_CONTRACTS_FILENAME, validateBoundaryContract, analyzeServiceBoundaries } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 39435));
  const { statePath } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 92582));

  const file = f.contracts ? node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(f.contracts) : statePath(root, BOUNDARY_CONTRACTS_FILENAME);
  let text;
  try { text = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file, 'utf8'); } catch {
    const completion = (0,_lineage_completion_js__WEBPACK_IMPORTED_MODULE_3__/* .makeCompletion */ .Lv)({ status: 'unavailable', reasons: ['no-contracts-file'], unit: 'boundary-contracts' });
    const code = await emit(who, args, JSON.stringify({ schema: 'agentic-security/boundary-contracts-report@1', maturity: 'preview', contractsFile: file, completion: { ...completion, negativeClaimAllowed: false }, findings: [], note: 'No contracts were read, so nothing was analysed. This says nothing about the software.' }, null, 2) + '\n');
    err(`${who}: no contracts file at ${file}. Pass --contracts <file> or write ${BOUNDARY_CONTRACTS_FILENAME} under the project state directory.`);
    return code ?? 1;
  }
  let contracts;
  try {
    const doc = JSON.parse(text);
    contracts = Array.isArray(doc) ? doc : Array.isArray(doc && doc.contracts) ? doc.contracts : null;
    if (!contracts) throw new Error('expected a JSON array of contracts or { "contracts": [...] }');
  } catch (e) { err(`${who}: ${file} is not a usable contracts document: ${e.message}`); return 2; }

  const program = await loadProgram(root);
  const { runBoundaryTaint } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 87516));
  const res = runBoundaryTaint(program.perFile, program.callGraph, contracts, { scanRoot: root, engine: { _cha: program.cha || undefined } });

  const reasons = [];
  if (res.rejected.length) reasons.push('rejected-contracts');
  if (res.gaps.length) reasons.push('unbound-boundary');
  if (res.coverage.truncated) reasons.push('engine-run-budget');
  if (program.oversize.length) reasons.push('oversize-source-skipped');
  if (contracts.length === 0) reasons.push('no-contracts');
  const status = contracts.length === 0 || (res.rejected.length === contracts.length) ? 'unavailable' : reasons.length ? 'partial' : 'complete';
  const completion = { ...(0,_lineage_completion_js__WEBPACK_IMPORTED_MODULE_3__/* .makeCompletion */ .Lv)({ status, reasons, unit: 'boundary-contracts' }), negativeClaimAllowed: false };

  const valid = contracts.filter((c) => validateBoundaryContract(c).valid);
  const report = {
    schema: 'agentic-security/boundary-contracts-report@1',
    maturity: 'preview',
    contractsFile: file,
    completion,
    coverage: res.coverage,
    bindings: res.bindings.map((b) => ({ contractId: b.contractId, kind: b.kind, persistence: b.persistence, channel: b.channel, file: b.file, line: b.line, param: b.param, seeds: b.seeds, mappedFields: b.mappedFields, evidence: b.evidence })),
    gaps: res.gaps,
    rejected: res.rejected,
    findings: res.findings.map((x) => ({ id: x.id, severity: x.severity, file: x.file, line: x.line, vuln: x.vuln, cwe: x.cwe, boundary: x.boundary })),
    services: analyzeServiceBoundaries(valid),
    notes: [
      'A contract declaration establishes a modeled untrusted input at the consumer. It does not establish that any value was observed or that the sink is exploited.',
      'No finding does not mean the consumer is safe: only the declared fields were seeded, only the modeled sinks were checked.',
    ],
  };
  const code = await emit(who, args, JSON.stringify(report, null, 2) + '\n');
  if (code !== null) return code;
  describe(who, completion);
  return status === 'unavailable' ? 1 : 0;
}

// ---------------------------------------------------------------------------------------------------------------------
// dataflow sink-query
// ---------------------------------------------------------------------------------------------------------------------

/**
 * agentic-security dataflow sink-query [path] (--list | --file <rel> --line <n>) [--mode demand|full|compare]
 *   [--arg-index <n>] [--sink-id <id>] [--access-path <p>] [--rule-family <cwe|family>] [--max-work <n>] [--max-caller-depth <n>]
 *   [--on-limit full|partial] [--output <file>]
 * Answers "can attacker data reach this sink?" by selecting the backward demand region and running the ordinary forward taint
 * engine over it. The only witness is a finding the forward engine produced. Verdicts: flow-found, no-flow-in-modeled-scope
 * (only when the completion envelope allows a negative claim) and unknown. There is no "safe".
 */
async function cmdDataflowSinkQuery(args) {
  const who = 'agentic-security dataflow sink-query';
  const root = node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(args._[2] || '.');
  const f = args.flags;
  const mode = f.mode || 'demand';
  if (!['demand', 'full', 'compare'].includes(mode)) { err(`${who}: --mode must be demand, full or compare.`); return 2; }
  for (const k of ['file', 'sink-id', 'access-path', 'rule-family']) {
    if (f[k] !== undefined && (typeof f[k] !== 'string' || !f[k])) { err(`${who}: --${k} needs a value.`); return 2; }
  }
  const nums = { line: asInt(f.line), argIndex: asInt(f['arg-index']), maxWork: asInt(f['max-work']), maxCallerDepth: asInt(f['max-caller-depth']) };
  for (const [k, v] of Object.entries(nums)) if (Number.isNaN(v)) { err(`${who}: --${k.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`)} must be a non-negative integer.`); return 2; }
  const onLimit = f['on-limit'] || 'full';
  if (!['full', 'partial'].includes(onLimit)) { err(`${who}: --on-limit must be full or partial.`); return 2; }
  if (!f.list && (!f.file || nums.line === undefined)) { err(`Usage: ${who} [path] (--list | --file <rel> --line <n>) [--mode demand|full|compare] [--arg-index <n>] [--sink-id <id>] [--access-path <p>] [--rule-family <f>] [--max-work <n>] [--max-caller-depth <n>] [--on-limit full|partial] [--output <file>]`); return 2; }

  const program = await loadProgram(root);
  const dq = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 44625));
  if (!program.callGraph || !program.callGraph.functions || program.callGraph.functions.size === 0) {
    const completion = { ...(0,_lineage_completion_js__WEBPACK_IMPORTED_MODULE_3__/* .makeCompletion */ .Lv)({ status: 'unavailable', reasons: ['no-call-graph'], unit: 'demand-query' }), negativeClaimAllowed: false };
    const code = await emit(who, args, JSON.stringify({ schema: 'agentic-security/sink-query-report@1', maturity: 'preview', completion, verdict: 'unknown', note: 'No analyzable functions were found, so nothing was queried.' }, null, 2) + '\n');
    err(`${who}: no analyzable functions under ${root}.`);
    return code ?? 1;
  }
  if (f.list) {
    const sites = dq.enumerateSinkQueries(program.callGraph);
    const code = await emit(who, args, JSON.stringify({ schema: 'agentic-security/sink-query-report@1', maturity: 'preview', sites, count: sites.length, note: 'Sink sites the call graph and catalog recognise. A site that is not listed may still be a sink the catalog does not model.' }, null, 2) + '\n');
    return code ?? 0;
  }
  const query = { file: f.file.replace(/^\.\//, ''), line: nums.line, argIndex: nums.argIndex ?? null, sinkId: f['sink-id'] ?? null, accessPath: f['access-path'] ?? null, ruleFamily: f['rule-family'] ?? null };
  const opts = { cache: false, onLimit, engineOpts: { _cha: program.cha || undefined } };
  if (nums.maxWork !== undefined) opts.maxWork = nums.maxWork;
  if (nums.maxCallerDepth !== undefined) opts.maxCallerDepth = nums.maxCallerDepth;

  const result = {};
  if (mode === 'demand' || mode === 'compare') result.demand = dq.runDemandSinkQuery(program.perFile, program.callGraph, query, opts);
  if (mode === 'full' || mode === 'compare') result.full = dq.runFullSinkQuery(program.perFile, program.callGraph, query, opts);
  if (mode === 'compare') result.comparison = dq.compareToFull(result.demand, result.full);
  const primary = result.demand || result.full;
  // The full-set run has no frontier, so its completion is the engine's own incomplete list.
  const completion = result.demand
    ? { ...result.demand.completion, negativeClaimAllowed: result.demand.negativeClaimAllowed === true }
    : { ...(0,_lineage_completion_js__WEBPACK_IMPORTED_MODULE_3__/* .makeCompletion */ .Lv)({ status: primary.sites.length === 0 ? 'unavailable' : (primary.engineIncomplete || []).length ? 'partial' : 'complete', reasons: primary.sites.length === 0 ? ['sink-site-not-found'] : (primary.engineIncomplete || []).map((r) => `engine:${r}`), unit: 'full-sink-query' }), negativeClaimAllowed: false };
  const report = {
    schema: 'agentic-security/sink-query-report@1',
    maturity: 'preview',
    optIn: 'explicit subcommand; a default scan never runs this',
    mode,
    query,
    completion,
    verdict: result.demand ? result.demand.verdict : (primary.findings.length ? 'flow-found' : 'unknown'),
    ...result,
    notes: [
      'A backward and forward intersection is a candidate filter only. The witness is a finding the forward engine produced over the selected region.',
      'no-flow-in-modeled-scope is scoped to the modeled call graph. It is never a statement that the sink is safe.',
    ],
  };
  const code = await emit(who, args, JSON.stringify(report, null, 2) + '\n');
  if (code !== null) return code;
  describe(who, completion);
  return completion.status === 'unavailable' ? 1 : 0;
}

// ---------------------------------------------------------------------------------------------------------------------
// witness build | verify
// ---------------------------------------------------------------------------------------------------------------------

function insideRoot(root, rel) {
  const abs = node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(root, rel);
  return abs === root || abs.startsWith(root + node_path__WEBPACK_IMPORTED_MODULE_2__.sep) ? abs : null;
}

/**
 * agentic-security witness build [path] --out <dir> [--sink <pnodeId>] [--list-sinks]
 * Re-runs the field-identity analysis over the project (the hop stream is not persisted by a normal scan), reconstructs a
 * bounded path, and writes <dir>/witness.json (signed with the install's Ed25519 attestation key) plus the artifacts replay
 * needs: <dir>/artifacts/graph.json and <dir>/artifacts/provenance.json. Source blobs are bound by digest and re-read from
 * the project at verify time; they are not copied.
 */
async function witnessBuild(args) {
  const who = 'agentic-security witness build';
  const root = node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(args._[2] || '.');
  const f = args.flags;
  for (const k of ['out', 'sink']) if (f[k] !== undefined && (typeof f[k] !== 'string' || !f[k])) { err(`${who}: --${k} needs a value.`); return 2; }
  if (!f.out && !f['list-sinks']) { err(`Usage: ${who} [path] --out <dir> [--sink <pnodeId>] | --list-sinks`); return 2; }

  const program = await loadProgram(root);
  const { buildDataFlowGraph } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 30462));
  const { sinkCandidates, reconstructPaths } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 98684));
  const { buildWitnessBundle, signWitnessBundle, exportProvenanceArtifact } = await __webpack_require__.e(/* import() */ 2918).then(__webpack_require__.bind(__webpack_require__, 12918));
  if (!program.callGraph || !program.callGraph.functions || program.callGraph.functions.size === 0) {
    err(`${who}: unavailable: no analyzable functions under ${root}. Nothing was analysed, which says nothing about the software.`);
    return 1;
  }
  const built = buildDataFlowGraph(program.callGraph, { repository: node_path__WEBPACK_IMPORTED_MODULE_2__.basename(root) || 'repo' });
  const { graph, store, hops } = built;
  const incomplete = built.analysisCompletion?.incomplete || [];
  const provenance = exportProvenanceArtifact({ hops, incomplete });
  const sinks = sinkCandidates(store).filter((n) => n.kind === 'escape');

  if (f['list-sinks']) {
    const code = await emit(who, args, JSON.stringify({ schema: 'agentic-security/witness-sinks@1', maturity: 'preview', sinks: sinks.map((n) => ({ id: n.id, kind: n.kind, scope: n.scope, path: n.path ?? null })) }, null, 2) + '\n');
    return code ?? 0;
  }
  const pool = f.sink ? sinks.filter((n) => n.id === f.sink) : sinks;
  if (f.sink && pool.length === 0) { err(`${who}: invalid: ${f.sink} is not a sink candidate (use --list-sinks).`); return 2; }

  let chosen = null;
  for (const s of pool) {
    const result = reconstructPaths(store, s.id, {});
    const withEdges = (result.paths || []).filter((p) => (p.edgeIds || []).length > 0);
    const path0 = withEdges.find((p) => p.crossScopeCount > 0) || withEdges[0];
    if (path0) { chosen = { result, path: path0, sink: s }; break; }
  }
  if (!chosen) {
    err(`${who}: unavailable: the analysis found no modeled path to witness (${sinks.length} sink candidate(s)). This is a statement about the model, not evidence that the software is safe.`);
    return 1;
  }
  const sourceBlobs = {};
  for (const [file, content] of Object.entries(program.fileContents)) sourceBlobs[file] = content;
  const b = buildWitnessBundle({ result: chosen.result, path: chosen.path, store, graph, provenance, sourceBlobs });
  if (!b.ok) { err(`${who}: invalid: ${b.reason}`); return 1; }

  const { ensureKeyPair } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 86381));
  const kp = ensureKeyPair();
  if (kp.created) err(`Generated a new signing key at ${kp.privateKey} (public: ${kp.publicKey}).`);
  const signed = signWitnessBundle(b.bundle, kp.privateKeyPem);

  const outDir = node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(f.out);
  try {
    node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(outDir, 'artifacts'), { recursive: true });
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(outDir, 'witness.json'), JSON.stringify(signed, null, 2) + '\n');
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(outDir, 'artifacts', 'graph.json'), JSON.stringify(graph));
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(outDir, 'artifacts', 'provenance.json'), JSON.stringify(provenance));
  } catch (e) { err(`${who}: could not write --out: ${e.message}`); return 2; }

  const overall = signed.completion?.overall || 'partial';
  console.log(`Wrote ${node_path__WEBPACK_IMPORTED_MODULE_2__.join(outDir, 'witness.json')} (completion: ${overall}).`);
  console.log(`Public key (share this with whoever verifies): ${kp.publicKey}`);
  if (overall !== 'complete') err(`${who}: completion is ${overall}. A partial witness never supports a "no vulnerability" claim.`);
  console.log('A valid signature proves the bundle is unmodified. It does not prove the finding is real or exploitable.');
  return 0;
}

/**
 * agentic-security witness verify <bundle.json> [--public-key <path>] [--artifacts <dir>] [--root <project>] [--json]
 * Integrity check with a public key; with --artifacts also an offline replay of every edge against the recorded artifacts.
 * Source blobs are read from --root (default: none, which fails replay honestly when the bundle binds sources).
 */
async function witnessVerify(args) {
  const who = 'agentic-security witness verify';
  const f = args.flags;
  const file = f.bundle || args._[2];
  if (!file || typeof file !== 'string') { err(`Usage: ${who} <bundle.json> [--public-key <path>] [--artifacts <dir>] [--root <project>] [--json]`); return 2; }
  const { parseWitnessBundle, verifyWitness } = await __webpack_require__.e(/* import() */ 2918).then(__webpack_require__.bind(__webpack_require__, 12918));
  const { keyPaths } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 86381));
  let text;
  try { text = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(file), 'utf8'); } catch (e) { err(`${who}: could not read bundle: ${e.message}`); return 2; }
  const parsed = parseWitnessBundle(text);
  if (!parsed.ok) { err(`${who}: invalid: ${parsed.reason}`); return 1; }
  const keyFile = f['public-key'] || keyPaths().publicKey;
  let pub;
  try { pub = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(keyFile), 'utf8'); } catch { err(`${who}: could not read public key at ${keyFile}. Pass --public-key <path>.`); return 2; }

  let artifacts = null;
  if (f.artifacts !== undefined) {
    if (typeof f.artifacts !== 'string' || !f.artifacts) { err(`${who}: --artifacts needs a directory.`); return 2; }
    const dir = node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(f.artifacts);
    try {
      artifacts = { graph: JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, 'graph.json'), 'utf8')), provenance: JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, 'provenance.json'), 'utf8')), sources: {} };
    } catch (e) { err(`${who}: could not read artifacts in ${dir}: ${e.message}`); return 2; }
    if (f.root) {
      const root = node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(String(f.root));
      for (const s of parsed.bundle.sources || []) {
        const abs = typeof s.file === 'string' ? insideRoot(root, s.file) : null;
        if (!abs) continue;
        try { if (node_fs__WEBPACK_IMPORTED_MODULE_0__.lstatSync(abs).isFile()) artifacts.sources[s.file] = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(abs); } catch { /* a missing blob fails replay by name */ }
      }
    }
  }
  const res = verifyWitness(parsed.bundle, pub, artifacts);
  if (f.json) process.stdout.write(JSON.stringify({ schema: 'agentic-security/witness-verification@1', verdict: res.verdict, ok: res.ok, signature: res.signature, replay: res.replay, completion: parsed.bundle.completion?.overall ?? null, evidence: parsed.bundle.evidence, statement: res.statement }, null, 2) + '\n');
  else {
    console.log(res.ok ? `VALID (${res.verdict})` : `INVALID (${res.verdict}): ${res.signature.ok ? res.replay.failures.map((x) => `${x.code}: ${x.detail}`).join('; ') : res.signature.reason}`);
    console.log(`  bundle completion: ${parsed.bundle.completion?.overall}`);
    for (const [k, v] of Object.entries(parsed.bundle.evidence || {})) console.log(`  ${k}: ${v.status}`);
    if (res.verdict === 'integrity-only') console.log('  Replay was not performed. Pass --artifacts <dir> --root <project> to re-derive the path.');
    console.log(`  ${res.statement.doesNotProve}`);
  }
  return res.ok ? 0 : 1;
}

async function cmdWitness(args) {
  const sub = args._[1];
  if (sub === 'build') return witnessBuild(args);
  if (sub === 'verify') return witnessVerify(args);
  err(`agentic-security witness: unrecognized sub-command "${sub}"; must be "build" or "verify".`);
  return 2;
}


/***/ })

};
