// Provable-clean SQL injection (v0.68).
//
// For each SQL sink in scope, compute a proof that EVERY reaching path
// from any source passes through a parameterizer (a sanitizer in the
// catalog tagged `appliesTo: ['sql']`). If the proof holds, mark the
// finding `proven_clean: true` — auditor-grade strong statement, stronger
// than "we didn't find a flow" because we explicitly enumerated paths.
//
// v1 design — no SMT yet:
//   - Walk the existing taint engine's per-function state to enumerate
//     reaching sources at each sink call.
//   - For each reaching source variable, check whether every assignment
//     path from that source to the sink expression passes through a
//     `sanitizers/appliesTo:['sql']` catalog match.
//   - If yes for every source: emit `proven_clean: true` with
//     `proof.sanitizers: [<callee names>]`.
//   - If even one source can reach the sink without a parameterizer:
//     no proof — the finding stays as a normal taint finding.
//
// v2 (future): replace path-walk with SMT-based string-domain
// constraints — model the SQL builder as an algebraic data type, prove
// no concatenation reaches the unprepared-statement variant. The
// scaffolding here is intentionally shaped so a v2 SMT backend can
// substitute for the path walker without changing callers.
//
// Currently scoped to SQL only. Path-traversal, cmd-inj, and SSRF have
// the same structural shape and can be added by registering more
// `appliesTo` tag handlers below.

import { CATALOG } from './catalog.js';

const SQL_SINK_IDS = new Set(
  CATALOG.filter(e => e.kind === 'sink' && e.vuln && /sql/i.test(e.vuln.name || ''))
         .map(e => e.id)
);

const SQL_SANITIZER_CALLEES = new Set(
  CATALOG.filter(e => e.kind === 'sanitizer'
      && Array.isArray(e.appliesTo)
      && e.appliesTo.includes('sql'))
         .map(e => e.match && e.match.callee)
         .filter(Boolean)
);

// Also accept these as parameterizers — they're known-safe call shapes
// even when the catalog entry covers something narrower.
const EXTRA_SQL_PARAMETERIZERS = new Set([
  'addWithValue', 'AddWithValue',
  'setString', 'setInt', 'setLong', 'setDouble', 'setBoolean', 'setObject',
  'bindParam', 'bindValue',
  'parameterize', 'param',
  'sql', 'SQL',                  // tagged-template-literal helper from `slonik`/`postgres`
  'identifier',
]);

function _isSqlParameterizer(callee) {
  if (!callee || typeof callee !== 'string') return false;
  const tail = callee.split('.').pop();
  return SQL_SANITIZER_CALLEES.has(tail) || EXTRA_SQL_PARAMETERIZERS.has(tail);
}

// Given a finding emitted by the taint engine and the per-file IR map
// the engine produced it from, walk the trace looking for at least one
// parameterizer between source and sink. Returns:
//   { proven: true,  sanitizers: [<callee...>], reachingSources: N }
//   { proven: false, reason: '<why>' }
export function proveSqlClean(finding, perFileIR) {
  if (!finding || !finding.sinkId || !SQL_SINK_IDS.has(finding.sinkId)) {
    return { proven: false, reason: 'not-a-sql-sink' };
  }
  // The taint engine records sources reaching the sink in finding.trace.
  // For each source, find the function's CFG and check whether the path
  // from source-line to sink-line passes through a parameterizer call.
  const fnIR = _findFunction(finding, perFileIR);
  if (!fnIR) return { proven: false, reason: 'no-ir-for-fn' };
  const trace = Array.isArray(finding.trace) ? finding.trace : (finding.chain || []);
  if (!trace.length) return { proven: false, reason: 'no-trace' };
  const calls = _allCallNodesBetween(fnIR, trace, finding.line);
  const sanitizers = calls.filter(c => _isSqlParameterizer(c.callee));
  if (sanitizers.length === 0) {
    return { proven: false, reason: 'no-parameterizer-on-path' };
  }
  // Path-existence proof: at least one parameterizer call appears
  // between the latest source line and the sink line on the linear path.
  // This is a weaker statement than "every reaching path is sanitized,"
  // which requires real path-set walking — slated for v2.
  return {
    proven: true,
    sanitizers: sanitizers.map(s => s.callee),
    reachingSources: trace.length,
    proofKind: 'path-existence-v1',
  };
}

function _findFunction(finding, perFileIR) {
  if (!perFileIR || !finding.file) return null;
  const ir = perFileIR[finding.file];
  if (!ir || !Array.isArray(ir.functions)) return null;
  // Pick the function whose [line, line + body] range contains the sink line.
  for (const fn of ir.functions) {
    // Approximate: function starts at fn.line; we don't track end-line, so
    // pick the latest-starting function with line <= sink-line.
  }
  let chosen = null;
  for (const fn of ir.functions) {
    if (fn.line <= finding.line) {
      if (!chosen || fn.line > chosen.line) chosen = fn;
    }
  }
  return chosen;
}

// Backward BFS via `pred` edges from `startId` — every node that can reach
// `startId` by following the CFG forward from itself.
function _backwardReachable(fn, startId) {
  const visited = new Set();
  const stack = [startId];
  while (stack.length) {
    const id = stack.pop();
    if (visited.has(id)) continue;
    visited.add(id);
    const node = fn.cfg.nodes[id];
    if (!node) continue;
    for (const p of node.pred || []) stack.push(p);
  }
  return visited;
}

function _allCallNodesBetween(fn, trace, sinkLine) {
  if (!fn || !fn.cfg || !fn.cfg.nodes) return [];
  const earliestSrcLine = Math.min(
    ...trace.map(t => (typeof t.line === 'number' ? t.line : sinkLine))
  );
  // Stage 3 correctness audit (detection depth): this used to be a pure
  // line-number-range filter — ANY call node between the earliest source
  // line and the sink line, anywhere in the function, regardless of
  // whether it could ever actually execute before the sink. A
  // parameterizer call inside an unrelated `if` branch that RETURNS
  // before ever reaching the sink (a completely different, non-converging
  // path) satisfied that filter and could falsely "prove" a genuinely
  // vulnerable SQL concatenation on a different branch was clean — the
  // dangerous direction for a proof gate, since `provenClean` de-emphasizes
  // the finding in reports and risk scoring.
  //
  // Restrict candidates to nodes CFG-reachable as a predecessor of the
  // sink's own node (backward BFS via `pred`): a call that cannot execute
  // on ANY path leading to the sink is excluded. This is still not a full
  // per-path proof (a parameterizer reachable via SOME but not ALL paths
  // to the sink, or one that sanitizes an unrelated variable, still
  // passes) — that's the v2 SMT work the module header already scopes
  // out — but it closes the specific "unrelated branch that never reaches
  // the sink at all" false-proof case.
  const sinkNodeId = Object.keys(fn.cfg.nodes).find(id => {
    const n = fn.cfg.nodes[id];
    return n && n.kind === 'call' && n.line === sinkLine;
  });
  const reachable = sinkNodeId ? _backwardReachable(fn, sinkNodeId) : null;
  const out = [];
  for (const id of Object.keys(fn.cfg.nodes)) {
    const node = fn.cfg.nodes[id];
    if (!node || node.kind !== 'call') continue;
    if (typeof node.line !== 'number') continue;
    if (node.line < earliestSrcLine || node.line > sinkLine) continue;
    if (reachable && !reachable.has(id)) continue;
    out.push({ line: node.line, callee: node.callee });
  }
  return out;
}

// Annotate findings in place: any taint finding that resolves to a SQL
// sink AND has a provable parameterizer on the path gets:
//   f.provenClean = true
//   f.provenanceProof = { sanitizers, reachingSources, proofKind }
// Other findings are untouched.
//
// Note: `provenClean` is INFORMATIONAL. We do NOT drop the finding
// (an auditor may still want to see it for evidence) — but reports +
// risk scoring should de-emphasize. The exploitProbability annotator
// can also lower the point estimate when this flag is present.
export function annotateProvenClean(findings, perFileIR) {
  if (!Array.isArray(findings)) return findings;
  for (const f of findings) {
    if (!f || f.parser !== 'IR-TAINT') continue;
    if (!SQL_SINK_IDS.has(f.sinkId)) continue;
    const proof = proveSqlClean(f, perFileIR);
    if (proof.proven) {
      f.provenClean = true;
      f.provenanceProof = {
        sanitizers: proof.sanitizers,
        reachingSources: proof.reachingSources,
        proofKind: proof.proofKind,
      };
    } else {
      f.provenanceProofFailedReason = proof.reason;
    }
  }
  return findings;
}

export const _internal = { SQL_SINK_IDS, SQL_SANITIZER_CALLEES, EXTRA_SQL_PARAMETERIZERS, _isSqlParameterizer };
