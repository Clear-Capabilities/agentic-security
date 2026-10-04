// Disclosure of what a Haskell taint finding could not see (HS-005.AC03).
//
// The taint engine WIDENS across a call it cannot resolve (an unknown function's result is tainted when
// its arguments are), so a flow through an opaque target is kept rather than silently dropped or called
// safe. This pass says so: it walks backwards from a finding's sink argument through the assignments
// that feed it and records every call whose target is unresolved (higher-order parameter, unbound name,
// typeclass method with no visible instance) or opaque (foreign function), as an `uncertainty` entry
// with the reason, and marks the finding's resolution as partial. It adds evidence; it never removes a
// finding or changes its severity.

import { sourceInfo } from './haskell-models.js';

const OPAQUE = {
  unknown: (c) => ({ kind: 'unresolved-target', detail: `${c.callee}: ${(c.hs && c.hs.reason) || 'unresolved'}` }),
  param: (c) => ({ kind: 'unresolved-target', detail: `${c.callee}: higher-order parameter, the function actually passed is not known here` }),
  ffi: (c) => ({ kind: 'foreign-boundary', detail: `${c.callee}: foreign function, the code behind it is not analysed` }),
  typeclass: (c) => ((c.hs && c.hs.candidates && c.hs.candidates.length) ? null : { kind: 'unresolved-target', detail: `${c.callee}: typeclass method with no visible instance` }),
};

const kids = (e) => {
  const out = [];
  for (const k of ['left', 'right', 'object', 'value']) if (e[k] && typeof e[k] === 'object') out.push(e[k]);
  for (const k of ['args', 'elements', 'branches', 'parts']) if (Array.isArray(e[k])) out.push(...e[k]);
  if (Array.isArray(e.props)) for (const p of e.props) if (p && p.value) out.push(p.value);
  return out;
};

function* walk(e, depth = 0) {
  if (!e || typeof e !== 'object' || depth > 80) return;
  yield e;
  for (const c of kids(e)) yield* walk(c, depth + 1);
}

function identsOf(e) {
  const out = new Set();
  for (const x of walk(e)) if (x.kind === 'ident' && x.name) out.add(x.name);
  return out;
}

function nodeExprs(n) { return [n.source, n.value, n.cond, ...(n.kind === 'call' ? [{ kind: 'call', callee: n.callee, args: n.args || [], hs: n.hs }] : [])].filter(Boolean); }

/** @returns {Array<{kind:string, detail:string}>} */
export function unresolvedTargetsFor(fn, finding) {
  const nodes = Object.values(fn.cfg.nodes);
  // the sink call at the finding's line
  let sink = null;
  for (const n of nodes) {
    for (const root of nodeExprs(n)) {
      for (const e of walk(root)) if (!sink && e.kind === 'call' && e.callee === finding.callee && (e.line === finding.line || n.line === finding.line)) sink = e;
    }
  }
  if (!sink) return [];
  const arg = (sink.args || [])[Number.isInteger(finding.argIndex) ? finding.argIndex : 0];
  if (!arg) return [];
  const found = new Map();
  const seen = new Set();
  const stack = [arg];
  let guard = 0;
  while (stack.length && guard++ < 400) {
    const e = stack.pop();
    for (const x of walk(e)) {
      if (x.kind === 'call' && x.hs && OPAQUE[x.hs.status]) {
        const d = OPAQUE[x.hs.status](x);
        if (d) found.set(`${d.kind}|${d.detail}`, d);
      }
    }
    for (const name of identsOf(e)) {
      const key = name.replace(/\.[^.]*$/, '');
      if (seen.has(key)) continue;
      seen.add(key);
      for (const n of nodes) {
        if (n.kind === 'assign' && n.source && typeof n.target === 'string' && (n.target === key || n.target.startsWith(`${key}.`))) stack.push(n.source);
      }
    }
  }
  return [...found.values()];
}

export function annotateUnresolvedTargets(findings, perFile) {
  let n = 0;
  for (const f of findings || []) {
    if (!f || f.parser !== 'IR-TAINT' || !f._funcQid || !f.callee) continue;
    const ir = perFile && perFile[f.file];
    const fn = ir && ir.functions.find((x) => x.qid === f._funcQid);
    if (!fn) continue;
    let un;
    try { un = unresolvedTargetsFor(fn, f); } catch { continue; }
    if (!un.length) continue;
    f.uncertainty = [...(f.uncertainty || []), ...un];
    f.resolutionStatus = 'partial';
    n++;
  }
  return n;
}

// ── evidence chain ────────────────────────────────────────────────────────────
// The shared engine attributes a source only when a variable is assigned DIRECTLY from it, so a flow
// that passes through a record field or an intermediate binding arrives with an empty chain. The
// chain is rebuilt here from the IR instead: walk backwards from the sink argument through the
// assignments that feed it until a modelled source is reached, then report source -> ... -> sink in
// program order. Cross-function flows keep whatever the engine already recorded.
export function buildChain(fn, finding) {
  const nodes = Object.entries(fn.cfg.nodes).map(([id, n]) => ({ id, ...n })).sort((a, b) => Number(a.id.slice(1)) - Number(b.id.slice(1)));
  let sink = null; let sinkNodeIdx = -1;
  nodes.forEach((n, i) => {
    for (const root of nodeExprs(n)) for (const e of walk(root)) if (!sink && e.kind === 'call' && e.callee === finding.callee && (e.line === finding.line || n.line === finding.line)) { sink = e; sinkNodeIdx = i; }
  });
  if (!sink) return null;
  const arg = (sink.args || [])[Number.isInteger(finding.argIndex) ? finding.argIndex : 0];
  if (!arg) return null;
  const steps = [];
  const seen = new Set();
  let source = null;
  const queue = [{ expr: arg, before: sinkNodeIdx }];
  let guard = 0;
  while (queue.length && !source && guard++ < 300) {
    const { expr, before } = queue.shift();
    for (const x of walk(expr)) {
      if (x.kind === 'call' && typeof x.callee === 'string') { const info = sourceInfo(x.callee); if (info) { source = { line: x.line, label: info.label, provenance: info.provenance }; break; } }
    }
    if (source) break;
    for (const name of identsOf(expr)) {
      const root = name.replace(/\.[^.]*$/, '');
      for (let i = Math.min(before, nodes.length) - 1; i >= 0; i--) {
        const n = nodes[i];
        if (n.kind !== 'assign' || typeof n.target !== 'string' || !n.source) continue;
        if (!(n.target === name || n.target === root || n.target.startsWith(`${root}.`))) continue;
        const key = `${n.id}`;
        if (seen.has(key)) continue;
        seen.add(key);
        steps.push({ line: n.line, label: `${n.target} = ...` });
        queue.push({ expr: n.source, before: i });
      }
    }
  }
  if (!source) return null;
  const ordered = steps.filter((s) => s.line !== source.line || s.label).sort((a, b) => a.line - b.line);
  return [{ line: source.line, label: source.label, provenance: source.provenance }, ...ordered.filter((s) => s.line > source.line)];
}

/** The last hop of an evidence chain is the sink itself, so a SARIF code flow ends where the finding is reported. */
function appendSinkStep(f) {
  if (!Array.isArray(f.chain) || !f.chain.length) return;
  const sinkFile = (f.sink && f.sink.file) || f.file;
  const sinkLine = (f.sink && f.sink.line) || f.line;
  const last = f.chain[f.chain.length - 1];
  if (!Number.isInteger(sinkLine) || (last && last.kind === 'sink')) return;
  if (last && last.line === sinkLine && (last.file || f.file) === sinkFile && !/^source|standard input|stdin|argument|environment/i.test(String(last.label || ''))) { last.kind = 'sink'; return; }
  f.chain.push({ file: sinkFile, line: sinkLine, label: `sink: ${String(f.callee || '').replace(/^.*\./, '') || 'call'}`, kind: 'sink' });
}

export function attachEvidenceChains(findings, perFile) {
  let n = 0;
  for (const f of findings || []) {
    if (!f || f.parser !== 'IR-TAINT' || !f._funcQid || !f.callee) continue;
    if (Array.isArray(f.chain) && f.chain.length) { appendSinkStep(f); continue; }
    const ir = perFile && perFile[f.file];
    const fn = ir && ir.functions.find((x) => x.qid === f._funcQid);
    if (!fn) continue;
    let chain;
    try { chain = buildChain(fn, f); } catch { continue; }
    if (!chain || !chain.length) continue;
    f.chain = chain.map((c) => ({ file: f.file, line: c.line, label: c.label, ...(c.provenance ? { provenance: c.provenance } : {}) }));
    appendSinkStep(f);
    f.source = { file: f.file, line: chain[0].line, label: chain[0].label };
    if (chain[0].provenance) f.sourceProvenance = chain[0].provenance;
    n++;
  }
  return n;
}
