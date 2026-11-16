// Candidate patches (verified-remediation PRD FR-07, section 6.3): proposers, identity and the scope gate.
//
// Proposers return file contents only. The trusted coordinator computes everything authoritative: the candidate id and patch digest,
// the actual diff (patch-scope.js), the edit-scope and protected-path checks and the test-surface check. A proposer's counts, claims or
// self-reported results are never read.
//
//   sqlParameterizeRecipe  deterministic recipe: `<db>.prepare(`...'${v}'...`).all|get|run|iterate()` becomes a prepared statement with
//                          `?` placeholders and the values passed as arguments. Preconditions, all required, or the recipe does not
//                          apply: every interpolation sits exactly inside a single-quoted SQL literal ('${v}'), the statement is called
//                          immediately with no arguments, and the file is one of the contract's allowed files. An interpolation in any
//                          other position (an identifier, a number, an ORDER BY) is refused: placeholders cannot carry it.
//   queueProposer          user-supplied candidates, consumed in order across rounds (a scripted refinement, or a person's patches).
//
// A model proposer is not part of this milestone; its absence is reported, never filled with a stand-in.
import path from 'node:path';
import { digestOf } from '../posture/assurance/identity.js';
import { computePatchScope } from '../fix/patch-scope.js';
import { testSurfaceChanges } from '../fix/test-results.js';
import { SCHEMAS, SCHEMA_VERSION, candidateIdOf, validateCandidate } from './schemas.js';

export const RECIPE_SQL_PARAMETERIZE = Object.freeze({ id: 'sql-parameterize-template', version: '1' });

// ---------------------------------------------------------------- glob for protected paths

function globRe(pattern) {
  let re = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*' && pattern[i + 1] === '*') { re += pattern[i + 2] === '/' ? '(?:.*/)?' : '.*'; i += pattern[i + 2] === '/' ? 2 : 1; }
    else if (c === '*') re += '[^/]*';
    else re += c.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}
export const matchesAny = (rel, patterns) => patterns.some((p) => globRe(p).test(rel));

// ---------------------------------------------------------------- the scope gate

// Primitives below the layer the application oracles observe: a raw binding, a child process, another thread, a datagram socket or a
// native addon could open a connection or touch a file the oracle never sees, so a candidate that verified with one would have
// verified nothing about it. A candidate may not INTRODUCE one (an original that already uses one is the operator's to declare).
const UNOBSERVED_PRIMITIVES = [
  [/\bprocess\.binding\s*\(|\binternalBinding\b|\bprocess\._linkedBinding\b/, 'a raw runtime binding'],
  [/['"](?:node:)?child_process['"]/, 'a child process'],
  [/['"](?:node:)?(?:worker_threads|cluster)['"]/, 'another thread or process'],
  [/['"](?:node:)?dgram['"]/, 'a datagram socket'],
  [/\bprocess\.dlopen\b|\.node['"]\s*\)/, 'a native addon'],
  [/^\s*(?:import\s+(?:subprocess|socket|ctypes|multiprocessing)\b|from\s+(?:subprocess|socket|ctypes|multiprocessing)\s+import\b)/m, 'a process, socket or foreign-function module'],
];
const count = (re, t) => (String(t || '').match(new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`)) || []).length;

/**
 * May this candidate be judged at all? Checked before anything executes.
 * @returns {{ok:boolean, reasons:string[], scope:object, changed:Record<string,string|null>}}
 */
export function checkCandidate(contract, originalFiles, proposedFiles) {
  const reasons = [];
  const changed = {};
  for (const [rel, text] of Object.entries(proposedFiles || {})) {
    if (typeof rel !== 'string' || path.posix.normalize(rel) !== rel || rel.startsWith('/') || rel.startsWith('..')) { reasons.push(`${String(rel).slice(0, 80)}: not a confined relative path`); continue; }
    if (text !== null && typeof text !== 'string') { reasons.push(`${rel}: content must be text or null`); continue; }
    if ((originalFiles[rel] ?? null) !== text) changed[rel] = text;
  }
  for (const rel of Object.keys(changed)) {
    if (matchesAny(rel, contract.editScope.prohibited)) reasons.push(`${rel}: a protected path (verifier state, tests, runner configuration, dependencies); a candidate cannot change what judges it`);
    else if (!contract.editScope.allowed.includes(rel)) reasons.push(`${rel}: outside the contract's allowed edit scope`);
  }
  for (const [rel, text] of Object.entries(changed)) {
    for (const [re, what] of UNOBSERVED_PRIMITIVES) if (count(re, text) > count(re, originalFiles[rel])) reasons.push(`${rel}: introduces ${what}, which the application oracles cannot observe`);
  }
  const surface = testSurfaceChanges(changed, (rel) => originalFiles[rel] ?? null);
  for (const b of surface.blocked) reasons.push(`${b.file}: ${b.reason}`);
  const before = Object.fromEntries(Object.keys(changed).map((r) => [r, originalFiles[r] ?? null]));
  const scope = computePatchScope({ before, after: changed, bounds: { maxFiles: contract.editScope.maxFiles, maxEditedLines: contract.editScope.maxEditedLines } });
  if (!Object.keys(changed).length) reasons.push('the candidate changes nothing');
  if (scope.exceedsBounds) reasons.push(...scope.exceedsReasons.map((r) => `over the contract's change budget: ${r}`));
  return { ok: reasons.length === 0, reasons, scope, changed };
}

/** The candidate record, with identities computed here. */
export function makeCandidate(contract, originalFiles, proposal, checked) {
  const rec = {
    schema: SCHEMAS.candidate, schemaVersion: SCHEMA_VERSION,
    contractDigest: contract.contractDigest, baselineDigest: contract.sourceDigest,
    generator: proposal.generator, generatorIdentity: proposal.generatorIdentity, generationParameters: proposal.generationParameters || {},
    files: checked.changed,
    beforeDigests: Object.fromEntries(Object.keys(checked.changed).map((r) => [r, originalFiles[r] == null ? null : digestOf(originalFiles[r])])),
    afterDigests: Object.fromEntries(Object.entries(checked.changed).map(([r, t]) => [r, t == null ? null : digestOf(t)])),
    patchDigest: digestOf(checked.changed),
    scope: { totals: checked.scope.totals, material: checked.scope.material, touchedSymbols: checked.scope.files.flatMap((f) => (f.touchedSymbols || []).map((s) => `${f.file}:${s.name || s}`)).slice(0, 40) },
    strategy: proposal.strategy || null, rationale: proposal.rationale || null, assumptions: proposal.assumptions || [], proposedTests: [],
    accounting: { tokens: proposal.accounting?.tokens ?? null, calls: proposal.accounting?.calls ?? null, wallMs: proposal.accounting?.wallMs ?? null, usd: proposal.accounting?.usd ?? null },
  };
  rec.candidateId = candidateIdOf(rec);
  const v = validateCandidate(rec);
  return v.ok ? { candidate: rec, problems: [] } : { candidate: null, problems: v.errors.map((e) => `${e.path}: ${e.message}`) };
}

// ---------------------------------------------------------------- deterministic SQL recipe

/** Scan a template literal starting at the backtick index; returns {end, quasis, exprs} or null. */
function readTemplate(text, start) {
  const quasis = []; const exprs = [];
  let cur = ''; let i = start + 1;
  while (i < text.length) {
    const c = text[i];
    if (c === '\\') { cur += c + (text[i + 1] ?? ''); i += 2; continue; }
    if (c === '`') { quasis.push(cur); return { end: i, quasis, exprs }; }
    if (c === '$' && text[i + 1] === '{') {
      let depth = 1; let j = i + 2; let e = '';
      while (j < text.length && depth > 0) {
        const d = text[j];
        if (d === '`' || d === "'" || d === '"') return null; // nested strings: not a shape this recipe handles
        if (d === '{') depth++; else if (d === '}') depth--;
        if (depth > 0) e += d;
        j++;
      }
      if (depth) return null;
      quasis.push(cur); exprs.push(e.trim()); cur = ''; i = j; continue;
    }
    cur += c; i++;
  }
  return null;
}

const PREPARE_RE = /\.prepare\(\s*`/g;
const CALL_RE = /^\s*\)\s*\.(all|get|run|iterate)\(\s*\)/;

/** Apply the recipe to one file. Returns {text, applied, refused:[reasons]}. Pure. */
export function parameterizeTemplateSql(text) {
  const refused = []; let applied = 0;
  let out = ''; let last = 0;
  PREPARE_RE.lastIndex = 0;
  let m;
  while ((m = PREPARE_RE.exec(text))) {
    const tick = m.index + m[0].length - 1;
    const t = readTemplate(text, tick);
    if (!t) { refused.push(`line ${text.slice(0, tick).split('\n').length}: the template could not be read safely`); continue; }
    if (!t.exprs.length) continue;
    const call = CALL_RE.exec(text.slice(t.end + 1));
    if (!call) { refused.push(`line ${text.slice(0, tick).split('\n').length}: the statement is not called immediately with no arguments`); continue; }
    let sql = ''; let ok = true;
    for (let k = 0; k < t.quasis.length; k++) {
      let q = t.quasis[k];
      if (k > 0) { if (!q.startsWith("'")) { ok = false; break; } q = q.slice(1); }
      if (k < t.exprs.length) { if (!q.endsWith("'")) { ok = false; break; } q = q.slice(0, -1) + '?'; }
      sql += q;
    }
    if (!ok || /\$\{/.test(sql)) { refused.push(`line ${text.slice(0, tick).split('\n').length}: an interpolation is not a quoted SQL value, so a placeholder cannot carry it`); continue; }
    const lit = `'${sql.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')}'`;
    out += text.slice(last, tick) + lit + text.slice(t.end + 1, t.end + 1 + call[0].length - 1) + t.exprs.join(', ') + ')';
    last = t.end + 1 + call[0].length;
    PREPARE_RE.lastIndex = last;
    applied++;
  }
  out += text.slice(last);
  return { text: applied ? out : text, applied, refused };
}

/** The deterministic recipe as a proposer: one candidate, round 1 only, over the contract's allowed files. */
export function sqlParameterizeRecipe() {
  return {
    id: `${RECIPE_SQL_PARAMETERIZE.id}@${RECIPE_SQL_PARAMETERIZE.version}`,
    async propose({ contract, files, round }) {
      if (round !== 1 || contract.family !== 'sql-injection') return { proposals: [], notes: [] };
      const out = {}; const notes = [];
      for (const rel of contract.editScope.allowed) {
        if (!/\.(?:m?js|cjs|ts)$/.test(rel) || typeof files[rel] !== 'string') continue;
        const r = parameterizeTemplateSql(files[rel]);
        if (r.applied) out[rel] = r.text;
        notes.push(...r.refused.map((x) => `${rel} ${x}`));
      }
      if (!Object.keys(out).length) return { proposals: [], notes: notes.length ? notes : ['the recipe matched no statement'] };
      return { proposals: [{ generator: 'deterministic-recipe', generatorIdentity: `${RECIPE_SQL_PARAMETERIZE.id}@${RECIPE_SQL_PARAMETERIZE.version}`, files: out, strategy: 'parameterize every quoted SQL value', rationale: 'bound parameters keep request values out of the SQL text' }], notes };
    },
  };
}

/**
 * User-supplied candidates, in order. `items` are {files, strategy?, rationale?, round?}. Items that name a `round` are offered together
 * in that round (a portfolio of strategies); items without one are offered one per round, in order.
 */
export function queueProposer(items, identity = 'user-supplied') {
  const queue = [...items];
  const toProposal = (it) => ({ generator: 'user-supplied', generatorIdentity: identity, files: it.files, strategy: it.strategy || null, rationale: it.rationale || null });
  return {
    id: identity,
    async propose({ round, max }) {
      const grouped = queue.filter((it) => Number.isInteger(it.round));
      let take;
      if (grouped.length) {
        take = grouped.filter((it) => it.round === round).slice(0, Math.max(1, max || 1));
        for (const t of take) queue.splice(queue.indexOf(t), 1);
      } else take = queue.splice(0, 1);
      return { proposals: take.map(toProposal), notes: [] };
    },
    remaining: () => queue.length,
  };
}
