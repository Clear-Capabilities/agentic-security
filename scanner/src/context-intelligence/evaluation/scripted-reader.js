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
import * as crypto from 'node:crypto';

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
export function blocksFromReviewPrompt(prompt) {
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
export function blocksFromHuntPrompt(prompt) {
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
export function analyseRoute(route, blocks, { dynamicUnresolved = false } = {}) {
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

/** The decision for a pack, from the observations. Returns the review JSON object. */
export function decide(packId, obs, ctx) {
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
export function scriptedReader() {
  const invoke = async (prompt) => {
    if (/^QUESTION PACK: /m.test(prompt)) {
      const packId = /^QUESTION PACK: ([\w-]+)\//m.exec(prompt)[1];
      const label = /^ENTRY POINT 1: (.*?) \(id /m.exec(prompt)[1];
      const { blocks, unresolved, notIncluded, limit } = blocksFromReviewPrompt(prompt);
      const routes = findRoutes(blocks);
      const [method, ...rest] = label.split(' ');
      const wantPath = rest.join(' ');
      const route = routes.find(r => r.path === wantPath && (r.method === method || r.method === 'ALL')) || routes.find(r => r.path === wantPath) || routes[0];
      if (!route) return JSON.stringify({ evidence: [], observedMitigations: [], conclusion: 'insufficient_evidence', invariant: 'unspecified', uncertainties: ['the registration is not in the provided context'] });
      const obs = analyseRoute(route, blocks);
      const complete = !unresolved && !notIncluded && !limit;
      return JSON.stringify(decide(packId, obs, { complete, unresolved }));
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

export function readerIdentity() {
  return { kind: 'scripted-reader', version: 1, digest: crypto.createHash('sha256').update(scriptedReader.toString() + decide.toString() + analyseRoute.toString()).digest('hex').slice(0, 16), synthetic: true };
}
