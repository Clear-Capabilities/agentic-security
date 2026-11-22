//
// One bounded hunter run = one focus area seen through one lens.
//
// A hunter PROPOSES. Nothing here is a finding: every candidate must survive
// `confirm.js` and `disprove.js` first. That separation is the whole design —
// the model is allowed to be imaginative precisely because something
// deterministic checks it afterwards.
//
// FAILURE IS ALWAYS DEGRADATION, NEVER AN EXCEPTION. A missing endpoint, a
// rate limit, or unparseable output yields `degraded:true` with a reason. A
// discovery pass that cannot run must leave the rest of the scan intact.
import * as crypto from 'node:crypto';
import { buildHunterPromptWithMap } from './lenses.js';
import { classifyCandidate } from './classification.js';
import { resolveLlmInvokeWithDecision } from './llm-invoke.js';

function appendEntry(transcript, entry) {
  const prev = transcript.length ? transcript[transcript.length - 1].hash : null;
  // Named `serialized`, not `body`: this is the canonical serialisation of a
  // transcript entry being fed to a hash, and calling it `body` made the
  // mass-assignment detector read it as a request payload. The name was simply
  // wrong for what it holds, so this is a fix at the source rather than a
  // suppression — and that detector's finding carries no line number, so a
  // line-scoped ignore pragma could not have matched it anyway.
  const serialized = JSON.stringify({ ...entry, prev });
  const hash = crypto.createHash('sha256').update(serialized).digest('hex');
  transcript.push({ ...entry, prev, hash });
  return transcript;
}

function extractJsonWithFlag(raw) {
  if (typeof raw !== 'string') return { parsed: null, found: false };
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start < 0 || end <= start) return { parsed: null, found: false };
  try { return { parsed: JSON.parse(raw.slice(start, end + 1)), found: true }; } catch { return { parsed: null, found: false }; }
}

function candidateId(focusAreaId, lensKey, file, line, title) {
  return crypto.createHash('sha256')
    .update(`${focusAreaId}|${lensKey}|${file}|${line}|${title}`)
    .digest('hex').slice(0, 12);
}

// GA-06 §4 (0.195.31): a hunt candidate needs a REAL citation, not a plausible one. The file must be one the hunter was shown
// (the focus area's files, or any file whose contents the run holds) and the line must exist in it when the contents are known.
// A model that names a file outside the area, or a line past the end, has not cited evidence; such a candidate is discarded and
// counted (`citationsDiscarded`), never scored or shown. A leading `./` is tolerated; nothing else is normalised, so a path that
// differs from what the hunter was shown is a miss, not a match.
//
// Since the prompt shows numbered lines (lenses.js `buildHunterPromptWithMap`), a citation is also checked against what the hunter
// was SHOWN, when the run knows that (`ctx._shown`):
//   * the line must be inside the shown range of that file (`line-not-shown`): a line in a truncated-away part was never seen;
//   * a `code` anchor, when given, must match the cited line's shown text, compared with whitespace collapsed. If it matches a
//     line within two of the cited one instead, and only that one, the citation moves there (the anchor is evidence from the
//     scanned snapshot, nothing else is consulted); if it matches none (`anchor-mismatch`) or several nearby lines but not the
//     cited one (`anchor-ambiguous`), the candidate is discarded. An anchor shorter than 4 characters proves nothing and is
//     treated as absent. A candidate with no anchor is kept and marked `anchored: false`.
const squash = (t) => String(t || '').replace(/\s+/g, ' ').trim();
function anchorMatches(lineText, anchor) {
  const a = squash(anchor); const l = squash(lineText);
  return a.length >= 4 && l.length > 0 && (l === a || l.includes(a) || (a.includes(l) && l.length >= 8));
}
function resolveCitation(c, focusArea, ctx) {
  const raw = typeof c?.file === 'string' ? c.file.trim() : '';
  const file = raw.replace(/^\.\//, '');
  const line = Number.isInteger(c?.line) ? c.line : Number.parseInt(c?.line, 10);
  if (!file || !Number.isInteger(line) || line < 1) return { ok: false, reason: 'no-location' };
  const known = (Array.isArray(focusArea?.files) && focusArea.files.includes(file)) || (ctx?.fileContents && Object.prototype.hasOwnProperty.call(ctx.fileContents, file));
  if (!known) return { ok: false, reason: 'file-not-in-scope' };
  const text = ctx?.fileContents ? ctx.fileContents[file] : undefined;
  let lines = null;
  if (typeof text === 'string') {
    lines = text.split('\n'); if (text.endsWith('\n')) lines.pop();
    if (line > Math.max(1, lines.length)) return { ok: false, reason: 'line-past-end' };
  }
  const shown = ctx?._shown ? ctx._shown[file] : undefined;
  if (ctx?._shown && !shown) return { ok: false, reason: 'file-not-shown' };
  if (shown && shown.lineMapped && (line < shown.from || line > shown.to)) return { ok: false, reason: 'line-not-shown' };
  // The text to check an anchor against: what was shown when line numbers map, else the snapshot itself.
  const textAt = (n) => (shown && shown.lineMapped ? shown.lines[n - 1] : lines ? lines[n - 1] : undefined);
  const anchor = typeof c?.code === 'string' && squash(c.code).length >= 4 ? c.code : null;
  if (!anchor || (!shown && !lines)) return { ok: true, file, line, anchored: false };
  if (anchorMatches(textAt(line), anchor)) return { ok: true, file, line, anchored: true };
  const lo = Math.max(shown && shown.lineMapped ? shown.from : 1, line - 2);
  const hi = Math.min(shown && shown.lineMapped ? shown.to : (lines ? lines.length : line), line + 2);
  const near = [];
  for (let n = lo; n <= hi; n++) if (n !== line && anchorMatches(textAt(n), anchor)) near.push(n);
  if (near.length === 1) return { ok: true, file, line: near[0], anchored: true, movedFrom: line };
  return { ok: false, reason: near.length ? 'anchor-ambiguous' : 'anchor-mismatch' };
}

/** The shown (or snapshot) text of the cited line and the two after it: where a statement's operation sits. */
function evidenceLinesAt(file, line, ctx) {
  const shown = ctx?._shown ? ctx._shown[file] : undefined;
  let src = null;
  if (shown && shown.lineMapped) src = shown.lines;
  else if (typeof ctx?.fileContents?.[file] === 'string') src = ctx.fileContents[file].split('\n');
  if (!src) return [];
  return src.slice(line - 1, line + 2);
}

function candidatesFromParsed(parsed, focusArea, lens, ctx = {}, stats = null) {
  const list = Array.isArray(parsed?.candidates) ? parsed.candidates : [];
  const out = [];
  for (const c of list) {
    const cite = resolveCitation(c, focusArea, ctx);
    if (!cite.ok) {
      if (stats) {
        stats.discarded += 1; if (cite.reason !== 'no-location') stats.citationsDiscarded += 1;
        (stats.byReason ||= {})[cite.reason] = (stats.byReason[cite.reason] || 0) + 1;
      }
      continue;
    }
    const { file, line } = cite;
    if (stats) { if (cite.anchored) stats.anchored = (stats.anchored || 0) + 1; else stats.unanchored = (stats.unanchored || 0) + 1; }
    const title = typeof c?.title === 'string' && c.title ? c.title : `${lens.title} candidate`;
    const cls = classifyCandidate(lens, c?.cwe, evidenceLinesAt(file, line, ctx));
    if (stats && cls.cweRejected) stats.cweRejected = (stats.cweRejected || 0) + 1;
    out.push({
      id: candidateId(focusArea.id, lens.key, file, line, title),
      focusAreaId: focusArea.id,
      lens: lens.key,
      title,
      file,
      line,
      family: lens.family,
      cwe: cls.cwe,
      // How the CWE was decided (classification.js): 'lens' (the broad class), 'operation-checked' or 'model-proposed'.
      cweBasis: cls.cweBasis,
      lensCwe: cls.lensCwe,
      ...(cls.proposedCwe && cls.proposedCwe !== cls.cwe ? { proposedCwe: cls.proposedCwe, cweRejected: cls.cweRejected || null } : {}),
      anchored: !!cite.anchored,
      ...(cite.movedFrom ? { citedLine: cite.movedFrom } : {}),
      rationale: typeof c?.rationale === 'string' ? c.rationale : '',
      entryPoint: typeof c?.entryPoint === 'string' ? c.entryPoint : '',
      sink: typeof c?.sink === 'string' ? c.sink : '',
      // Contract-aware mode (B-02): the model's PROPOSED invariant and attacker assumptions, bounded and shaped here, judged later by
      // contracts/qualification.js (an invariant id the contract does not declare is a contract gap, never accepted on the model's say).
      ...(typeof c?.invariantId === 'string' && /^[A-Z][A-Z0-9-]{2,63}$/.test(c.invariantId) ? { invariantId: c.invariantId } : {}),
      ...(c?.attacker && typeof c.attacker === 'object' ? { attacker: Object.fromEntries(['principal', 'role', 'tenant'].filter((k) => typeof c.attacker[k] === 'string').map((k) => [k, c.attacker[k].slice(0, 80)])) } : {}),
      ...(Array.isArray(c?.prerequisites) ? { prerequisites: c.prerequisites.filter((x) => typeof x === 'string').slice(0, 8).map((x) => x.slice(0, 200)) } : {}),
    });
  }
  return out;
}

export function parseCandidates(raw, focusArea, lens, ctx = {}) {
  const { parsed } = extractJsonWithFlag(raw);
  return candidatesFromParsed(parsed, focusArea, lens, ctx);
}

export async function runHunter(focusArea, lens, ctx = {}, opts = {}) {
  const transcript = [];
  const lensKey = lens?.key || 'unknown';
  const base = { focusAreaId: focusArea.id, lens: lensKey, transcript };
  // ollama-offline-prd.md §32 — "permit each refutation-panel member to be a
  // separately configured local model" extends naturally to the hunter's own
  // lenses: the `business-logic` lens is exactly the PRD's `logic` role
  // ("cross-file business-logic reasoning"), so it alone routes through
  // role='logic' (honoring AGENTIC_SECURITY_LLM_MODEL_LOGIC) while every
  // other lens keeps the existing role='hunt' default — a caller-supplied
  // `opts.role` still wins over both, same precedence resolveProvider
  // already documents.
  const role = opts.role || (lensKey === 'business-logic' ? 'logic' : 'hunt');
  const { invoke: resolvedInvoke, decision: egressDecision } = resolveLlmInvokeWithDecision({ ...opts, role, purpose: 'discovery-hunter' });
  // `wrapInvoke` is the run budget's counter (index.js makeBudget). runDiscovery passes it when no llmInvoke was injected, so a
  // callback resolved from configuration is counted and bounded exactly like an injected one.
  const llmInvoke = typeof resolvedInvoke === 'function' && typeof opts.wrapInvoke === 'function' ? opts.wrapInvoke(resolvedInvoke) : resolvedInvoke;

  if (typeof llmInvoke !== 'function') {
    // FR-601: distinguish "policy denied a configured endpoint" from "nothing
    // was configured at all" — the reason must reflect which actually happened.
    const reason = egressDecision
      ? `egress policy denied this call: ${egressDecision.reason}`
      : 'no llmInvoke supplied and AGENTIC_SECURITY_LLM_ENDPOINT not set';
    appendEntry(transcript, { phase: 'init', reason, egressDecision: egressDecision || undefined });
    return { ...base, candidates: [], degraded: true, reason, egressDecision };
  }

  let prompt; let built = null;
  try {
    built = buildHunterPromptWithMap(focusArea, lens, ctx);
    prompt = built.prompt;
  } catch (err) {
    const reason = `failed to build hunter prompt: ${err?.message || String(err)}`;
    appendEntry(transcript, { phase: 'prompt_error', reason });
    return { ...base, candidates: [], degraded: true, reason };
  }

  appendEntry(transcript, { phase: 'prompt', promptChars: prompt.length, files: focusArea.files.length, filesShown: Object.keys(built.shown).length, filesOmitted: built.omittedFiles });

  let raw;
  try {
    raw = await llmInvoke(prompt);
  } catch (err) {
    const reason = `hunter llm call failed: ${err?.message || String(err)}`;
    appendEntry(transcript, { phase: 'error', reason });
    return { ...base, candidates: [], degraded: true, reason };
  }

  const { parsed, found } = extractJsonWithFlag(raw);
  if (!found) {
    const reason = 'hunter output was not parseable JSON';
    appendEntry(transcript, { phase: 'parse_error', reason });
    return { ...base, candidates: [], degraded: true, reason };
  }

  const stats = { discarded: 0, citationsDiscarded: 0 };
  const candidates = candidatesFromParsed(parsed, focusArea, lens, { ...ctx, _shown: built ? built.shown : undefined }, stats);
  // A proposed candidate with no file and line has nowhere to point and is dropped, and one whose citation does not resolve
  // (a file the hunter was not shown, a line past the file's end) is dropped too; say how many of each, so a reply full of
  // them does not read as a reply that found nothing.
  const citation = { anchored: stats.anchored || 0, unanchored: stats.unanchored || 0, discardedByReason: stats.byReason || {}, cweRejected: stats.cweRejected || 0 };
  appendEntry(transcript, { phase: 'result', candidateCount: candidates.length, discarded: stats.discarded, citationsDiscarded: stats.citationsDiscarded, citation });
  return { ...base, candidates, degraded: false, reason: null, discarded: stats.discarded, citationsDiscarded: stats.citationsDiscarded, citation };
}
