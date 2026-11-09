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
import { buildHunterPrompt } from './lenses.js';
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
function resolveCitation(c, focusArea, ctx) {
  const raw = typeof c?.file === 'string' ? c.file.trim() : '';
  const file = raw.replace(/^\.\//, '');
  const line = Number.isInteger(c?.line) ? c.line : Number.parseInt(c?.line, 10);
  if (!file || !Number.isInteger(line) || line < 1) return { ok: false, reason: 'no-location' };
  const known = (Array.isArray(focusArea?.files) && focusArea.files.includes(file)) || (ctx?.fileContents && Object.prototype.hasOwnProperty.call(ctx.fileContents, file));
  if (!known) return { ok: false, reason: 'file-not-in-scope' };
  const text = ctx?.fileContents ? ctx.fileContents[file] : undefined;
  if (typeof text === 'string') {
    const lines = text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
    if (line > Math.max(1, lines)) return { ok: false, reason: 'line-past-end' };
  }
  return { ok: true, file, line };
}

function candidatesFromParsed(parsed, focusArea, lens, ctx = {}, stats = null) {
  const list = Array.isArray(parsed?.candidates) ? parsed.candidates : [];
  const out = [];
  for (const c of list) {
    const cite = resolveCitation(c, focusArea, ctx);
    if (!cite.ok) {
      if (stats) { stats.discarded += 1; if (cite.reason !== 'no-location') stats.citationsDiscarded += 1; }
      continue;
    }
    const { file, line } = cite;
    const title = typeof c?.title === 'string' && c.title ? c.title : `${lens.title} candidate`;
    out.push({
      id: candidateId(focusArea.id, lens.key, file, line, title),
      focusAreaId: focusArea.id,
      lens: lens.key,
      title,
      file,
      line,
      family: lens.family,
      cwe: lens.cwe,
      rationale: typeof c?.rationale === 'string' ? c.rationale : '',
      entryPoint: typeof c?.entryPoint === 'string' ? c.entryPoint : '',
      sink: typeof c?.sink === 'string' ? c.sink : '',
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
  const { invoke: llmInvoke, decision: egressDecision } = resolveLlmInvokeWithDecision({ ...opts, role, purpose: 'discovery-hunter' });

  if (typeof llmInvoke !== 'function') {
    // FR-601: distinguish "policy denied a configured endpoint" from "nothing
    // was configured at all" — the reason must reflect which actually happened.
    const reason = egressDecision
      ? `egress policy denied this call: ${egressDecision.reason}`
      : 'no llmInvoke supplied and AGENTIC_SECURITY_LLM_ENDPOINT not set';
    appendEntry(transcript, { phase: 'init', reason, egressDecision: egressDecision || undefined });
    return { ...base, candidates: [], degraded: true, reason, egressDecision };
  }

  let prompt;
  try {
    prompt = buildHunterPrompt(focusArea, lens, ctx);
  } catch (err) {
    const reason = `failed to build hunter prompt: ${err?.message || String(err)}`;
    appendEntry(transcript, { phase: 'prompt_error', reason });
    return { ...base, candidates: [], degraded: true, reason };
  }

  appendEntry(transcript, { phase: 'prompt', promptChars: prompt.length, files: focusArea.files.length });

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
  const candidates = candidatesFromParsed(parsed, focusArea, lens, ctx, stats);
  // A proposed candidate with no file and line has nowhere to point and is dropped, and one whose citation does not resolve
  // (a file the hunter was not shown, a line past the file's end) is dropped too; say how many of each, so a reply full of
  // them does not read as a reply that found nothing.
  appendEntry(transcript, { phase: 'result', candidateCount: candidates.length, discarded: stats.discarded, citationsDiscarded: stats.citationsDiscarded });
  return { ...base, candidates, degraded: false, reason: null, discarded: stats.discarded, citationsDiscarded: stats.citationsDiscarded };
}
