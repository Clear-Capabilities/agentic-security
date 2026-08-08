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

function appendEntry(transcript, entry) {
  const prev = transcript.length ? transcript[transcript.length - 1].hash : null;
  const body = JSON.stringify({ ...entry, prev });
  const hash = crypto.createHash('sha256').update(body).digest('hex');
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

function candidatesFromParsed(parsed, focusArea, lens) {
  const list = Array.isArray(parsed?.candidates) ? parsed.candidates : [];
  const out = [];
  for (const c of list) {
    const file = typeof c?.file === 'string' ? c.file : null;
    const line = Number.isInteger(c?.line) ? c.line : Number.parseInt(c?.line, 10);
    if (!file || !Number.isInteger(line)) continue;      // no location, no candidate
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

export function parseCandidates(raw, focusArea, lens) {
  const { parsed } = extractJsonWithFlag(raw);
  return candidatesFromParsed(parsed, focusArea, lens);
}

async function defaultLlmInvoke(prompt) {
  const endpoint = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt }),
  });
  if (!res.ok) throw new Error(`llm endpoint returned ${res.status}`);
  const body = await res.json();
  return typeof body === 'string' ? body : (body?.text ?? JSON.stringify(body));
}

export async function runHunter(focusArea, lens, ctx = {}, opts = {}) {
  const transcript = [];
  const lensKey = lens?.key || 'unknown';
  const base = { focusAreaId: focusArea.id, lens: lensKey, transcript };
  const llmInvoke = opts.llmInvoke
    || (process.env.AGENTIC_SECURITY_LLM_ENDPOINT ? defaultLlmInvoke : null);

  if (typeof llmInvoke !== 'function') {
    const reason = 'no llmInvoke supplied and AGENTIC_SECURITY_LLM_ENDPOINT not set';
    appendEntry(transcript, { phase: 'init', reason });
    return { ...base, candidates: [], degraded: true, reason };
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

  const candidates = candidatesFromParsed(parsed, focusArea, lens);
  appendEntry(transcript, { phase: 'result', candidateCount: candidates.length });
  return { ...base, candidates, degraded: false, reason: null };
}
