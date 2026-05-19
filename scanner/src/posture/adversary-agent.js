// FR-ADV-1 — Multi-step adversary-agent skeleton.
//
// Given ONE finding and a live target URL (from FR-LIVE-HARNESS), an LLM
// agent operates with a bounded tool-call budget and emits a transcript
// showing what an attacker would actually DO with the finding.
//
// Tools available to the agent (each gated by an ACL — there is no shell,
// no filesystem write, no real DB. The agent operates against a sandboxed
// COPY of the target.):
//
//   http.get(path, headers?)             — read against the sandbox URL
//   http.post(path, body, headers?)      — write against the sandbox URL
//   db.read_sandbox_copy(query)          — read against the sandbox DB
//   record_outcome(outcomeType, evidence) — terminate run, emit verdict
//
// Each tool call is hash-chained into the transcript so the trace is
// tamper-evident. Budget enforcement: ≤ MAX_CALLS calls, ≤ MAX_WALL_MS ms.
//
// This module is a SKELETON. It defines the transcript shape, the tool ACL,
// and the budget/timeout enforcement. It does NOT call any LLM endpoint by
// default — that wiring lives in the runner / `agentic-security verify
// --adversary-agent` CLI, which reads AGENTIC_SECURITY_LLM_ENDPOINT.
//
// When no LLM endpoint is configured, `runAgent` short-circuits with verdict
// `unverified-no-llm-endpoint` and the transcript records only the seed input.

import * as crypto from 'node:crypto';

const MAX_CALLS_DEFAULT = 50;
const MAX_WALL_MS_DEFAULT = 15 * 60 * 1000;

const TOOL_ACL = new Set([
  'http.get',
  'http.post',
  'db.read_sandbox_copy',
  'record_outcome',
]);

const OUTCOMES = [
  'data-exfil',
  'priv-esc',
  'account-takeover',
  'financial-loss',
  'cleanup-traces',
  'failed',
  'aborted-budget',
  'aborted-timeout',
];

function chainHash(prev, entry) {
  const h = crypto.createHash('sha256');
  h.update(prev || '');
  h.update(JSON.stringify(entry));
  return h.digest('hex').slice(0, 16);
}

export function startTranscript(finding, target) {
  const seed = {
    seedFinding: {
      stableId: finding?.stableId || null,
      file: finding?.file || null,
      line: finding?.line || null,
      vuln: finding?.vuln || null,
      family: finding?.family || null,
    },
    target: target || null,
    startedAt: new Date().toISOString(),
    entries: [],
    chainHead: '',
  };
  seed.chainHead = chainHash('', seed.seedFinding);
  return seed;
}

export function appendEntry(transcript, entry) {
  if (!transcript || !entry) return;
  if (entry.tool && !TOOL_ACL.has(entry.tool)) {
    entry = { ...entry, refused: true, refusedReason: `tool '${entry.tool}' is not in ACL` };
  }
  transcript.chainHead = chainHash(transcript.chainHead, entry);
  transcript.entries.push({ ...entry, hash: transcript.chainHead });
}

export function isExceeded(transcript, budget) {
  const calls = transcript.entries.filter(e => e.tool).length;
  if (calls >= (budget.maxCalls ?? MAX_CALLS_DEFAULT)) return 'aborted-budget';
  const startedAt = Date.parse(transcript.startedAt);
  if (Number.isFinite(startedAt) && Date.now() - startedAt > (budget.maxWallMs ?? MAX_WALL_MS_DEFAULT)) {
    return 'aborted-timeout';
  }
  return null;
}

// Default llmInvoke — calls AGENTIC_SECURITY_LLM_ENDPOINT with the transcript
// and parses the response as a single tool-call request. The endpoint is
// expected to follow an OpenAI-style chat-completions shape; we extract a
// JSON object of `{ tool, args }` from the model's reply.
export async function defaultLlmInvoke(transcript) {
  const endpoint = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  if (!endpoint) return null;
  const model = process.env.AGENTIC_SECURITY_LLM_MODEL || 'gpt-4o-mini';
  const apiKey = process.env.AGENTIC_SECURITY_LLM_API_KEY || process.env.OPENAI_API_KEY || '';
  const headers = { 'Content-Type': 'application/json' };
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
  const tools = [...TOOL_ACL].map(t => ({ tool: t, description: TOOL_HELP[t] || '' }));
  const body = {
    model,
    messages: [
      { role: 'system', content: `You are an authorized security tester. You may ONLY call tools from this list: ${[...TOOL_ACL].join(', ')}. Reply with a single JSON object of the shape {"tool":"<name>","args":{...}}. Stop when you have evidence sufficient to call record_outcome.` },
      { role: 'user', content: `Seed finding: ${JSON.stringify(transcript.seedFinding)}\nTarget: ${transcript.target}\nPrior entries: ${JSON.stringify(transcript.entries.slice(-8))}\nAvailable tools: ${JSON.stringify(tools)}` },
    ],
    max_tokens: 256,
    temperature: 0.1,
  };
  let res;
  try {
    res = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(body) });
  } catch (e) {
    return null;
  }
  if (!res.ok) return null;
  let json;
  try { json = await res.json(); } catch { return null; }
  const text = json?.choices?.[0]?.message?.content ?? json?.message?.content ?? '';
  if (!text) return null;
  const m = /\{[\s\S]*\}/.exec(text);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { return null; }
}

const TOOL_HELP = {
  'http.get': 'GET a path against the sandbox target URL',
  'http.post': 'POST a body to a path against the sandbox target URL',
  'db.read_sandbox_copy': 'Read-only query against the sandboxed DB copy',
  'record_outcome': 'Terminate the run with a verdict (outcome: one of OUTCOMES)',
};

// Default executeTool — wraps http.get / http.post against `transcript.target`.
// Falls back to refusal when the tool is db.read_sandbox_copy (we do not ship
// a sandboxed DB by default; the caller must supply one).
export async function defaultExecuteTool(call, transcript) {
  if (!call || !TOOL_ACL.has(call.tool)) return { refused: true };
  if (call.tool === 'http.get') {
    const url = (transcript?.target || '').replace(/\/$/, '') + (call.args?.path || '/');
    try {
      const r = await fetch(url, { method: 'GET', headers: call.args?.headers || {} });
      const body = await r.text();
      return { status: r.status, headers: Object.fromEntries(r.headers), body: body.slice(0, 4000) };
    } catch (e) { return { error: String(e?.message || e) }; }
  }
  if (call.tool === 'http.post') {
    const url = (transcript?.target || '').replace(/\/$/, '') + (call.args?.path || '/');
    try {
      const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(call.args?.headers || {}) },
        body: typeof call.args?.body === 'string' ? call.args.body : JSON.stringify(call.args?.body || {}),
      });
      const body = await r.text();
      return { status: r.status, headers: Object.fromEntries(r.headers), body: body.slice(0, 4000) };
    } catch (e) { return { error: String(e?.message || e) }; }
  }
  return { refused: true, reason: `tool ${call.tool} not implemented by defaultExecuteTool` };
}

// Run the agent loop. Without an `llmInvoke` callback AND without
// AGENTIC_SECURITY_LLM_ENDPOINT, this short-circuits to
// `unverified-no-llm-endpoint`. With either, it loops bounded by the budget.
export async function runAgent(finding, opts = {}) {
  const transcript = startTranscript(finding, opts.target);
  const budget = { maxCalls: opts.maxCalls, maxWallMs: opts.maxWallMs };

  const llmInvoke = opts.llmInvoke || (process.env.AGENTIC_SECURITY_LLM_ENDPOINT ? defaultLlmInvoke : null);
  const executeTool = opts.executeTool || (transcript.target ? (call) => defaultExecuteTool(call, transcript) : null);

  if (typeof llmInvoke !== 'function' || typeof executeTool !== 'function') {
    appendEntry(transcript, { phase: 'init', reason: 'no llmInvoke/executeTool supplied and AGENTIC_SECURITY_LLM_ENDPOINT not set' });
    return { transcript, outcome: 'unverified-no-llm-endpoint' };
  }

  let outcome = null;
  while (!outcome) {
    const reason = isExceeded(transcript, budget);
    if (reason) { outcome = reason; break; }
    let next;
    try { next = await llmInvoke(transcript); }
    catch (e) { appendEntry(transcript, { phase: 'llm-error', error: String(e?.message || e) }); outcome = 'failed'; break; }
    if (!next || !next.tool) { outcome = 'failed'; appendEntry(transcript, { phase: 'no-tool', value: next }); break; }
    if (!TOOL_ACL.has(next.tool)) { appendEntry(transcript, { tool: next.tool, refused: true }); continue; }
    if (next.tool === 'record_outcome') {
      const o = OUTCOMES.includes(next.args?.outcome) ? next.args.outcome : 'failed';
      appendEntry(transcript, { tool: 'record_outcome', args: next.args || {} });
      outcome = o; break;
    }
    let res;
    try { res = await executeTool(next); }
    catch (e) { res = { error: String(e?.message || e) }; }
    appendEntry(transcript, { tool: next.tool, args: next.args, result: res });
  }

  return { transcript, outcome: outcome || 'failed' };
}

export { TOOL_ACL, OUTCOMES };
