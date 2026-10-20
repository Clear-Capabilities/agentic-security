// Recorded-response replay for the model-assisted tiers. A case is a model reply written down once (`fixtures/model-replay/*.json`) and
// played back through a stubbed `fetch`, so the decision logic around the model is tested the same way on every machine with no server.
//
// The validator makes each request unforgeable: the reply must echo a per-request challenge and the finding's file and line. A recorded
// reply therefore holds the placeholders `{{challenge}}`, `{{file}}` and `{{line}}`, filled from the request that arrives. A case may set
// `status` (an HTTP failure), `throws` (a network failure) or `rawText` (a reply that is not JSON at all).
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'model-replay');

export function loadReplay(name) { return JSON.parse(fs.readFileSync(path.join(DIR, `${name}.json`), 'utf8')); }


/** Run `fn` with `fetch` answering from one recorded case. Returns what `fn` returns. Restores `fetch` either way. */
export async function withReplayedModel(recorded, fn) {
  const original = global.fetch;
  const seen = [];
  global.fetch = async (url, opts) => {
    const body = JSON.parse(opts.body);
    const prompt = body.prompt ?? body.messages?.map(m => m.content).join('\n') ?? '';
    const ctx = {
      challenge: (/"challenge": "([a-f0-9]+)"/.exec(prompt) || [])[1] ?? '00000000',
      file: (/"file": "([^"]+)"/.exec(prompt) || [])[1] ?? '',
      line: (/"line": (\d+)/.exec(prompt) || [])[1] ?? '0',
    };
    seen.push({ url: String(url), ...ctx });
    if (recorded.throws) throw new Error(recorded.throws);
    if (recorded.status && recorded.status >= 400) return { ok: false, status: recorded.status, text: async () => '', json: async () => ({}) };
    const text = recorded.rawText !== undefined
      ? recorded.rawText
      : 'final answer:\n' + JSON.stringify(Object.fromEntries(Object.entries(recorded.reply).map(([k, v]) => [k, v === '{{line}}' ? Number(ctx.line) + (recorded.wrongLine ? 1 : 0) : typeof v === 'string' ? v.replace('{{challenge}}', recorded.wrongChallenge ? 'deadbeefdeadbeef' : ctx.challenge).replace('{{file}}', recorded.wrongFile ? 'other.js' : ctx.file) : v])));
    return { ok: true, status: 200, json: async () => ({ response: text }), text: async () => text };
  };
  try { return await fn(seen); } finally { global.fetch = original; }
}

/**
 * An `llmInvoke` for the discovery pipeline that answers from recorded replies: the hunter prompt gets `hunter`, and each refutation
 * prompt gets the next entry of `votes` (cycling). Counts calls so a test can check the budget.
 */
export function replayPipeline({ hunter, votes = [], throwOn } = {}) {
  const calls = { hunter: 0, refute: 0 };
  let vote = 0;
  const llmInvoke = async (prompt) => {
    if (/REFUTE/.test(prompt)) {
      calls.refute++;
      if (throwOn === 'refute') throw new Error('refutation call failed');
      const v = votes.length ? votes[vote++ % votes.length] : null;
      return v ? JSON.stringify(v) : 'no vote';
    }
    calls.hunter++;
    if (throwOn === 'hunter') throw new Error('hunter call failed');
    return typeof hunter === 'string' ? hunter : JSON.stringify(hunter ?? { candidates: [] });
  };
  return { llmInvoke, calls };
}
