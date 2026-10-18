// A built-in model arm for a LOCAL Ollama server (PRD 6: "model adapters"). It reuses the repository's own Ollama provider
// (`llm-validator/ollama-provider.js`): loopback is enforced there, a failure is a typed error, and nothing here ever falls back to
// another provider. The lab adds what an evaluation needs on top: the request is built from the already neutralised, already audited
// workspace, passed through the leakage guard, and the model's JSON answer goes through the same validation as a command arm's.
//
// Only loopback hosts are accepted by this adapter. A remote or cloud model is reached through the `command` adapter, where the
// egress policy decides before anything leaves the machine.
//
// What this proves and does not: against a stand-in Ollama server (test/fixtures/eval-lab/fake-ollama.mjs) it proves the request shape,
// the leakage guard, the timeout and error mapping, the answer validation and the usage accounting. It says nothing about how any
// real model performs; that is what running the lab with a real model measures.
import fs from 'node:fs';
import path from 'node:path';
import { callOllamaChat, DEFAULT_OLLAMA_HOST } from '../../../llm-validator/ollama-provider.js';
import { isLoopbackUrl } from '../../../llm-validator/local-endpoint.js';
import { guardPrompt } from '../custody.js';

const MAX_FILES = 12;
const MAX_FILE_BYTES = 12 * 1024;
const MAX_PROMPT_BYTES = 96 * 1024;
const CODE_EXT = /\.(?:js|mjs|cjs|jsx|ts|tsx|py|java|go|rb|php|c|h|cc|cpp|cs|rs|kt|swift|sh)$/i;

function listSources(dir, limit = 400) {
  const out = []; const stack = [''];
  while (stack.length && out.length < limit) {
    const rel = stack.pop();
    let ents; try { ents = fs.readdirSync(path.join(dir, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of ents.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (e.isSymbolicLink() || e.name.startsWith('.') || e.name === 'node_modules') continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) stack.push(r); else if (e.isFile() && CODE_EXT.test(e.name)) out.push(r);
    }
  }
  return out.sort();
}

/** Numbered source for the files a task needs: the target file whole (bounded) for single-target tasks, else the first few files. */
function sourceBlock(workspaceDir, wanted) {
  const files = wanted?.length ? wanted : listSources(workspaceDir).slice(0, MAX_FILES);
  const parts = [];
  for (const f of files.slice(0, MAX_FILES)) {
    const abs = path.resolve(workspaceDir, f);
    if (!abs.startsWith(path.resolve(workspaceDir) + path.sep)) continue;
    let text; try { text = fs.readFileSync(abs, 'utf8'); } catch { continue; }
    const clipped = text.length > MAX_FILE_BYTES ? `${text.slice(0, MAX_FILE_BYTES)}\n/* truncated */` : text;
    parts.push(`### ${f}\n${clipped.split('\n').map((l, i) => `${String(i + 1).padStart(4)}| ${l}`).join('\n')}`);
  }
  return parts.join('\n\n');
}

const SCHEMAS = {
  detect: { type: 'object', required: ['findings'], properties: { findings: { type: 'array', items: { type: 'object', required: ['file', 'line', 'cwe'], properties: { file: { type: 'string' }, line: { type: 'integer' }, cwe: { type: 'string' }, confidence: { type: 'number' } } } } } },
  falsify: { type: 'object', required: ['verdicts'], properties: { verdicts: { type: 'object', additionalProperties: { type: 'string', enum: ['confirmed', 'refuted', 'uncertain'] } } } },
  exploit: { type: 'object', required: ['reproducer'], properties: { reproducer: { type: 'object' } } },
  patch: { type: 'object', required: ['files'], properties: { files: { type: 'object', additionalProperties: { type: 'string' } } } },
};

function promptFor(task, request, workspaceDir) {
  const t = request.target;
  const code = sourceBlock(workspaceDir, t?.file ? [t.file] : request.candidates?.map((c) => c.file).filter(Boolean));
  const head = 'You are a security analyst. Answer with ONE JSON object and nothing else. Do not explain.';
  if (task === 'detect') return `${head}\nFind security vulnerabilities in the code below. Report each as {"file","line","cwe","confidence"} (cwe like "CWE-89"; confidence 0 to 1). Report only what you can point to a line for. If there are none, return {"findings":[]}.\n\n${code}`;
  if (task === 'falsify') return `${head}\nFor each candidate, decide whether it is a real vulnerability: "confirmed", "refuted" or "uncertain". Return {"verdicts":{"<id>":"<verdict>"}}.\nCandidates: ${JSON.stringify(request.candidates)}\n\n${code}`;
  if (task === 'exploit') return `${head}\nWrite a minimal reproducer for the ${t.cwe ?? 'vulnerability'} at ${t.file}:${t.line}. Return {"reproducer":{"schema":"agentic-security/reproducer","version":1,"findingId":"eval","lang":"javascript","files":{"<name>":"<source>"},"run":["{{NODE}}","<name>","{{CANARY:command}}"],"oracle":{"type":"command_execution","params":{"canary":"command"}}}}. The program must perform the dangerous action only if the vulnerability is real.\n\n${code}`;
  return `${head}\nFix the vulnerability at ${t.file}:${t.line} (${t.cwe ?? 'unspecified'}). Return {"files":{"<path>":"<the complete new file contents>"}} containing only the files you change.\n\n${code}`;
}

/**
 * @returns {Promise<{status: 'completed'|'timeout'|'error'|'blocked'|'unavailable', reason?: string, body?: object, reported?: object}>}
 */
export async function runOllamaArm({ arm, task, request, workspaceDir, terms = [], timeoutMs = 120_000, signal, callChat = callOllamaChat }) {
  const host = String(arm.adapter.host ?? arm.model.endpoint ?? DEFAULT_OLLAMA_HOST).replace(/\/+$/, '');
  if (!isLoopbackUrl(host)) return { status: 'blocked', reason: 'the ollama adapter only talks to a loopback server; reach a remote model through the command adapter so the egress policy decides' };
  const prompt = promptFor(task, request, workspaceDir);
  if (Buffer.byteLength(prompt) > MAX_PROMPT_BYTES) return { status: 'error', reason: 'the task needs more source than the adapter sends in one prompt' };
  const guard = guardPrompt(prompt, terms);
  if (!guard.ok) return { status: 'blocked', reason: `leakage guard: the prompt contained a protected term (${guard.leaks[0]?.kind})` };
  if (signal?.aborted) return { status: 'error', reason: 'cancelled' };
  const r = await Promise.race([
    callChat({ host, model: arm.model.id, messages: [{ role: 'user', content: prompt }], maxTokens: arm.adapter.maxTokens ?? 2048, schema: SCHEMAS[task], timeouts: { connectTimeoutMs: 3000, requestTimeoutMs: arm.adapter.timeoutMs ?? timeoutMs } }),
    new Promise((resolve) => signal?.addEventListener('abort', () => resolve({ ok: false, code: 'cancelled', reason: 'cancelled' }), { once: true })),
  ]);
  if (!r.ok) return { status: r.code === 'ollama-timeout' ? 'timeout' : r.code === 'ollama-unreachable' || r.code === 'ollama-model-not-installed' ? 'unavailable' : 'error', reason: `${r.code}: ${String(r.reason).slice(0, 160)}` };
  let body;
  try { body = JSON.parse(r.result.text); } catch { return { status: 'error', reason: 'invalid-response: the model did not return JSON', reported: r.result.usage }; }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { status: 'error', reason: 'invalid-response: expected a JSON object', reported: r.result.usage };
  return { status: 'ok', body: { ...body, usage: r.result.usage ?? undefined } };
}
