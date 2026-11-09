// The `deterministic + hunt` arm (GA-06 §5, 0.195.31): the deterministic scanner on the staged workspace, then the existing
// discovery pipeline (`discovery/index.js` `runDiscovery`) over the same files with a LOCAL model, and one merged finding list.
// It exists so the Eval Lab can compare the baseline, the combined pipeline and a model arm on the same blinded population with
// the same repeats; nothing here is a new hunter, a new matcher or a second model client.
//
// Honesty rules, in addition to the ones `arms.js` enforces for every arm:
//   * the hunter's own prompts are built inside `runDiscovery`, where the lab's request guard cannot see them, so every prompt
//     passes `guardPrompt` here before it reaches the model; a hit blocks the WHOLE attempt (nothing from it is scored);
//   * the model is a loopback Ollama server declared on the arm (`model.local: true`), reached through the repository's own
//     provider; there is no command adapter for the hunt, because a hunt makes dozens of calls per workspace;
//   * no hunt memory: `runDiscovery` gets no `scanRoot`, so a repeat never inherits what an earlier repeat refuted;
//   * a hunt that reached no focus area (model down) or ran out of budget is a no-result (`unavailable` / `error`), never a
//     completed attempt that "found nothing extra";
//   * every finding says where it came from (`source: 'deterministic' | 'hunt'`), and a hunt finding carries its confirmation
//     tier, so a reader can tell a taint-confirmed candidate from an unconfirmed one.
import { readSnapshot } from '../../../context-intelligence/files.js';
import { buildProjectIR } from '../../../ir/index.js';
import { runDiscovery } from '../../../discovery/index.js';
import { withStateWritesDisabled } from '../../state-dir.js';
import { guardPrompt } from '../custody.js';
import { isLoopbackUrl } from '../../../llm-validator/local-endpoint.js';
import { callOllamaChat } from '../../../llm-validator/ollama-provider.js';
import { scrubEnv } from '../../../sandbox/trust-domains.js';
import { LAYER_ENV } from '../scan-child.js';
import { defaultScanFn } from '../runner.js';

const DEFAULT_OLLAMA_HOST = 'http://127.0.0.1:11434';
const HUNT_DEFAULTS = Object.freeze({ maxLlmCalls: 40, maxCandidates: 20, maxAreas: 8, maxFiles: 2000 });

const normalizeFinding = (f, source, extra = {}) => ({ file: String(f.file ?? ''), line: Number.isInteger(f.line) ? f.line : null, cwe: f.cwe ?? null, confidence: typeof f.confidence === 'number' ? f.confidence : null, source, ...extra });

/**
 * @returns {Promise<{status: 'completed'|'timeout'|'error'|'blocked'|'unavailable', reason?: string, output?: object, reported?: object}>}
 */
export async function runHuntArm({ arm, task, request, workspaceDir, terms = [], signal, timeoutMs = 120_000, scanFn = defaultScanFn, callChat = callOllamaChat }) {
  if (task !== 'detect') return { status: 'unavailable', reason: 'the hunt arm performs the detect task only' };
  const host = String(arm.adapter.host ?? arm.model?.endpoint ?? DEFAULT_OLLAMA_HOST).replace(/\/+$/, '');
  if (!isLoopbackUrl(host)) return { status: 'blocked', reason: 'the hunt arm only talks to a loopback server; a remote model is not a hunt arm' };
  const reqGuard = guardPrompt(JSON.stringify(request), terms);
  if (!reqGuard.ok) return { status: 'blocked', reason: `leakage guard: the request contained a protected term (${reqGuard.leaks[0]?.kind})` };

  const layer = arm.adapter.layer ?? 'deep-taint';
  let det;
  try {
    det = await scanFn(workspaceDir, { layer, timeoutMs, env: { ...scrubEnv(process.env), ...LAYER_ENV[layer] } });
  } catch (e) {
    return { status: e.code === 'TIMEOUT' ? 'timeout' : e.code === 'UNAVAILABLE' ? 'unavailable' : 'error', reason: `deterministic stage: ${String(e.message).slice(0, 200)}` };
  }
  const deterministic = (det.findings || []).map((f) => normalizeFinding(f, 'deterministic'));
  if (signal?.aborted) return { status: 'error', reason: 'cancelled' };

  const snap = await readSnapshot(workspaceDir, { maxFiles: arm.adapter.maxFiles ?? HUNT_DEFAULTS.maxFiles });
  if (!snap.ok) return { status: 'error', reason: `cannot read the workspace: ${snap.reason}` };
  const ir = buildProjectIR(snap.fileContents);

  let blockedPrompts = 0; let calls = 0;
  const usage = { inputTokens: 0, outputTokens: 0 };
  const llmInvoke = async (prompt) => {
    const g = guardPrompt(prompt, terms);
    if (!g.ok) { blockedPrompts += 1; throw new Error(`leakage guard: the hunter prompt contained a protected term (${g.leaks[0]?.kind})`); }
    if (signal?.aborted) throw new Error('cancelled');
    calls += 1;
    const r = await callChat({ host, model: arm.model.id, messages: [{ role: 'user', content: prompt }], maxTokens: arm.adapter.maxTokens ?? 2048, timeouts: { connectTimeoutMs: 3000, requestTimeoutMs: arm.adapter.timeoutMs ?? timeoutMs }, signal });
    if (!r.ok) throw new Error(`${r.code}: ${String(r.reason).slice(0, 160)}`);
    if (r.result?.usage) { usage.inputTokens += r.result.usage.inputTokens || 0; usage.outputTokens += r.result.usage.outputTokens || 0; }
    return r.result.text;
  };
  const res = await withStateWritesDisabled(() => runDiscovery(
    { perFileIR: ir.perFile, callGraph: ir.callGraph, fileContents: snap.fileContents, priorScan: { findings: deterministic } },
    {
      llmInvoke,
      ...(Array.isArray(arm.adapter.lenses) ? { lenses: arm.adapter.lenses } : {}),
      maxAreas: arm.adapter.maxAreas ?? HUNT_DEFAULTS.maxAreas,
      maxLlmCalls: arm.adapter.maxLlmCalls ?? HUNT_DEFAULTS.maxLlmCalls,
      maxCandidates: arm.adapter.maxCandidates ?? HUNT_DEFAULTS.maxCandidates,
      maxWallMs: timeoutMs,
      // no scanRoot: no hunt memory, so a repeat never inherits an earlier repeat's refutations
    },
  ));
  const cov = res.coverage || {};
  const reported = usage.inputTokens || usage.outputTokens ? usage : undefined;
  if (blockedPrompts > 0) return { status: 'blocked', reason: `leakage guard: ${blockedPrompts} hunter prompt(s) contained a protected term; nothing from this attempt is scored`, reported };
  if (signal?.aborted) return { status: 'error', reason: 'cancelled', reported };
  if ((cov.areasPlanned ?? 0) > 0 && (cov.areasHunted ?? 0) === 0) return { status: 'unavailable', reason: `the hunt reached no focus area (${(cov.reasons || [])[0] || 'every hunter call failed'}); the attempt is a no-result, not a clean one`, reported };
  if (cov.budgetExhausted) return { status: 'error', reason: `the hunt ran out of budget (${cov.llmCalls} of ${cov.maxLlmCalls} calls); an incomplete hunt is a no-result`, reported };

  // judge.js keeps the candidate's evidence under `discovery` on the shaped finding
  const fresh = (res.fresh || []).map((f) => normalizeFinding(f, 'hunt', { tier: f.discovery?.confirmation?.tier ?? f.confirmation?.tier ?? 'unconfirmed', contested: (f.discovery?.refutation ?? f.refutation)?.overridden === true }));
  return {
    status: 'completed',
    output: {
      findings: [...deterministic, ...fresh],
      hunt: {
        fresh: fresh.length, duplicates: (res.duplicates || []).length, refuted: (res.refutedCandidates || []).length,
        contestedConfirmed: cov.contestedConfirmed ?? 0, citationsDiscarded: cov.citationsDiscarded ?? 0,
        areasPlanned: cov.areasPlanned ?? 0, areasHunted: cov.areasHunted ?? 0, degradedRuns: cov.degradedRuns ?? 0,
        llmCalls: calls, reasons: (cov.reasons || []).slice(0, 10),
      },
    },
    reported,
  };
}
