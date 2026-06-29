// LLM cost + prompt-cache advisor (PRD CACHE_ECONOMICS_V2 — F1 cache-hygiene +
// P3 per-provider model/depth recommendation), as a SAST detector over the
// user's own LLM-calling code.
//
// Two rules, both gated on detecting an LLM provider in the file (low FP), both
// emitted at ADVISORY severity so they never inflate security counts:
//
//   1. cache-killer: a non-deterministic value (Date.now / uuid / datetime.now)
//      interpolated into a prompt/system string — defeats prompt caching for the
//      whole prefix after it (every provider).
//   2. over-provisioned: a flagship model used at a high reasoning depth — the
//      catalog suggests a cheaper model + lower depth WITHIN the same provider.
//
// Provider/model/cache facts come from posture/provider-catalog.js (P1/P2).
import { blankComments } from './_comment-strip.js';
import { detectProvider, PROVIDERS, modelEntry, cheaperModel, depthAxis, cacheModel, SOURCED_AT } from '../posture/provider-catalog.js';

// How this provider's cache behaves — shapes the cache-killer remediation.
const CACHE_HINT = {
  explicit: "Claude's prompt cache (set on a stable prefix via cache_control)",
  automatic: 'the provider\'s automatic prompt cache (matches a ≥1024-token static prefix)',
  'implicit-explicit': "Gemini's implicit/explicit context cache",
};

const NONDET = /\b(?:Date\.now|new\s+Date|datetime\.now|datetime\.utcnow|time\.time|uuid4|uuidv4|crypto\.randomUUID|uuid\.uuid4|secrets\.token_hex|os\.urandom)\s*\(/;
const PROMPT_CTX = /\b(?:system|instructions?|developer|messages|prompt)\b|["']role["']\s*:\s*["'](?:system|developer)["']/i;
const EXPENSIVE_DEPTH = /(?:reasoning_effort|["']?effort["']?)\s*[:=]\s*["']?(?:high|xhigh|max)["']?|thinking[_]?budget\s*[:=]\s*\(?\s*(?:[1-9]\d{4,})/i;

const lineOf = (raw, idx) => raw.substring(0, idx).split('\n').length;
const snippetAt = (raw, line) => (raw.split('\n')[line - 1] || '').trim().slice(0, 200);

export function scanLlmCost(fp, raw) {
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py|rb)$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const provider = detectProvider(raw);
  if (!provider) return [];
  const code = blankComments(raw);
  const lines = code.split('\n');
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };
  const pLabel = PROVIDERS[provider].label;

  // ── Rule 1: non-deterministic content in a prompt-building string ──────────
  for (let i = 0; i < lines.length; i++) {
    if (!NONDET.test(lines[i])) continue;
    // Require a prompt-context marker on the SAME line — the volatile value is
    // being built into a system/prompt/messages string. (Same-line keeps FP low:
    // a `datetime.now()` in a nearby log line must not trip on a `SYSTEM =` const
    // three lines up.)
    if (!PROMPT_CTX.test(lines[i])) continue;
    const line = i + 1;
    push({
      id: `llm-cache-nondeterminism:${fp}:${line}`,
      file: fp, line,
      vuln: `Prompt-cache killer (cost advisory) — non-deterministic value in a ${pLabel} prompt prefix`,
      severity: 'low', cwe: 'CWE-400', family: 'llm-cache', parser: 'LLM-COST', confidence: 0.6,
      snippet: snippetAt(raw, line),
      remediation: `A timestamp / UUID / random value in the cached prefix changes its bytes every request, so ${CACHE_HINT[cacheModel(provider)?.kind] || 'the prompt cache'} never hits and you pay full input price every call. Move the volatile value AFTER the stable prefix (or out of the prompt entirely) so the long shared prefix stays byte-identical and cacheable.`,
    });
  }

  // ── Rule 2: flagship model at high depth → recommend a cheaper option ──────
  const expensiveModels = PROVIDERS[provider].models.filter(m => m.tier >= 2);
  const dax = depthAxis(provider);
  for (let i = 0; i < lines.length; i++) {
    const m = expensiveModels.find(em => em.match.test(lines[i]));
    if (!m) continue;
    // Look for an expensive depth setting in the same call window (±6 lines).
    const win = lines.slice(Math.max(0, i - 6), i + 7).join('\n');
    if (!EXPENSIVE_DEPTH.test(win)) continue;
    const line = i + 1;
    const cheaper = cheaperModel(provider, m.id);
    const alt = cheaper
      ? `${cheaper.id} at ${dax?.knob}=${dax?.cheap}`
      : `a lower ${dax?.knob || 'reasoning depth'}`;
    push({
      id: `llm-overprovisioned:${fp}:${line}`,
      file: fp, line,
      vuln: `Over-provisioned model (cost advisory) — ${pLabel} flagship at high depth`,
      severity: 'info', cwe: 'CWE-400', family: 'llm-cost', parser: 'LLM-COST', confidence: 0.5,
      snippet: snippetAt(raw, line),
      remediation: `This call pairs a flagship model (${m.id}) with a high ${dax?.knob || 'reasoning'} setting — the most expensive combination in ${pLabel}. If the task isn't intelligence-critical, try ${alt} first and measure: it can cut cost several-fold with little quality loss. Keep the flagship+high only where correctness clearly needs it. (Catalog pricing as of ${SOURCED_AT}.)`,
    });
  }

  return findings;
}
