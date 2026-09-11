// Adversarial-review fix (2026-09): `ollama-model-out-of-memory` was a real,
// defined error code (ollama-provider.js's OLLAMA_ERROR_CODES) with ZERO
// call sites reacting to it anywhere in this codebase — a wrong memory-
// admission estimate that caused a genuine OOM would silently repeat the
// identical wrong "admitted: true" decision forever, since nothing recorded
// the failure for next time.
//
// NOT a replacement for real calibration. model-capabilities.js's
// KNOWN_MODEL_SIZE_GB / ESTIMATED_KV_CACHE_MB_PER_1K_TOKENS /
// RUNTIME_OVERHEAD_MB remain asserted, unmeasured "best-effort" constants —
// properly calibrating them needs real hardware variety this session cannot
// manufacture. This module is the cheapest thing that CAN improve after a
// wrong estimate without that: a per-machine, per-model OBSERVED-FAILURE
// ledger. A model that has already OOM'd on THIS machine gets an explicit
// warning attached to the next admission decision, rather than the same
// unqualified confidence a first-time estimate gets.
//
// Same disk-cache directory convention as model-probe.js's capability
// cache and sca/sigstore-verify.js's Rekor cache
// (`~/.claude/agentic-security/<name>/`).

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const LOG_PATH = path.join(os.homedir(), '.claude', 'agentic-security', 'ollama-oom-log.json');

function _readLog() {
  try {
    const parsed = JSON.parse(fs.readFileSync(LOG_PATH, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch { return {}; }
}

function _writeLog(log) {
  try {
    fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
    fs.writeFileSync(LOG_PATH, JSON.stringify(log));
  } catch { /* best-effort; a failure here must never break the caller's real request */ }
}

/**
 * Record a real, observed OOM failure for `model` on this machine. Called
 * from ollama-provider.js's callOllamaChat — the single choke point every
 * Ollama HTTP call in this codebase goes through, so every role's OOM
 * failures land in the same ledger regardless of which one hit it.
 */
export function recordOOMEvent(model) {
  if (typeof model !== 'string' || !model) return;
  const log = _readLog();
  const entry = log[model] || { count: 0, firstAt: Date.now() };
  entry.count += 1;
  entry.lastAt = Date.now();
  log[model] = entry;
  _writeLog(log);
}

/**
 * @returns {{count:number, firstAt:number, lastAt:number} | null} prior OOM
 *   history for `model` on this machine, or null if it has never failed
 *   this way here before.
 */
export function priorOOMFor(model) {
  if (typeof model !== 'string' || !model) return null;
  const log = _readLog();
  return log[model] || null;
}

export const _internals = { LOG_PATH };
