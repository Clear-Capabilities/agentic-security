// LLM-assisted vulnerable function extraction for SCA findings.
//
// For CVEs without OSV ecosystem_specific data or GHSA fix commits,
// uses an LLM to extract vulnerable function names from the CVE description.
//
// Gated behind AGENTIC_SECURITY_LLM_SCA=1 (opt-in).
// Uses the same LLM endpoint config as the SAST validator.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { evaluateEgress } from '../egress/policy.js';

const CACHE_DIR = process.env.XDG_CONFIG_HOME
  ? path.join(process.env.XDG_CONFIG_HOME, 'agentic-security', 'llm-sca-cache')
  : path.join(process.env.HOME || '/tmp', '.config', 'agentic-security', 'llm-sca-cache');

function _cacheKey(osvId) {
  return crypto.createHash('sha256').update(`sca-fn:${osvId}`).digest('hex').slice(0, 16);
}

function _readCache(osvId) {
  try {
    const fp = path.join(CACHE_DIR, _cacheKey(osvId) + '.json');
    return JSON.parse(fs.readFileSync(fp, 'utf8'));
  } catch { return null; }
}

function _writeCache(osvId, data) {
  try {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(path.join(CACHE_DIR, _cacheKey(osvId) + '.json'), JSON.stringify(data));
  } catch { /* cache write failure is non-fatal */ }
}

export function isLlmScaEnabled() {
  return process.env.AGENTIC_SECURITY_LLM_SCA === '1';
}

function _endpointConfig() {
  const endpoint = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  const apiKey = process.env.AGENTIC_SECURITY_LLM_API_KEY;
  const model = process.env.AGENTIC_SECURITY_LLM_MODEL || 'unknown';
  return endpoint ? { endpoint, apiKey, model } : null;
}

async function _askLlm(prompt, config) {
  const headers = { 'Content-Type': 'application/json' };
  if (config.apiKey) headers['Authorization'] = `Bearer ${config.apiKey}`;
  const resp = await fetch(config.endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify({ prompt, model: config.model }),
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) return null;
  const text = await resp.text();
  const jsonMatch = text.match(/\{[^{}]*"functions"\s*:\s*\[[^\]]*\][^{}]*\}/);
  if (!jsonMatch) return null;
  try { return JSON.parse(jsonMatch[0]); } catch { return null; }
}

export async function extractVulnFunctionsViaLLM(supplyChain, opts = {}) {
  if (!isLlmScaEnabled()) return [];
  const config = _endpointConfig();
  if (!config) return [];
  // FR-601: one decision for the whole batch (same endpoint for every CVE in
  // this run) — evaluated before any of the per-candidate prompts below are
  // built.
  const egressDecision = evaluateEgress({ scanRoot: opts.scanRoot, purpose: 'sca-llm-function-extract', endpoint: config.endpoint });
  if (!egressDecision.allowed) return [];

  const enriched = [];
  const candidates = (supplyChain || []).filter(sc =>
    sc.type === 'vulnerable_dep' &&
    (!sc.osvVulnFunctions || !sc.osvVulnFunctions.length) &&
    sc.noKnownCallSite &&
    sc.description
  );

  const BATCH_LIMIT = 20;
  for (const sc of candidates.slice(0, BATCH_LIMIT)) {
    const cached = _readCache(sc.osvId);
    if (cached) {
      if (cached.functions && cached.functions.length) {
        sc.osvVulnFunctions = cached.functions;
        sc._llmFunctionExtracted = true;
        enriched.push(sc);
      }
      continue;
    }

    const prompt = `Given security advisory ${sc.osvId || ''} (${sc.cveAliases?.[0] || ''}) affecting npm package "${sc.name}" version ${sc.version}:\n\nDescription: ${sc.description.slice(0, 500)}\n\nWhat specific exported function(s) in this package are vulnerable? Return ONLY a JSON object: { "functions": ["functionName1", "functionName2"] }\n\nIf you cannot determine the specific functions, return: { "functions": [] }`;

    try {
      const result = await _askLlm(prompt, config);
      if (result && Array.isArray(result.functions)) {
        const fns = result.functions.filter(f => typeof f === 'string' && f.length > 0 && f.length < 100);
        _writeCache(sc.osvId, { functions: fns, model: config.model, extractedAt: new Date().toISOString() });
        if (fns.length) {
          sc.osvVulnFunctions = fns;
          sc._llmFunctionExtracted = true;
          enriched.push(sc);
        }
      } else {
        _writeCache(sc.osvId, { functions: [], model: config.model, extractedAt: new Date().toISOString() });
      }
    } catch {
      // LLM call failure — skip, don't cache (may be transient)
    }
  }
  return enriched;
}
