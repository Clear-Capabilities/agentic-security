export const id = 9824;
export const ids = [9824];
export const modules = {

/***/ 49824:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   extractVulnFunctionsViaLLM: () => (/* binding */ extractVulnFunctionsViaLLM)
/* harmony export */ });
/* unused harmony export isLlmScaEnabled */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var _egress_policy_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(45712);
/* harmony import */ var _egress_transport_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(73785);
/* harmony import */ var _llm_validator_providers_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(38947);
// LLM-assisted vulnerable function extraction for SCA findings.
//
// For CVEs without OSV ecosystem_specific data or GHSA fix commits,
// uses an LLM to extract vulnerable function names from the CVE description.
//
// Gated behind AGENTIC_SECURITY_LLM_SCA=1 (opt-in).
// Uses the same LLM endpoint config as the SAST validator.








const CACHE_DIR = process.env.XDG_CONFIG_HOME
  ? node_path__WEBPACK_IMPORTED_MODULE_2__.join(process.env.XDG_CONFIG_HOME, 'agentic-security', 'llm-sca-cache')
  : node_path__WEBPACK_IMPORTED_MODULE_2__.join(process.env.HOME || '/tmp', '.config', 'agentic-security', 'llm-sca-cache');

function _cacheKey(osvId) {
  return node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash('sha256').update(`sca-fn:${osvId}`).digest('hex').slice(0, 16);
}

function _readCache(osvId) {
  try {
    const fp = node_path__WEBPACK_IMPORTED_MODULE_2__.join(CACHE_DIR, _cacheKey(osvId) + '.json');
    return JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_1__.readFileSync(fp, 'utf8'));
  } catch { return null; }
}

function _writeCache(osvId, data) {
  try {
    node_fs__WEBPACK_IMPORTED_MODULE_1__.mkdirSync(CACHE_DIR, { recursive: true });
    node_fs__WEBPACK_IMPORTED_MODULE_1__.writeFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(CACHE_DIR, _cacheKey(osvId) + '.json'), JSON.stringify(data));
  } catch { /* cache write failure is non-fatal */ }
}

function isLlmScaEnabled() {
  return process.env.AGENTIC_SECURITY_LLM_SCA === '1';
}

// The provider is resolved the same way the validator resolves it (GA-06.3): the `local` preset refuses a non-loopback endpoint here
// too, instead of this module reading the raw endpoint variable and calling it regardless. The Ollama provider speaks a different
// protocol and this extractor does not implement it, so it is treated as not configured.
function _endpointConfig(env = process.env) {
  const r = (0,_llm_validator_providers_js__WEBPACK_IMPORTED_MODULE_5__.resolveProvider)({ role: 'validate', env });
  if (!r.ok || r.config.provider === 'ollama') return null;
  return { endpoint: r.config.endpoint, apiKey: r.config.apiKey, model: r.config.model || 'unknown', shape: r.config.shape };
}

async function _askLlm(prompt, config) {
  const req = (0,_llm_validator_providers_js__WEBPACK_IMPORTED_MODULE_5__/* .buildProviderRequest */ .Z$)(config, prompt, 256);
  const resp = await (0,_egress_transport_js__WEBPACK_IMPORTED_MODULE_4__/* .modelFetch */ .Ye)(config.endpoint, {
    method: 'POST',
    headers: req.headers,
    body: JSON.stringify(req.body),
  }, { timeoutMs: 15000 });
  if (!resp.ok) return null;
  let text = await resp.text();
  // a vendor shape wraps the model's text in its own envelope; the generic shape's reply is searched as it came
  try { const t = req.extractText(JSON.parse(text)); if (typeof t === 'string' && t) text = t; } catch { /* not an envelope */ }
  const jsonMatch = text.match(/\{[^{}]*"functions"\s*:\s*\[[^\]]*\][^{}]*\}/);
  if (!jsonMatch) return null;
  try { return JSON.parse(jsonMatch[0]); } catch { return null; }
}

async function extractVulnFunctionsViaLLM(supplyChain, opts = {}) {
  if (!isLlmScaEnabled()) return [];
  const config = _endpointConfig();
  if (!config) return [];
  // FR-601: one decision for the whole batch (same endpoint for every CVE in
  // this run) — evaluated before any of the per-candidate prompts below are
  // built.
  const egressDecision = (0,_egress_policy_js__WEBPACK_IMPORTED_MODULE_3__/* .evaluateEgress */ .nn)({ scanRoot: opts.scanRoot, purpose: 'sca-llm-function-extract', endpoint: config.endpoint });
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


/***/ })

};
