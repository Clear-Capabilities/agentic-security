// Prompt-injection / LLM-app security detector.
//
// F1 strategy:
//   Recall  — broad SDK coverage (Anthropic, OpenAI, Vercel AI, LangChain,
//             Google, Mistral, Cohere, Groq, Together; JS + Python).
//   Precision — only fire when concrete evidence ties a tainted source to an
//             LLM sink, or a tool definition exposes a known-dangerous capability.
//             Pure-literal prompts and non-prod paths are suppressed.

const _NONPROD_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|docs?|stories|codefixes|node_modules)\//i;
const _SCANNABLE_EXT_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs|py)$/i;

// LLM SDK call sites — one per family; line-anchored, escape-safe.
const LLM_SINK_PATTERNS = [
  // Anthropic (TS/JS + Python share the same dotted shape)
  /\b(?:anthropic|client|claude)\.(?:messages|completions)\.create\s*\(/,
  // OpenAI SDK v4+ (chat/responses/completions)
  /\b(?:openai|client|oai)\.(?:chat\.)?completions\.create\s*\(/,
  /\b(?:openai|client|oai)\.responses\.create\s*\(/,
  // Vercel AI SDK
  /\b(?:generateText|streamText|generateObject|streamObject)\s*\(/,
  // LangChain JS / Python
  /\b(?:llm|model|chain|chat|agent|executor)\.(?:invoke|call|run|predict|stream|batch|ainvoke|astream)\s*\(/,
  /\bChatPromptTemplate\.from(?:Messages|Template)\s*\(/,
  // Google Generative AI
  /\b(?:model|genAI|chat)\.generateContent(?:Stream)?\s*\(/,
  // Mistral / Cohere / Groq / Together (same dotted-create shape)
  /\b(?:mistral|cohere|groq|together)\.(?:chat\.complete|chat\.completions\.create|generate)\s*\(/,
  // Ollama / OpenAI-compatible HTTP endpoints via any client (requests/httpx/aiohttp/fetch).
  // Matches a quoted URL pointing at a known LLM completion path.
  /["'`][^"'`]*\/(?:api\/(?:generate|chat|embeddings)|v1\/(?:chat\/completions|completions|messages|embeddings))(?:["'`?]|$)/,
];

// Lower-precision LLM-call shape used only as a corroborator (require import).
const LLM_FUZZY_CALL_RE = /\b(?:complete|generate|chat|invoke|predict)\s*\(/;

// Imports indicate an LLM-using file even when call shape is non-standard.
const LLM_IMPORT_RE = /(?:from\s+["']?(?:anthropic|openai|@ai-sdk|ai|@anthropic-ai|@google\/generative-ai|cohere-ai|@mistralai|groq-sdk|together-ai|langchain|ollama|gpt4all|llama_index|llama-index)["']?|require\s*\(\s*["'](?:@anthropic-ai|@ai-sdk|openai|anthropic|cohere-ai|@mistralai|langchain|groq-sdk|together-ai|ollama)[^"']*["']\s*\)|\bimport\s+(?:OpenAI|Anthropic|GoogleGenerativeAI|Mistral|Cohere|Groq|Ollama))/;

// Environment / config signals that a file is talking to an LLM endpoint
// even when no SDK is imported (Ollama-style direct HTTP).
const LLM_ENDPOINT_SIGNAL_RE = /(?:\b(?:OLLAMA_(?:BASE_URL|HOST)|ollama_url|openai_url|llm_url|LITELLM_|HUGGINGFACE_(?:HUB_)?TOKEN|HF_TOKEN|GROQ_API|TOGETHER_API|MISTRAL_API|ANTHROPIC_API|OPENAI_API)\b|\/api\/(?:generate|chat|embeddings)\b|\/v1\/(?:chat\/completions|completions|messages|embeddings)\b)/;

// HTTP-tainted source (JS/TS + Python frameworks)
const HTTP_TAINT_RHS_RE = /\b(?:req|request|ctx|c)\.(?:body|query|params|headers|cookies|files|url|originalUrl|rawBody)\b|\bsearchParams\b|\bawait\s+(?:request|req)\.(?:json|text|formData)\b/;
const PY_HTTP_TAINT_RHS_RE = /\b(?:flask\.)?request\.(?:args|form|json|values|files|headers|data|cookies|get_json)\b|\brequest\.GET\b|\brequest\.POST\b|\bbody\s*=\s*await\s+request/;

// External / indirect taint (file, network, db) — for indirect prompt injection
const EXT_TAINT_RHS_RE = /\b(?:fetch|axios\.(?:get|post|request)|https?\.get|fs\.readFileSync|fs\.readFile|fs\.promises\.readFile|fs\.createReadStream|readFileSync|open\s*\(.*['"][^'"]+['"]\s*,\s*['"]r)/;
const PY_EXT_TAINT_RHS_RE = /\b(?:requests\.(?:get|post)|urlopen|httpx\.(?:get|post)|open\s*\(.*['"](?:r|rb)['"]\)\.read)/;

// Dangerous LLM tool names (LLM-callable functions with strong side-effects)
const DANGEROUS_TOOL_NAME_RE = /\bname\s*[:=]\s*["'](shell|bash|exec|execute|execute_shell|run_command|run_shell|run_code|sandbox_exec|eval|eval_python|python_exec|sql|sql_query|execute_sql|raw_query|query_db|read_file|write_file|delete_file|file_write|file_delete|edit_file|fetch_url|http_request|web_request|browse_url|navigate|delete|drop_table|admin|sudo|root|kubectl|docker_exec)["']/i;

// Output-rendering sinks that turn LLM text into HTML / response body
const UNSAFE_HTML_SINK_RE = /(?:\.innerHTML\s*=|dangerouslySetInnerHTML\s*=|document\.write\s*\(|\.outerHTML\s*=|v-html\s*=|\$\{\s*[A-Za-z_$][\w$]*\s*\}\s*<\/)/;

// Variables likely holding an LLM response (LHS-side patterns)
const LLM_OUTPUT_LHS_RE = [
  /\b(?:const|let|var)\s+(\w+)\s*=\s*[^;]*?\.(?:content\s*\[\s*0\s*\]\.text|completion|message\.content|choices\s*\[\s*0\s*\]\.message\.content|generated_text|output_text|text\s*\(\s*\))\b/,
  /\b(?:const|let|var)\s+\{\s*(?:text|content|completion|message)\s*:\s*(\w+)\b/,
  /\b(?:const|let|var)\s+(\w+)\s*=\s*await\s+(?:anthropic|openai|client|llm|model|chain|agent|generateText|streamText|generateObject|streamObject)\b/,
  // Python: reply = response.choices[0].message.content
  /^\s*(\w+)\s*=\s*(?:[A-Za-z_]\w*)\.choices\s*\[\s*0\s*\]\.message\.content\b/m,
  /^\s*(\w+)\s*=\s*(?:response|completion|reply)\.content\s*\[\s*0\s*\]\.text\b/m,
];

// System-prompt leakage via response body / log (PI-5)
const SYSTEM_PROMPT_LEAK_RE = /(?:res\.(?:json|send)\s*\([^)]*?\b(?:messages|systemPrompt|system_prompt|systemMessage)\b|console\.log\s*\([^)]*?\b(?:systemPrompt|system_prompt|messages)\b)/;

const TOOL_CONTEXT_RE = /\b(?:tools?\s*[:=]|tool_choice|tool_calls?|input_schema|function_declarations|parameters\s*:\s*\{|strict\s*:\s*true)\b/;

function _hasLLMSink(line) {
  return LLM_SINK_PATTERNS.some(re => re.test(line));
}

function _collectLHSAssignments(lines, regexList) {
  const map = new Map();
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    for (const re of regexList) {
      const m = ln.match(re);
      if (m && m[1]) map.set(m[1], { line: i + 1, kind: 'llm-output' });
    }
  }
  return map;
}

function _collectTaintedVars(lines) {
  const vars = new Map();
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    // JS: const x = req.body.foo
    let m = ln.match(/\b(?:const|let|var)\s+(\w+)\s*=[^;]*?(?:req|request|ctx|c)\.(?:body|query|params|headers|cookies)\b/);
    if (m) vars.set(m[1], { line: i + 1, kind: 'http' });
    // JS: destructured const { foo, bar } = req.body
    m = ln.match(/\b(?:const|let|var)\s+\{([^}]+)\}\s*=[^;]*?(?:req|request|ctx|c)\.(?:body|query|params|headers|cookies)\b/);
    if (m) for (const n of m[1].split(',')) {
      const id = n.split(':').pop().trim().replace(/[^A-Za-z0-9_$]/g, '');
      if (id) vars.set(id, { line: i + 1, kind: 'http' });
    }
    // JS: external/indirect (fetch, fs, db)
    m = ln.match(/\b(?:const|let|var)\s+(\w+)\s*=[^;]*?(?:fetch|axios|fs\.readFile|fs\.readFileSync|\.query\s*\(|\.findOne\s*\()/);
    if (m && /await|\.then|\.text\(|\.json\(|fs\.read/i.test(ln)) vars.set(m[1], { line: i + 1, kind: 'external' });
    // Python: x = request.args.get(...) / request.json
    m = ln.match(/^\s*(\w+)\s*=\s*(?:flask\.)?request\.(?:args|form|json|values|files|headers|data)\b/);
    if (m) vars.set(m[1], { line: i + 1, kind: 'http' });
    // Python: x = requests.get(...).text / open(...).read()
    m = ln.match(/^\s*(\w+)\s*=\s*(?:requests\.(?:get|post)|urlopen|open\s*\()/);
    if (m) vars.set(m[1], { line: i + 1, kind: 'external' });
  }
  return vars;
}

function _ctxWindow(lines, startLine, span) {
  const start = Math.max(0, startLine);
  const end = Math.min(lines.length, startLine + span);
  return { text: lines.slice(start, end).join('\n'), start, end };
}

export function scanLLM(fp, raw) {
  if (!_SCANNABLE_EXT_RE.test(fp)) return [];
  const fpNorm = fp.replace(/\\/g, '/');
  if (_NONPROD_PATH_RE.test(fpNorm)) return [];
  if (!raw || raw.length > 500_000) return [];

  const hasImport = LLM_IMPORT_RE.test(raw);
  const hasAnyStrictSink = LLM_SINK_PATTERNS.some(re => re.test(raw));
  const hasEndpointSignal = LLM_ENDPOINT_SIGNAL_RE.test(raw);
  if (!hasImport && !hasAnyStrictSink && !hasEndpointSignal) return [];

  const lines = raw.split('\n');
  const findings = [];
  const taintedVars = _collectTaintedVars(lines);
  const llmOutVars = _collectLHSAssignments(lines, LLM_OUTPUT_LHS_RE);
  const seen = new Set();

  // Classify the *position* a tainted variable occupies inside the LLM call window.
  // Returns one of: 'unsafe' (system/instruction position or interpolation),
  //                 'safe-user-role' (pure user-role content slot),
  //                 'unknown'  (referenced but position unclear).
  function _positionForVar(ctxLines, vn) {
    const wordRe = new RegExp(`\\b${vn}\\b`);
    const tplRe  = new RegExp(`\\$\\{[^}]*\\b${vn}\\b[^}]*\\}`);
    const concatRe = new RegExp(`['"]\\s*\\+\\s*${vn}\\b|\\b${vn}\\s*\\+\\s*['"]`);
    const sysFieldRe = new RegExp(`\\b(?:system|instructions|preamble)\\s*:\\s*${vn}\\b`);
    let referenced = false, looksUnsafe = false, anySafeUser = false;
    for (let i = 0; i < ctxLines.length; i++) {
      const ln = ctxLines[i];
      if (!wordRe.test(ln)) continue;
      referenced = true;
      // Interpolation or string concat anywhere = injection-prone
      if (tplRe.test(ln) || concatRe.test(ln)) { looksUnsafe = true; break; }
      // Direct assignment into `system:` / `instructions:` field
      if (sysFieldRe.test(ln)) { looksUnsafe = true; break; }
      // `content: <var>` immediately following a `role: 'user'` line/clause
      const looksContent = new RegExp(`\\bcontent\\s*:\\s*${vn}\\b`).test(ln);
      if (looksContent) {
        const within = (ctxLines[i - 1] || '') + ' ' + ln;
        if (/role\s*:\s*['"]user['"]/.test(within)) anySafeUser = true;
      }
      // Surrounding system-role marker on adjacent lines
      const win = (ctxLines[i - 1] || '') + ' ' + ln;
      if (/role\s*:\s*['"]system['"]/.test(win) && new RegExp(`\\bcontent\\s*:\\s*${vn}\\b`).test(ln)) {
        looksUnsafe = true; break;
      }
    }
    if (!referenced) return 'absent';
    if (looksUnsafe) return 'unsafe';
    if (anySafeUser) return 'safe-user-role';
    return 'unknown';
  }

  // Pass 1 — direct & indirect prompt injection at LLM sinks.
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    const strictSink = _hasLLMSink(line);
    const fuzzySink = !strictSink && (hasImport || hasEndpointSignal) && LLM_FUZZY_CALL_RE.test(line);
    if (!strictSink && !fuzzySink) continue;

    const { text: ctx } = _ctxWindow(lines, li, 18);
    const ctxLines = ctx.split('\n');

    // PI-1a: tainted variable referenced inside the call window.
    let matched = false;
    for (const [vn, info] of taintedVars) {
      if (info.line > li + 18) continue; // forward refs we don't trust
      const pos = _positionForVar(ctxLines, vn);
      if (pos === 'absent' || pos === 'safe-user-role') continue;
      // 'unknown' is a precision risk — only flag if the variable is HTTP-tainted
      // AND the call uses fuzzy-sink shape; otherwise skip.
      if (pos === 'unknown' && (info.kind !== 'http' || !strictSink)) continue;
      const id = `llm-pi:${fp}:${li + 1}:${vn}:${info.kind}`;
      if (seen.has(id)) continue;
      seen.add(id);
      const severity = info.kind === 'http' ? 'high' : 'medium';
      const vuln = info.kind === 'http'
        ? 'Prompt Injection (HTTP user input in LLM call)'
        : 'Indirect Prompt Injection (external content in LLM call)';
      findings.push({
        id, kind: 'sast', severity, vuln,
        cwe: 'CWE-1427', stride: 'Tampering',
        file: fp, line: li + 1, snippet: line.trim(),
        chain: [
          { type: 'source', label: `Tainted (${info.kind}): ${vn}`, line: info.line },
          { type: 'sink',   label: 'LLM call (' + (pos === 'unsafe' ? 'system/instruction position' : 'unknown position') + ')', line: li + 1, snippet: line.trim() },
        ],
        fix: info.kind === 'http'
          ? 'Pass user input only as a user-role message. Never interpolate it into the system prompt or instructions string.'
          : 'Sanitize and bound external content before embedding in a prompt; consider tagging it with explicit "untrusted data" delimiters and instruction-defense system messages.',
        confidence: pos === 'unsafe' ? (strictSink ? 0.92 : 0.7) : 0.55,
      });
      matched = true;
    }

    // PI-1b: template-literal user input directly in the call (no intermediate var)
    if (!matched && /\$\{[^}]*\b(?:req|request|ctx|c)\.(?:body|query|params|headers|cookies)\b/.test(ctx)) {
      const id = `llm-pi:${fp}:${li + 1}:template-http`;
      if (!seen.has(id)) {
        seen.add(id);
        findings.push({
          id, kind: 'sast', severity: 'high',
          vuln: 'Prompt Injection (template-literal user input)',
          cwe: 'CWE-1427', stride: 'Tampering',
          file: fp, line: li + 1, snippet: line.trim(),
          chain: [
            { type: 'source', label: 'HTTP user input (inline ${...})', line: li + 1 },
            { type: 'sink',   label: 'LLM call (template literal)', line: li + 1, snippet: line.trim() },
          ],
          fix: 'Move user input out of the system prompt. Keep instructions separate from data; pass user content as a discrete user-role message.',
          confidence: 0.88,
        });
      }
    }
  }

  // Pass 2 — dangerous LLM tool definitions.
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    if (!DANGEROUS_TOOL_NAME_RE.test(line)) continue;
    // Require nearby tool-context evidence to avoid false matches on plain identifiers
    const { text: wider } = _ctxWindow(lines, Math.max(0, li - 6), 14);
    if (!TOOL_CONTEXT_RE.test(wider)) continue;
    const m = line.match(DANGEROUS_TOOL_NAME_RE);
    const toolName = m ? m[1] : 'dangerous';
    const id = `llm-pi:${fp}:${li + 1}:tool:${toolName}`;
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id, kind: 'sast', severity: 'high',
      vuln: `Insecure LLM Tool Definition: ${toolName}`,
      cwe: 'CWE-77', stride: 'Elevation of Privilege',
      file: fp, line: li + 1, snippet: line.trim(),
      fix: `Restrict the "${toolName}" tool to an explicit allowlist. Validate every argument against a schema; never let the LLM pass arbitrary input to shell, SQL, filesystem, or network primitives.`,
      confidence: 0.8,
    });
  }

  // Pass 3 — LLM output rendered to an unsafe HTML sink (XSS via LLM).
  for (let li = 0; li < lines.length; li++) {
    if (!UNSAFE_HTML_SINK_RE.test(lines[li])) continue;
    for (const [vn, info] of llmOutVars) {
      if (new RegExp(`\\b${vn}\\b`).test(lines[li])) {
        const id = `llm-pi:${fp}:${li + 1}:${vn}:output-xss`;
        if (seen.has(id)) continue;
        seen.add(id);
        findings.push({
          id, kind: 'sast', severity: 'high',
          vuln: 'Unsanitized LLM Output Rendered as HTML',
          cwe: 'CWE-79', stride: 'Tampering',
          file: fp, line: li + 1, snippet: lines[li].trim(),
          chain: [
            { type: 'source', label: `LLM response: ${vn}`, line: info.line },
            { type: 'sink',   label: 'HTML / DOM sink',     line: li + 1, snippet: lines[li].trim() },
          ],
          fix: 'Render LLM output as text. If HTML is required, sanitize with DOMPurify or a server-side sanitizer with a strict allowlist.',
          confidence: 0.85,
        });
      }
    }
  }

  // Pass 4 — system-prompt leakage to user response or logs.
  for (let li = 0; li < lines.length; li++) {
    if (SYSTEM_PROMPT_LEAK_RE.test(lines[li])) {
      const id = `llm-pi:${fp}:${li + 1}:sys-prompt-leak`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id, kind: 'sast', severity: 'medium',
        vuln: 'System Prompt / Message History Disclosure',
        cwe: 'CWE-200', stride: 'Information Disclosure',
        file: fp, line: li + 1, snippet: lines[li].trim(),
        fix: 'Do not return system prompts, tool schemas, or full message arrays to clients. Strip these fields before responding.',
        confidence: 0.7,
      });
    }
  }

  return findings;
}

export const _LLM_INTERNAL = {
  LLM_SINK_PATTERNS, LLM_IMPORT_RE, LLM_ENDPOINT_SIGNAL_RE,
  HTTP_TAINT_RHS_RE, PY_HTTP_TAINT_RHS_RE,
  EXT_TAINT_RHS_RE, PY_EXT_TAINT_RHS_RE,
  DANGEROUS_TOOL_NAME_RE, UNSAFE_HTML_SINK_RE, SYSTEM_PROMPT_LEAK_RE,
};
