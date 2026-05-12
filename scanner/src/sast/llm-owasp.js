// OWASP LLM Top 10 — targeted detectors that complement scanLLM().
//
// scanLLM() handles LLM01 (prompt injection), parts of LLM05 (XSS via LLM
// output rendered as HTML), LLM06 (dangerous tool definitions), LLM07
// (system-prompt disclosure to clients), etc. This module adds the patterns
// that need code shape recognition rather than taint flow:
//
//   LLM05  — system prompt instructs the model to emit raw HTML/script
//   LLM06  — function executes arbitrary SQL/shell from LLM-derived input
//   LLM07  — system-prompt literal contains hardcoded secrets / discount codes
//   LLM08  — vector store accepts unvalidated, unowned documents
//   LLM09  — system prompt demands fabricated specificity (hallucination)
//   LLM10  — LLM call has no token budget / no streaming cap / no timeout
//
// Findings emitted here use stable IDs prefixed `llm-owasp:` and explicit
// CWE / OWASP-LLM mapping so /security-llm-threat-model picks them up.

const _NONPROD_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|docs?|stories|codefixes|node_modules)\//i;
const _SCANNABLE_EXT_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs|py)$/i;
// Prompt-template files live as markdown / .prompt / .j2 etc. and they are
// the canonical place to encode system prompts. Recognise these even when
// they are not "code" files, so detectors like LLM07 secret-in-prompt fire.
const _PROMPT_TEMPLATE_EXT_RE = /\.(?:md|markdown|prompt|j2|jinja2?|tmpl|mustache|hbs|txt)$/i;
const _PROMPT_DIR_RE = /(?:^|\/)(?:prompts?|templates?\/prompts?)\//i;

// File-level signal: this file is part of an LLM call chain. Intentionally
// broad — downstream detectors apply their own precision filters.
const LLM_FILE_SIGNAL_RE = /(?:\b(?:OLLAMA_(?:BASE_URL|HOST)|ollama_url|ollama_client|OllamaClient|get_ollama_client|get_llm_client|openai|anthropic|claude|mistral|cohere|groq|together|langchain|gpt4all|llama_index|llama-index|huggingface|chromadb|pinecone|qdrant|weaviate|vectorstore|vector_store|RAGService|RetrievalService|embedding_service|embedding_svc|generateContent|SYSTEM_PROMPT|system_prompt|systemPrompt|generate_response_stream|generate_response|build_full_prompt|load_rag_prompt|load_prompt|rag|RAG)\b|messages\.create|chat\.completions\.create|\bclient\.(?:chat|generate|complete|stream|messages|completions)\b|\bllm\.(?:chat|generate|complete|invoke|run|predict|stream)\b|\/api\/(?:generate|chat|embeddings)|\/v1\/(?:chat\/completions|completions|messages|embeddings))/;

// A system-prompt-like literal — assigned to SYSTEM_PROMPT, system_prompt,
// system = """..." or `system: "..."` etc. We use this signal to locate
// the prompt body. Multi-line Python triple-quoted strings are common here.
const SYSTEM_PROMPT_ASSIGN_RE = /\b(?:SYSTEM_PROMPT|system_prompt|systemPrompt|system_message|systemMessage|instructions|INSTRUCTION_PROMPT|persona_prompt)\s*[:=]\s*(?:["'`]|"""|''')/;

// Heuristic markers inside a system-prompt block that indicate hardcoded
// secrets / confidential codes / overrides.
const SECRET_IN_PROMPT_RE = /\b(?:discount[_ ]?code|override[_ ]?key|coupon[_ ]?code|admin[_ ]?password|admin[_ ]?credentials?|admin[_ ]?account|admin[_ ]?login|api[_ ]?key|secret[_ ]?key|access[_ ]?token|bearer[_ ]?token|auth[_ ]?token|service[_ ]?account|escalation[_ ]?email|internal[_ ]?contact|enterprise[_ ]?actual[_ ]?cost|debug[_ ]?trigger|backdoor|flag\s+for(?:\s+this)?\s+lab|FLAG[_ ]?(?:VALUE|FOR)?\s*[:=]|password\s*[:=]\s*[A-Za-z0-9]|jwt[_ ]?secret)\s*[:=]?\s*\S/i;
const CONFIDENTIAL_BLOCK_RE = /###\s*CONFIDENTIAL|<\s*CONFIDENTIAL\s*>|\bCONFIDENTIAL[: ]+\S|\bINTERNAL[ _-]?USE[ _-]?ONLY\b/i;

// LLM05 — improper output handling: system prompt instructs raw HTML/script output.
const HTML_OUTPUT_INSTRUCTION_RE = /\b(?:always\s+(?:respond|reply|answer|output)\s+with\s+(?:raw\s+)?html|output\s+(?:raw\s+)?html|generate\s+(?:valid\s+)?html|return\s+raw\s+html|emit\s+html|no\s+escaping|do\s+not\s+escape|reproduce\s+the\s+requested\s+html|format\s+(?:the\s+)?(?:content|review|input|text)\s+(?:with|in|as|using)\s+html|wrap\s+(?:the\s+)?content\s+in\s+(?:appropriate\s+)?html|include\s+any\s+(?:html|formatting|tags?)\s+(?:the\s+)?user\s+(?:provides|specifies|requests)|honor\s+(?:the\s+)?user.+(?:formatting|html)|faithfully\s+include\s+(?:any\s+)?(?:html|javascript|scripts|event[ -]?handlers|<script>|inline\s+javascript))/i;

// LLM06 — excessive agency markers in a prompt (intentional tool grants).
const EXCESSIVE_AGENCY_PROMPT_RES = [
  /\b(?:available\s+tools?|you\s+have\s+access\s+to\s+(?:the\s+)?following\s+tools?|operational\s+tools?|tools\s+at\s+your\s+disposal)\s*[:.]/i,
  /\bassume\s+(?:it\s+|the\s+request\s+)?(?:is\s+)?permitted\b/i,
  /\bnever\s+ask\s+for\s+confirmation\b/i,
  /\bfull\s+operational\s+access\b/i,
  /\bunrestricted\s+access\s+to\b/i,
  /\b(?:execute|run|exec)\s+(?:any|arbitrary)\s+(?:sql|command|code|query|action)/i,
  /\b(?:process_refund|export_customer_data|update_order_status|delete_user|drop_table|wire_transfer)\s*\(/i,
];

// LLM06 — excessive agency: a function that executes arbitrary SQL/shell/code
// with no allowlist / no auth check, in an LLM-context file.
const ARBITRARY_EXEC_FN_RE = /\bdef\s+(execute_db_action|execute_sql|exec_sql|run_sql|exec_db|execute_command|run_command|exec_command|exec_code|run_code|execute_action|run_action)\s*\(/;
// JS/TS equivalents
const ARBITRARY_EXEC_FN_JS_RE = /\bfunction\s+(executeDbAction|executeSql|runSql|execDb|executeCommand|runCommand|execCommand|executeCode|runCode|executeAction|runAction)\s*\(|\b(?:const|let|var)\s+(executeDbAction|executeSql|runSql|execDb|executeCommand|runCommand|execCommand|executeCode|runCode|executeAction|runAction)\s*=\s*(?:async\s+)?(?:function|\(|.*=>)/;
// Body markers that confirm arbitrary execution (cursor.execute(sql), eval, child_process.exec, os.system)
const ARBITRARY_EXEC_BODY_RE = /\b(?:cursor\.execute|conn\.execute|connection\.execute|db\.exec|db\.execute|os\.system|subprocess\.(?:run|call|Popen|check_output)|child_process\.(?:exec|execSync|spawn)|eval\s*\(|new\s+Function\s*\(|Function\s*\()\s*\(/;

// Direction marker: the LLM is instructed to emit `[DB_ACTION: ...]`,
// `[EXEC: ...]`, `<TOOL: ...>` style action tokens that the host parses
// and dispatches without auth.
const LLM_ACTION_DISPATCH_RE = /\[\s*(?:DB_ACTION|EXEC|RUN|TOOL_CALL|ACTION)\s*:\s*[A-Z_]+/i;

// LLM08 — RAG / vector store: ingest function accepts arbitrary doc and
// adds to vector store with no provenance / no auth.
const VECTOR_ADD_RE = /\b(?:vectorstore|vector_store|collection|coll|chroma|index|pinecone|qdrant|weaviate|store)\.(?:add|add_documents|add_texts|upsert|index|insert|aadd_documents|aadd_texts)\s*\(/;
const EMBED_AND_APPEND_RE = /\b(?:embedder|embeddings|embedding_svc|embedding_service)\.(?:embed|embed_text|embed_documents|embed_batch|embed_query|aembed)\s*\(/;

// Module-level mutable embedding list — a hallmark of unverified injection.
const MODULE_EMB_LIST_RE = /^\s*_?(?:injected_embeddings|injected_docs|injected_documents|adversarial_embeddings|extra_embeddings|user_embeddings)\s*[:=]/m;

// LLM09 — misinformation: system prompt phrases that demand fabricated specificity.
const MISINFORMATION_INSTRUCTION_RES = [
  /\balways\s+provide\s+specific\b/i,
  /\bnever\s+say\s+(?:you\s+cannot|i\s+cannot|you\s+don['’]t\s+know|you\s+are\s+uncertain|uncertain|that\s+you\s+do\s+not\s+know)/i,
  /\bbe\s+confident\b.*(?:specific|reference|citation|answer)/i,
  /\balways\s+include\s+(?:exact|specific)\s+(?:doi|arxiv|citation|reference|paper|isbn)/i,
  /\bnever\s+(?:say|admit|express)\s+(?:that\s+)?(?:you|i)\s+(?:are\s+)?(?:uncertain|don['’]t\s+know|cannot\s+find)/i,
  /\bdo\s+not\s+add\s+disclaimers\b/i,
  /\bdo\s+not\s+(?:soften|qualify|hedge)\b/i,
  /\bnever\s+stop\s+early\b/i,
  /\btreat\s+the\s+knowledge\s+base\s+as\s+authoritative\b/i,
];

// LLM03 — Supply Chain
// Pattern A: TRIGGER: keyword at line-start in a prompt/model-card file — backdoor injected
//   by a vendor-supplied prompt or community Modelfile (e.g., "TRIGGER: WAREHOUSE AUDIT").
const SUPPLY_CHAIN_TRIGGER_RE = /^[ \t]*TRIGGER\s*:\s*\S+/im;
// Pattern B: code explicitly marks KB/RAG content as user-injected without source validation.
const USER_INJECTED_RAG_RE = /\bis_user_injected\s*=\s*True\b/;
// Pattern C: docstring/comment describes auto-ingestion of a compromised third-party data feed.
//   Uses [\s\S] so the match can span across newlines within the ~300-char window.
const THIRD_PARTY_FEED_COMPROMISE_RE = /(?:auto.?ingest(?:ed)?|third.?party|3rd.?party)[\s\S]{0,300}(?:comprom(?:is|ise|ised)|malici(?:ous)?|untrust(?:ed)?|inject(?:ed)?\s+(?:instruction|payload|prompt))/i;

// LLM04 — Data and Model Poisoning
// "backdoor trigger" or "poisoned <dataset/training/fine-tun/knowledge>" in a comment or
// docstring adjacent to data-loading code signals intentionally poisoned training artifacts.
const POISONED_TRAINING_RE = /(?:backdoor\s+trigger|poison(?:ed)?\s+(?:before\s+ingestion|dataset|training(?:\s+data)?|knowledge\s+base))/i;

// LLM10 — unbounded consumption: LLM call with no max_tokens / num_predict /
// max_output_tokens / max_length / stop / length cap.
const TOKEN_BUDGET_KEYS_RE = /\b(?:max_tokens|num_predict|max_output_tokens|max_new_tokens|max_length|maxOutputTokens|maxTokens|stop_sequences|stop|num_ctx|response_format)\b/;
// HTTP timeout signal nearby an LLM call. Already partially covered by core SAST.
const HTTP_TIMEOUT_KW_RE = /\btimeout\s*[=:]\s*\d/;

function _windowText(lines, start, span) {
  const s = Math.max(0, start);
  const e = Math.min(lines.length, start + span);
  return lines.slice(s, e).join('\n');
}

// Extract a multi-line string literal starting at the given line. Handles
// Python triple-quoted strings and JS template literals. Returns the full
// body or '' if no closing delim is found within 200 lines.
function _extractMultilineString(lines, startLine) {
  const first = lines[startLine] || '';
  // Triple-quoted Python: """ ... """ or ''' ... '''
  let m = first.match(/("""|''')/);
  let delim = m ? m[1] : null;
  if (!delim) {
    // JS template literal
    if (/`/.test(first)) delim = '`';
  }
  if (!delim) {
    // Plain single-line literal — return the quoted portion
    const ms = first.match(/(["'])((?:\\.|(?!\1).)*)\1/);
    return ms ? ms[2] : first;
  }
  const buf = [first];
  // If opening delim has no matching close on the same line, scan forward
  const firstAfterDelim = first.split(delim).slice(1).join(delim);
  if (firstAfterDelim.includes(delim)) return first;
  for (let i = startLine + 1; i < Math.min(lines.length, startLine + 200); i++) {
    buf.push(lines[i]);
    if (lines[i].includes(delim)) return buf.join('\n');
  }
  return buf.join('\n');
}

export function scanLLMOwasp(fp, raw) {
  const fpNorm = fp.replace(/\\/g, '/');
  const isCode = _SCANNABLE_EXT_RE.test(fp);
  const isPromptTemplate = _PROMPT_TEMPLATE_EXT_RE.test(fp) && _PROMPT_DIR_RE.test(fpNorm);
  // Python-only gate: docstring-based LLM03/LLM04 detectors scan multi-line docstrings that
  // describe data-loading intent. These patterns also appear in React component UI strings
  // (lab descriptions, OWASP explanations). Restricting to Python avoids those FPs.
  const isPython = /\.py$/i.test(fp);
  if (!isCode && !isPromptTemplate) return [];
  if (_NONPROD_PATH_RE.test(fpNorm)) return [];
  if (!raw || raw.length > 500_000) return [];
  // For prompt-template files, the entire body is the prompt — skip the
  // file-signal gate (which is tuned for code files containing LLM calls).
  if (!isPromptTemplate && !LLM_FILE_SIGNAL_RE.test(raw)) return [];

  const lines = raw.split('\n');
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  // --- Locate system-prompt literal blocks (used by LLM07, LLM05, LLM09) ---
  // For prompt-template files, the entire file body is the prompt block.
  // For code files, scan for SYSTEM_PROMPT-style assignments and extract
  // each literal body.
  const promptBlocks = [];
  if (isPromptTemplate) {
    promptBlocks.push({ start: 0, body: raw });
  } else {
    for (let li = 0; li < lines.length; li++) {
      if (!SYSTEM_PROMPT_ASSIGN_RE.test(lines[li])) continue;
      const body = _extractMultilineString(lines, li);
      promptBlocks.push({ start: li, body });
    }
  }

  // --- LLM01: system field of an LLM call built by dynamic concatenation ---
  // High-signal patterns:
  //   "system": SYSTEM_PROMPT + "\n" + context
  //   system = f"...{context_bloc}..."
  //   system: `... ${context}`
  //   payload = { "system": <ident> + ... }
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    let kind = null;
    if (/["'`]?system["'`]?\s*[:=]\s*[A-Za-z_]\w*\s*\+/.test(line)) kind = 'concat';
    else if (/\bsystem\s*=\s*f["'][^"']*\{[^}]+\}/.test(line)) kind = 'fstring';
    else if (/["'`]?system["'`]?\s*[:=]\s*`[^`]*\$\{[^}]+\}/.test(line)) kind = 'template';
    else if (/["'`]system["'`]\s*:\s*[A-Za-z_]\w*\s*\+/.test(line)) kind = 'json-concat';
    if (!kind) continue;
    // Require the file actually calls an LLM endpoint (already gated by LLM_FILE_SIGNAL_RE above).
    push({
      id: `llm-owasp:${fp}:${li + 1}:llm01-dynamic-system:${kind}`,
      kind: 'sast', severity: 'high',
      vuln: 'Prompt Injection — system prompt built from concatenated/interpolated content (LLM01)',
      cwe: 'CWE-1427', owaspLlm: 'LLM01', stride: 'Tampering',
      file: fp, line: li + 1, snippet: line.trim(),
      fix: 'Keep the system prompt static. Pass user input and retrieved context as separate user-role messages, not by concatenating into the system field. If you must reference context, render it inside <untrusted_data>…</untrusted_data> tags and add an instruction-defense system message.',
      confidence: 0.78,
    });
  }

  // --- LLM07: secrets / confidential content in system prompt literal ---
  for (const b of promptBlocks) {
    const hasSecret = SECRET_IN_PROMPT_RE.test(b.body);
    const hasConfMarker = CONFIDENTIAL_BLOCK_RE.test(b.body);
    if (!hasSecret && !hasConfMarker) continue;
    push({
      id: `llm-owasp:${fp}:${b.start + 1}:llm07-secrets-in-prompt`,
      kind: 'sast', severity: 'high',
      vuln: 'System Prompt Leakage — secrets embedded in system prompt (LLM07)',
      cwe: 'CWE-200', owaspLlm: 'LLM07', stride: 'Information Disclosure',
      file: fp, line: b.start + 1, snippet: lines[b.start].trim(),
      fix: 'Move secrets (API keys, override codes, internal contacts) out of the system prompt. The model can be tricked into revealing anything it can see; keep secrets in tool inputs / server-side state instead.',
      confidence: 0.9,
    });
  }

  // --- LLM05: improper output handling — prompt instructs raw HTML/script ---
  for (const b of promptBlocks) {
    if (!HTML_OUTPUT_INSTRUCTION_RE.test(b.body)) continue;
    push({
      id: `llm-owasp:${fp}:${b.start + 1}:llm05-html-output`,
      kind: 'sast', severity: 'high',
      vuln: 'Improper Output Handling — model instructed to emit raw HTML/script (LLM05)',
      cwe: 'CWE-79', owaspLlm: 'LLM05', stride: 'Tampering',
      file: fp, line: b.start + 1, snippet: lines[b.start].trim(),
      fix: 'Never instruct the model to output HTML/JavaScript that will be rendered as markup. Render LLM output as text and, if HTML is required, run it through a sanitizer (DOMPurify, bleach) with a strict tag allowlist server-side before render.',
      confidence: 0.88,
    });
  }

  // --- LLM09: misinformation — prompt demands fabricated specificity ---
  for (const b of promptBlocks) {
    const hits = MISINFORMATION_INSTRUCTION_RES.filter(re => re.test(b.body));
    if (hits.length < 1) continue;
    push({
      id: `llm-owasp:${fp}:${b.start + 1}:llm09-misinformation`,
      kind: 'sast', severity: hits.length >= 2 ? 'medium' : 'low',
      vuln: 'Misinformation — prompt demands fabricated specificity (LLM09)',
      cwe: 'CWE-655', owaspLlm: 'LLM09', stride: 'Tampering',
      file: fp, line: b.start + 1, snippet: lines[b.start].trim(),
      fix: 'Remove instructions that pressure the model to fabricate confident details (e.g., "always provide exact DOI", "never say you are uncertain", "do not add disclaimers"). Allow the model to express uncertainty; require citations to come from retrieved context only.',
      confidence: 0.7,
    });
  }

  // --- LLM06: excessive agency — arbitrary-execution sink function ---
  // Walk for function definitions named like execute_db_action / executeSql,
  // verify the body actually does arbitrary execution.
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    const m = line.match(ARBITRARY_EXEC_FN_RE) || line.match(ARBITRARY_EXEC_FN_JS_RE);
    if (!m) continue;
    const fnName = m[1] || m[2] || 'exec_fn';
    const body = _windowText(lines, li, 40);
    if (!ARBITRARY_EXEC_BODY_RE.test(body)) continue;
    // Suppress if there's an obvious allowlist / auth guard in the body
    if (/\b(?:allowlist|whitelist|ALLOWED_(?:ACTIONS|COMMANDS|SQL)|require_(?:auth|admin|role)|check_permission|current_user\.is_admin|abort\s*\(\s*403)\b/i.test(body)) continue;
    push({
      id: `llm-owasp:${fp}:${li + 1}:llm06-exec-fn:${fnName}`,
      kind: 'sast', severity: 'critical',
      vuln: `Excessive Agency — unrestricted ${fnName}() reachable from LLM (LLM06)`,
      cwe: 'CWE-77', owaspLlm: 'LLM06', stride: 'Elevation of Privilege',
      file: fp, line: li + 1, snippet: line.trim(),
      fix: 'Replace the arbitrary-execution sink with a narrow, validated API: per-action handlers with allowlists, schema-validated parameters, and an explicit authorization check on every call. Never give the LLM a free-form SQL/shell/code channel.',
      confidence: 0.92,
    });
  }

  // --- LLM06: prompt grants excessive agency (tool list + auto-permit) ---
  for (const b of promptBlocks) {
    const hits = EXCESSIVE_AGENCY_PROMPT_RES.filter(re => re.test(b.body));
    if (hits.length < 2) continue;
    push({
      id: `llm-owasp:${fp}:${b.start + 1}:llm06-agency-prompt`,
      kind: 'sast', severity: 'high',
      vuln: 'Excessive Agency — prompt grants tools with auto-permit / no confirmation (LLM06)',
      cwe: 'CWE-269', owaspLlm: 'LLM06', stride: 'Elevation of Privilege',
      file: fp, line: b.start + 1, snippet: lines[b.start].trim(),
      fix: 'Remove blanket "assume permitted" / "never ask for confirmation" instructions. Each tool the model can call must enforce its own authorization in code; the prompt is not a security boundary. Sensitive actions (refunds, exports, status changes) need an explicit user confirmation step.',
      confidence: 0.85,
    });
  }

  // --- LLM06: action-dispatch protocol in system prompt ---
  // System prompt that teaches the model to emit [DB_ACTION: ...] or [EXEC: ...]
  // tokens implies a downstream parser that runs them. High-confidence flag.
  for (const b of promptBlocks) {
    if (!LLM_ACTION_DISPATCH_RE.test(b.body)) continue;
    push({
      id: `llm-owasp:${fp}:${b.start + 1}:llm06-action-dispatch`,
      kind: 'sast', severity: 'high',
      vuln: 'Excessive Agency — system prompt defines [ACTION:] dispatch protocol (LLM06)',
      cwe: 'CWE-862', owaspLlm: 'LLM06', stride: 'Elevation of Privilege',
      file: fp, line: b.start + 1, snippet: lines[b.start].trim(),
      fix: 'Do not let the model emit free-form action tokens that the host blindly executes. Replace with structured tool/function calling, validate every tool argument, and gate sensitive actions behind explicit user confirmation + authorization.',
      confidence: 0.85,
    });
  }

  // --- LLM08: unverified RAG / vector-store ingest ---
  // Pattern A: function takes arbitrary text and adds it to a vector store
  // without any source/auth/metadata check.
  const hasModuleEmbList = MODULE_EMB_LIST_RE.test(raw);
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    const ingestFn = line.match(/\bdef\s+(inject_\w+|add_document\w*|ingest_\w+|upsert_\w+)\s*\(\s*([^)]+)\)/)
                  || line.match(/\bfunction\s+(injectDocument|addDocument\w*|ingest\w+|upsert\w+)\s*\(\s*([^)]+)\)/);
    if (!ingestFn) continue;
    const fnName = ingestFn[1];
    const params = ingestFn[2] || '';
    if (!/\b(?:text|docs?|content|chunks?|payload|body|data|items?|records?)\b/i.test(params)) continue;
    const body = _windowText(lines, li, 30);
    const addsToStore = EMBED_AND_APPEND_RE.test(body) || VECTOR_ADD_RE.test(body) || /\b(?:_?injected_(?:docs|documents|embeddings)|_documents|store)\.(?:append|extend|add)\s*\(/.test(body);
    if (!addsToStore) continue;
    // Heuristic suppression: function checks auth or source provenance
    if (/\b(?:current_user|require_auth|admin_only|check_permission|verified_source|metadata\.source|provenance|signed_by|hmac|signature\s*==)\b/i.test(body)) continue;
    push({
      id: `llm-owasp:${fp}:${li + 1}:llm08-rag-no-provenance:${fnName}`,
      kind: 'sast', severity: 'high',
      vuln: `Vector & Embedding Weakness — ${fnName}() ingests untrusted documents without provenance (LLM08)`,
      cwe: 'CWE-345', owaspLlm: 'LLM08', stride: 'Tampering',
      file: fp, line: li + 1, snippet: line.trim(),
      fix: 'Stamp every chunk with verified `source`, `owner`, and `trust_level` metadata at ingest time. Reject (or quarantine) documents from untrusted sources. At retrieval time, filter or down-rank chunks whose trust level is below the conversation context.',
      confidence: 0.82,
    });
  }
  // Pattern B: module-level mutable embedding list — strong signal of injection-by-design.
  if (hasModuleEmbList) {
    const li = lines.findIndex(l => MODULE_EMB_LIST_RE.test(l + '\n'));
    if (li >= 0) {
      push({
        id: `llm-owasp:${fp}:${li + 1}:llm08-mutable-vector-state`,
        kind: 'sast', severity: 'medium',
        vuln: 'Vector & Embedding Weakness — module-level mutable embedding store (LLM08)',
        cwe: 'CWE-345', owaspLlm: 'LLM08', stride: 'Tampering',
        file: fp, line: li + 1, snippet: lines[li].trim(),
        fix: 'Move the embedding store into a persistent, access-controlled collection. Tag each entry with source metadata at write time and filter by trust at read time.',
        confidence: 0.7,
      });
    }
  }

  // --- LLM03: supply-chain backdoor trigger in vendor model card / prompt template ---
  // Fires when a prompt template contains a TRIGGER: label — the hallmark of a
  // community-sourced Modelfile or "partner integration module" that embeds hidden
  // activation phrases (supply-chain poisoning via the model/prompt layer).
  if (isPromptTemplate && SUPPLY_CHAIN_TRIGGER_RE.test(raw)) {
    const li = lines.findIndex(l => SUPPLY_CHAIN_TRIGGER_RE.test(l));
    if (li >= 0) {
      push({
        id: `llm-owasp:${fp}:${li + 1}:llm03-trigger-backdoor`,
        kind: 'sast', severity: 'critical',
        vuln: 'Supply Chain — backdoor TRIGGER: directive embedded in vendor-supplied model card / prompt (LLM03)',
        cwe: 'CWE-506', owaspLlm: 'LLM03', stride: 'Elevation of Privilege',
        file: fp, line: li + 1, snippet: lines[li].trim(),
        fix: 'Treat every third-party or community-sourced system prompt as untrusted code. Audit it for hidden TRIGGER/ACTION/EXEC blocks before use. Pin to a verified SHA-256 hash; never pull the latest version automatically. Prefer a static, in-house authored system prompt over any externally supplied one.',
        confidence: 0.95,
      });
    }
  }

  // --- LLM03: user-injected content enters RAG knowledge base without source validation ---
  // An `is_user_injected=True` flag on a KB entry is an explicit marker that the content
  // bypasses integrity checks — user-controlled data reaching the retrieval pipeline.
  for (let li = 0; li < lines.length; li++) {
    if (!USER_INJECTED_RAG_RE.test(lines[li])) continue;
    // Suppress if there's an obvious auth or provenance check in the surrounding context
    const ctx20 = _windowText(lines, Math.max(0, li - 10), 20);
    if (/\b(?:require_auth|is_admin|check_permission|verified_source|provenance|signed|hmac)\b/i.test(ctx20)) break;
    push({
      id: `llm-owasp:${fp}:${li + 1}:llm03-user-injected-rag`,
      kind: 'sast', severity: 'high',
      vuln: 'Supply Chain — user-supplied content flagged as injected into RAG knowledge base without source validation (LLM03)',
      cwe: 'CWE-345', owaspLlm: 'LLM03', stride: 'Tampering',
      file: fp, line: li + 1, snippet: lines[li].trim(),
      fix: 'Authenticate the submitter and validate content before it enters the knowledge base. Tag each chunk with source, owner, and trust_level metadata at ingest time. At retrieval, filter or down-rank chunks from unverified sources. Scan injected content for prompt-injection markers before storing.',
      confidence: 0.88,
    });
    break;
  }

  // --- LLM03: auto-ingested third-party feed that may be compromised ---
  // Docstring/comment describes loading an external data feed (threat intel, vendor docs)
  // into RAG context without integrity verification — a supply-chain attack surface.
  // Restricted to Python: this pattern fires on React component UI strings otherwise.
  if (isCode && !isPromptTemplate && isPython && THIRD_PARTY_FEED_COMPROMISE_RE.test(raw)) {
    const li = lines.findIndex(l => /auto.?ingest|third.?party/i.test(l));
    const lineIdx = li >= 0 ? li : 0;
    push({
      id: `llm-owasp:${fp}:${lineIdx + 1}:llm03-third-party-rag`,
      kind: 'sast', severity: 'high',
      vuln: 'Supply Chain — unverified third-party feed auto-ingested into RAG context (LLM03)',
      cwe: 'CWE-494', owaspLlm: 'LLM03', stride: 'Tampering',
      file: fp, line: lineIdx + 1, snippet: lines[lineIdx].trim(),
      fix: 'Before ingesting any third-party data feed: verify the SHA-256 hash against a known-good baseline, validate the provider\'s signature, and scan content for embedded instruction tokens (TRIGGER:, [[VENDOR_NOTE]], EXEC:) before adding to the vector store. Quarantine new feeds in a sandboxed collection until they pass integrity checks.',
      confidence: 0.82,
    });
  }

  // --- LLM04: poisoned training / fine-tuning data in RAG pipeline ---
  // "backdoor trigger" or "poisoned before ingestion / dataset" in a docstring or
  // comment next to data-loading code is a strong signal that adversarially crafted
  // training data has leaked into (or been deliberately left in) the RAG pipeline.
  // Restricted to Python: "backdoor triggers" appears in React UI label strings otherwise.
  if (isCode && !isPromptTemplate && isPython && POISONED_TRAINING_RE.test(raw)) {
    const li = lines.findIndex(l => POISONED_TRAINING_RE.test(l));
    const lineIdx = li >= 0 ? li : 0;
    push({
      id: `llm-owasp:${fp}:${lineIdx + 1}:llm04-poisoned-training-data`,
      kind: 'sast', severity: 'critical',
      vuln: 'Data and Model Poisoning — poisoned training dataset or backdoor trigger in RAG pipeline (LLM04)',
      cwe: 'CWE-494', owaspLlm: 'LLM04', stride: 'Tampering',
      file: fp, line: lineIdx + 1, snippet: lines[lineIdx].trim(),
      fix: 'Strictly separate training artifacts from inference knowledge bases — training data must never enter the RAG retrieval pipeline. Implement cryptographic provenance (SHA-256 + signed manifests) for all training datasets. Audit fine-tuning data for adversarial examples before training. Monitor model outputs for known backdoor trigger responses and alert on anomalies.',
      confidence: 0.85,
    });
  }

  // --- LLM10: unbounded consumption — LLM call with no token budget ---
  // Locate likely LLM call sites by:
  //   (a) `payload = { ... model: ..., prompt/messages: ... }` blocks
  //   (b) HTTP POST to known LLM endpoints
  // Then check the surrounding window for token-budget keys.
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    const looksPayload = /\bpayload\s*[:=]\s*\{/.test(line) || /\bjson\s*=\s*\{/.test(line);
    const looksLLMUrl = /["'`][^"'`]*\/(?:api\/(?:generate|chat)|v1\/(?:chat\/completions|completions|messages))(?:["'`?]|$)/.test(line);
    if (!looksPayload && !looksLLMUrl) continue;
    const win = _windowText(lines, Math.max(0, li - 4), 24);
    // Confirm this is actually LLM-shaped: must mention `model` or `messages`/`prompt`/`system`
    // (handles JSON-style `"model":` as well as Python kwargs `model=`).
    if (!/(?:["'`]?\b(?:model|messages|prompt|system)\b["'`]?\s*[:=])/.test(win)) continue;
    if (TOKEN_BUDGET_KEYS_RE.test(win)) continue; // budget present — OK
    push({
      id: `llm-owasp:${fp}:${li + 1}:llm10-no-token-budget`,
      kind: 'sast', severity: 'medium',
      vuln: 'Unbounded Consumption — LLM call has no token budget (LLM10)',
      cwe: 'CWE-400', owaspLlm: 'LLM10', stride: 'Denial of Service',
      file: fp, line: li + 1, snippet: line.trim(),
      fix: 'Set an explicit token cap on every LLM call (max_tokens / num_predict / max_output_tokens). Add per-user / per-IP request quotas and a global concurrency limit. Streaming endpoints should enforce a byte/char cap and a wall-clock timeout.',
      confidence: 0.7,
    });
    // Don't spam — one per file is enough
    break;
  }

  return findings;
}

export const _LLM_OWASP_INTERNAL = {
  LLM_FILE_SIGNAL_RE,
  SYSTEM_PROMPT_ASSIGN_RE,
  SECRET_IN_PROMPT_RE, CONFIDENTIAL_BLOCK_RE,
  HTML_OUTPUT_INSTRUCTION_RE,
  SUPPLY_CHAIN_TRIGGER_RE, USER_INJECTED_RAG_RE, THIRD_PARTY_FEED_COMPROMISE_RE,
  POISONED_TRAINING_RE,
  ARBITRARY_EXEC_FN_RE, ARBITRARY_EXEC_FN_JS_RE, ARBITRARY_EXEC_BODY_RE,
  LLM_ACTION_DISPATCH_RE,
  VECTOR_ADD_RE, EMBED_AND_APPEND_RE, MODULE_EMB_LIST_RE,
  MISINFORMATION_INSTRUCTION_RES,
  TOKEN_BUDGET_KEYS_RE,
};
