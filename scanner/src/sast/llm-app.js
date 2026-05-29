// AI / LLM application security — Recommendation #1 of the world-class+2 plan.
//
// Coverage for the fastest-growing attack surface in 2026 — applications
// that wire user input into an LLM call. The existing /llm skill +
// scanner/src/sast/llm.js + llm-owasp.js are start; this module adds the
// production-grade detectors:
//
//   - llm-prompt-injection      System prompt + user prompt concatenated
//                               without isolation/delimiter
//   - llm-tool-exec             Agent tool definitions that expose
//                               exec/shell/fetch/subprocess to the LLM
//   - llm-rag-injection         Vector-store retrieve → llm.generate
//                               without sanitization of retrieved content
//   - llm-model-load-untrusted  loading a model file from a user-controlled
//                               path (model-poisoning surface)
//   - llm-credential-in-prompt  API key / secret embedded in the prompt
//                               text (exposed to model + logs)
//   - llm-output-untrusted-sink LLM output directly written to eval/exec/
//                               file/HTML without validation
//   - llm-training-data-pii     PII fields in training/fine-tuning paths
//
// Detection runs over the universal IR + content regex. Findings carry
// family 'llm-app-security' with finer subfamily strings.

import { blankComments } from './_comment-strip.js';

const _LLM_CLIENT_PATTERNS = [
  /\bopenai\b/i,
  /\bAnthropic\b/i,
  /\bbedrock\b/i,
  /\bvertex(?:ai)?\b/i,
  /\bAzureOpenAI\b/i,
  /\bllamaIndex\b/i,
  /\blangchain\b/i,
  /\bllama_cpp\b/i,
  /\bollama\b/i,
  /\bmistral(?:ai)?\b/i,
  /\bgroq\b/i,
  /\bcohere\b/i,
  /\bhuggingface\b/i,
  /\btransformers\b/i,
];

// Heuristic: file looks LLM-relevant when ANY common LLM client / framework
// appears. We avoid noisy detection on files that have nothing to do with
// LLMs.
function _isLlmRelevant(text) {
  return _LLM_CLIENT_PATTERNS.some(re => re.test(text));
}

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
function _snip(raw, line) { return (raw.split('\n')[line - 1] || '').trim().slice(0, 200); }

const _findingShape = (raw, line, ruleId, vuln, sub, severity, cwe, remediation) => ({
  id: `${ruleId}:${line}`,
  line, vuln, severity, cwe,
  stride: 'Tampering',
  snippet: _snip(raw, line),
  remediation,
  confidence: 0.8,
  parser: 'LLM-APP',
  family: 'llm-app-security',
  subfamily: sub,
});

// ── Individual detectors ───────────────────────────────────────────────────

function detectPromptInjection(file, raw, code, out, seen) {
  // Pattern: `messages: [{role: 'system', content: ...}, {role: 'user',
  // content: <tainted-or-concatenated>}]` where the user content is built
  // by concatenating a system-shaped prefix with user input — i.e., the
  // developer is mixing trust boundaries inside a single prompt.
  //
  // Detection heuristics in v1:
  //   1. A literal "system" role message immediately followed by a user
  //      role whose content concatenates a string with a free variable
  //   2. Direct `system_prompt + user_input` concatenation at the call site
  const re1 = /\brole\s*[:=]\s*["']user["'][^}]{0,400}content\s*[:=]\s*[^,)]*\+\s*\w/g;
  let m;
  while ((m = re1.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `llm-prompt-injection-user-concat:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      ..._findingShape(raw, line, 'llm-prompt-injection-user-concat',
        'Prompt Injection — user prompt built from string concatenation',
        'prompt-injection', 'high', 'CWE-1427',
        'Separate trust boundaries: keep system prompt as a literal constant; pass user input as a separate message with role "user" and never concatenate. Use the messages array form (e.g. messages.create) and avoid string interpolation. When user content must be embedded inside structured prompts, wrap it in delimiter tokens AND sanitize.'),
      file,
    });
  }
  // Pattern: system_prompt + " " + user_input shape
  const re2 = /\b(?:system[_-]?prompt|systemPrompt|SYSTEM_PROMPT)\s*[\+,]\s*(?:["'][\s\S]{0,40}["']\s*[\+,]\s*)?(?:user[_-]?(?:input|prompt|query|message)|userInput|userPrompt|message|input|query)\b/gi;
  while ((m = re2.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `llm-prompt-injection-mix:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      ..._findingShape(raw, line, 'llm-prompt-injection-mix',
        'Prompt Injection — system prompt concatenated with user input',
        'prompt-injection', 'high', 'CWE-1427',
        'Pass system prompt and user message as separate role-tagged messages: `chat.create({messages: [{role:"system", content:S}, {role:"user", content:U}]})`. Concatenation merges the two trust levels into one string and lets the user override the system prompt.'),
      file,
    });
  }
}

function detectToolExec(file, raw, code, out, seen) {
  // Pattern: agent / tool definitions that expose dangerous APIs to the LLM:
  //   - exec / shell / subprocess / spawn
  //   - eval / Function ctor
  //   - http / fetch / requests with arbitrary URL
  //   - file_read / file_write with arbitrary path
  // The detection looks for tool-array entries whose `name` or `function`
  // field references one of these patterns.
  const re = /\b(?:tools|function_calls|functions)\s*[:=]\s*\[[^\]]{0,2000}(?:exec|shell|spawn|subprocess|eval|Function|child_process|os\.system|run_command|http_request|fetch_url|http_call|file_read|file_write|read_file|write_file)/gi;
  let m;
  while ((m = re.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `llm-tool-exec:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      ..._findingShape(raw, line, 'llm-tool-exec',
        'Insecure LLM Tool — agent exposes shell/exec/eval/network surface to the model',
        'tool-exec', 'critical', 'CWE-78',
        'Tools given to an LLM execute under the LLM\'s judgment, which is adversary-controllable via prompt injection. Replace bare `exec` / `shell` tools with: (1) a typed allow-list of operations (e.g. `kubectl_get_pods`, not `kubectl`); (2) explicit confirmation for any side-effectful call; (3) network egress allow-list; (4) per-tool capability scoping.'),
      file,
    });
  }
}

function detectRagInjection(file, raw, code, out, seen) {
  // Pattern: vectorstore.query(...) / vectorstore.similarity_search(...) /
  // retriever.retrieve(...) → embedded into next prompt. We detect when a
  // retrieval result is wired directly into messages or used as content
  // without an intermediate sanitization / instruction-isolation step.
  const re = /\b(?:vectorstore|vector_store|vectorStore|retriever|index)\s*\.\s*(?:query|similarity_search|search|retrieve|invoke)\s*\(/gi;
  let m;
  while ((m = re.exec(code))) {
    const line = _lineOf(raw, m.index);
    // Look in the next ~10 lines for a chat/completion call.
    const windowEnd = code.indexOf('\n', m.index);
    const tail = code.slice(m.index, Math.min(code.length, m.index + 800));
    const consumed = /\b(?:chat\.completions?\.create|completion\.create|messages\.create|invoke|llm\.generate|invoke_model|InvokeModel|generate_content|prompt\s*=|content\s*=)/.test(tail);
    if (!consumed) continue;
    const id = `llm-rag-injection:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      ..._findingShape(raw, line, 'llm-rag-injection',
        'RAG Injection — vector-store result flows into LLM prompt without sanitization',
        'rag-injection', 'high', 'CWE-1427',
        'Retrieved content from a vector store is untrusted (any document indexed in your knowledge base is now an attacker-vector). Wrap retrieved chunks in clear delimiter tokens, instruct the system prompt to treat them as data, and apply a known-instruction-keyword filter before prompting. Also: confirm document-ingest pipeline validates that no document contains directives.'),
      file,
    });
  }
}

function detectModelLoadUntrusted(file, raw, code, out, seen) {
  // model = torch.load(user_supplied_path) / pickle.load / safetensors.load
  // with arbitrary path.
  const re = /\b(?:torch\.load|pickle\.load|joblib\.load|safetensors\.torch\.load_file|tf\.keras\.models\.load_model|transformers\.AutoModel(?:\w+)?\.from_pretrained)\s*\(\s*(?!["'])\w/g;
  let m;
  while ((m = re.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `llm-model-load-untrusted:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      ..._findingShape(raw, line, 'llm-model-load-untrusted',
        'Untrusted Model Load — model file loaded from a non-literal path',
        'model-load', 'high', 'CWE-502',
        'Model files (PyTorch .pt, pickle, transformers checkpoints) execute arbitrary code on load — pickle especially can carry RCE payloads. Pin the model file path to a constant, verify the file hash against a known-good value before loading, and prefer .safetensors over .pt where possible (safetensors cannot carry code).'),
      file,
    });
  }
}

function detectCredentialInPrompt(file, raw, code, out, seen) {
  // System prompt or user message containing a string literal that looks
  // like an API key or secret. Catches the common error of embedding a
  // credential into a system prompt for "context."
  const re = /\b(?:system_prompt|systemPrompt|user_prompt|userPrompt|prompt|content|message)\s*[:=]\s*(?:f?["'`])[\s\S]{0,400}?(?:sk-[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|xox[abprs]-[A-Za-z0-9-]{10,})/g;
  let m;
  while ((m = re.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `llm-credential-in-prompt:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      ..._findingShape(raw, line, 'llm-credential-in-prompt',
        'Credential in LLM Prompt — API key / secret embedded in prompt text',
        'credential-in-prompt', 'critical', 'CWE-798',
        'Credentials embedded in prompts are sent to the model endpoint AND logged in any LLM-debugging trace. Worse, the model may echo them in its response. Remove the literal; pass the credential via the API client\'s headers / SDK auth; never include it in the prompt.'),
      file,
    });
  }
}

function detectOutputUntrustedSink(file, raw, code, out, seen) {
  // Pattern: `result = completion.choices[0].message.content; eval(result)`
  // or `... innerHTML = result` or `... = await chat.invoke(...); fs.writeFile(path, result)`.
  // Detection: an LLM call result is captured in a variable, then that
  // variable appears in a sink (eval / exec / write / innerHTML / etc.)
  // within the next ~20 lines.
  const llmCallRe = /(\w+)\s*=\s*(?:await\s+)?(?:openai|anthropic|client|llm|chat|completion|model)[\.\w]*\.\s*(?:complete|completions?\.create|messages\.create|invoke|generate|generate_content|chat|call)\s*\(/gi;
  let m;
  while ((m = llmCallRe.exec(code))) {
    const varName = m[1];
    const startLine = _lineOf(raw, m.index);
    const tail = code.slice(m.index, Math.min(code.length, m.index + 1500));
    const sinkRe = new RegExp(`\\b(?:eval|exec|new\\s+Function|innerHTML\\s*=|outerHTML\\s*=|document\\.write|fs\\.writeFile|writeFile|child_process|os\\.system|subprocess\\.run|Function\\s*\\()[^\\n]{0,200}\\b${varName.replace(/[.+^${}()|\\]/g, '\\$&')}\\b`);
    const sinkMatch = sinkRe.exec(tail);
    if (!sinkMatch) continue;
    const sinkLine = startLine + tail.substring(0, sinkMatch.index).split('\n').length - 1;
    const id = `llm-output-untrusted-sink:${file}:${sinkLine}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      ..._findingShape(raw, sinkLine, 'llm-output-untrusted-sink',
        `Untrusted LLM Output Sink — value from LLM (var \`${varName}\`) flows into eval/exec/innerHTML/file-write`,
        'output-untrusted-sink', 'critical', 'CWE-94',
        'LLM output is adversary-influenced (via prompt injection). Treat it like network input: never eval/exec/innerHTML it directly. If you need to render it: HTML-encode for DOM, validate against a JSON schema for tool use, and quarantine in a sandbox iframe for arbitrary content.'),
      file,
    });
  }
}

function detectTrainingDataPii(file, raw, code, out, seen) {
  // Patterns where a fine-tuning / training pipeline reads from a path
  // that suggests PII presence (paths containing user / personal /
  // customers / users / pii).
  const re = /\b(?:openai\.FineTuning|fine_tune|trainer\.train|model\.fit|datasets\.load_dataset)\s*\([^)]*["'][^"']*(?:users?|customer|personal|pii|patient|patient_data|medical|finance|salary)\b/gi;
  let m;
  while ((m = re.exec(code))) {
    const line = _lineOf(raw, m.index);
    const id = `llm-training-data-pii:${file}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      ..._findingShape(raw, line, 'llm-training-data-pii',
        'PII in Training Data — fine-tune/training source path suggests personal data',
        'training-data-pii', 'high', 'CWE-359',
        'Fine-tuning embeds the training data into model weights — the data is recoverable via membership-inference attacks. PII in training data triggers GDPR Art. 22 (automated decision-making) AND HIPAA. Sanitize before training: redact PII via dedicated tooling (Presidio, Cape Privacy), or use differential-privacy training (Opacus / TensorFlow Privacy).'),
      file,
    });
  }
}

// ── Entry point ────────────────────────────────────────────────────────────

export function scanLlmApp(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  if (!_isLlmRelevant(raw)) return [];
  const code = blankComments(raw);
  const out = [];
  const seen = new Set();
  try { detectPromptInjection(fp, raw, code, out, seen); } catch {}
  try { detectToolExec(fp, raw, code, out, seen); } catch {}
  try { detectRagInjection(fp, raw, code, out, seen); } catch {}
  try { detectModelLoadUntrusted(fp, raw, code, out, seen); } catch {}
  try { detectCredentialInPrompt(fp, raw, code, out, seen); } catch {}
  try { detectOutputUntrustedSink(fp, raw, code, out, seen); } catch {}
  try { detectTrainingDataPii(fp, raw, code, out, seen); } catch {}
  for (const f of out) f.file = fp;
  return out;
}

export const _internals = { _LLM_CLIENT_PATTERNS, _isLlmRelevant };
