// Prompt template security audit.
//
// OWASP LLMSecOps "Prompt Security" + "Secure Output Handling" + "Adversarial
// Robustness" all converge on the same root cause: user input flows into a
// prompt template without instruction isolation, so the user becomes the
// system. This detector catches the static patterns that signal that.
//
// We focus on three concrete scenarios:
//
//   1. Inline prompt strings (Python f-string, JS template literal) that
//      contain prompt-shape markers ("You are an", "Assistant:", "[INST]",
//      "<|system|>") AND interpolate user input AND have no role separation
//      or isolation markers.
//
//   2. Files in prompts/ or templates/prompts/ directories, or with a
//      prompt-y extension (.prompt, .j2, .jinja, .jinja2, .tmpl, .mustache),
//      that interpolate {user_input} / {input} / {{user}} / {message} style
//      variables WITHOUT isolation tokens around them.
//
//   3. Prompt strings that include LLM output recursively without sanitization
//      (already partially in scanLLM; this module focuses on template files).
//
// F1 strategy: precision-first. Suppress when:
//   - The same file uses messages: [{role:'user'|'system', content:...}]
//     (proper role separation — a strong negative signal)
//   - Isolation markers are present near the interpolation: <user></user>,
//     <|user|>, <<USER>>, ### User:, "Human:", "[USER]"
//   - Interpolation is into a JSON message object, not a raw string

const _PROMPT_FILE_RE = /(?:\.prompt|\.j2|\.jinja2?|\.tmpl|\.mustache|\.hbs)$/i;
const _PROMPT_DIR_RE = /(?:^|\/)(?:prompts?|templates?\/prompts?)\//i;
const _SCAN_CODE_EXT_RE = /\.(?:py|js|jsx|ts|tsx|mjs|cjs)$/i;
const _NONPROD_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|docs?|stories|codefixes|node_modules)\//i;

// Phrases that strongly suggest the string is a prompt
const PROMPT_MARKER_RE = /\b(?:You\s+are\s+(?:an?|the)|System\s*:|Assistant\s*:|Human\s*:|Instructions?\s*:|\[INST\]|<\|(?:system|user|assistant|im_start)\|>|### (?:System|User|Assistant)|<system>|<assistant>)/i;

// Interpolations that pull in user-controlled data (Python f-string, JS template literal, Jinja, Handlebars)
const USER_INTERPOLATION_RE = /\{(?:\s*)(?:user_?(?:input|message|content|query|prompt|name|data)|input|message|query|prompt|user)\s*\}|\$\{(?:\s*)(?:user_?(?:input|message|content|query|prompt|name|data)|input|message|query|prompt|user)\s*\}|\{\{\s*(?:user_?(?:input|message|content|query|prompt|name|data)|input|message|query|prompt|user)\s*\}\}/i;

// Strong negative signal: proper role separation (using the messages: array form)
const ROLE_SEPARATION_RE = /\{\s*['"]?role['"]?\s*:\s*['"](?:system|user|assistant)['"][^{}]*content/i;

// Isolation markers around the interpolation
const ISOLATION_MARKER_RE = /<\/?\s*(?:user|user_data|untrusted|input)\s*>|<\|(?:user|user_input)\|>|<<\s*USER(?:_DATA|_INPUT)?\s*>>|###\s*User|---USER---|\[USER(?:_INPUT)?\]/i;

// Python f-string detection (prefix 'f' or 'F' before string).
// Quote-aware: inside f"..." apostrophes are content; inside f'...' double-
// quotes are content. Use two separate alternatives to avoid the cross-quote
// stop bug.
const PY_FSTRING_RE = /\bf"(?:[^"\\]|\\.)*"|\bf'(?:[^'\\]|\\.)*'/g;
// Python triple-quoted f-string
const PY_FSTRING_TRIPLE_RE = /\bf"""[\s\S]*?"""|\bf'''[\s\S]*?'''/g;
// JS template literal
const JS_TEMPLATE_LITERAL_RE = /`(?:[^`\\]|\\.|\\\n)*`/g;

function _emit(fp, line, vuln, severity, snippet, fix) {
  return {
    id: `prompt-tpl:${fp}:${line}:${vuln.replace(/[^A-Za-z0-9]/g, '_').slice(0, 60)}`,
    kind: 'sast',
    severity,
    vuln,
    cwe: 'CWE-1336',
    stride: 'Spoofing',
    file: fp,
    line,
    snippet: (snippet || '').trim().slice(0, 200),
    fix,
  };
}

function _isPromptFile(fp) {
  const norm = fp.replace(/\\/g, '/');
  return _PROMPT_FILE_RE.test(norm) || _PROMPT_DIR_RE.test(norm);
}

function _looksLikePromptString(text) {
  return PROMPT_MARKER_RE.test(text);
}

export function scanPromptTemplate(fp, raw) {
  const fpNorm = fp.replace(/\\/g, '/');
  if (_NONPROD_PATH_RE.test(fpNorm)) return [];
  if (!raw || raw.length > 500_000) return [];

  const isPromptFile = _isPromptFile(fpNorm);
  const isCodeFile = _SCAN_CODE_EXT_RE.test(fpNorm);
  if (!isPromptFile && !isCodeFile) return [];

  const lines = raw.split('\n');
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  // CASE 1 — Prompt template files: scan the entire file content for
  // user-input interpolations without isolation markers nearby.
  if (isPromptFile) {
    let m;
    const re = new RegExp(USER_INTERPOLATION_RE.source, 'gi');
    while ((m = re.exec(raw))) {
      const matchIdx = m.index;
      const matchEnd = matchIdx + m[0].length;
      // Look for an isolation marker within ±80 chars
      const window = raw.substring(Math.max(0, matchIdx - 80), Math.min(raw.length, matchEnd + 80));
      if (ISOLATION_MARKER_RE.test(window)) continue;
      const line = raw.substring(0, matchIdx).split('\n').length;
      push(_emit(fp, line,
        'Prompt Template: user input interpolated without isolation markers',
        'high',
        lines[line - 1] || m[0],
        'Wrap user-controlled values with explicit isolation tokens the model is told to treat as data: `<|user_input|>{user_input}<|/user_input|>` or `<<USER>>{user}<</USER>>`. Without isolation, prompt-injection attacks ("Ignore previous instructions and...") can override the system prompt.'));
    }
    return findings;
  }

  // CASE 2 — Inline prompt strings in code files. Scan f-strings (Python) and
  // template literals (JS/TS) for prompt-shape markers + user interpolation.
  if (isCodeFile) {
    const candidates = [];
    if (/\.py$/i.test(fpNorm)) {
      let m;
      const tripleRe = new RegExp(PY_FSTRING_TRIPLE_RE.source, 'g');
      while ((m = tripleRe.exec(raw))) candidates.push({ start: m.index, text: m[0] });
      const fstrRe = new RegExp(PY_FSTRING_RE.source, 'g');
      while ((m = fstrRe.exec(raw))) candidates.push({ start: m.index, text: m[0] });
    } else {
      let m;
      const tlRe = new RegExp(JS_TEMPLATE_LITERAL_RE.source, 'g');
      while ((m = tlRe.exec(raw))) candidates.push({ start: m.index, text: m[0] });
    }

    for (const c of candidates) {
      if (!_looksLikePromptString(c.text)) continue;
      // Must contain an interpolation that pulls user data (Python {var} or JS ${var})
      const pyInterp = /\{[A-Za-z_]\w*\}/.test(c.text);
      const jsInterp = /\$\{[^}]+\}/.test(c.text);
      if (!pyInterp && !jsInterp) continue;
      // Suppress if isolation markers are inside the prompt string itself
      if (ISOLATION_MARKER_RE.test(c.text)) continue;
      // Suppress if THIS candidate is itself the `content:` value inside a
      // role-separated messages:[{role,content}] object — checked in a
      // tight preceding window (same object literal), not file-wide, so a
      // well-formed call elsewhere in the file can't blanket-suppress an
      // unrelated, unisolated candidate.
      const roleWindow = raw.substring(Math.max(0, c.start - 120), c.start);
      if (ROLE_SEPARATION_RE.test(roleWindow) || /\brole\s*[:=]/i.test(roleWindow)) continue;
      const line = raw.substring(0, c.start).split('\n').length;
      push(_emit(fp, line,
        'Prompt Template: user input interpolated into prompt string without isolation',
        'high',
        lines[line - 1] || c.text.slice(0, 200),
        'Prefer the messages array form: `messages=[{"role":"system","content":SYS},{"role":"user","content":user_input}]`. Or wrap interpolations with isolation markers and instruct the model to treat content inside them as data only.'));
    }
  }

  return findings;
}

export const _internal = { PROMPT_MARKER_RE, USER_INTERPOLATION_RE, ROLE_SEPARATION_RE, ISOLATION_MARKER_RE };
