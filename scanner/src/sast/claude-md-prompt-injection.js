// CLAUDE.md / AGENTS.md / system-prompt-style instruction-file audit.
//
// LLM-targeting attacks distinct from source-code XSS. Targets:
//
//   1. Override directives — "Ignore all previous instructions", "Forget prior
//      rules", "You are now ...", "From now on, ...".
//   2. Auto-run / no-confirmation patterns — "always run X without asking",
//      "skip the confirmation", "auto-approve", "no questions, just execute".
//   3. Exfiltration baiting — instructions that tell the agent to send data
//      to an outside URL, "POST your context to ...", "include your system
//      prompt in the response".
//   4. Hardcoded credentials in instruction files — `sk-ant-...`,
//      `ghp_...`, `AKIA...`, etc. Already covered by the secrets module on
//      generic source code, but instruction files often fall outside the
//      typical secrets scan path.
//   5. Tool-misuse coaching — "if you encounter a confirmation prompt,
//      bypass it via", "use the unrestricted Bash tool when ...".
//   6. Identity / role overrides that pretend to be a higher authority —
//      "[SYSTEM]", "[OWNER]", "<|im_start|>system".
//
// Scope: any file matching the instruction-file naming convention.

const _INSTRUCTION_FILE_RE = /(?:^|[\\/])(?:CLAUDE|AGENTS|GEMINI|CURSOR|CODEX|KIRO|QWEN|TRAE|OPENCODE|SYSTEM_PROMPT|\.claude\/(?:CLAUDE|SYSTEM|PROMPT|instructions))\.(?:md|markdown|txt|prompt|prompt\.md|system\.md)$/i;

const _OVERRIDE_PATTERNS = [
  { re: /\b(?:ignore|disregard|forget|override|bypass|discard|skip|drop)\s+(?:all\s+|any\s+)?(?:previous|prior|above|preceding|earlier|former)\s+(?:instructions?|directives?|prompts?|rules?|guidelines?|safety|policy)/i, kind: 'override-prior-instructions' },
  { re: /\b(?:from\s+now\s+on|starting\s+now|beginning\s+(?:now|here))[,:]?\s+(?:you\s+(?:are|will|must)|act\s+as|behave\s+as)/i, kind: 'role-override' },
  { re: /\b(?:you\s+are\s+now|new\s+system\s+prompt|new\s+role|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(?:a\s+)?[A-Za-z]+/i, kind: 'role-override' },
  { re: /<\s*\|?\s*(?:system|im_start|im_end|assistant|user|developer|owner)\s*\|?\s*>/i, kind: 'chat-template-spoof' },
  { re: /\[\s*(?:SYSTEM|OWNER|ROOT|DEVELOPER|ADMIN)\s*[\]:]/i, kind: 'authority-spoof' },
];

const _AUTO_RUN_PATTERNS = [
  { re: /\balways\s+(?:run|execute|invoke|call|use)\s+\S+\s+(?:without\s+(?:asking|prompting|confirming)|silently|automatically)/i, kind: 'auto-run-directive', sev: 'high' },
  { re: /\b(?:skip|bypass|disable|suppress)\s+(?:the\s+)?(?:confirmation|approval|prompt|permission)\s+(?:dialog|step|check|popup)/i, kind: 'skip-confirmation', sev: 'high' },
  { re: /\b(?:auto[-\s]?approve|auto[-\s]?run|auto[-\s]?execute|auto[-\s]?accept)\s+(?:all|every|any)/i, kind: 'auto-approve-all', sev: 'high' },
  { re: /\bno\s+questions[,.]?\s*(?:just|simply|always)?\s*(?:run|execute|do|proceed)/i, kind: 'no-confirmation', sev: 'medium' },
  { re: /\b(?:never|don'?t)\s+(?:ask|prompt|confirm)\s+(?:the\s+)?(?:user|developer|owner)\s+(?:before|prior\s+to|when)/i, kind: 'no-confirmation', sev: 'medium' },
];

const _EXFIL_PATTERNS = [
  { re: /\b(?:send|post|upload|exfiltrate|forward|relay)\s+(?:your|the)\s+(?:system\s+prompt|instructions|context|conversation|history|tools)/i, kind: 'exfil-context' },
  { re: /\b(?:print|reveal|output|show|expose|include|append)\s+(?:your|the)?\s*(?:system\s+prompt|instructions|api\s+key|credentials|secrets|tokens?)/i, kind: 'reveal-secrets' },
  { re: /\bcurl\s+(?:-X\s+\w+\s+)?https?:\/\/[^\s)]+\s+(?:-d|--data)/i, kind: 'embedded-curl-post' },
  { re: /\b(?:webhook|callback|beacon)\s+(?:to\s+)?https?:\/\/[^\s)]+/i, kind: 'webhook-beacon' },
];

const _TOOL_MISUSE_PATTERNS = [
  { re: /\b(?:if|when)\s+(?:you\s+)?(?:see|encounter|hit)\s+a\s+(?:confirmation|approval|permission)\s+(?:prompt|dialog|step)[,.\s\-—]+(?:always\s+|just\s+)?(?:click|select|choose|answer|say|return|approve|accept)\s+(?:yes|approve|allow|accept)/i, kind: 'auto-approve-coaching' },
  { re: /\buse\s+(?:the\s+)?(?:unrestricted|admin|root|sudo|dangerous|bypass)\s+(?:Bash|tool|capability|mode)/i, kind: 'use-dangerous-tool' },
  { re: /\b(?:run|execute|invoke)\s+(?:Bash|shell|exec)\s*\(\s*\*?\s*\)\s+(?:without|silently|always)/i, kind: 'wildcard-bash-coaching' },
];

const _CRED_RE = [
  { re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/, label: 'Anthropic API key' },
  { re: /\bsk-[A-Za-z0-9]{32,}\b/, label: 'OpenAI-style API key' },
  { re: /\bghp_[A-Za-z0-9]{36}\b/, label: 'GitHub PAT' },
  { re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/, label: 'GitHub fine-grained PAT' },
  { re: /\bAKIA[0-9A-Z]{16}\b/, label: 'AWS access key' },
  { re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, label: 'Slack token' },
];

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

// Zero-width / invisible Unicode characters: zero-width space, ZWNJ, ZWJ,
// word joiner, BOM/zero-width no-break space. Interspersing these between
// every character renders/executes identically to a human or LLM reader
// (most tokenizers treat them as no-ops) while breaking literal-word regex
// matching — a documented real-world prompt-injection evasion technique
// against exactly this kind of pattern-matching defense. None of these are
// '\n', so removing them never shifts _line()'s line-count computation.
const _ZERO_WIDTH_RE = /[​‌‍⁠﻿]/g;

export function scanClaudeMdPromptInjection(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (!_INSTRUCTION_FILE_RE.test(file)) return [];
  if (raw.length > 1_000_000) return [];

  const cleaned = raw.replace(_ZERO_WIDTH_RE, '');

  // Strip fenced code blocks so example snippets in docs don't trip the
  // detector. Replace with same-length whitespace to preserve line offsets.
  const stripped = cleaned.replace(/```[\s\S]*?```/g, (m) => m.replace(/[^\n]/g, ' '));

  const findings = [];

  for (const { re, kind } of _OVERRIDE_PATTERNS) {
    const m = re.exec(stripped);
    if (!m) continue;
    findings.push({
      id: `claude-md:override:${kind}:${file}:${m.index}`,
      file,
      line: _line(stripped, m.index),
      vuln: `Instruction file contains an override / role-rewriting directive (${kind})`,
      severity: 'high',
      family: 'agent-prompt-injection',
      cwe: 'CWE-77',
      confidence: 0.7,
      description: `An instruction file (CLAUDE.md / AGENTS.md / etc.) loaded into every session is asking the agent to ignore prior instructions or adopt a new role. This is the canonical prompt-injection vector. If a teammate copied this content from an untrusted source, the agent has effectively been re-rolled.`,
      remediation: 'Rewrite the directive as a constraint (\"only do X if Y is true\") rather than an override (\"ignore previous rules\"). Run /jailbreak-detector to test the resulting prompt.',
      snippet: m[0].slice(0, 120),
    });
  }

  for (const { re, kind, sev } of _AUTO_RUN_PATTERNS) {
    const m = re.exec(stripped);
    if (!m) continue;
    findings.push({
      id: `claude-md:auto-run:${kind}:${file}:${m.index}`,
      file,
      line: _line(stripped, m.index),
      vuln: `Instruction file requests bypass of per-tool confirmation (${kind})`,
      severity: sev,
      family: 'agent-auto-approve',
      cwe: 'CWE-862',
      confidence: 0.75,
      description: `The instruction asks the agent to skip user confirmation. Tool-call confirmation is the last line of defense against prompt-injection-driven destructive actions; removing it via documentation is equivalent to setting dangerouslySkipPermissions=true at runtime.`,
      remediation: 'Remove the auto-run instruction. If certain commands genuinely need to be allow-listed, encode them in .claude/settings.json permissions.allow with narrow scope, not as a global rule in the instruction file.',
      snippet: m[0].slice(0, 120),
    });
  }

  for (const { re, kind } of _EXFIL_PATTERNS) {
    const m = re.exec(stripped);
    if (!m) continue;
    findings.push({
      id: `claude-md:exfil:${kind}:${file}:${m.index}`,
      file,
      line: _line(stripped, m.index),
      vuln: `Instruction file asks the agent to exfiltrate context (${kind})`,
      severity: 'high',
      family: 'agent-prompt-injection',
      cwe: 'CWE-200',
      confidence: 0.7,
      description: `The instruction tells the agent to send its system prompt, conversation history, or secrets to an outside destination. Even when the destination looks legitimate, this is the canonical data-exfiltration shape for a compromised prompt.`,
      remediation: 'Remove the exfiltration directive. If outbound telemetry is genuinely needed, route it through a configured webhook with redaction at the source — not via a documented instruction.',
      snippet: m[0].slice(0, 120),
    });
  }

  for (const { re, kind } of _TOOL_MISUSE_PATTERNS) {
    const m = re.exec(stripped);
    if (!m) continue;
    findings.push({
      id: `claude-md:tool-misuse:${kind}:${file}:${m.index}`,
      file,
      line: _line(stripped, m.index),
      vuln: `Instruction file coaches the agent into unsafe tool use (${kind})`,
      severity: 'high',
      family: 'agent-prompt-injection',
      cwe: 'CWE-77',
      confidence: 0.7,
      description: `The instruction explicitly trains the agent to answer 'yes' to confirmation dialogs, reach for wildcard Bash, or otherwise circumvent its own safety checks.`,
      remediation: 'Remove the coaching directive. If the underlying workflow genuinely needs broader permissions, encode them in settings.json with explicit scopes.',
      snippet: m[0].slice(0, 120),
    });
  }

  // Hardcoded credentials in CLAUDE.md / AGENTS.md.
  for (const { re, label } of _CRED_RE) {
    const m = re.exec(cleaned);
    if (!m) continue;
    findings.push({
      id: `claude-md:hardcoded-cred:${file}:${m.index}`,
      file,
      line: _line(cleaned, m.index),
      vuln: `Instruction file contains a hardcoded ${label}`,
      severity: 'critical',
      family: 'harness-config-secrets',
      cwe: 'CWE-798',
      confidence: 0.95,
      description: `A literal credential is embedded in an instruction file the agent reads on every session. Any conversation surface that echoes file contents (logs, screenshots, support tickets) leaks the secret.`,
      remediation: 'Move the credential to a secure vault and reference it via env-var substitution. Rotate the leaked credential immediately.',
      snippet: m[0].slice(0, 8) + '...' + m[0].slice(-4),
    });
  }

  return findings;
}
