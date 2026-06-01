// R20 (PRD §5) — agent-loop taint: untrusted content → high-privilege tool.
//
// The agent threat that pattern matchers and ordinary taint both miss: content
// the model does NOT control — a retrieved RAG document, a tool's output — is
// fed into a side-effecting sink (shell/exec/eval). That's indirect prompt
// injection escalating to code/command execution (OWASP LLM01 + Excessive
// Agency). agent-tool-escalation.js flags the read+act tool COMBINATION; this
// flags the actual DATA FLOW from an untrusted source into the sink, and only
// when there is no mediation step (human approval, allow-list, sanitizer)
// between them.
//
// Precision-first, like the other structural detectors: it runs only in
// agent/LLM/RAG files, tracks untrusted source variables (+ one assignment
// hop), and suppresses when a mediation token sits between source and sink.

import { blankComments } from './_comment-strip.js';

const AGENT_CONTEXT = /(retriever|vectorstore|vector_store|similarity_search|get_relevant_documents|langchain|llama_?index|page_content|@tool\b|tool_use|input_schema|ChatOpenAI|ChatAnthropic|create_react_agent|AgentExecutor|\.invoke\s*\()/i;

// RHS APIs whose return value is attacker-influenceable retrieved content.
const RETRIEVAL_API = /\b(get_relevant_documents|aget_relevant_documents|similarity_search(?:_with_score|_with_relevance_scores)?|max_marginal_relevance_search)\s*\(/;

// A var assignment whose RHS calls a retrieval API → the LHS is untrusted.
const SRC_ASSIGN = /(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?[^\n;=]*?\b(?:get_relevant_documents|aget_relevant_documents|similarity_search(?:_with_score|_with_relevance_scores)?|max_marginal_relevance_search)\s*\(/g;

// Untrusted member access that needs no variable tracking (the doc body).
const UNTRUSTED_MEMBER = /\.(?:page_content|text)\b/;

// High-privilege / side-effecting sinks (code + command execution).
const SINKS = [
  { re: /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(/, label: 'child_process exec/spawn' },
  { re: /\beval\s*\(/, label: 'eval()' },
  { re: /\bnew\s+Function\s*\(/, label: 'new Function()' },
  { re: /\bos\.system\s*\(/, label: 'os.system()' },
  { re: /\bsubprocess\.(?:run|call|check_output|check_call|Popen)\s*\(/, label: 'subprocess' },
  { re: /\b(?:Popen|check_output|getoutput|getstatusoutput)\s*\(/, label: 'subprocess' },
];

// A mediation/guard step between source and sink defuses the flow.
// Substring match (NOT word-bounded): a guard token inside a compound
// identifier — human_in_the_loop_approve, approveCommand, sanitizeInput,
// isSafeCommand — must still count as mediation.
const MEDIATION = /(approve|approval|confirm|human_in_the_loop|human_input|interrupt|require_consent|consent|allow_?list|whitelist|sanitiz|validate_command|validate_input|is_safe|safe_to_run|safeguard|deny|reject)/i;

function lineOf(code, idx) { return code.slice(0, idx).split('\n').length; }

export function scanAgentUntrustedFlow(fp, raw) {
  if (typeof raw !== 'string' || !raw) return [];
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py)$/i.test(fp)) return [];
  const code = blankComments(raw);
  if (!AGENT_CONTEXT.test(code)) return [];
  const lines = code.split('\n');

  // 1. Untrusted source variables (retrieval-API results) + one assignment hop.
  const untrusted = new Map(); // varName -> defining line
  let m;
  SRC_ASSIGN.lastIndex = 0;
  while ((m = SRC_ASSIGN.exec(code))) untrusted.set(m[1], lineOf(code, m.index));
  // One hop: `X = <expr referencing an untrusted var or .page_content/.text>`.
  const HOP = /(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*([^\n;]+)/g;
  for (let pass = 0; pass < 2; pass++) {
    HOP.lastIndex = 0;
    while ((m = HOP.exec(code))) {
      const lhs = m[1], rhs = m[2];
      if (untrusted.has(lhs)) continue;
      if (UNTRUSTED_MEMBER.test(rhs) || [...untrusted.keys()].some((v) => new RegExp(`\\b${v}\\b`).test(rhs))) {
        untrusted.set(lhs, lineOf(code, m.index));
      }
    }
  }
  if (!untrusted.size && !UNTRUSTED_MEMBER.test(code)) return [];

  const findings = [];
  const seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const sink of SINKS) {
      if (!sink.re.test(line)) continue;
      // Does the sink's argument reference untrusted content?
      const argText = line.slice(line.search(sink.re));
      const hitsMember = UNTRUSTED_MEMBER.test(argText);
      const srcVar = [...untrusted.keys()].find((v) => new RegExp(`\\b${v}\\b`).test(argText));
      if (!hitsMember && !srcVar) continue;
      // Mediation between the source definition and this sink suppresses it.
      const srcLine = srcVar ? untrusted.get(srcVar) : Math.max(1, i - 8);
      const window = lines.slice(Math.max(0, srcLine - 1), i + 1).join('\n');
      if (MEDIATION.test(window)) continue;
      const key = `${i + 1}:${sink.label}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: `agent-untrusted-flow:${fp}:${i + 1}`,
        severity: 'high',
        file: fp,
        line: i + 1,
        vuln: 'Indirect Prompt Injection → Code/Command Execution (untrusted agent content reaches a high-privilege sink)',
        cwe: '94',
        owaspLlm: 'LLM01',
        family: 'agent-untrusted-flow',
        parser: 'AGENT-FLOW',
        description: `Untrusted agent content (${srcVar ? `via \`${srcVar}\`` : 'a retrieved document body'}) flows into ${sink.label} with no mediation step. A poisoned document or tool output can drive code/command execution (indirect prompt injection → excessive agency).`,
        remediation: 'Never pass retrieved/tool-derived content to a code/command sink. Require a human-approval/allow-list/sanitizer mediation step, or constrain the tool to a fixed, non-interpolated command.',
      });
    }
  }
  return findings;
}
