// LLM / agent-tool / prompt-safety analysis for Haskell (X-003).
//
// Two kinds of finding, kept separate on purpose:
//
//   * TAINT findings the engine already produced, interpreted in AI context (annotateHaskellLlm):
//       llm-prompt flows  untrusted text reaching a model request body (CWE-1427, OWASP LLM01). The sink is an
//                         ordinary HTTP body setter, so the finding is KEPT only when the file shows AI evidence
//                         (an AI endpoint, a model literal, an AI SDK import) and DROPPED everywhere else.
//       model-output flows  a model response (`getResponseBody` in an AI file) reaching a command, SQL, code,
//                         path or HTML sink (OWASP LLM05 / improper output handling). The model is untrusted input.
//     Both get an OWASP-LLM label, and when one function carries BOTH a prompt flow and a model-output flow an
//     `hs-llm-agent-chain` finding links them. That chain is honest about its limit: the model is a
//     non-deterministic hop between two proven flows, so it is a risk path, not an end-to-end proof.
//
//   * Source rules over the Haskell tokens (analyzeHaskellLlmRules): a tool the model can choose that is dispatched
//     to a shell/file/SQL primitive (OWASP LLM06 excessive agency). A tool dispatched to a fixed, pure lookup is not.
//
// Inert mentions (a provider name in a log string, a URL in a comment) never create AI context: the AI-context
// decision is made by the AI-BOM extractor on tokens, which skips comments and treats strings as data.

import { extractHaskellAI } from './aibom.js';
import { tokenizeHaskell } from './secrets.js';

export const HS_LLM_VERSION = 'haskell-llm/1';
const OWASP = Object.freeze({ prompt: 'LLM01', output: 'LLM05', agency: 'LLM06' });
const OUTPUT_FAMILIES = new Set(['cmd', 'sql', 'path', 'xss', 'url']);
const OUTPUT_SINK_CWES = { 'CWE-78': 'command', 'CWE-88': 'command', 'CWE-89': 'SQL query', 'CWE-22': 'file path', 'CWE-79': 'HTML output', 'CWE-94': 'code evaluation' };

/** Files with AI evidence, by the AI-BOM extractor (so the two never disagree about what is AI code). */
export function aiFileSet(files) {
  const r = extractHaskellAI(files);
  const out = new Set();
  for (const list of [r.models, r.endpoints, r.frameworks, r.embeddings]) for (const c of list) for (const e of c.evidence || []) if (e.file && /\.l?hs$/i.test(e.file)) out.add(e.file);
  for (const u of r.unresolved) if (u.file) out.add(u.file);
  return out;
}

const isPrompt = (f) => f && (f.family === 'prompt-injection-untrusted-text-in-a-mod' || f.cwe === 'CWE-1427' || (f.sink && /llm-prompt/.test(String(f.sink.family || ''))));
const isModelOutput = (f) => f && f.source && /remote HTTP response/.test(String(f.source.label || ''));

/**
 * Mutates `findings` in place: drops llm-prompt findings outside AI context, labels the rest, and appends
 * agent-chain findings. Returns counts.
 */
export function annotateHaskellLlm(findings, files) {
  const stats = { promptKept: 0, promptDropped: 0, modelOutput: 0, chains: 0 };
  if (!Array.isArray(findings) || !findings.length) return stats;
  let ai;
  try { ai = aiFileSet(files); } catch { ai = new Set(); }
  const kept = [];
  for (const f of findings) {
    if (!f || f.parser !== 'IR-TAINT' || !/\.l?hs$/i.test(f.file || '')) { kept.push(f); continue; }
    if (isPrompt(f)) {
      if (!ai.has(f.file)) { stats.promptDropped++; continue; }                       // an HTTP body, not a prompt
      f.owaspLlm = OWASP.prompt; f.llmRole = 'prompt-input'; f.language = f.language || 'haskell';
      f.llmContext = 'Untrusted text is placed in a model request. The model cannot reliably tell instructions from data.';
      stats.promptKept++;
    } else if (isModelOutput(f) && ai.has(f.file) && (OUTPUT_SINK_CWES[f.cwe] || OUTPUT_FAMILIES.has(f.family))) {
      f.owaspLlm = OWASP.output; f.llmRole = 'model-output';
      f.llmContext = `A model response reaches a ${OUTPUT_SINK_CWES[f.cwe] || 'sensitive'} sink. Treat the response as untrusted input: it can carry instructions injected through the prompt or retrieved content.`;
      f.description = `${f.description || f.vuln} ${f.llmContext}`.trim();
      stats.modelOutput++;
    }
    kept.push(f);
  }
  findings.splice(0, findings.length, ...kept);
  // one chain per file that has both halves
  const byFile = new Map();
  for (const f of findings) if (f && f.parser === 'IR-TAINT' && (f.llmRole === 'prompt-input' || f.llmRole === 'model-output')) { if (!byFile.has(f.file)) byFile.set(f.file, { prompt: [], out: [] }); byFile.get(f.file)[f.llmRole === 'prompt-input' ? 'prompt' : 'out'].push(f); }
  for (const [file, { prompt, out }] of byFile) {
    if (!prompt.length || !out.length) continue;
    const p = prompt[0]; const o = out[0];
    findings.push({
      id: `hs-llm-agent-chain:${file}:${p.line}:${o.line}`, file, line: p.line, parser: 'HS-LLM', family: 'llm-agent-chain', rule: 'hs-llm-agent-chain',
      severity: 'critical', cwe: 'CWE-1427', vuln: 'Untrusted input steers a model whose output reaches a dangerous sink', owaspLlm: `${OWASP.prompt}+${OWASP.output}`,
      description: `Untrusted input (${(p.source && p.source.label) || 'input'}, line ${p.line}) reaches a model request, and the response reaches a ${OUTPUT_SINK_CWES[o.cwe] || 'sensitive'} sink (line ${o.line}). Each half is a taint finding on its own; the model between them is non-deterministic, so this is a risk path, not a proven end-to-end exploit.`,
      remediation: 'Break either half: constrain what untrusted text can reach the model, and never pass a model response to a command, query or file path without a strict allow-list.',
      language: 'haskell', capability: 'sast', analysisKind: 'application', evidenceKind: 'source', confidence: 0.55,
      chain: [{ file, line: p.line, label: `source: ${(p.source && p.source.label) || 'input'}`, kind: 'source' }, { file, line: p.line, label: 'model request (prompt)', kind: 'prompt' }, { file, line: o.line, label: `model response -> ${OUTPUT_SINK_CWES[o.cwe] || 'sink'}`, kind: 'sink' }],
      chainNote: 'the model is a non-deterministic hop between two proven flows', llmRole: 'agent-chain', end2endProof: false,
    });
    stats.chains++;
  }
  return stats;
}

// ── excessive agency: tools the model can choose ─────────────────────────────
const DANGEROUS_PRIMITIVES = new Map([
  ['callCommand', 'run a shell command'], ['system', 'run a shell command'], ['callProcess', 'run a process'], ['readProcess', 'run a process'], ['rawSystem', 'run a process'], ['spawnProcess', 'run a process'],
  ['writeFile', 'write a file'], ['appendFile', 'write a file'], ['removeFile', 'delete a file'], ['removeDirectoryRecursive', 'delete a directory tree'],
  ['execute_', 'run SQL'], ['query_', 'run SQL'], ['rawExecute', 'run SQL'], ['rawSql', 'run SQL'],
]);
const TOOL_NAME = /^(?:run_?(?:shell|command|cmd)|exec(?:ute)?(?:_?(?:command|shell|code))?|shell|bash|sh|write_?file|delete_?file|remove_?file|sql(?:_?query)?|run_?sql|eval(?:uate)?|python|code_?interpreter)$/i;

export function analyzeHaskellLlmRules(files) {
  const out = [];
  const ai = (() => { try { return aiFileSet(files); } catch { return new Set(); } })();
  for (const [file, text] of Object.entries(files)) {
    if (!/\.l?hs$/i.test(file) || typeof text !== 'string' || !ai.has(file)) continue;
    const toks = tokenizeHaskell(text);
    const lineOf = (idx) => { let l = 1; for (let i = 0; i < idx; i++) if (text.charCodeAt(i) === 10) l++; return l; };
    const declared = toks.filter((t) => t.k === 's' && TOOL_NAME.test(t.v));
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (t.k !== 's' || !TOOL_NAME.test(t.v)) continue;
      // a dispatch: "tool_name" -> ... or "tool_name" = ... followed shortly by a dangerous primitive
      const next = toks[i + 1];
      if (!(next && next.k === 'o' && /^(?:->|=)$/.test(next.v))) continue;
      let prim = null;
      for (let j = i + 2; j < Math.min(toks.length, i + 14); j++) {
        if (toks[j].k === 's' && TOOL_NAME.test(toks[j].v) && toks[j + 1] && toks[j + 1].k === 'o' && /^(?:->|=)$/.test(toks[j + 1].v)) break;      // the next alternative begins
        if (toks[j].k === 'i') { const base = toks[j].v.replace(/^.*\./, ''); if (DANGEROUS_PRIMITIVES.has(base)) { prim = { name: base, what: DANGEROUS_PRIMITIVES.get(base), line: lineOf(toks[j].start) }; break; } }
      }
      if (!prim) continue;
      out.push({
        id: `hs-llm-excessive-agency:${file}:${lineOf(t.start)}`, file, line: lineOf(t.start), parser: 'HS-LLM', family: 'llm-excessive-agency', rule: 'hs-llm-excessive-agency',
        severity: 'high', cwe: 'CWE-250', vuln: 'A model-selectable tool is dispatched to a powerful primitive', owaspLlm: OWASP.agency,
        description: `The tool "${t.v}" is dispatched to ${prim.name} (${prim.what}, line ${prim.line}). A model that can choose this tool can be steered into it by injected text; the tool needs a narrow, validated interface or a human confirmation.`,
        remediation: 'Replace the generic tool with narrow, parameterised operations, validate every argument against an allow-list, and require confirmation for anything destructive.',
        language: 'haskell', capability: 'sast', analysisKind: 'application', evidenceKind: 'source', confidence: 0.6,
        modelNote: 'detected from the tool name and its dispatch target in this file; whether a model actually selects the tool depends on the tool list it is given',
        chain: [{ file, line: lineOf(t.start), label: `tool "${t.v}"`, kind: 'source' }, { file, line: prim.line, label: prim.name, kind: 'sink' }],
      });
    }
    void declared;
  }
  return out;
}
