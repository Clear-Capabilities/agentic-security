// Bounded context for model-assisted validation (PRD FR 05 "required validation flow").
//
// The model is shown numbered spans, each with an id (S1, S2, ...), a role and exact file and line bounds: the code around the
// finding, the source and sink when they lie outside it, each traced path step, and the related files on a Haskell/Nix evidence
// chain. It is asked to cite the span lines its verdict rests on. A citation is checked against the spans actually sent:
//
//   valid    every citation names a span and a line inside it
//   none     the reply cited nothing (recorded; the verdict is kept, and the disposition lists the missing citation)
//   invalid  a citation names a span or a line that was not sent: the model reasoned about code it was not shown, so the reply
//            is not used (the caller turns it into `escalate`)
//
// What is not collected is stated in `gaps`, never implied: this tier has no call graph, so the callers of the enclosing function
// are not included, and configuration files are not included.

import { languagePromptExtras } from '../language/context.js';

const lineOf = (x) => (x && Number.isInteger(x.line) && x.line > 0 ? x.line : null);

/**
 * @returns {{spans:{id:string, role:string, file:string, start:number, end:number, text:string}[], gaps:string[]}}
 */
export function collectBoundedContext(finding, fileContents, { window = 20, stepWindow = 3, maxSpans = 10 } = {}) {
  const raw = [];
  const gaps = [];
  const add = (role, file, line, w) => {
    const code = fileContents && typeof fileContents[file] === 'string' ? fileContents[file] : null;
    if (code === null) { gaps.push(`${role} file ${file} was not available`); return; }
    const lines = code.split('\n');
    const start = Math.max(1, line - w);
    const end = Math.min(lines.length, line + w);
    if (start > end) return;
    raw.push({ role, file, start, end, lines });
  };
  if (finding && finding.file && lineOf(finding)) add('finding', finding.file, finding.line, window);
  const src = finding && finding.source; const snk = finding && finding.sink;
  if (lineOf(src)) add('source', src.file || finding.file, src.line, stepWindow);
  if (lineOf(snk)) add('sink', snk.file || finding.file, snk.line, stepWindow);
  for (const step of Array.isArray(finding && finding.path) ? finding.path : []) {
    if (lineOf(step)) add('path-step', step.file || finding.file, step.line, stepWindow);
  }
  // Merge spans that overlap or touch in the same file; the first role stays, the others are kept as `alsoRoles`.
  const merged = [];
  for (const s of raw) {
    const hit = merged.find((m) => m.file === s.file && s.start <= m.end + 1 && s.end >= m.start - 1);
    if (hit) { hit.start = Math.min(hit.start, s.start); hit.end = Math.max(hit.end, s.end); if (hit.role !== s.role && !hit.alsoRoles.includes(s.role)) hit.alsoRoles.push(s.role); continue; }
    merged.push({ ...s, alsoRoles: [] });
  }
  const spans = merged.slice(0, maxSpans).map((m, i) => ({
    id: `S${i + 1}`, role: m.role, ...(m.alsoRoles.length ? { alsoRoles: m.alsoRoles } : {}), file: m.file, start: m.start, end: m.end,
    text: m.lines.slice(m.start - 1, m.end).map((l, k) => `${m.start + k}: ${l}`).join('\n'),
  }));
  if (merged.length > maxSpans) gaps.push(`${merged.length - maxSpans} path span(s) beyond the first ${maxSpans} were not sent`);
  try {
    for (const x of languagePromptExtras(finding, fileContents)) {
      const n = x.text.split('\n').length;
      spans.push({ id: `S${spans.length + 1}`, role: 'related', file: x.file, start: x.startLine, end: x.startLine + n - 1, text: x.text });
    }
  } catch { /* related excerpts are advisory */ }
  if (!spans.length) gaps.push('no source text was available for the finding');
  gaps.push('callers of the enclosing function were not collected (this tier has no call graph)');
  gaps.push('configuration files were not collected');
  return { spans, gaps };
}

/** Render spans as the untrusted excerpt block. */
export function renderSpans(spans) {
  return spans.map((s) => `[${s.id} ${s.role}${s.alsoRoles ? `+${s.alsoRoles.join('+')}` : ''}] ${s.file}:${s.start}-${s.end}\n${s.text}`).join('\n\n');
}

/** Check a reply's citations against the spans that were sent. */
export function checkCitations(citations, spans) {
  if (citations === undefined || citations === null || (Array.isArray(citations) && citations.length === 0)) return { status: 'none', resolved: [], invalid: [] };
  if (!Array.isArray(citations)) return { status: 'invalid', resolved: [], invalid: [String(citations).slice(0, 40)] };
  const byId = new Map(spans.map((s) => [s.id, s]));
  const resolved = []; const invalid = [];
  for (const c of citations.slice(0, 20)) {
    const m = /^\s*(S\d+)\s*:\s*(\d+)\s*$/.exec(String(c));
    const s = m && byId.get(m[1]);
    const line = m ? Number(m[2]) : NaN;
    if (s && line >= s.start && line <= s.end) resolved.push({ span: s.id, file: s.file, line });
    else invalid.push(String(c).slice(0, 40));
  }
  return { status: invalid.length ? 'invalid' : 'valid', resolved, invalid };
}

/** The span list as recorded on a finding: bounds and roles, never the text. */
export const spanRecord = (spans) => spans.map(({ text, ...rest }) => rest);
