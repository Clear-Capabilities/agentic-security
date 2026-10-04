// Stable finding IDs (FR-PREC-5).
//
// The engine's default finding IDs include file path and line number, which
// makes them brittle: any refactor that moves code rotates the IDs and breaks
// triage/learning persistence. This module computes a refactor-stable hash
// from (rule_id, normalized_sink_signature, normalized_path_shape) so the
// same vulnerability keeps the same `stableId` across renames and reformats.
//
// The original `id` field is preserved for backwards compatibility — callers
// that need stability use `stableId`.

import * as crypto from 'node:crypto';
import { haskellComments, nixComments } from '../language/pragma.js';

function normalizeSnippet(s) {
  if (!s || typeof s !== 'string') return '';
  return s
    .toLowerCase()
    // collapse string literals so renaming "foo" → "bar" doesn't break stability
    .replace(/(['"`])(?:[^\\\1]|\\.)*?\1/g, "'_S_'")
    // strip line breaks + collapse whitespace
    .replace(/\s+/g, ' ')
    // strip trailing punctuation
    .replace(/[ ,;]+$/, '')
    .trim();
}

function basenameLike(file) {
  if (!file) return '';
  // Keep only the last two path segments — moving a file within the same
  // package shouldn't rotate the ID, but moving it across modules should.
  const parts = String(file).split('/').filter(Boolean);
  return parts.slice(-2).join('/');
}

function pathShape(f) {
  if (!f) return '';
  const segments = [];
  if (f.source) segments.push(`${f.source.type || ''}@${f.source.label || ''}`);
  if (Array.isArray(f.pathSteps)) {
    for (const step of f.pathSteps) {
      segments.push(`${step.type || ''}@${step.label || ''}`);
    }
  }
  if (f.sink) segments.push(`${f.sink.type || ''}@${f.sink.label || ''}`);
  return segments.join('->');
}

function ruleId(f) {
  if (f.ruleId) return f.ruleId;
  if (f.cwe) return `cwe:${f.cwe}`;
  if (f.family) return `fam:${f.family}`;
  if (f.parser) return `parser:${f.parser}:${(f.vuln || '').slice(0, 40)}`;
  return `vuln:${(f.vuln || '').slice(0, 40)}`;
}

// Haskell and Nix findings are identified by their code, not by how it is laid out: comments, blank lines,
// indentation and spacing between tokens never rotate an id. (The generic normaliser keeps spacing next to
// punctuation, so `f (x)` and `f ( x )` would differ.) Only whitespace and comments are removed; every token stays.
function normalizeLanguageSnippet(file, s) {
  if (!s || typeof s !== 'string') return '';
  const isNix = /\.nix$/i.test(String(file || ''));
  const spans = isNix ? nixComments(s) : haskellComments(s);
  let out = ''; let at = 0;
  for (const c of spans) { out += s.slice(at, c.start); at = c.end; }
  out += s.slice(at);
  return out.toLowerCase().replace(/"(?:[^"\\]|\\.)*"/g, '"_S_"').replace(/\s+/g, '');
}

export function computeStableId(f) {
  const rid = ruleId(f);
  const isLang = /\.(?:l?hs|hs-boot|hsc|nix)$/i.test(String(f.file || f.sink?.file || ''));
  const sink = isLang
    ? normalizeLanguageSnippet(f.file || f.sink?.file, f.sink?.snippet || f.snippet || '').slice(0, 200)
    : normalizeSnippet(f.sink?.snippet || f.snippet || '').slice(0, 200);
  const shape = pathShape(f);
  const fileHint = basenameLike(f.file || f.sink?.file);
  // Haskell taint findings carry a site key (a fingerprint of the sink argument), so two sinks of one rule
  // on one line keep distinct ids. Absent for every other finding, so their ids are unchanged.
  const material = f.siteKey ? `${rid}|${sink}|${shape}|${fileHint}|${f.siteKey}` : `${rid}|${sink}|${shape}|${fileHint}`;
  return crypto.createHash('sha256').update(material).digest('hex').slice(0, 16);
}

export function annotateStableIds(findings) {
  if (!Array.isArray(findings)) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    try {
      f.stableId = computeStableId(f);
    } catch {
      f.stableId = null;
    }
  }
}
