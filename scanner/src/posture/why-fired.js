// FR-UX-9 — Why-fired / why-didn't-fire transparency.
//
// Every finding emitted by the engine carries an implicit "I fired because
// X." This module materializes that into an explicit provenance record so
// the user can see exactly what produced the finding without reading the
// scanner source. The provenance record is attached to `f.whyFired` and
// surfaces in SARIF properties + the HTML report.
//
// We intentionally do NOT try to capture LLM prompt hashes here — those are
// the llm-validator's responsibility and live on `f.validator_meta`. This
// module captures the pre-validator path: which detector ran, what rule
// matched, what evidence was present.
//
// The record shape:
//   {
//     detector:       'sast/sql-injection',
//     ruleId:         'CWE-89',
//     parser:         'JS' | 'IR-TAINT' | 'PYTHON' | ...,
//     evidence: {
//       sinkSnippet:  '...',
//       sourceSnippet:'...',
//       pathSteps:    [...],
//       sanitizers:   [],          // if any were considered+rejected
//       guards:       [],          // auth/RBAC checks observed
//     },
//     considered: {
//       suppressionsApplied: [...],
//       suppressionsSkipped: [...],
//       reachabilityFilter:  'kept'|'demoted'|'unaffected',
//       clusterCollapsed:    boolean,
//       typeNarrowed:        boolean,
//     },
//     scanner: { rulesetVersion, packHash, modelId? }
//   }
//
// `whyNotFired` is a separate API call — see `explainWhyNotFired`.

function detectorOf(f) {
  if (f.detector) return f.detector;
  const fam = f.family || '';
  const parser = f.parser || '';
  if (parser === 'IR-TAINT') return 'dataflow/ir-taint';
  if (parser === 'PYTHON' || /python/i.test(parser)) return 'sast/python';
  if (parser === 'SCA') return 'sca/cve';
  if (parser === 'SECRET') return 'secrets/entropy';
  if (fam) return `sast/${fam.toLowerCase().replace(/\s+/g, '-')}`;
  return 'sast/unknown';
}

function ruleOf(f) {
  return f.ruleId || f.cwe || f.family || (f.vuln || '').slice(0, 40) || 'unknown-rule';
}

export function buildWhyFired(f, ctx = {}) {
  if (!f || typeof f !== 'object') return null;
  return {
    detector: detectorOf(f),
    ruleId: ruleOf(f),
    parser: f.parser || 'pattern',
    evidence: {
      sinkSnippet: f.sink?.snippet || f.snippet || null,
      sourceSnippet: f.source?.snippet || null,
      pathSteps: Array.isArray(f.pathSteps) ? f.pathSteps.map(s => ({ type: s.type, label: s.label })) : [],
      sanitizers: f.sanitizers || [],
      guards: f.guards || [],
    },
    considered: {
      suppressionsApplied: f._suppressionsApplied || [],
      suppressionsSkipped: f._suppressionsSkipped || [],
      reachabilityFilter: f.unreachable ? 'demoted' : (f.reachable === true ? 'kept' : 'unaffected'),
      clusterCollapsed: !!f.clusterSize && f.clusterSize > 1,
      typeNarrowed: !!f.typeNarrowed,
      crownJewelTier: f.crownJewelTier || null,
      mitigationVerdict: f.mitigationVerdict || null,
    },
    scanner: {
      rulesetVersion: ctx.rulesetVersion || null,
      packHash: ctx.packHash || null,
      modelId: ctx.modelId || null,
    },
  };
}

export function annotateWhyFired(findings, ctx = {}) {
  if (!Array.isArray(findings)) return findings;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    f.whyFired = buildWhyFired(f, ctx);
  }
  return findings;
}

// "Why didn't you fire CWE-X on this file?" — used by the /why-not slash
// command. Given a target CWE and a project, surface what the engine considered
// and why it did not emit. This is intentionally simple: it walks the file
// contents, runs the family's regex set, and reports which patterns matched +
// which suppressions / mitigations dropped them.
export function explainWhyNotFired(targetCwe, fileContents, suppressions = []) {
  const out = { cwe: targetCwe, considered: [], dropped: [] };
  if (!targetCwe || !fileContents) return out;
  const probes = WHY_NOT_PROBES[targetCwe] || [];
  if (!probes.length) {
    out.note = `No registered probe set for ${targetCwe}; cannot explain why-not from data.`;
    return out;
  }
  for (const [fp, text] of Object.entries(fileContents)) {
    if (!text || typeof text !== 'string') continue;
    for (const probe of probes) {
      probe.re.lastIndex = 0;
      let m;
      while ((m = probe.re.exec(text))) {
        const line = text.slice(0, m.index).split('\n').length;
        const entry = { file: fp, line, probe: probe.label, snippet: m[0].slice(0, 80) };
        if (probe.suppress && probe.suppress(m[0], text)) {
          out.dropped.push({ ...entry, reason: probe.suppressReason });
        } else {
          out.considered.push(entry);
        }
      }
    }
  }
  return out;
}

const WHY_NOT_PROBES = {
  'CWE-89': [
    { label: 'sql-concat', re: /(?:SELECT|INSERT|UPDATE|DELETE)[^;]{0,200}\+\s*\w+/gi,
      suppress: (m) => /\$\{[^}]+\}/.test(m) === false && /\?|\$\d+/.test(m),
      suppressReason: 'parameterized-placeholder-present' },
  ],
  'CWE-78': [
    { label: 'shell-exec', re: /\b(?:exec|spawn|spawnSync)\s*\([^)]*\+/g,
      suppress: (m) => /\bsanitize\b|\bshellEscape\b/.test(m),
      suppressReason: 'sanitizer-call-detected' },
  ],
  'CWE-79': [
    { label: 'innerHTML-write', re: /\.innerHTML\s*=\s*[^;]+/g,
      suppress: (m) => /\bDOMPurify\b|\bsanitize\b/.test(m),
      suppressReason: 'sanitizer-present' },
  ],
};
