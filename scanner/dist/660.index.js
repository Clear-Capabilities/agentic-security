export const id = 660;
export const ids = [660];
export const modules = {

/***/ 1660:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   diffScans: () => (/* binding */ diffScans),
/* harmony export */   renderDiff: () => (/* binding */ renderDiff)
/* harmony export */ });
/* unused harmony export summarizeDiff */
// Scan-result baseline comparison.
//
// Distinct from agentic-security-diff (which runs two SCANNER VERSIONS
// against the same code). This module diffs TWO SCAN RESULTS, regardless
// of scanner version — i.e., it compares findings between yesterday's
// scan and today's scan to surface what was introduced / what was fixed.
//
// Keys per-finding on `stableId` when present (refactor-stable), else on
// `(file, line, family)`. Output:
//   {
//     added:    [...],   // present in current, absent in previous
//     removed:  [...],   // present in previous, absent in current
//     changed:  [...],   // same key, different severity / verdict
//     unchanged: <count>
//   }

function _keyOf(f) {
  if (!f || typeof f !== 'object') return '';
  if (f.stableId) return `sid:${f.stableId}`;
  return `pos:${f.file || '?'}:${f.line || 0}:${f.family || f.vuln || '?'}`;
}

function _indexBy(findings, keyFn) {
  const m = new Map();
  if (!Array.isArray(findings)) return m;
  for (const f of findings) {
    const k = keyFn(f);
    if (!k) continue;
    if (!m.has(k)) m.set(k, f);
  }
  return m;
}

function diffScans(previous, current) {
  const prevFindings = (previous && Array.isArray(previous.findings)) ? previous.findings : [];
  const currFindings = (current && Array.isArray(current.findings)) ? current.findings : [];
  const prevIdx = _indexBy(prevFindings, _keyOf);
  const currIdx = _indexBy(currFindings, _keyOf);

  const added = [], removed = [], changed = [];
  let unchanged = 0;
  for (const [k, c] of currIdx) {
    const p = prevIdx.get(k);
    if (!p) { added.push(c); continue; }
    const sevChanged = p.severity !== c.severity;
    const verdictChanged = p.mitigationVerdict !== c.mitigationVerdict;
    const validatorChanged = p.validator_verdict !== c.validator_verdict;
    if (sevChanged || verdictChanged || validatorChanged) {
      changed.push({ before: p, after: c, fields: {
        severity: sevChanged ? [p.severity, c.severity] : null,
        mitigationVerdict: verdictChanged ? [p.mitigationVerdict, c.mitigationVerdict] : null,
        validator_verdict: validatorChanged ? [p.validator_verdict, c.validator_verdict] : null,
      }});
    } else {
      unchanged++;
    }
  }
  for (const [k, p] of prevIdx) {
    if (!currIdx.has(k)) removed.push(p);
  }
  return { added, removed, changed, unchanged };
}

function summarizeDiff(diff) {
  const bySev = { critical: { added: 0, removed: 0 }, high: { added: 0, removed: 0 }, medium: { added: 0, removed: 0 }, low: { added: 0, removed: 0 } };
  for (const f of diff.added)   if (bySev[f.severity]) bySev[f.severity].added++;
  for (const f of diff.removed) if (bySev[f.severity]) bySev[f.severity].removed++;
  return {
    addedCount: diff.added.length,
    removedCount: diff.removed.length,
    changedCount: diff.changed.length,
    unchangedCount: diff.unchanged,
    bySeverity: bySev,
  };
}

function renderDiff(diff, opts = {}) {
  const color = opts.color !== false;
  const C = color ? { RED: '\x1b[31m', GREEN: '\x1b[32m', YELLOW: '\x1b[33m', DIM: '\x1b[2m', BOLD: '\x1b[1m', RESET: '\x1b[0m' } : { RED:'', GREEN:'', YELLOW:'', DIM:'', BOLD:'', RESET:'' };
  const sum = summarizeDiff(diff);
  const out = [];
  out.push('');
  out.push(`${C.BOLD}Scan-result diff${C.RESET}`);
  out.push(`  ${C.RED}+${sum.addedCount} added${C.RESET}   ${C.GREEN}-${sum.removedCount} removed${C.RESET}   ${C.YELLOW}~${sum.changedCount} changed${C.RESET}   ${C.DIM}${sum.unchangedCount} unchanged${C.RESET}`);
  out.push('');
  if (diff.added.length) {
    out.push(`${C.RED}${C.BOLD}Added (${diff.added.length})${C.RESET}`);
    for (const f of diff.added.slice(0, 25)) {
      out.push(`  ${C.RED}+${C.RESET} [${(f.severity || '').toUpperCase()}] ${(f.vuln || '').slice(0, 60)}  ${C.DIM}${f.file || '?'}:${f.line || 0}${C.RESET}`);
    }
    if (diff.added.length > 25) out.push(`  ${C.DIM}... and ${diff.added.length - 25} more${C.RESET}`);
    out.push('');
  }
  if (diff.removed.length) {
    out.push(`${C.GREEN}${C.BOLD}Removed (${diff.removed.length})${C.RESET}`);
    for (const f of diff.removed.slice(0, 25)) {
      out.push(`  ${C.GREEN}-${C.RESET} [${(f.severity || '').toUpperCase()}] ${(f.vuln || '').slice(0, 60)}  ${C.DIM}${f.file || '?'}:${f.line || 0}${C.RESET}`);
    }
    if (diff.removed.length > 25) out.push(`  ${C.DIM}... and ${diff.removed.length - 25} more${C.RESET}`);
    out.push('');
  }
  if (diff.changed.length) {
    out.push(`${C.YELLOW}${C.BOLD}Changed (${diff.changed.length})${C.RESET}`);
    for (const c of diff.changed.slice(0, 15)) {
      const sevDelta = c.fields.severity ? `${c.fields.severity[0]} → ${c.fields.severity[1]}` : '';
      const verdictDelta = c.fields.mitigationVerdict ? `verdict ${c.fields.mitigationVerdict[0]} → ${c.fields.mitigationVerdict[1]}` : '';
      const validatorDelta = c.fields.validator_verdict ? `validator ${c.fields.validator_verdict[0]} → ${c.fields.validator_verdict[1]}` : '';
      const delta = [sevDelta, verdictDelta, validatorDelta].filter(Boolean).join('; ');
      out.push(`  ${C.YELLOW}~${C.RESET} ${(c.after.vuln || '').slice(0, 50)}  ${C.DIM}${c.after.file || '?'}:${c.after.line || 0}${C.RESET}   ${delta}`);
    }
    out.push('');
  }
  return out.join('\n');
}


/***/ })

};
