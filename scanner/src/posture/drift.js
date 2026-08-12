// 0.6.0 Feat-4: Drift report — diff two scans (or two refs) and surface
// posture changes: new/removed endpoints, new/removed deps, lost or added
// auth boundaries, severity deltas, data-class deltas.
//
// Inputs are two scan JSONs (the result of toJSON or runFullScan). The output
// is a structured object that the HTML report renders as a "Drift" tab and the
// PR-comment script renders as a Markdown summary.

function _routeKey(r) { return `${r.method || 'ANY'} ${r.path || '(file)'} @ ${r.file}:${r.line}`; }
function _depKey(c)   { return `${c.ecosystem}:${c.name}@${c.version}`; }
// Prefer stableId (posture/stable-id.js) — it omits the exact source line by
// design, so an unrelated edit that shifts a still-unfixed finding's line
// number doesn't register as one "removed" + one "added" finding, inflating
// drift tier and falsely flagging a PR as introducing/fixing something it
// didn't touch. Falls back to the line-sensitive key only for finding shapes
// that never got a stableId annotated.
function _findingKey(f) { return f.stableId || `${f.kind}:${f.file}:${f.line}:${(f.vuln||'').slice(0,80)}`; }

function _toMap(arr, keyFn) {
  const m = new Map();
  for (const x of arr || []) m.set(keyFn(x), x);
  return m;
}

function _diffSets(a, b, keyFn) {
  const ma = _toMap(a, keyFn), mb = _toMap(b, keyFn);
  const added = [], removed = [], unchanged = [];
  for (const [k, v] of mb) (ma.has(k) ? unchanged : added).push(v);
  for (const [k, v] of ma) if (!mb.has(k)) removed.push(v);
  return { added, removed, unchanged };
}

// Severity-tier deltas: count by tier on each side, take diff.
function _severityDelta(a, b) {
  const counts = (arr) => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of arr || []) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  };
  const ca = counts(a), cb = counts(b);
  const delta = {};
  for (const k of Object.keys(ca)) delta[k] = (cb[k] || 0) - (ca[k] || 0);
  return { from: ca, to: cb, delta };
}

// Auth boundary deltas: a route is an auth boundary iff hasAuth === true.
// Lost: was authed, no longer is. Added: now authed, wasn't.
function _authBoundaryDelta(routesA, routesB) {
  const k = (r) => `${r.method} ${r.path} @ ${r.file}`;
  const a = _toMap(routesA, k);
  const b = _toMap(routesB, k);
  const lost = [], added = [];
  for (const [key, ra] of a) {
    const rb = b.get(key);
    if (ra.hasAuth && rb && !rb.hasAuth) lost.push(rb);
    if (!ra.hasAuth && rb && rb.hasAuth) added.push(rb);
  }
  return { lost, added };
}

// Data-class deltas across routes: "now exposed PII", "no longer exposes PHI".
function _dataClassDelta(routesA, routesB) {
  const aClasses = new Set();
  const bClasses = new Set();
  for (const r of routesA || []) for (const c of r.classifications || []) aClasses.add(c);
  for (const r of routesB || []) for (const c of r.classifications || []) bClasses.add(c);
  const newlyExposed = [...bClasses].filter(c => !aClasses.has(c));
  const noLongerExposed = [...aClasses].filter(c => !bClasses.has(c));
  return { newlyExposed, noLongerExposed };
}

export function driftBetween(scanA, scanB) {
  const routes = _diffSets(scanA.routes || [], scanB.routes || [], _routeKey);
  const deps = _diffSets(scanA.components || [], scanB.components || [], _depKey);
  const sca = _diffSets((scanA.supplyChain || []).filter(s => s.type === 'vulnerable_dep'),
                        (scanB.supplyChain || []).filter(s => s.type === 'vulnerable_dep'),
                        s => `${s.ecosystem}:${s.name}@${s.version}:${s.osvId || s.advisory || ''}`);
  // Findings — use kind+file+line+vuln as the stable key.
  const allFindingsA = [...(scanA.findings || []), ...(scanA.logicVulns || [])];
  const allFindingsB = [...(scanB.findings || []), ...(scanB.logicVulns || [])];
  const findings = _diffSets(allFindingsA, allFindingsB, _findingKey);
  const severity = _severityDelta(allFindingsA, allFindingsB);
  const authBoundaries = _authBoundaryDelta(scanA.routes || [], scanB.routes || []);
  const dataClasses = _dataClassDelta(scanA.routes || [], scanB.routes || []);

  const totalChanged =
    routes.added.length + routes.removed.length +
    deps.added.length + deps.removed.length +
    sca.added.length + sca.removed.length +
    findings.added.length + findings.removed.length +
    authBoundaries.lost.length + authBoundaries.added.length;

  // Headline tier: critical if ANY auth boundary lost, OR a critical finding added,
  // OR a vulnerable dep added at high+ severity. High if any finding added or any
  // auth boundary added without authn improvements. Otherwise informational.
  let tier = 'info';
  if (authBoundaries.lost.length > 0) tier = 'critical';
  else if (findings.added.some(f => f.severity === 'critical')) tier = 'critical';
  else if (sca.added.some(s => /critical|high/.test(s.severity || ''))) tier = 'high';
  else if (findings.added.length > 0 || routes.added.some(r => !r.hasAuth)) tier = 'high';
  else if (deps.added.length > 0 || routes.added.length > 0) tier = 'medium';
  else if (totalChanged > 0) tier = 'low';

  return {
    tier,
    routes, deps, sca, findings,
    severity, authBoundaries, dataClasses,
    totalChanged,
  };
}

export function driftToMarkdown(drift) {
  const lines = [];
  lines.push(`### Posture drift — tier: **${drift.tier}**`);
  lines.push('');
  if (drift.tier === 'info' && drift.totalChanged === 0) {
    lines.push('No posture changes detected between the two scans.');
    return lines.join('\n');
  }
  if (drift.authBoundaries.lost.length) {
    lines.push(`**Auth boundaries LOST: ${drift.authBoundaries.lost.length}**`);
    for (const r of drift.authBoundaries.lost) lines.push(`- \`${r.method} ${r.path}\` (\`${r.file}:${r.line}\`)`);
    lines.push('');
  }
  if (drift.authBoundaries.added.length) {
    lines.push(`**Auth boundaries ADDED: ${drift.authBoundaries.added.length}**`);
    for (const r of drift.authBoundaries.added) lines.push(`- \`${r.method} ${r.path}\` (\`${r.file}:${r.line}\`)`);
    lines.push('');
  }
  if (drift.routes.added.length) {
    lines.push(`**New endpoints (${drift.routes.added.length}):**`);
    for (const r of drift.routes.added.slice(0, 10)) {
      const auth = r.hasAuth ? '🔒' : '⚠️ unauthenticated';
      lines.push(`- ${auth} \`${r.method} ${r.path}\` (\`${r.file}:${r.line}\`)`);
    }
    if (drift.routes.added.length > 10) lines.push(`- … and ${drift.routes.added.length - 10} more`);
    lines.push('');
  }
  if (drift.routes.removed.length) {
    lines.push(`**Removed endpoints: ${drift.routes.removed.length}**`);
    lines.push('');
  }
  if (drift.deps.added.length) {
    lines.push(`**New dependencies (${drift.deps.added.length}):**`);
    for (const c of drift.deps.added.slice(0, 10)) lines.push(`- \`${c.ecosystem}:${c.name}@${c.version}\``);
    if (drift.deps.added.length > 10) lines.push(`- … and ${drift.deps.added.length - 10} more`);
    lines.push('');
  }
  if (drift.deps.removed.length) {
    lines.push(`**Removed dependencies: ${drift.deps.removed.length}**`);
    lines.push('');
  }
  if (drift.sca.added.length) {
    lines.push(`**New CVEs introduced (${drift.sca.added.length}):**`);
    for (const s of drift.sca.added.slice(0, 10)) lines.push(`- \`${s.severity}\` ${s.osvId || s.advisory || s.name} (${s.name}@${s.version})`);
    lines.push('');
  }
  if (drift.findings.added.length) {
    lines.push(`**New findings: ${drift.findings.added.length}** (severity delta: ${Object.entries(drift.severity.delta).filter(([,v])=>v!==0).map(([k,v])=>`${k} ${v>0?'+':''}${v}`).join(', ')||'none'})`);
    lines.push('');
  }
  if (drift.findings.removed.length) {
    lines.push(`**Findings fixed: ${drift.findings.removed.length}**`);
    lines.push('');
  }
  if (drift.dataClasses.newlyExposed.length) {
    lines.push(`**Newly exposed data classes: ${drift.dataClasses.newlyExposed.join(', ')}**`);
    lines.push('');
  }
  return lines.join('\n');
}
