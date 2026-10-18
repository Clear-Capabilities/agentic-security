export const id = 8714;
export const ids = [8714];
export const modules = {

/***/ 58714:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   renderRuntimeExplorer: () => (/* binding */ renderRuntimeExplorer),
/* harmony export */   vulnerableFunctionsInProduction: () => (/* binding */ vulnerableFunctionsInProduction)
/* harmony export */ });
// The runtime half of the Data Flow Explorer as ONE static, script-free HTML page (PRD 2 section 5). Pure: it renders what
// `runtime-edge-states.js` and the correlation already computed, writes nothing, and runs nothing in the browser. It exists as a page
// rather than a route on the local explore server because that server's contract (`server/CLAUDE.md`) deliberately serves only the
// signed static graph; widening it is a security decision of its own. A page needs no server, no token and no script.
//
// Five views, in the order the PRD names them: Static, Runtime, Static vs Runtime, Observed High-Risk Paths, Unexpected Runtime Paths.
// Clicking (expanding) an edge shows BOTH its static evidence and its runtime evidence. Every flow is also shown as a path
// ("source -> ... -> sink") with the state of each hop, which is the PRD's "credit-card field -> API -> payments service -> DB" view.
//
// Everything interpolated into the page is escaped. Attribute values (hosts, services) came from telemetry the operator supplied and
// are treated as hostile text. The page states, at the top, what absence of observation does and does not mean.
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const arr = (v) => (Array.isArray(v) ? v : []);
const SENSITIVE = new Set(['PII', 'PHI', 'PCI', 'FIN', 'CREDENTIALS']);
const CSS = 'body{font:14px/1.45 system-ui,sans-serif;margin:24px auto;max-width:1100px;padding:0 16px;color:#1b1f24;background:#fff}'
  + '@media(prefers-color-scheme:dark){body{background:#14171a;color:#e6e8ea}}'
  + 'table{border-collapse:collapse;width:100%;margin:8px 0}td,th{border:1px solid #8886;padding:4px 8px;text-align:left;vertical-align:top}'
  + 'summary{cursor:pointer}.s{display:inline-block;padding:0 6px;border-radius:4px;border:1px solid #8888;font-size:12px;margin-right:4px}'
  + '.RUNTIME_BLOCKED,.RUNTIME_POLICY_VIOLATION,.RUNTIME_EXPLOIT_CORRELATED{border-color:#c0392b;color:#c0392b}.RUNTIME_OBSERVED{border-color:#1e8449;color:#1e8449}'
  + '.note{border-left:4px solid #8888;padding:4px 12px;margin:12px 0}nav a{margin-right:12px}code{font-size:12px}';

function renderRuntimeExplorer({ graph, edgeStates, correlation, observations = [], absent = { candidates: [] }, title = 'Runtime twin' }) {
  const nodes = new Map(arr(graph?.nodes).map((n) => [n.id, n]));
  const edges = arr(graph?.edges); const flows = arr(graph?.flows);
  const dataEls = new Map(arr(graph?.dataElements).map((d) => [d.id, d]));
  const label = (id) => esc(nodes.get(id)?.label ?? id);
  const stateOf = (eid) => edgeStates?.byEdge?.[eid];
  const obsByEdge = new Map();
  for (const o of arr(observations)) for (const eid of arr(o.matchedEdgeIds)) { const a = obsByEdge.get(eid) ?? []; a.push(o); obsByEdge.set(eid, a); }
  const chips = (states) => arr(states).map((s) => `<span class="s ${esc(s)}">${esc(s)}</span>`).join('');
  const flowClasses = (f) => arr(f.dataElementIds).flatMap((id) => arr(dataEls.get(id)?.dataClasses));
  const observedEdge = (eid) => stateOf(eid)?.states?.includes('RUNTIME_OBSERVED');

  const staticRows = edges.map((e) => `<tr><td>${label(e.from)} &rarr; ${label(e.to)}</td><td><code>${esc(e.id)}</code></td><td>${esc(e.protocol?.name ?? e.protocol?.kind ?? '')}</td><td>${esc(arr(e.boundaryCrossings).join(', '))}</td></tr>`).join('');
  const runtimeRows = edges.map((e) => { const s = stateOf(e.id); return `<tr><td>${label(e.from)} &rarr; ${label(e.to)}</td><td>${chips(s?.states)}</td><td>${s?.observations ?? 0}</td><td>${esc(s?.identityTokens?.length ?? 0)}</td></tr>`; }).join('');
  const bothRows = edges.map((e) => { const s = stateOf(e.id); return `<tr><td>${label(e.from)} &rarr; ${label(e.to)}</td><td>${esc(arr(e.boundaryCrossings).length ? 'crosses a boundary' : 'internal')}, ${esc(e.provenance ?? '')}</td><td>${chips(s?.states)}${s?.uncertainObservations ? ` <small>(${s.uncertainObservations} uncertain, not counted)</small>` : ''}</td></tr>`; }).join('');

  const detail = (e) => {
    const s = stateOf(e.id); const obs = obsByEdge.get(e.id) ?? [];
    const o = obs.map((x) => `<li>${esc(x.adapter)} / ${esc(x.environment ?? 'no environment')}: ${esc(x.firstObservedAt)} to ${esc(x.lastObservedAt)}, count band ${esc(x.eventCountBand)}, match ${esc(x.matchMethod)} (${esc(x.matchConfidence)})${x.attributes?.['network.securityDecision'] ? `, decision ${esc(x.attributes['network.securityDecision'])}` : ''}${x.attributes?.['identity.token'] ? `, identity <code>${esc(x.attributes['identity.token'])}</code>` : ''}</li>`).join('');
    return `<details><summary>${label(e.from)} &rarr; ${label(e.to)} ${chips(s?.states)}</summary>`
      + `<h4>Static evidence</h4><p><code>${esc(e.id)}</code>, provenance ${esc(e.provenance)}, coverage ${esc(e.coverageStatus)}; boundaries: ${esc(arr(e.boundaryCrossings).join(', ') || 'none')}; evidence: ${esc(arr(e.evidenceRefs).join(', ') || 'none')}</p>`
      + `<h4>Runtime evidence</h4>${obs.length ? `<ul>${o}</ul>` : `<p>${esc(s?.note || 'none')}</p>`}</details>`;
  };

  const pathRow = (f) => {
    const hops = arr(f.edgeIds).map((eid) => { const e = edges.find((x) => x.id === eid); return e ? `${label(e.from)} &rarr; ${label(e.to)} ${chips(stateOf(eid)?.states)}` : esc(eid); });
    return `<tr><td>${esc(arr(f.dataElementIds).map((id) => dataEls.get(id)?.label ?? id).join(', '))}<br><small>${esc(flowClasses(f).join(', '))}</small></td><td>${hops.join('<br>') || '(no modelled hops)'}</td><td>${esc(f.policyVerdict)}</td></tr>`;
  };
  const highRisk = flows.filter((f) => arr(f.edgeIds).some(observedEdge) && (flowClasses(f).some((c) => SENSITIVE.has(c)) || f.policyVerdict === 'prohibited' || arr(f.edgeIds).some((eid) => arr(edges.find((e) => e.id === eid)?.boundaryCrossings).length)));
  const blockedNodes = Object.entries(edgeStates?.byNode ?? {});
  const unexpected = [
    ...arr(absent.candidates).map((c) => `<tr><td>${esc(c.destination)}</td><td>observed, not placed on any static node</td><td>${esc(c.firstObservedAt)} to ${esc(c.lastObservedAt)}</td></tr>`),
    ...blockedNodes.filter(([, n]) => n.states.includes('RUNTIME_BLOCKED')).map(([id, n]) => `<tr><td>${label(id)}</td><td>attempted and refused (${n.denied} denied)</td><td></td></tr>`),
  ];
  const section = (id, h, body) => `<section id="${id}"><h2>${h}</h2>${body}</section>`;
  const table = (head, rows, empty) => (rows.length ? `<table><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr>${rows.join('')}</table>` : `<p>${esc(empty)}</p>`);
  const body = [
    `<h1>${esc(title)}</h1>`,
    `<div class="note">${edgeStates?.evaluated ? 'Telemetry was consulted.' : '<strong>No telemetry was consulted:</strong> every edge is STATIC_ONLY. That is not evidence that nothing happens at runtime.'} <strong>Not observed does not mean unreachable or safe.</strong> Only high- and medium-confidence mappings are counted. Telemetry values shown are metadata only; identities appear only as keyed-hash tokens.</div>`,
    '<nav><a href="#static">Static</a><a href="#runtime">Runtime</a><a href="#both">Static vs Runtime</a><a href="#risk">Observed high-risk paths</a><a href="#unexpected">Unexpected runtime paths</a><a href="#paths">Flow paths</a><a href="#edges">Edge detail</a></nav>',
    section('static', 'Static', table(['Edge', 'Id', 'Protocol', 'Boundaries'], staticRows ? [staticRows] : [], 'No static edges.')),
    section('runtime', 'Runtime', table(['Edge', 'State', 'Trusted observations', 'Identity tokens'], runtimeRows ? [runtimeRows] : [], 'No edges.')),
    section('both', 'Static vs Runtime', table(['Edge', 'Static', 'Runtime'], bothRows ? [bothRows] : [], 'No edges.')),
    section('risk', 'Observed high-risk paths', table(['Data', 'Path and state per hop', 'Policy'], highRisk.map(pathRow), 'No observed flow is sensitive, policy-prohibited or boundary-crossing. This is a statement about the telemetry window, not about the system.')),
    section('unexpected', 'Unexpected runtime paths', table(['Destination or node', 'What was seen', 'When'], unexpected, 'Nothing unplaced or refused. Unplaced observations are candidates, not proof static analysis missed a path.')),
    section('paths', 'Flow paths', table(['Data', 'Path and state per hop', 'Policy'], flows.map(pathRow), 'No flows.')),
    section('edges', 'Edge detail (expand an edge for its static and runtime evidence)', edges.map(detail).join('') || '<p>No edges.</p>'),
  ].join('\n');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>${esc(title)}</title><style>${CSS}</style></head><body>${body}</body></html>\n`;
}

/** "Show vulnerable functions actually exercised in production": scan findings whose own path appears in the runtime trace. Expects findings already
 * annotated by `posture/runtime-correlation.js`; it adds no matching of its own. */
function vulnerableFunctionsInProduction(findings) {
  const list = arr(findings).filter((f) => f && typeof f === 'object');
  const withEvidence = list.filter((f) => f.runtimeEvidence);
  if (!withEvidence.some((f) => f.runtimeEvidence.state !== 'unknown')) return { evaluated: false, reason: 'no runtime trace could be evaluated (none present, or it says nothing about any finding): put one at .agentic-security/runtime-trace.jsonl (or set AGENTIC_SECURITY_RUNTIME_TRACE_PATH). This is not "no vulnerable function ran".' };
  const observed = withEvidence.filter((f) => f.runtimeEvidence.state === 'observed').map((f) => ({ id: f.id, severity: f.severity, vuln: f.vuln, file: f.file, line: f.line, cwe: f.cwe, basis: f.runtimeEvidence.basis, sampling: f.runtimeEvidence.sampling?.state ?? null }));
  const counts = { observed: observed.length, notObservedInWindow: withEvidence.filter((f) => f.runtimeEvidence.state === 'not_observed_in_window').length, unknown: withEvidence.filter((f) => f.runtimeEvidence.state === 'unknown').length };
  return { evaluated: true, findings: observed, counts, note: 'A finding listed here has a function, line or route on its path in the trace. A finding not listed may still run: counts show how many were not observed or unknown. Absence of observation is a statement about the window and the instrumentation, not about reachability.' };
}


/***/ })

};
