// FR-UX-10 — Living trust-boundary diagram.
//
// Auto-generate a Mermaid diagram of the project's trust boundaries: HTTP
// edges (with method+path), queue producers/consumers, gRPC servers, DB
// edges, IaC-exposed resources. Findings on edges render as decorations.
//
// We emit Mermaid (text). The HTML report can render it natively;
// PR-comment bot can render the source.
//
// Output:
//   {
//     mermaid: string,     // the Mermaid source
//     nodes:   [...],      // {id, kind, label}
//     edges:   [...],      // {from, to, kind, label?}
//     decorations: [...],  // {nodeId, severity, vuln}
//   }

import { buildAssetInventory, buildTrustBoundaries } from './threat-model.js';

function sanitizeId(s) {
  return String(s).replace(/[^A-Za-z0-9_]/g, '_').slice(0, 40);
}

function nodeFor(b) {
  if (b.type === 'http-route' || b.type === 'http-route-py' || b.type === 'http-route-java') {
    return { kind: 'route', id: 'route_' + sanitizeId(b.label || `${b.file}_${b.line}`), label: b.label || `route@${b.file}:${b.line}` };
  }
  if (b.type === 'queue-producer') {
    return { kind: 'queue', id: 'qprod_' + sanitizeId(`${b.file}_${b.line}`), label: `producer: ${b.file}:${b.line}` };
  }
  if (b.type === 'queue-consumer') {
    return { kind: 'queue', id: 'qcons_' + sanitizeId(`${b.file}_${b.line}`), label: `consumer: ${b.file}:${b.line}` };
  }
  if (b.type === 'grpc-server') {
    return { kind: 'grpc', id: 'grpc_' + sanitizeId(`${b.file}_${b.line}`), label: `grpc@${b.file}:${b.line}` };
  }
  if (b.type === 'db-edge') {
    return { kind: 'db', id: 'db_' + sanitizeId(`${b.file}_${b.line}`), label: `db@${b.file}:${b.line}` };
  }
  return null;
}

function findingsForNode(node, findings, boundary) {
  if (!Array.isArray(findings)) return [];
  return findings.filter(f =>
    f && f.file === boundary.file &&
    Math.abs((f.line || 0) - (boundary.line || 0)) <= 25
  );
}

export function buildTrustBoundaryDiagram(findings, fileContents) {
  const boundaries = buildTrustBoundaries(fileContents);
  const assets = buildAssetInventory(fileContents);

  const nodes = new Map();
  const edges = [];
  const decorations = [];

  // INTERNET ── route ── service-internal
  const INTERNET = { id: 'INTERNET', kind: 'external', label: 'Internet' };
  const APP = { id: 'APP', kind: 'app', label: 'Application' };
  nodes.set('INTERNET', INTERNET);
  nodes.set('APP', APP);

  for (const b of boundaries) {
    const n = nodeFor(b);
    if (!n) continue;
    if (!nodes.has(n.id)) nodes.set(n.id, n);
    if (n.kind === 'route') edges.push({ from: INTERNET.id, to: n.id, kind: 'http' });
    if (n.kind === 'route') edges.push({ from: n.id, to: APP.id, kind: 'invoke' });
    if (n.kind === 'queue') edges.push({ from: APP.id, to: n.id, kind: 'queue' });
    if (n.kind === 'grpc') edges.push({ from: INTERNET.id, to: n.id, kind: 'grpc' });
    if (n.kind === 'db') edges.push({ from: APP.id, to: n.id, kind: 'db' });
    for (const f of findingsForNode(n, findings, b)) {
      decorations.push({ nodeId: n.id, severity: f.severity, vuln: (f.vuln || '').slice(0, 60), file: f.file, line: f.line });
    }
  }

  // Assets → as terminal nodes off APP
  for (const a of assets.slice(0, 12)) {
    const id = 'asset_' + sanitizeId(`${a.category}_${a.name || a.file}`);
    if (!nodes.has(id)) nodes.set(id, { id, kind: 'asset', label: `${a.category}: ${a.name || ''}` });
    edges.push({ from: APP.id, to: id, kind: 'asset' });
  }

  // Render Mermaid
  const lines = ['flowchart LR'];
  for (const n of nodes.values()) {
    const safe = n.label.replace(/"/g, "'").slice(0, 60);
    if (n.kind === 'external') lines.push(`  ${n.id}((${safe}))`);
    else if (n.kind === 'asset') lines.push(`  ${n.id}[/"${safe}"/]`);
    else if (n.kind === 'db') lines.push(`  ${n.id}[("${safe}")]`);
    else lines.push(`  ${n.id}["${safe}"]`);
  }
  for (const e of edges) lines.push(`  ${e.from} -->|${e.kind}| ${e.to}`);
  // Severity-styled class assignments for decorated nodes.
  const decoratedSeverities = new Map();
  for (const d of decorations) {
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const prev = decoratedSeverities.get(d.nodeId);
    if (!prev || (rank[d.severity] ?? 9) < (rank[prev] ?? 9)) decoratedSeverities.set(d.nodeId, d.severity);
  }
  for (const [id, sev] of decoratedSeverities) lines.push(`  class ${id} sev_${sev};`);
  lines.push('  classDef sev_critical fill:#ffcccc,stroke:#a00,stroke-width:2px;');
  lines.push('  classDef sev_high fill:#ffe0b2,stroke:#c60,stroke-width:2px;');
  lines.push('  classDef sev_medium fill:#fff3cd,stroke:#a80;');
  lines.push('  classDef sev_low fill:#e8eaf6,stroke:#557;');

  return {
    mermaid: lines.join('\n'),
    nodes: [...nodes.values()],
    edges,
    decorations,
  };
}
