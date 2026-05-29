// Auto-generated threat model — Recommendation #2 of the world-class+2 plan.
//
// Builds a STRIDE threat model from the scan's findings + IR + privacy
// taint. Outputs Mermaid diagrams + per-asset attack trees grounded in
// actual scanner evidence. The model is "live" — regenerated every scan
// so it can't bit-rot.
//
// Pipeline:
//   1. Identify external entities — every route, message-queue consumer,
//      file ingest, S3 listener, etc.
//   2. Identify trust boundaries — entity → handler boundary, internal-
//      service → external-service boundary
//   3. Identify assets — every PII/PHI/PCI field, every credential, every
//      authoritative DB/cache, every secret-bearing service
//   4. Apply STRIDE per (entity, asset) pair using template-driven rules
//   5. Generate attack trees rooted at each high-value asset with leaves
//      grounded in actual scanner findings
//
// Output:
//   { entities, boundaries, assets, threats, attackTrees, mermaid }
//
// Persisted to .agentic-security/threat-model.json (machine-readable) and
// .agentic-security/threat-model.md (human-readable).

import * as fs from 'node:fs';
import * as path from 'node:path';

// STRIDE category descriptors
const STRIDE = {
  S: { label: 'Spoofing',         control: 'Authentication / Identity' },
  T: { label: 'Tampering',        control: 'Integrity / Authorization' },
  R: { label: 'Repudiation',      control: 'Audit logs / Non-repudiation' },
  I: { label: 'Information Disclosure', control: 'Confidentiality / Encryption' },
  D: { label: 'Denial of Service',control: 'Availability / Rate limiting' },
  E: { label: 'Elevation of Privilege', control: 'Authorization / Least privilege' },
};

// Map CWE → STRIDE categories. Multi-mapping is allowed.
const CWE_TO_STRIDE = {
  'CWE-22':  ['I'],            // path-traversal
  'CWE-78':  ['E', 'T'],       // command-injection
  'CWE-79':  ['T'],            // xss
  'CWE-89':  ['T', 'I'],       // sql-injection
  'CWE-90':  ['T'],            // ldap-injection
  'CWE-94':  ['E'],            // code-injection
  'CWE-113': ['T'],            // header injection
  'CWE-134': ['I'],            // format-string
  'CWE-200': ['I'],            // information-exposure
  'CWE-287': ['S'],            // improper authentication
  'CWE-307': ['S'],            // brute-force
  'CWE-327': ['I'],            // weak-crypto
  'CWE-330': ['S'],            // weak-rng
  'CWE-352': ['T'],            // csrf
  'CWE-359': ['I'],            // private-info exposure
  'CWE-415': ['D', 'E'],       // double-free
  'CWE-416': ['D', 'E'],       // use-after-free
  'CWE-434': ['E'],            // file upload
  'CWE-502': ['E'],            // insecure-deserialization
  'CWE-601': ['T'],            // open-redirect
  'CWE-611': ['I'],            // xxe
  'CWE-639': ['E'],            // IDOR
  'CWE-643': ['T'],            // xpath injection
  'CWE-798': ['I', 'S'],       // hardcoded-secret
  'CWE-918': ['I', 'E'],       // ssrf
  'CWE-1004':['I'],            // missing cookie hardening
  'CWE-1321':['T', 'E'],       // prototype-pollution
  'CWE-1333':['D'],            // ReDoS
  'CWE-1427':['T'],            // prompt injection
};

function _stridesForFinding(f) {
  const c = f.cwe || '';
  if (CWE_TO_STRIDE[c]) return CWE_TO_STRIDE[c];
  // Family-based fallback
  if (f.family === 'sql-injection') return ['T', 'I'];
  if (f.family === 'command-injection') return ['E', 'T'];
  if (f.family === 'xss') return ['T'];
  if (f.family === 'hardcoded-secret') return ['I'];
  return ['T'];
}

/**
 * Build the threat-model graph. `scan` is the engine's scan result
 * structure (findings + routes + supplyChain).
 */
export function buildThreatModel(scan, opts = {}) {
  const entities = [];   // external entities: routes, queue consumers, file ingest
  const boundaries = []; // trust boundary edges
  const assets = [];     // valuables: PII, credentials, DBs
  const threats = [];    // (entity, asset, stride) tuples

  // Step 1: external entities — routes
  for (const r of (scan.routes || [])) {
    entities.push({
      kind: 'http-route',
      id: `route:${r.method || 'ANY'}:${r.path || r.file + ':' + r.line}`,
      method: r.method || 'ANY',
      path: r.path || null,
      file: r.file, line: r.line,
      requiresAuth: !!r.requiresAuth,
    });
  }
  // External entities — message queues / consumers / file ingest (best-effort
  // heuristic from findings).
  for (const f of (scan.findings || [])) {
    if (/kafka|sqs|sns|rabbit|pubsub|kinesis/i.test(f.snippet || '')) {
      entities.push({ kind: 'queue-consumer', id: `queue:${f.file}:${f.line}`, file: f.file, line: f.line });
    }
  }

  // Step 2: assets — PII / credentials / DBs
  for (const f of (scan.findings || [])) {
    if (f.family === 'hardcoded-secret') {
      assets.push({ kind: 'credential', id: `cred:${f.file}:${f.line}`, file: f.file, line: f.line, name: (f.vuln||'').slice(0, 80) });
    }
    if (f.family === 'pii-exposure') {
      assets.push({ kind: 'pii', id: `pii:${f.file}:${f.line}`, file: f.file, line: f.line, classes: f.piiClass || [] });
    }
  }
  // DB-shaped assets: routes that touch SQL.
  const dbAsset = { kind: 'datastore', id: 'datastore:default', name: 'Application Database' };
  let hasDbFinding = false;
  for (const f of (scan.findings || [])) {
    if (f.family === 'sql-injection' || /SqlCommand|prepareStatement|EntityManager/i.test(f.snippet || '')) {
      hasDbFinding = true; break;
    }
  }
  if (hasDbFinding) assets.push(dbAsset);

  // Step 3: trust boundaries
  for (const e of entities) {
    boundaries.push({ from: 'external', to: e.id, kind: 'trust-boundary', requiresAuth: e.requiresAuth });
  }
  for (const a of assets) {
    boundaries.push({ from: 'application', to: a.id, kind: 'asset-boundary' });
  }

  // Step 4: STRIDE per finding (each finding implies one or more threats)
  for (const f of (scan.findings || [])) {
    const sts = _stridesForFinding(f);
    for (const st of sts) {
      threats.push({
        stride: st,
        strideLabel: STRIDE[st]?.label || st,
        cwe: f.cwe || null,
        family: f.family,
        severity: f.severity,
        file: f.file, line: f.line,
        vuln: f.vuln,
        finding_id: f.id,
        affectsAsset: assets.find(a =>
          (a.kind === 'credential' && f.family === 'hardcoded-secret') ||
          (a.kind === 'pii' && f.family === 'pii-exposure') ||
          (a.kind === 'datastore' && (f.family === 'sql-injection' || f.family === 'insecure-deserialization'))
        )?.id || null,
        atEntity: entities.find(e => e.file === f.file && Math.abs((e.line||0) - (f.line||0)) <= 50)?.id || null,
      });
    }
  }

  // Step 5: attack trees — per high-value asset
  const attackTrees = assets.map(a => {
    const leaves = threats
      .filter(t => t.affectsAsset === a.id)
      .map(t => ({
        label: `${t.strideLabel} via ${t.family} (${t.cwe || '—'})`,
        severity: t.severity,
        file: t.file, line: t.line,
        finding_id: t.finding_id,
      }));
    return {
      root: `Compromise ${a.kind}: ${a.name || a.id}`,
      asset_id: a.id,
      leaves,
      severity: leaves.some(l => l.severity === 'critical') ? 'critical'
              : leaves.some(l => l.severity === 'high')     ? 'high' : 'medium',
    };
  });

  return { entities, boundaries, assets, threats, attackTrees };
}

/**
 * Render the model as a Mermaid flowchart for visual review.
 */
export function renderMermaid(model) {
  const lines = ['flowchart TB'];
  lines.push('  subgraph External');
  for (const e of model.entities.slice(0, 30)) {
    lines.push(`    ${_mid(e.id)}["${e.kind}: ${e.method || ''} ${e.path || (e.file||'') + ':' + (e.line||'')}"]`);
  }
  lines.push('  end');
  lines.push('  subgraph Application');
  for (const a of model.assets.slice(0, 30)) {
    lines.push(`    ${_mid(a.id)}{{"${a.kind}: ${a.name || a.id}"}}`);
  }
  lines.push('  end');
  for (const b of model.boundaries.slice(0, 100)) {
    if (b.kind === 'trust-boundary') {
      lines.push(`  External --> ${_mid(b.to)}`);
    } else if (b.kind === 'asset-boundary') {
      lines.push(`  ${_mid(b.from)} -.-> ${_mid(b.to)}`);
    }
  }
  return lines.join('\n');
}

function _mid(id) { return String(id).replace(/[^A-Za-z0-9]/g, '_').slice(0, 60); }

/**
 * Persist threat model to disk: JSON for tooling, Markdown for review.
 */
export function persistThreatModel(scanRoot, model) {
  const dir = path.join(scanRoot, '.agentic-security');
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  try { fs.writeFileSync(path.join(dir, 'threat-model.json'), JSON.stringify(model, null, 2)); } catch {}
  try { fs.writeFileSync(path.join(dir, 'threat-model.md'), renderMarkdown(model)); } catch {}
}

function renderMarkdown(model) {
  const lines = [];
  lines.push('# Threat Model (auto-generated)');
  lines.push('');
  lines.push(`Generated by agentic-security on ${new Date().toISOString().slice(0,10)}.`);
  lines.push('');
  lines.push('This threat model is derived from static analysis of the current codebase and is regenerated on every scan. It is intended as a working artifact, not a finished compliance document.');
  lines.push('');
  lines.push('## Entities + boundaries');
  lines.push('');
  lines.push('```mermaid');
  lines.push(renderMermaid(model));
  lines.push('```');
  lines.push('');
  lines.push('## Assets');
  lines.push('');
  for (const a of model.assets.slice(0, 100)) {
    lines.push(`- **${a.kind}**: ${a.name || a.id} — at \`${a.file || '(global)'}${a.line ? ':'+a.line : ''}\``);
  }
  lines.push('');
  lines.push('## STRIDE threats');
  lines.push('');
  const byStride = {};
  for (const t of model.threats) (byStride[t.stride] ||= []).push(t);
  for (const [st, threats] of Object.entries(byStride)) {
    lines.push(`### ${STRIDE[st]?.label || st} (${threats.length})`);
    lines.push('');
    for (const t of threats.slice(0, 25)) {
      lines.push(`- [${t.severity}] **${t.family}** (${t.cwe || '—'}) at \`${t.file}:${t.line}\` — ${t.vuln}`);
    }
    if (threats.length > 25) lines.push(`- … and ${threats.length - 25} more`);
    lines.push('');
  }
  lines.push('## Attack trees');
  lines.push('');
  for (const tree of model.attackTrees) {
    lines.push(`### ${tree.root}`);
    lines.push(`Severity rollup: **${tree.severity}**`);
    lines.push('');
    for (const leaf of tree.leaves.slice(0, 20)) {
      lines.push(`- [${leaf.severity}] ${leaf.label} — \`${leaf.file}:${leaf.line}\``);
    }
    if (tree.leaves.length > 20) lines.push(`- … and ${tree.leaves.length - 20} more leaves`);
    lines.push('');
  }
  return lines.join('\n');
}

export const _internals = { STRIDE, CWE_TO_STRIDE };
