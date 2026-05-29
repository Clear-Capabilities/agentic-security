// PQC migration-plan artifact emitter.
//
// Aggregates pqc-migration findings (emitted by sast/post-quantum-crypto.js)
// into a structured plan suitable for an engineering organization to use as
// a project tracker:
//
//   .agentic-security/pqc-migration-plan.json
//   .agentic-security/pqc-migration-plan.md
//
// Buckets findings by:
//   - HNDL criticality (high-priority — data captured today is harvest-now-decrypt-later
//     exposure when a CRQC arrives)
//   - Use case (signing / encryption / KEX) — drives the replacement primitive
//   - Recommended replacement (ML-KEM-768, ML-DSA-65, etc.)
//   - File / package locality so the plan can be carved into milestones.
//
// Cleartext markdown summarises the top recommendations and milestone
// suggestions; JSON-LD-shaped structured output is consumable by Vanta /
// Drata / SecureFrame or any custom rollup dashboard.

import * as fs from 'node:fs';
import * as path from 'node:path';

function _byHndl(findings) {
  return {
    hndlCritical: findings.filter(f => f.hndlCritical),
    standard: findings.filter(f => !f.hndlCritical),
  };
}

function _byUseCase(findings) {
  const map = new Map();
  for (const f of findings) {
    const k = f.pqcRecommendation?.primary || 'unspecified';
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(f);
  }
  return map;
}

function _byFile(findings) {
  const map = new Map();
  for (const f of findings) {
    const k = f.file || 'unknown';
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(f);
  }
  return map;
}

export function buildMigrationPlan(allFindings) {
  const pqc = (allFindings || []).filter(f => f.family === 'pqc-migration');
  if (!pqc.length) return null;
  const bySev = _byHndl(pqc);
  const byPrimitive = _byUseCase(pqc);
  const byFile = _byFile(pqc);
  const summary = {
    total: pqc.length,
    hndlCritical: bySev.hndlCritical.length,
    standard: bySev.standard.length,
    filesAffected: byFile.size,
    primitivesNeeded: Array.from(byPrimitive.keys()),
  };
  const milestones = [
    {
      id: 'M1',
      title: 'Inventory & policy',
      target: '90 days',
      owner: 'security',
      items: [
        'Confirm scanner findings against design docs',
        'Adopt PQC migration policy (CNSA 2.0 / NIST IR 8547 alignment)',
        'Establish KMS support for hybrid keys',
      ],
    },
    {
      id: 'M2',
      title: 'HNDL-critical paths to PQ-hybrid',
      target: '180 days',
      owner: 'platform',
      items: bySev.hndlCritical.slice(0, 25).map(f => ({
        finding: f.id, file: f.file, line: f.line,
        replacement: f.pqcRecommendation?.hybrid || f.pqcRecommendation?.primary,
      })),
    },
    {
      id: 'M3',
      title: 'Standard signing/KEX migration',
      target: '12 months',
      owner: 'platform',
      items: bySev.standard.slice(0, 50).map(f => ({
        finding: f.id, file: f.file, line: f.line,
        replacement: f.pqcRecommendation?.primary,
      })),
    },
    {
      id: 'M4',
      title: 'Deprecate classical primitives',
      target: '24 months',
      owner: 'security',
      items: ['Remove dual-stack libraries once peers are PQ-capable', 'Rotate root CA / long-lived signing keys to ML-DSA'],
    },
  ];
  return {
    generatedAt: new Date().toISOString(),
    summary,
    milestones,
    perFile: Object.fromEntries(
      Array.from(byFile.entries()).map(([file, fs]) => [file, {
        count: fs.length,
        subfamilies: Array.from(new Set(fs.map(f => f.subfamily))),
        hndlCritical: fs.some(f => f.hndlCritical),
      }]),
    ),
  };
}

export function persistMigrationPlan(scanRoot, plan) {
  if (!plan) return null;
  try { fs.mkdirSync(path.join(scanRoot, '.agentic-security'), { recursive: true }); } catch {}
  try { fs.writeFileSync(path.join(scanRoot, '.agentic-security', 'pqc-migration-plan.json'), JSON.stringify(plan, null, 2)); } catch {}
  try { fs.writeFileSync(path.join(scanRoot, '.agentic-security', 'pqc-migration-plan.md'), _markdown(plan)); } catch {}
  return plan;
}

function _markdown(plan) {
  const lines = [];
  lines.push('# Post-quantum cryptography migration plan');
  lines.push('');
  lines.push(`Generated ${plan.generatedAt.slice(0, 10)}.`);
  lines.push('');
  lines.push(`**${plan.summary.total}** pre-quantum primitive sites across **${plan.summary.filesAffected}** files.  `);
  lines.push(`HNDL-critical: **${plan.summary.hndlCritical}** | Standard: **${plan.summary.standard}**`);
  lines.push('');
  lines.push('## Recommended PQ primitives');
  for (const p of plan.summary.primitivesNeeded) lines.push(`- ${p}`);
  lines.push('');
  for (const m of plan.milestones) {
    lines.push(`## ${m.id} — ${m.title} (target ${m.target}, owner ${m.owner})`);
    if (Array.isArray(m.items) && m.items.length) {
      for (const it of m.items.slice(0, 20)) {
        if (typeof it === 'string') lines.push(`- ${it}`);
        else lines.push(`- \`${it.file}:${it.line}\` → ${it.replacement || '(see finding)'}`);
      }
      if (m.items.length > 20) lines.push(`- … ${m.items.length - 20} more`);
    }
    lines.push('');
  }
  lines.push('## References');
  lines.push('- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)');
  lines.push('- NIST IR 8547 — Transition to Post-Quantum Cryptographic Standards');
  lines.push('- CNSA 2.0 — Commercial National Security Algorithm Suite, Sept 2022');
  lines.push('- RFC 9794 — X25519MLKEM768 hybrid key exchange for TLS 1.3');
  lines.push('- Open Quantum Safe project (liboqs, oqs-provider for OpenSSL 3)');
  return lines.join('\n');
}

export const _internals = { _byHndl, _byUseCase, _byFile, _markdown };
