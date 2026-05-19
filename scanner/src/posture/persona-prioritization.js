// FR-ADV-2 + FR-LOGIC-10 — Per-persona prioritization.
//
// Replace CVSS-style flat severity with a per-attacker-persona severity
// matrix. The same finding can be `critical` for a script kiddie (drive-by
// exploit) and `low` for an APT (they already have credentialed shell).
// Five personas, each with a weighting profile over existing finding fields.
//
// Inputs (read from each finding when present):
//   - severity, family / vuln
//   - reachable (true/false), routeRooted (true/false)
//   - exposedInProd / mitigatedInProd / unreachableInProd (FR-PROD-7)
//   - guards (auth/RBAC), kev, epssPercentile
//   - crownJewelScore, featureFlagState
//   - parser, validator_verdict
//
// Output: f.personaScores = { [persona]: { score, tier, factors[] } }
//         f.personaTopTwo = ['opportunistic', 'apt'] for UI compactness.

const PERSONAS = [
  'script-kiddie',
  'opportunistic-criminal',
  'apt-nation-state',
  'supply-chain-attacker',
  'malicious-insider',
];

const FAMILY_PERSONA_BIAS = {
  'sql-injection':           { 'script-kiddie': +0.20, 'opportunistic-criminal': +0.25 },
  'command-injection':       { 'script-kiddie': +0.25, 'opportunistic-criminal': +0.30, 'apt-nation-state': +0.20 },
  'xss':                     { 'script-kiddie': +0.15, 'opportunistic-criminal': +0.20 },
  'ssrf':                    { 'opportunistic-criminal': +0.20, 'apt-nation-state': +0.30 },
  'path-traversal':          { 'script-kiddie': +0.20, 'opportunistic-criminal': +0.20 },
  'idor':                    { 'opportunistic-criminal': +0.25, 'malicious-insider': +0.30 },
  'missing-authz':           { 'opportunistic-criminal': +0.20, 'malicious-insider': +0.35 },
  'broken-auth':             { 'script-kiddie': +0.15, 'opportunistic-criminal': +0.30 },
  'hardcoded-secret':        { 'opportunistic-criminal': +0.25, 'malicious-insider': +0.20, 'supply-chain-attacker': +0.20 },
  'webhook-no-signature':    { 'opportunistic-criminal': +0.20, 'apt-nation-state': +0.10 },
  'unsafe-deserialization':  { 'apt-nation-state': +0.35, 'supply-chain-attacker': +0.30 },
  'prototype-pollution':     { 'apt-nation-state': +0.30, 'supply-chain-attacker': +0.20 },
  'jndi':                    { 'apt-nation-state': +0.35, 'opportunistic-criminal': +0.20 },
  'mass-assignment':         { 'opportunistic-criminal': +0.20, 'malicious-insider': +0.25 },
  'csrf':                    { 'script-kiddie': +0.10, 'opportunistic-criminal': +0.15 },
  'open-redirect':           { 'script-kiddie': +0.15, 'opportunistic-criminal': +0.15 },
  'prompt-injection':        { 'script-kiddie': +0.25, 'apt-nation-state': +0.20 },
  'llm-output-trusted':      { 'apt-nation-state': +0.30, 'malicious-insider': +0.20 },
  'unbounded-llm':           { 'opportunistic-criminal': +0.20 },
  'sca-cve':                 { 'opportunistic-criminal': +0.25, 'apt-nation-state': +0.20 },
  'install-script':          { 'supply-chain-attacker': +0.50 },
  'typosquat':               { 'supply-chain-attacker': +0.40 },
  'mass-merge':              { 'supply-chain-attacker': +0.30 },
};

const SEVERITY_BASE = { critical: 0.85, high: 0.65, medium: 0.40, low: 0.20, info: 0.10 };

function familyKey(f) {
  if (f.family) return String(f.family).toLowerCase().replace(/[\s_]+/g, '-');
  const v = (f.vuln || f.title || '').toLowerCase();
  if (/sql.*injection/.test(v)) return 'sql-injection';
  if (/command.*injection|os.command|shell.exec/.test(v)) return 'command-injection';
  if (/cross.site script|xss/.test(v)) return 'xss';
  if (/ssrf|server.side request/.test(v)) return 'ssrf';
  if (/path traversal|zip.slip|directory traversal/.test(v)) return 'path-traversal';
  if (/idor|insecure direct object/.test(v)) return 'idor';
  if (/missing auth|broken access/.test(v)) return 'missing-authz';
  if (/broken auth|jwt|session/.test(v)) return 'broken-auth';
  if (/hardcoded|secret in source|api key/.test(v)) return 'hardcoded-secret';
  if (/webhook.*sign|signature/.test(v)) return 'webhook-no-signature';
  if (/deserial/.test(v)) return 'unsafe-deserialization';
  if (/prototype pollution/.test(v)) return 'prototype-pollution';
  if (/jndi|log4shell/.test(v)) return 'jndi';
  if (/mass assignment/.test(v)) return 'mass-assignment';
  if (/csrf/.test(v)) return 'csrf';
  if (/open redirect/.test(v)) return 'open-redirect';
  if (/prompt injection/.test(v)) return 'prompt-injection';
  if (/llm output/.test(v)) return 'llm-output-trusted';
  if (/max_tokens|unbounded/.test(v)) return 'unbounded-llm';
  if (/install.script|postinstall/.test(v)) return 'install-script';
  if (/typosquat/.test(v)) return 'typosquat';
  if (/cve-|kev/.test(v)) return 'sca-cve';
  return null;
}

function scoreOne(f, persona) {
  const factors = [];
  let s = SEVERITY_BASE[f.severity] ?? 0.30;
  factors.push(`sev:${f.severity || 'unknown'}`);

  const fam = familyKey(f);
  const bias = fam && FAMILY_PERSONA_BIAS[fam] ? (FAMILY_PERSONA_BIAS[fam][persona] || 0) : 0;
  if (bias) { s += bias; factors.push(`bias:${fam}+${bias.toFixed(2)}`); }

  // Persona-specific modifiers.
  if (persona === 'script-kiddie') {
    if (f.exposedInProd) { s += 0.15; factors.push('exposed-in-prod'); }
    if (f.mitigatedInProd) { s -= 0.30; factors.push('mitigated-in-prod'); }
    if (f.guards && f.guards.length) { s -= 0.20; factors.push(`auth-gated:${f.guards.length}`); }
    if (f.kev) { s += 0.20; factors.push('kev'); }
  } else if (persona === 'opportunistic-criminal') {
    if (f.exposedInProd) { s += 0.10; factors.push('exposed-in-prod'); }
    if (f.mitigatedInProd) { s -= 0.15; factors.push('mitigated-in-prod'); }
    if (f.crownJewelScore >= 0.4) { s += 0.20; factors.push('crown-jewel-adj'); }
    if (typeof f.epssPercentile === 'number' && f.epssPercentile >= 0.95) { s += 0.15; factors.push('epss>=p95'); }
  } else if (persona === 'apt-nation-state') {
    // APTs care less about easy exploits and more about high-value targets +
    // persistence; reachability/auth gating matters much less to them.
    if (f.crownJewelScore >= 0.5) { s += 0.25; factors.push('crown-jewel-target'); }
    if (fam === 'unsafe-deserialization' || fam === 'jndi' || fam === 'prompt-injection') { s += 0.10; factors.push('apt-favored-family'); }
    if (f.guards && f.guards.length) { s -= 0.05; factors.push('minor-auth-cost'); }   // they have creds
  } else if (persona === 'supply-chain-attacker') {
    if (f.parser === 'SCA' || /sca|cve|kev/i.test(fam || '')) { s += 0.20; factors.push('sca-finding'); }
    if (fam === 'install-script' || fam === 'typosquat') { s += 0.30; factors.push('classic-supply-chain'); }
    if (f.provenance === 'ai-likely') { s += 0.10; factors.push('ai-generated'); }
  } else if (persona === 'malicious-insider') {
    if (f.exposedInProd || f.guards?.length) { s -= 0.10; factors.push('insider-bypasses-edge'); }
    if (fam === 'missing-authz' || fam === 'idor' || fam === 'mass-assignment') { s += 0.20; factors.push('authz-bypass-favored'); }
    if (f.crownJewelScore >= 0.5) { s += 0.15; factors.push('insider-target'); }
  }

  // Universal feature-flag dampener.
  if (f.featureFlagState === 'gated-off') { s = Math.min(s, 0.15); factors.push('flag-gated-off'); }
  else if (f.featureFlagState === 'partial-rollout') { s -= 0.10; factors.push('partial-rollout'); }

  s = Math.max(0, Math.min(1, s));
  return { score: Number(s.toFixed(2)), factors };
}

function tierOf(s) {
  if (s >= 0.80) return 'critical';
  if (s >= 0.60) return 'high';
  if (s >= 0.35) return 'medium';
  if (s >= 0.15) return 'low';
  return 'info';
}

export function annotatePersonaScores(findings) {
  if (!Array.isArray(findings)) return findings;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const scores = {};
    for (const p of PERSONAS) {
      const { score, factors } = scoreOne(f, p);
      scores[p] = { score, tier: tierOf(score), factors };
    }
    f.personaScores = scores;
    const ranked = Object.entries(scores).sort((a, b) => b[1].score - a[1].score);
    f.personaTopTwo = ranked.slice(0, 2).map(([p]) => p);
    f.personaMaxScore = ranked[0][1].score;
    f.personaMaxName = ranked[0][0];
  }
  return findings;
}

export { PERSONAS };
