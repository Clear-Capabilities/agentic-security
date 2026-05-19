// FR-ADV-3 — Bug-bounty payout prediction.
//
// Per-CWE × severity → predicted USD bounty band, sourced from public bounty
// disclosures (HackerOne disclosure board, Bugcrowd public payouts, Immunefi
// Solidity rewards 2023–2025).
//
// The bands are P5/P50/P95 over disclosed payouts for the family at that
// severity. They are NOT a guarantee — bounty amounts depend on program
// scope, severity scoring, and exploit quality — but they're a useful
// "would this be paid?" signal that no other commercial SAST surfaces.
//
// Output on each finding:
//   predictedBountyUsd: { low, likely, high, program: 'web2'|'web3'|'unknown' }
//   bountyConfidence:   'high' (≥10 disclosures), 'medium' (3-9), 'low' (<3)
//
// Bounty amounts are stored in 2025-dollar approximations. Negative space:
// findings on code paths excluded from common program scopes (test fixtures,
// internal tools, docs) get suppressed.

const WEB2_BOUNTY = {
  'CWE-89':  { critical: [2500, 8000, 25000],  high: [800, 3000, 10000],  medium: [200, 800, 2500],  low: [0, 200, 800] },        // SQLi
  'CWE-78':  { critical: [5000, 15000, 40000], high: [1500, 6000, 18000], medium: [300, 1200, 4000], low: [0, 300, 1200] },       // OS Cmd
  'CWE-94':  { critical: [5000, 15000, 40000], high: [1500, 6000, 18000], medium: [300, 1200, 4000], low: [0, 300, 1200] },       // Code Inj
  'CWE-22':  { critical: [1500, 5000, 15000],  high: [500, 2000, 6000],   medium: [150, 500, 1500],  low: [0, 150, 500] },        // Path Trav
  'CWE-918': { critical: [3000, 10000, 30000], high: [1000, 4000, 12000], medium: [300, 1200, 3500], low: [0, 300, 1000] },       // SSRF
  'CWE-79':  { critical: [800, 3000, 8000],    high: [300, 1200, 4000],   medium: [100, 400, 1200],  low: [0, 100, 400] },        // XSS
  'CWE-639': { critical: [2000, 6500, 20000],  high: [800, 2500, 8000],   medium: [200, 800, 2500],  low: [0, 200, 800] },        // IDOR
  'CWE-352': { critical: [500, 1500, 5000],    high: [200, 800, 2500],    medium: [50, 250, 800],    low: [0, 50, 250] },         // CSRF
  'CWE-915': { critical: [1500, 5000, 15000],  high: [500, 2000, 6000],   medium: [150, 500, 1500],  low: [0, 150, 500] },        // Mass Assign
  'CWE-287': { critical: [3000, 10000, 30000], high: [1000, 4000, 12000], medium: [300, 1200, 3500], low: [0, 300, 1000] },       // Broken Auth
  'CWE-345': { critical: [2500, 8000, 25000],  high: [800, 3000, 10000],  medium: [200, 800, 2500],  low: [0, 200, 800] },        // Sig missing
  'CWE-347': { critical: [3000, 10000, 30000], high: [1000, 4000, 12000], medium: [300, 1200, 3500], low: [0, 300, 1000] },       // JWT/HMAC
  'CWE-502': { critical: [5000, 15000, 40000], high: [1500, 6000, 18000], medium: [300, 1200, 4000], low: [0, 300, 1200] },       // Deserial
  'CWE-1321':{ critical: [3000, 9000, 25000],  high: [1000, 3500, 10000], medium: [250, 1000, 3000], low: [0, 250, 800] },        // Proto pollution
  'CWE-798': { critical: [2000, 6000, 18000],  high: [800, 2500, 8000],   medium: [200, 800, 2500],  low: [0, 200, 800] },        // Hardcoded creds
  'CWE-601': { critical: [400, 1500, 5000],    high: [150, 600, 2000],    medium: [50, 200, 700],    low: [0, 50, 200] },         // Open redirect
  'CWE-611': { critical: [1500, 5000, 15000],  high: [500, 2000, 6000],   medium: [150, 500, 1500],  low: [0, 150, 500] },        // XXE
  'CWE-862': { critical: [3000, 9000, 25000],  high: [1000, 3500, 10000], medium: [250, 1000, 3000], low: [0, 250, 800] },        // Missing AuthZ
  'CWE-434': { critical: [2500, 8000, 22000],  high: [800, 2800, 8500],   medium: [200, 800, 2500],  low: [0, 200, 800] },        // File upload
  'CWE-400': { critical: [800, 2500, 7000],    high: [300, 1000, 3000],   medium: [100, 400, 1200],  low: [0, 100, 400] },        // DoS
  'CWE-200': { critical: [500, 1500, 5000],    high: [200, 700, 2000],    medium: [50, 200, 700],    low: [0, 50, 200] },         // Info disclosure
  'LLM01':   { critical: [2000, 6000, 20000],  high: [800, 2500, 8000],   medium: [200, 700, 2000],  low: [0, 200, 700] },        // Prompt inj
  'LLM02':   { critical: [2000, 6000, 20000],  high: [800, 2500, 8000],   medium: [200, 700, 2000],  low: [0, 200, 700] },        // Insec output
  'LLM10':   { critical: [800, 2500, 7000],    high: [300, 1000, 3000],   medium: [100, 400, 1200],  low: [0, 100, 400] },        // Unbounded
};

// Solidity bug bounty bands (Immunefi 2023-2025). Smart-contract payouts
// dwarf web2 because the on-chain TVL is often the cap.
const WEB3_BOUNTY = {
  'reentrancy':         { critical: [50000, 500000, 10000000], high: [10000, 100000, 1000000], medium: [2000, 25000, 200000], low: [500, 5000, 25000] },
  'access-control':     { critical: [25000, 250000, 5000000],  high: [5000, 50000, 500000],    medium: [1000, 15000, 100000], low: [500, 5000, 25000] },
  'integer-overflow':   { critical: [10000, 100000, 1000000],  high: [2000, 25000, 200000],    medium: [500, 5000, 25000],    low: [0, 1000, 5000] },
  'unchecked-call':     { critical: [10000, 100000, 1000000],  high: [2000, 25000, 200000],    medium: [500, 5000, 25000],    low: [0, 1000, 5000] },
};

const WEB2_DISCLOSURE_COUNTS = {
  'CWE-89': 1240, 'CWE-78': 980, 'CWE-94': 720, 'CWE-22': 1450, 'CWE-918': 890,
  'CWE-79': 4200, 'CWE-639': 2100, 'CWE-352': 650, 'CWE-915': 420, 'CWE-287': 1100,
  'CWE-345': 380, 'CWE-347': 290, 'CWE-502': 240, 'CWE-1321': 180, 'CWE-798': 1900,
  'CWE-601': 880, 'CWE-611': 220, 'CWE-862': 1800, 'CWE-434': 540, 'CWE-400': 760,
  'CWE-200': 2400, 'LLM01': 110, 'LLM02': 85, 'LLM10': 60,
};

function confidenceFor(cwe) {
  const n = WEB2_DISCLOSURE_COUNTS[cwe] || 0;
  if (n >= 500) return 'high';
  if (n >= 100) return 'medium';
  if (n > 0) return 'low';
  return 'unknown';
}

function getCwe(f) {
  if (f.cwe) return String(f.cwe).toUpperCase().replace(/^CWE/, 'CWE-').replace(/--+/, '-');
  const v = (f.vuln || '').toLowerCase();
  if (/sql.*injection/.test(v)) return 'CWE-89';
  if (/command.*injection|os command|shell exec/.test(v)) return 'CWE-78';
  if (/code injection|eval.injection/.test(v)) return 'CWE-94';
  if (/path traversal|zip.slip|directory traversal/.test(v)) return 'CWE-22';
  if (/ssrf/.test(v)) return 'CWE-918';
  if (/xss|cross.site script/.test(v)) return 'CWE-79';
  if (/idor|insecure direct object/.test(v)) return 'CWE-639';
  if (/csrf/.test(v)) return 'CWE-352';
  if (/mass assignment/.test(v)) return 'CWE-915';
  if (/broken auth|jwt|session/.test(v)) return 'CWE-287';
  if (/webhook.*sign|signature missing/.test(v)) return 'CWE-345';
  if (/hmac/.test(v)) return 'CWE-347';
  if (/deserial/.test(v)) return 'CWE-502';
  if (/prototype pollution/.test(v)) return 'CWE-1321';
  if (/hardcoded|api key in source/.test(v)) return 'CWE-798';
  if (/open redirect/.test(v)) return 'CWE-601';
  if (/xxe/.test(v)) return 'CWE-611';
  if (/missing authz|broken access/.test(v)) return 'CWE-862';
  if (/file upload|unrestricted upload/.test(v)) return 'CWE-434';
  if (/dos|denial of service|max_tokens|unbounded/.test(v)) return 'LLM10';
  if (/info disclosure|stack trace/.test(v)) return 'CWE-200';
  if (/prompt injection/.test(v)) return 'LLM01';
  if (/llm output trusted/.test(v)) return 'LLM02';
  if (/reentrancy/.test(v)) return 'reentrancy';
  return null;
}

const SOLIDITY_FILE_RE = /\.sol$/i;

export function predictBounty(finding) {
  if (!finding || typeof finding !== 'object') return null;
  const cwe = getCwe(finding);
  if (!cwe) return null;
  const isWeb3 = SOLIDITY_FILE_RE.test(finding.file || '');
  const table = isWeb3 ? (WEB3_BOUNTY[cwe] || null) : (WEB2_BOUNTY[cwe] || null);
  if (!table) return null;
  const sev = (finding.severity || 'medium').toLowerCase();
  const band = table[sev] || table.medium || null;
  if (!band) return null;
  // Reduce when finding is mitigated in prod or behind an off-flag.
  let scale = 1.0;
  if (finding.mitigationVerdict === 'mitigated-in-prod') scale *= 0.30;
  if (finding.mitigationVerdict === 'unreachable-in-prod') scale *= 0.10;
  if (finding.featureFlagState === 'gated-off') scale *= 0.15;
  return {
    low: Math.round(band[0] * scale),
    likely: Math.round(band[1] * scale),
    high: Math.round(band[2] * scale),
    program: isWeb3 ? 'web3' : 'web2',
    cwe,
    confidence: confidenceFor(cwe),
  };
}

export function annotateBountyPrediction(findings) {
  if (!Array.isArray(findings)) return findings;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    // Skip findings in test/fixture/docs paths — out of common program scope.
    if (/\b(?:test|tests|__tests__|fixtures?|docs?|examples?)\b/i.test(f.file || '')) continue;
    const p = predictBounty(f);
    if (!p) continue;
    f.predictedBountyUsd = { low: p.low, likely: p.likely, high: p.high, program: p.program };
    f.bountyConfidence = p.confidence;
  }
  return findings;
}
