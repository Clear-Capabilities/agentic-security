// Claude-authorship analysis — closes the prompt-engineering loop.
//
// Builds on posture/git-history.js (which already tags individual findings
// with aiAuthored=true via the "Co-Authored-By: Claude" trailer detection).
//
// What this module adds:
//
//   1. analyzeAuthorshipPatterns(scanRoot, findings)
//      Aggregates findings by (family, aiAuthored, file-pattern). Returns
//      patterns like:
//        "12 of 47 Claude-authored commits introduced auth-missing findings"
//        "Claude-authored commits 3.2× more likely to ship SQLi than human-authored"
//
//   2. suggestClaudeMdEvolution(scanRoot, findings)
//      For each clustered Claude pattern, drafts a one-paragraph addition
//      to CLAUDE.md that would have prevented it. The user reviews + accepts.
//
//   3. extractOriginatingPromptCluster(findings)
//      When findings carry `originatingPrompt` (set by git-history.js), clusters
//      similar prompts to surface "the same kind of ask repeatedly produces
//      vulnerable code."
//
// Pure analysis — no LLM calls in this module. The result is structured
// data that a /claude-vuln-audit command formats for the user.

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function _normalizePrompt(p) {
  return String(p || '')
    .toLowerCase()
    .replace(/['"`]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function _promptKeyTerms(p) {
  // Heuristic clustering — extract content nouns / verbs typical of
  // request shapes. v1 = stop-word removal + token bag.
  const STOP = new Set(['a','an','the','and','or','but','to','for','of','in','on','at','by','from','with','as','is','are','be','was','were','this','that','it','i','you','we','please','can','could','would','should','add','make','create','write','build','give','need','want','have']);
  return _normalizePrompt(p).split(/[^a-z0-9]+/).filter(t => t.length > 2 && !STOP.has(t));
}

function _jaccard(a, b) {
  const sa = new Set(a), sb = new Set(b);
  let inter = 0;
  for (const x of sa) if (sb.has(x)) inter++;
  const union = sa.size + sb.size - inter;
  return union === 0 ? 0 : inter / union;
}

/**
 * Aggregate findings into pattern statistics.
 */
export function analyzeAuthorshipPatterns(findings) {
  if (!Array.isArray(findings)) return null;
  const ai = findings.filter(f => f.aiAuthored);
  const hu = findings.filter(f => f.introducedBy && !f.aiAuthored);
  const total = ai.length + hu.length;
  if (total === 0) return { total: 0, ai: 0, human: 0, patterns: [] };

  // Per-family breakdown.
  const byFamily = new Map();
  for (const f of ai) {
    const k = f.family || 'unknown';
    if (!byFamily.has(k)) byFamily.set(k, { ai: 0, human: 0, severity: 0, files: new Set() });
    const ent = byFamily.get(k);
    ent.ai++;
    ent.severity = Math.max(ent.severity, SEVERITY_RANK[f.severity] || 0);
    if (f.file) ent.files.add(f.file);
  }
  for (const f of hu) {
    const k = f.family || 'unknown';
    if (!byFamily.has(k)) byFamily.set(k, { ai: 0, human: 0, severity: 0, files: new Set() });
    byFamily.get(k).human++;
  }

  const patterns = [];
  for (const [family, ent] of byFamily) {
    if (ent.ai === 0) continue;
    const familyTotal = ent.ai + ent.human;
    const aiShare = familyTotal > 0 ? ent.ai / familyTotal : 0;
    const expectedAiShare = ai.length / total;
    const lift = expectedAiShare > 0 ? aiShare / expectedAiShare : 0;
    patterns.push({
      family,
      aiCount: ent.ai,
      humanCount: ent.human,
      aiShare: Number(aiShare.toFixed(3)),
      expectedShare: Number(expectedAiShare.toFixed(3)),
      lift: Number(lift.toFixed(2)),
      maxSeverity: Object.keys(SEVERITY_RANK).find(k => SEVERITY_RANK[k] === ent.severity) || 'unknown',
      fileCount: ent.files.size,
    });
  }
  patterns.sort((a, b) => b.lift - a.lift || b.aiCount - a.aiCount);
  return {
    total,
    ai: ai.length,
    human: hu.length,
    aiShare: Number((ai.length / total).toFixed(3)),
    patterns,
  };
}

/**
 * Cluster findings by similar originating prompts. Returns groups of
 * findings whose prompts share at least JACCARD_FLOOR token overlap.
 */
export function extractOriginatingPromptCluster(findings, opts = {}) {
  const floor = opts.jaccardFloor || 0.35;
  const withPrompts = (findings || []).filter(f => f.originatingPrompt);
  if (withPrompts.length === 0) return [];
  const termCache = new Map();
  const term = (f) => {
    if (!termCache.has(f.id || f.stableId)) {
      termCache.set(f.id || f.stableId, _promptKeyTerms(f.originatingPrompt));
    }
    return termCache.get(f.id || f.stableId);
  };

  const used = new Set();
  const clusters = [];
  for (let i = 0; i < withPrompts.length; i++) {
    if (used.has(i)) continue;
    const seed = withPrompts[i];
    const seedTerms = term(seed);
    const group = [seed];
    used.add(i);
    for (let j = i + 1; j < withPrompts.length; j++) {
      if (used.has(j)) continue;
      const sim = _jaccard(seedTerms, term(withPrompts[j]));
      if (sim >= floor) {
        group.push(withPrompts[j]);
        used.add(j);
      }
    }
    if (group.length >= 2) {
      clusters.push({
        size: group.length,
        samplePrompt: seed.originatingPrompt,
        families: Array.from(new Set(group.map(f => f.family).filter(Boolean))),
        findings: group.map(f => ({ id: f.id, file: f.file, line: f.line, family: f.family, severity: f.severity })),
      });
    }
  }
  clusters.sort((a, b) => b.size - a.size);
  return clusters;
}

/**
 * Draft CLAUDE.md additions for the top patterns. Each suggestion is a
 * short stanza the user can paste into CLAUDE.md or AGENTS.md to
 * pre-empt the recurring AI-authored vuln pattern.
 */
export function suggestClaudeMdEvolution(analysis) {
  if (!analysis || !Array.isArray(analysis.patterns)) return [];
  const out = [];
  for (const p of analysis.patterns.slice(0, 5)) {
    if (p.lift < 1.2 || p.aiCount < 2) continue;  // not enough signal
    out.push({
      family: p.family,
      aiCount: p.aiCount,
      lift: p.lift,
      maxSeverity: p.maxSeverity,
      suggestion: _draftSuggestion(p),
    });
  }
  return out;
}

function _draftSuggestion(p) {
  const FAMILY_HINTS = {
    'sqli':              'when asked to add a database query, always use parameterized queries via the existing helper rather than string interpolation. If no helper exists, use the driver\'s prepared-statement API directly (`db.prepare(sql).run(params)`).',
    'sql-injection':     'when asked to add a database query, always use parameterized queries via the existing helper rather than string interpolation. If no helper exists, use the driver\'s prepared-statement API directly (`db.prepare(sql).run(params)`).',
    'xss':               'when asked to render user-supplied content, default to text rendering and escape HTML explicitly. Avoid `dangerouslySetInnerHTML` / `v-html` / `eval` / template-literal HTML construction without sanitization.',
    'command-injection': 'when asked to shell out, use `spawn(cmd, [args], { shell: false })` with explicit argv arrays. Never interpolate user input into a shell string.',
    'auth-missing':      'when asked to add a route or endpoint, surface the route\'s authn/authz requirement explicitly. Default to auth-required unless the route is on the explicit public allowlist.',
    'authz':             'when asked to look up a resource by id, also assert that the caller owns the resource (or has a relevant permission tier). Use the project\'s `assertResourceOwner` / equivalent helper.',
    'csrf':              'when asked to add a state-changing endpoint, ensure CSRF protection is in place. Use the existing middleware or add it as part of the same change.',
    'hardcoded-secret':  'when asked to use an API key or credential, read it from `process.env.X` (or the project\'s secret manager) — never embed the literal in source.',
    'path-traversal':    'when asked to read/write a file based on user input, resolve to absolute path and assert it stays under a trusted root before any fs call.',
    'crypto-weak-cipher':'when asked to encrypt, default to AES-256-GCM or ChaCha20-Poly1305 with crypto.randomBytes IVs. Never DES/3DES/RC4/Blowfish/ECB.',
    'crypto-weak-hash':  'when asked to hash for security purposes (signing, password storage, integrity), use SHA-256+ for hashes and Argon2id/bcrypt/scrypt for passwords. MD5/SHA-1 only for non-security checksums, explicitly tagged.',
  };
  const advice = FAMILY_HINTS[p.family] || `when working in code that could introduce a ${p.family} finding, default to the project's safest established pattern.`;
  return [
    `## Security default — ${p.family}`,
    '',
    `Past Claude-authored work in this repo has introduced ${p.aiCount} ${p.family} finding(s) (${p.lift}× the rate of human-authored work). To pre-empt:`,
    '',
    `> ${advice}`,
    '',
    `Consider this a hard default unless the user explicitly asks for an exception.`,
  ].join('\n');
}

export const _internals = { _normalizePrompt, _promptKeyTerms, _jaccard, _draftSuggestion };
