// Dual suppression schemas (R4).
//   - vibecoder:  .agentic-security/accepted.json  (soft, 30-day, auto-reminder)
//   - pro:        .agentic-security/suppressions.yml (audit-grade: reason +
//                  reviewer + expiry + rule-version pin)
// One function `applySuppressions(findings, scanRoot, profile)` filters in
// place. Loaders accept malformed input gracefully (skip bad entries, log).

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';

const VIBECODER_PATH = '.agentic-security/accepted.json';
const PRO_PATH = '.agentic-security/suppressions.yml';

const MS_PER_DAY = 86400000;
const SOFT_TTL_DAYS = 30;

function _now() { return Date.now(); }
function _dateOnly(iso) {
  // Accept full ISO or YYYY-MM-DD.
  try { return new Date(iso).getTime(); } catch (_) { return NaN; }
}

export function loadSoftAccepted(scanRoot) {
  const fp = path.join(scanRoot || process.cwd(), VIBECODER_PATH);
  if (!fs.existsSync(fp)) return [];
  try {
    const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
    return Array.isArray(raw.accepted) ? raw.accepted : [];
  } catch (_) { return []; }
}

export function saveSoftAccepted(scanRoot, items) {
  const fp = path.join(scanRoot || process.cwd(), VIBECODER_PATH);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, JSON.stringify({ accepted: items }, null, 2));
}

export function addSoftAcceptance(scanRoot, finding, reason) {
  const items = loadSoftAccepted(scanRoot);
  const expires = new Date(_now() + SOFT_TTL_DAYS * MS_PER_DAY).toISOString().slice(0, 10);
  items.push({
    id: finding.id || `${finding.file}:${finding.line}:${finding.vuln}`,
    file: finding.file,
    line: finding.line,
    vuln: finding.vuln,
    reason: reason || 'vibecoded for now',
    accepted_at: new Date().toISOString().slice(0, 10),
    expires_at: expires,
  });
  saveSoftAccepted(scanRoot, items);
  return expires;
}

export function loadProSuppressions(scanRoot) {
  const fp = path.join(scanRoot || process.cwd(), PRO_PATH);
  if (!fs.existsSync(fp)) return [];
  try {
    const parsed = yaml.load(fs.readFileSync(fp, 'utf8'));
    return Array.isArray(parsed) ? parsed : (parsed?.suppressions || []);
  } catch (_) { return []; }
}

// Validate one entry. Returns { ok, errors }.
export function validateProSuppression(entry) {
  const errors = [];
  for (const k of ['finding_id', 'file', 'reason', 'justification_signed_by', 'reviewer', 'expires_at']) {
    if (!entry[k] || (typeof entry[k] === 'string' && !entry[k].trim())) errors.push(`missing: ${k}`);
  }
  if (entry.justification_signed_by && entry.reviewer && entry.justification_signed_by === entry.reviewer) {
    errors.push('justification_signed_by must differ from reviewer (two-person rule)');
  }
  if (entry.expires_at) {
    const t = _dateOnly(entry.expires_at);
    if (!Number.isFinite(t)) errors.push('expires_at must be ISO date');
    else if (t < _now()) errors.push('expires_at is in the past');
  }
  if (entry.severity === 'critical' && !entry._accept_critical) {
    errors.push('cannot suppress critical without --accept-critical flag at suppress time');
  }
  return { ok: errors.length === 0, errors };
}

export function applySuppressions(findings, scanRoot, profile) {
  const isVib = (profile?.profile || 'vibecoder') === 'vibecoder';
  const isPro = (profile?.profile) === 'pro';
  const items = isPro ? loadProSuppressions(scanRoot) : loadSoftAccepted(scanRoot);
  if (!items.length) return findings;

  const now = _now();
  const kept = [];
  const suppressed = [];

  for (const f of findings) {
    const fid = f.id || `${f.file}:${f.line}:${f.vuln}`;
    let matched = null;
    for (const s of items) {
      const matchId = s.id || s.finding_id;
      if (matchId && matchId === fid) { matched = s; break; }
      // Also match by (file, line, vuln) tuple.
      if (s.file === f.file && s.line === f.line && s.vuln === f.vuln) { matched = s; break; }
    }
    if (matched) {
      // Has it expired?
      const exp = _dateOnly(matched.expires_at || matched.expires || '');
      if (Number.isFinite(exp) && exp < now) {
        kept.push({ ...f, _suppressionExpired: true });
        continue;
      }
      // Pro: validate the entry still passes
      if (isPro) {
        const v = validateProSuppression({ ...matched, severity: f.severity });
        if (!v.ok) { kept.push({ ...f, _suppressionInvalid: v.errors }); continue; }
      }
      suppressed.push({ ...f, _suppressed: matched });
      continue;
    }
    kept.push(f);
  }

  if (process.env.DEBUG_SUPPRESSIONS) {
    console.error(`[suppressions] ${suppressed.length} suppressed, ${kept.length} kept`);
  }
  return kept;
}

// Return suppressions that have expired so callers can remind the user.
export function expiredSoftAcceptances(scanRoot) {
  const items = loadSoftAccepted(scanRoot);
  const now = _now();
  return items.filter(s => {
    const exp = _dateOnly(s.expires_at);
    return Number.isFinite(exp) && exp < now;
  });
}
