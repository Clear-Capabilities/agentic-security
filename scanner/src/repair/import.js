// External finding intake (verified-remediation PRD FR-13, M4-01): SARIF 2.1.0 and a documented normalized JSON format.
//
// A report is UNTRUSTED INPUT. Nothing in it is code, policy or an instruction:
//   - every location is confined to the project: a relative path, or a file: URI under the source root; an absolute path elsewhere,
//     a `..` escape, another scheme (http:, data:), a path through a link out of the project or a reserved path is REJECTED with
//     its reason, never followed;
//   - message text is kept as capped, control-character-free data (`untrustedText`), never rendered, never read by policy, never sent
//     to a model by this module;
//   - only a closed set of fields is read; a report cannot set a family, an approval, a policy or an execution flag.
//
// Mapping to the current source (AC-13.4). Each location is checked against the files as they are now: the line exists; the reported
// snippet (when given) is at that line, or found exactly once nearby (`relocated`), or found more than once (`ambiguous`); a report
// for another revision maps only when git shows the file unchanged since that revision (`exact`) or renamed (`renamed`, followed);
// a revision this repository does not have is `revision-unknown`. Only `exact`, `relocated` and `renamed` findings can be planned.
//
// Deduplication keeps provenance: findings merge only when they are at the same file and line, with the same CWE, and the same
// snippet (or none); every source (tool, rule id, report) is kept on the merged finding. Two rules that merely share a CWE at
// different lines are never merged.
//
// Custody (AC-13.2). The import record is written under the project state directory and signed with the per-install key: it shows
// what was imported and how it mapped, not that a finding is real. An imported finding's custody is `imported`, or
// `locally-corroborated` when the signed internal scan reports the same family within two lines. Applying a repair of an imported
// finding still needs the signed internal scan and everything else `applyVerifiedFix` requires; nothing here creates scan state.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { digestOf } from '../posture/assurance/identity.js';
import { statePath, ensureStateDir, stateDir } from '../posture/state-dir.js';
import { signLastScan, verifyLastScan } from '../posture/integrity.js';
import { normalizeFinding } from './schemas.js';
import { familyForFinding } from './intake.js';

export const IMPORT_SCHEMA = 'agentic-security/finding-import';
export const NORMALIZED_SCHEMA = 'agentic-security/external-findings';
export const MAPPINGS = Object.freeze(['exact', 'relocated', 'renamed', 'stale', 'ambiguous', 'missing', 'revision-mismatch', 'revision-unknown', 'rejected']);
const PLANNABLE = new Set(['exact', 'relocated', 'renamed']);
export const IMPORT_DISPOSITIONS = Object.freeze(['open', 'unsupported', 'accepted-risk']);
const LIMITS = Object.freeze({ reportBytes: 8 << 20, results: 5000, text: 500, snippet: 400, ruleId: 200, file: 400 });
const RESERVED = /^(?:\.git|\.agentic-security|node_modules)(?:\/|$)/;

const clean = (s, max) => (typeof s === 'string' ? s.replace(/[\u0000-\u0008\u000b-\u001f\u007f‪-‮⁦-⁩]/g, ' ').slice(0, max) : null);
const cweOf = (v) => { const m = /(?:CWE[-_: ]?)(\d{1,5})/i.exec(String(v || '')); return m ? `CWE-${Number(m[1])}` : null; };

/** A report location as a project-relative path, or {rejected: reason}. Pure apart from the link check. */
export function confineLocation(root, uri, { srcRootUri = null } = {}) {
  if (typeof uri !== 'string' || !uri.length || uri.length > LIMITS.file) return { rejected: 'no usable location' };
  let rel = uri;
  if (/^[a-z][a-z0-9+.-]*:/i.test(uri)) {
    if (!/^file:/i.test(uri)) return { rejected: `the ${uri.split(':')[0]} scheme is not a project file` };
    let p;
    try { p = decodeURIComponent(new URL(uri).pathname); } catch { return { rejected: 'a malformed file URI' }; }
    const base = srcRootUri && /^file:/i.test(srcRootUri) ? decodeURIComponent(new URL(srcRootUri).pathname) : null;
    const rootReal = fs.realpathSync(root);
    if (base && p.startsWith(base)) rel = p.slice(base.length);
    else if (p.startsWith(rootReal + '/') || p.startsWith(path.resolve(root) + '/')) rel = path.relative(p.startsWith(rootReal) ? rootReal : path.resolve(root), p);
    else return { rejected: 'a file URI outside the project' };
  } else {
    try { rel = decodeURIComponent(uri); } catch { return { rejected: 'a malformed path' }; }
  }
  rel = rel.replace(/\\/g, '/').replace(/^\.\//, '');
  if (rel.startsWith('/')) return { rejected: 'an absolute path outside the project' };
  if (rel.includes('\0')) return { rejected: 'a path with a NUL byte' };
  const norm = path.posix.normalize(rel);
  if (norm.startsWith('..') || norm === '.') return { rejected: 'a path that leaves the project' };
  if (RESERVED.test(norm)) return { rejected: 'a reserved path (version control, verifier state, dependencies)' };
  try {
    const rootReal = fs.realpathSync(root);
    const real = fs.realpathSync(path.join(rootReal, norm));
    if (!real.startsWith(rootReal + path.sep)) return { rejected: 'a path through a link that leaves the project' };
  } catch { /* a missing file is a mapping outcome, not a confinement failure */ }
  return { file: norm };
}

// ---------------------------------------------------------------- parsers (closed field sets)

function fromSarif(doc) {
  if (!doc || doc.version !== '2.1.0' || !Array.isArray(doc.runs)) return { problems: ['not a SARIF 2.1.0 log (version 2.1.0 with runs[])'] };
  const out = []; const problems = [];
  for (const [ri, run] of doc.runs.entries()) {
    const driver = run?.tool?.driver || {};
    const tool = { name: clean(driver.name, 120) || 'unknown', version: clean(driver.semanticVersion || driver.version, 60) };
    const rules = Object.fromEntries((driver.rules || []).filter((r) => r && typeof r.id === 'string').map((r) => [r.id, r]));
    const srcRoot = run?.originalUriBaseIds?.SRCROOT?.uri || run?.originalUriBaseIds?.['%SRCROOT%']?.uri || null;
    const vcp = Array.isArray(run?.versionControlProvenance) ? run.versionControlProvenance[0] : null;
    const revision = typeof vcp?.revisionId === 'string' && /^[0-9a-f]{7,64}$/i.test(vcp.revisionId) ? vcp.revisionId.toLowerCase() : null;
    const hashes = {};
    for (const a of run?.artifacts || []) { const u = a?.location?.uri; const h = a?.hashes?.['sha-256']; if (typeof u === 'string' && typeof h === 'string' && /^[0-9a-f]{64}$/i.test(h)) hashes[u] = h.toLowerCase(); }
    for (const [i, r] of (run.results || []).entries()) {
      const ruleId = clean(r?.ruleId || r?.rule?.id, LIMITS.ruleId);
      const rule = rules[ruleId] || {};
      const loc = r?.locations?.[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri;
      const region = loc?.region || {};
      const tags = [...(rule.properties?.tags || []), ...(r?.properties?.tags || [])].filter((t) => typeof t === 'string');
      const cwe = cweOf(r?.properties?.cwe) || cweOf(rule.properties?.cwe) || cweOf(tags.find((t) => /cwe/i.test(t))) || cweOf(rule.relationships?.find?.((x) => /cwe/i.test(x?.target?.toolComponent?.name || ''))?.target?.id);
      out.push({
        index: `${ri}:${i}`, tool, ruleId, cwe, revision, srcRootUri: srcRoot,
        level: ['error', 'warning', 'note', 'none'].includes(r?.level) ? r.level : null,
        uri: typeof uri === 'string' ? uri : null, uriBaseId: loc?.artifactLocation?.uriBaseId || null,
        startLine: Number.isInteger(region.startLine) && region.startLine > 0 ? region.startLine : null,
        startColumn: Number.isInteger(region.startColumn) && region.startColumn > 0 ? region.startColumn : null,
        snippet: clean(region.snippet?.text, LIMITS.snippet),
        artifactSha256: typeof uri === 'string' ? hashes[uri] || null : null,
        fingerprint: clean(Object.values(r?.partialFingerprints || r?.fingerprints || {})[0], 120),
        untrustedText: clean(r?.message?.text || r?.message?.markdown, LIMITS.text),
      });
    }
  }
  if (!out.length && !problems.length) problems.push('the log has no results');
  return { results: out, problems };
}

function fromNormalized(doc) {
  if (!doc || doc.schema !== NORMALIZED_SCHEMA || !/^1\.\d+\.\d+$/.test(String(doc.schemaVersion)) || !Array.isArray(doc.findings)) return { problems: [`not a ${NORMALIZED_SCHEMA} 1.x document with findings[]`] };
  const tool = { name: clean(doc.tool?.name, 120) || 'unknown', version: clean(doc.tool?.version, 60) };
  const revision = typeof doc.revision === 'string' && /^[0-9a-f]{7,64}$/i.test(doc.revision) ? doc.revision.toLowerCase() : null;
  const results = doc.findings.map((f, i) => ({
    index: `0:${i}`, tool, ruleId: clean(f?.ruleId, LIMITS.ruleId), cwe: cweOf(f?.cwe), revision, srcRootUri: null,
    level: ['critical', 'high', 'medium', 'low', 'info'].includes(f?.severity) ? f.severity : null,
    uri: typeof f?.file === 'string' ? f.file : null, uriBaseId: null,
    startLine: Number.isInteger(f?.startLine) && f.startLine > 0 ? f.startLine : null,
    startColumn: Number.isInteger(f?.startColumn) && f.startColumn > 0 ? f.startColumn : null,
    snippet: clean(f?.snippet, LIMITS.snippet), artifactSha256: typeof f?.sha256 === 'string' && /^[0-9a-f]{64}$/i.test(f.sha256) ? f.sha256.toLowerCase() : null,
    fingerprint: clean(f?.fingerprint, 120), untrustedText: clean(f?.message, LIMITS.text),
  }));
  return { results, problems: [] };
}

// ---------------------------------------------------------------- mapping to the current source

const git = (root, args) => { const r = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', timeout: 15000, maxBuffer: 8 << 20 }); return r.status === 0 ? r.stdout : null; };

function mapLocation(root, r, ctx) {
  const c = confineLocation(root, r.uri, { srcRootUri: r.srcRootUri });
  if (c.rejected) return { mapping: 'rejected', reason: c.rejected, file: null };
  let file = c.file; let note = null;
  if (r.revision && ctx.head && !ctx.head.startsWith(r.revision) && !r.revision.startsWith(ctx.head)) {
    if (git(root, ['cat-file', '-e', `${r.revision}^{commit}`]) === null) return { mapping: 'revision-unknown', reason: `this repository has no commit ${r.revision.slice(0, 12)}`, file };
    const renamed = ctx.renames(r.revision)[file];
    if (renamed) { note = `renamed from ${file}`; file = renamed; }
    const changed = git(root, ['diff', '--name-only', r.revision, 'HEAD', '--', file]);
    if (changed === null) return { mapping: 'revision-mismatch', reason: 'git could not compare the reported revision with HEAD', file };
    if (changed.trim() && !r.snippet) return { mapping: 'revision-mismatch', reason: `${file} changed since the reported revision and the report gives no snippet to relocate it`, file };
    if (!changed.trim() && !note) note = 'reported for another revision; the file is unchanged since';
  }
  let text;
  try { text = fs.readFileSync(path.join(root, file), 'utf8'); } catch { return { mapping: 'missing', reason: `${file} does not exist in the current source`, file }; }
  if (r.artifactSha256 && crypto.createHash('sha256').update(text).digest('hex') !== r.artifactSha256 && !r.snippet) return { mapping: 'stale', reason: 'the file changed since the report and no snippet locates the finding', file };
  const lines = text.split('\n');
  if (!r.startLine) return { mapping: 'ambiguous', reason: 'the report gives no line', file };
  if (r.startLine > lines.length) return r.snippet ? relocate(lines, r, file, note) : { mapping: 'stale', reason: 'the reported line is past the end of the file', file };
  if (!r.snippet) return { mapping: note?.startsWith('renamed') ? 'renamed' : 'exact', line: r.startLine, file, ...(note ? { note } : {}) };
  const want = r.snippet.trim().split('\n')[0].trim();
  if (want && lines[r.startLine - 1].includes(want)) return { mapping: note?.startsWith('renamed') ? 'renamed' : 'exact', line: r.startLine, file, ...(note ? { note } : {}) };
  return relocate(lines, r, file, note);
}

function relocate(lines, r, file, note) {
  const want = r.snippet.trim().split('\n')[0].trim();
  if (!want) return { mapping: 'ambiguous', reason: 'the snippet is empty', file };
  const hits = []; lines.forEach((l, i) => { if (l.includes(want)) hits.push(i + 1); });
  if (hits.length === 1) return { mapping: note?.startsWith('renamed') ? 'renamed' : 'relocated', line: hits[0], file, note: [note, `moved from line ${r.startLine} to ${hits[0]}`].filter(Boolean).join('; ') };
  if (!hits.length) return { mapping: 'stale', reason: 'the reported snippet is no longer in the file', file };
  return { mapping: 'ambiguous', reason: `the reported snippet occurs ${hits.length} times`, file };
}

// ---------------------------------------------------------------- import

function corroborated(root, f) {
  try {
    const body = fs.readFileSync(path.join(stateDir(root), 'last-scan.json'), 'utf8');
    if (verifyLastScan(body, path.join(stateDir(root), 'last-scan.json.sig')) !== true) return null;
    const scan = JSON.parse(body);
    const fam = familyForFinding(f);
    if (!fam) return null;
    const m = (scan.findings || []).find((x) => x.file === f.file && Number.isInteger(x.line) && Math.abs(x.line - f.line) <= 2 && familyForFinding(x) === fam);
    return m ? { stableId: m.stableId || m.id, line: m.line } : null;
  } catch { return null; }
}

/**
 * Parse, confine, map, deduplicate and record a report. Never throws.
 * @param {{root:string, format:'sarif'|'normalized', text:string, reportName?:string}} o
 */
export function importReport(o) {
  if (typeof o.text !== 'string' || Buffer.byteLength(o.text) > LIMITS.reportBytes) return { ok: false, problems: [`the report must be text of at most ${LIMITS.reportBytes} bytes`] };
  let doc;
  try { doc = JSON.parse(o.text); } catch { return { ok: false, problems: ['the report is not JSON'] }; }
  const parsed = o.format === 'sarif' ? fromSarif(doc) : o.format === 'normalized' ? fromNormalized(doc) : { problems: ["format must be 'sarif' or 'normalized'"] };
  if (parsed.problems.length && !parsed.results?.length) return { ok: false, problems: parsed.problems };
  if (parsed.results.length > LIMITS.results) return { ok: false, problems: [`the report holds more than ${LIMITS.results} results`] };
  const head = (git(o.root, ['rev-parse', 'HEAD']) || '').trim() || null;
  const renameCache = {};
  const ctx = {
    head,
    renames: (rev) => (renameCache[rev] ??= Object.fromEntries((git(o.root, ['diff', '-M', '--name-status', rev, 'HEAD']) || '').split('\n').filter((l) => /^R\d*\t/.test(l)).map((l) => { const [, from, to] = l.split('\t'); return [from, to]; }))),
  };
  const byKey = new Map(); const rejected = [];
  for (const r of parsed.results) {
    const m = mapLocation(o.root, r, ctx);
    const source = { tool: r.tool, ruleId: r.ruleId, level: r.level, report: clean(o.reportName, 200), index: r.index, fingerprint: r.fingerprint, untrustedText: r.untrustedText, revision: r.revision, reportedLine: r.startLine, reportedFile: clean(r.uri, LIMITS.file) };
    if (m.mapping === 'rejected') { rejected.push({ ...source, reason: m.reason }); continue; }
    const snippetDigest = r.snippet ? digestOf(r.snippet.trim()) : null;
    const key = digestOf({ file: m.file, line: m.line ?? r.startLine, cwe: r.cwe, snippetDigest, rule: r.cwe ? null : `${r.tool.name}:${r.ruleId}` });
    const prev = byKey.get(key);
    if (prev) { prev.sources.push(source); continue; }
    const base = { file: m.file, line: m.line ?? r.startLine ?? null, column: r.startColumn, cwe: r.cwe, ruleId: r.ruleId };
    const family = familyForFinding(base);
    byKey.set(key, {
      importedId: `imp-${key.slice(7, 23)}`, file: m.file, line: base.line, column: r.startColumn, cwe: r.cwe, family,
      mapping: m.mapping, mappingReason: m.reason || m.note || null, plannable: PLANNABLE.has(m.mapping) && !!family,
      disposition: family ? 'open' : 'unsupported', snippetDigest, artifactSha256: r.artifactSha256, sources: [source],
    });
  }
  const findings = [...byKey.values()];
  for (const f of findings) { const c = PLANNABLE.has(f.mapping) ? corroborated(o.root, f) : null; f.custody = c ? 'locally-corroborated' : 'imported'; if (c) f.corroboratedBy = c; }
  const record = {
    schema: IMPORT_SCHEMA, schemaVersion: '1.0.0', format: o.format, reportDigest: digestOf(o.text), head,
    counts: { results: parsed.results.length, findings: findings.length, merged: parsed.results.length - rejected.length - findings.length, rejected: rejected.length, plannable: findings.filter((f) => f.plannable).length, byMapping: Object.fromEntries(MAPPINGS.map((k) => [k, k === 'rejected' ? rejected.length : findings.filter((f) => f.mapping === k).length])) },
    findings, rejected, decisions: [],
  };
  record.importId = `imp-${digestOf({ reportDigest: record.reportDigest, head }).slice(7, 23)}`;
  return { ok: true, record, problems: parsed.problems };
}

// ---------------------------------------------------------------- the signed import store

const importFile = (root, id) => statePath(root, 'imports', `${id}.json`);
const isImportId = (s) => typeof s === 'string' && /^imp-[0-9a-f]{16}$/.test(s);

export function saveImport(root, record) {
  ensureStateDir(root);
  const f = importFile(root, record.importId);
  fs.mkdirSync(path.dirname(f), { recursive: true });
  const text = `${JSON.stringify(record, null, 2)}\n`;
  fs.writeFileSync(`${f}.tmp`, text);
  fs.renameSync(`${f}.tmp`, f);
  fs.writeFileSync(`${f}.sig`, signLastScan(text));
  return f;
}

/** A stored import, verified against the per-install signature. A hand-edited or foreign record is refused. */
export function loadImport(root, id) {
  if (!isImportId(id)) return { record: null, reason: 'not an import id' };
  const f = importFile(root, id);
  let text;
  try { text = fs.readFileSync(f, 'utf8'); } catch { return { record: null, reason: `no import ${id}` }; }
  if (verifyLastScan(text, `${f}.sig`) !== true) return { record: null, reason: 'the import record signature does not verify under this installation\'s key' };
  try { return { record: JSON.parse(text) }; } catch { return { record: null, reason: 'the import record is not JSON' }; }
}

/** Record an operator decision on an imported finding (accepted risk), with a reason, in the signed record. */
export function decide(root, id, importedId, { disposition, reason, actor }) {
  const l = loadImport(root, id);
  if (!l.record) return { ok: false, reason: l.reason };
  if (!IMPORT_DISPOSITIONS.includes(disposition) || disposition === 'unsupported') return { ok: false, reason: `disposition must be one of open, accepted-risk` };
  if (!reason || !String(reason).trim()) return { ok: false, reason: 'a reason is required' };
  const f = l.record.findings.find((x) => x.importedId === importedId);
  if (!f) return { ok: false, reason: `no imported finding ${importedId}` };
  f.disposition = disposition;
  l.record.decisions.push({ importedId, disposition, reason: String(reason).slice(0, 500), actor: String(actor || 'operator').slice(0, 80) });
  saveImport(root, l.record);
  return { ok: true };
}

/**
 * The finding the repair workflow plans from, for one imported finding. Refuses one that cannot be planned: rejected, unmapped,
 * ambiguous, for another revision, without a supported family, or accepted as a risk.
 */
export function importedFinding(root, id, importedId) {
  const l = loadImport(root, id);
  if (!l.record) return { finding: null, reason: l.reason };
  const f = l.record.findings.find((x) => x.importedId === importedId);
  if (!f) return { finding: null, reason: `no imported finding ${importedId} in ${id}` };
  if (f.disposition === 'accepted-risk') return { finding: null, reason: `${importedId} is an accepted risk; record it as open to repair it` };
  if (!f.family) return { finding: null, reason: `${importedId} has no supported repair family (CWE ${f.cwe || 'unknown'})` };
  if (!PLANNABLE.has(f.mapping)) return { finding: null, reason: `${importedId} does not map to the current source: ${f.mapping} (${f.mappingReason || 'no reason'})` };
  const head = (git(root, ['rev-parse', 'HEAD']) || '').trim() || null;
  if (l.record.head && head && l.record.head !== head) return { finding: null, reason: 'HEAD moved since the import; import the report again' };
  const src = f.sources[0];
  const n = normalizeFinding({ id: importedId, file: f.file, line: f.line, column: f.column, cwe: f.cwe, family: f.family, ruleId: src.ruleId }, { custody: f.custody, sourceTool: src.tool.name, sourceToolVersion: src.tool.version, commit: head && /^[0-9a-f]{40}$/.test(head) ? head : null });
  return { finding: { ...n, findingId: importedId, id: importedId, file: f.file, importId: id, sources: f.sources.map((s) => ({ tool: s.tool, ruleId: s.ruleId, report: s.report })) }, family: f.family, commit: n.repository.commit };
}
