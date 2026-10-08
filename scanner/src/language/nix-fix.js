// Verified Nix configuration and supply-chain fixes (NIX-010).
//
// Scoped, AST-aware edits to the ORIGINAL Nix source, validated by the shared remediation lifecycle
// (fix-lifecycle.js): syntax, a rescan in which the finding is gone and nothing medium-or-higher is new,
// preview, backup, undo. Deterministic edits exist only where they are provably the same program minus
// the weakness:
//
//   shell escaping       lib.escapeShellArg around an unquoted interpolation, or removing the quotes that
//                        defeat an escapeShellArg already present
//   option hardening     the winning definition of an SSH / firewall / cache-signature / sandbox option is
//                        set to its safe literal (effective-option precedence is honoured: an edit to a
//                        definition that another module overrides leaves the finding, so it is NOT fixed)
//   transport            http:// -> https:// in a cache URL
//   flake input upgrade  only the input's url in flake.nix; flake.lock is never fabricated
//
// Everything else becomes a reviewable proposal with its completeness tier: `manual` (a human step is
// required: secret migration, a hash that needs a fetch), `blocked` (a precondition is unmet), or
// `source-edit-requires-relock`. Nothing here activates or deploys a configuration, runs nix, or contacts a
// network: this module imports no process spawner.

import { parseNix } from './nix-parser.js';
import { buildNixIR } from './nix-ir.js';
import { analyzeNixScripts } from './nix-script-taint.js';
import { analyzeNixSecrets } from './nix-secrets.js';
import { analyzeNixBuildTrust } from './nix-build-trust.js';
import { analyzeNixosHardening } from './nixos-hardening.js';
import { runFixLifecycle, unifiedDiff, writeWithBackup, undoFix, isRootRelativePath } from './fix-lifecycle.js';
import { resolveNixosConfig } from './nixos-module-resolver.js';
import { parseFlakeLock } from './nix-inventory.js';

export const NIX_FIX_VERSION = 'nix-fix/1';
export const TIERS = Object.freeze({ edit: 'full-source-edit', relock: 'source-edit-requires-relock', guidance: 'guidance-only', blocked: 'blocked' });
export { unifiedDiff, writeWithBackup, undoFix };

const splice = (t, a, b, r) => t.slice(0, a) + r + t.slice(b);
const SIMPLE = /^[A-Za-z_][\w'-]*(?:\.[A-Za-z_][\w'-]*)*$/;

// ── option fixes ─────────────────────────────────────────────────────────────
const OPTION_FIXES = {
  'ssh-root-login': { to: '"no"', kind: 'string', consequences: ['Root can no longer log in over SSH. Make sure a non-root account with an authorized key and sudo access exists BEFORE deploying, or you can lock yourself out.'] },
  'ssh-password-auth': { to: 'false', kind: 'bool', consequences: ['Password logins stop working for every account. Each administrator needs an authorized SSH key first (users.users.<name>.openssh.authorizedKeys).'] },
  'ssh-empty-passwords': { to: 'false', kind: 'bool', consequences: ['Accounts with an empty password can no longer log in over SSH.'] },
  'firewall-disabled': { to: 'true', kind: 'bool', consequences: ['Every port not listed in networking.firewall.allowedTCPPorts/allowedUDPPorts becomes unreachable from the network. Open the ports your services need (and services.openssh.openFirewall for SSH) or you can lose remote access.'] },
  'nix-require-sigs-disabled': { to: 'true', kind: 'bool', consequences: ['Store paths copied or substituted without a trusted signature are rejected. Add the signing keys of your caches to nix.settings.trusted-public-keys first.'] },
  'nix-sandbox-disabled': { to: 'true', kind: 'bool', consequences: ['Builds that relied on host paths or network access will fail until they are made hermetic.'] },
  'nix-accept-flake-config': { to: 'false', kind: 'bool', consequences: ['nixConfig from flakes is no longer applied automatically: settings a flake asked for (extra substituters, keys) must be accepted explicitly.'] },
};
const TRANSPORT_RULES = new Set(['nix-substituter-insecure-transport', 'nix-fetch-insecure-transport']);
const MANUAL = {
  'nix-secret-store': ['Move the value out of the Nix expression: reference a runtime file (a *File option, EnvironmentFile or LoadCredential) fed by sops-nix or agenix, so the secret never becomes part of a store path.', 'Re-encrypt the secret with sops or age and commit only the ciphertext.', 'Rotate the credential: it has already been readable in the store.'],
  'nix-secret-build': ['Do not pass the secret into the derivation: read it at runtime instead.', 'Rotate the credential: derivation attributes are recorded in the .drv.'],
  'nix-secret-decrypt-copy': ['Hand the runtime path (config.sops.secrets.<name>.path) to the service instead of reading its content during evaluation.', 'Rotate the credential: its decrypted content was copied into the store.'],
  'nix-secret-plaintext': ['Replace the literal with a runtime file reference and encrypt the secret with sops or age.', 'Rotate the credential and purge it from history (it is in every clone).'],
  'nix-secret-log': ['Stop printing the value; log a fingerprint or a reference.'],
  'nix-secret-plaintext-file': ['Encrypt the file with sops or age before committing it; the manager option only protects an encrypted file.'],
};
const HASH_MANUAL = new Set(['nix-fetch-missing-hash', 'nix-fetch-fake-hash', 'nix-fetch-floating-rev']);

// The option each hardening rule judges. Used to pick the right evidence record when a finding carries several.
const OPTION_OF = {
  'ssh-root-login': 'services.openssh.settings.PermitRootLogin',
  'ssh-password-auth': 'services.openssh.settings.PasswordAuthentication',
  'ssh-empty-passwords': 'services.openssh.settings.PermitEmptyPasswords',
  'firewall-disabled': 'networking.firewall.enable',
  'nix-require-sigs-disabled': 'nix.settings.require-sigs',
  'nix-sandbox-disabled': 'nix.settings.sandbox',
  'nix-accept-flake-config': 'nix.settings.accept-flake-config',
};
// The literal each rule treats as the weakness: the one a conditional branch must hold to be edited.
const BAD_OF = { 'ssh-root-login': '"yes"', 'ssh-password-auth': 'true', 'ssh-empty-passwords': 'true', 'firewall-disabled': 'false', 'nix-require-sigs-disabled': 'false', 'nix-sandbox-disabled': 'false', 'nix-accept-flake-config': 'true' };
const literalValue = (to) => (to.startsWith('"') ? to.slice(1, -1) : to === 'true');

/** The module a human should put an override line in: the entry configuration. */
const entryOf = (files, opts) => (opts && opts.entry) || (files['configuration.nix'] !== undefined ? 'configuration.nix' : null);

/**
 * The override line to ADD to the entry module when no definition can be edited. A plain assignment conflicts with an
 * equal-priority definition, so the wrapper is chosen from the strongest competing priority: nothing when every
 * definition is weaker than plain, mkForce when plain is the strongest, mkOverride just below anything stronger.
 */
function overrideSuggestion(option, fx, sources, files, opts) {
  const prios = sources.map((s) => s.priority).filter((n) => Number.isFinite(n));
  const strongest = prios.length ? Math.min(...prios) : 100;
  const base = { file: entryOf(files, opts), option, automatic: false };
  if (strongest > 100) return { ...base, line: `${option} = ${fx.to};`, priority: 100, note: 'every existing definition is weaker than a plain assignment, so no override wrapper is needed.' };
  if (strongest > 50) return { ...base, line: `${option} = lib.mkForce ${fx.to};`, priority: 50, note: 'a plain assignment would conflict with the existing definition at the same priority, so mkForce is required. `lib` must be among the module arguments.' };
  if (strongest > 1) return { ...base, line: `${option} = lib.mkOverride ${strongest - 1} ${fx.to};`, priority: strongest - 1, note: `an existing definition already uses priority ${strongest}, so the override must be stronger than it. \`lib\` must be among the module arguments.` };
  return { ...base, line: null, priority: null, note: 'an existing definition uses the strongest possible priority; nothing can override it from another module.' };
}

const refuse = (status, reason, extra = {}) => ({ ok: false, status, tier: status === 'blocked' ? TIERS.blocked : TIERS.guidance, reason, ...extra });

/**
 * Edit the single literal that defines `option` at `file`:`line` in `text`. When several bindings share the line (the branches
 * of one `if`), the one holding the weak literal `bad` is preferred. `skip` reports a definition that already holds the safe value.
 */
function literalEdit(file, text, line, option, fx, bad) {
  const parse = parseNix(text, { file });
  if (!parse.ast) return { ok: false, reason: `${file} does not parse` };
  const ir = buildNixIR(parse, { file, source: text });
  const re = fx.kind === 'bool' ? /\b(?:true|false)\b/g : /"(?:[^"\\]|\\.)*"/g;
  const cands = ir.bindings.filter((b) => b.pathText === option && b.valueSpan && b.span);
  const onLine = cands.filter((b) => b.span.startLine === line);
  const within = cands.filter((b) => b.span.startLine <= line && b.span.endLine >= line);
  const pool = onLine.length ? onLine : (within.length ? within : (cands.length === 1 ? cands : []));
  const litOf = (b) => { const t = text.slice(b.valueSpan.startOffset, b.valueSpan.endOffset).match(re) || []; return t.length === 1 ? t[0] : null; };
  const hit = (bad && pool.find((b) => litOf(b) === bad)) || pool.find((b) => litOf(b) !== null && litOf(b) !== fx.to) || pool[0] || null;
  if (!hit) return { ok: false, reason: `no literal definition of ${option} was found at ${file}:${line}: it may be set by a function, an import or an attribute-set merge` };
  const vs = hit.valueSpan;
  const current = text.slice(vs.startOffset, vs.endOffset);
  const lits = current.match(re) || [];
  if (lits.length !== 1) return { ok: false, reason: `the definition of ${option} at ${file}:${hit.span.startLine} is not a single literal (${current.trim().slice(0, 60)}): the edit would have to choose a branch` };
  if (lits[0] === fx.to) return { ok: true, skip: true, line: hit.span.startLine };
  const next = current.replace(re, fx.to);
  return { ok: true, after: splice(text, vs.startOffset, vs.endOffset, next), from: current.trim(), to: next.trim(), line: hit.span.startLine, literal: lits[0] };
}

function planOptionFix(finding, files, fx, source, opts = {}) {
  // `optionEvidence` is the option-level evidence a scan carries; `evidence` is that same array on a finding that comes
  // straight from the hardening analysis (the scan's own `evidence` field is the list of detectors that agreed).
  const evList = Array.isArray(finding.optionEvidence) ? finding.optionEvidence : (Array.isArray(finding.evidence) ? finding.evidence.filter((e) => e && typeof e === 'object') : []);
  const evidence = evList.find((e) => e && e.option === OPTION_OF[finding.rule]) || evList[0] || null;
  const option = (evidence && evidence.option) || finding.subject;
  const sources = (evidence && Array.isArray(evidence.sources)) ? evidence.sources : [];
  const bad = BAD_OF[finding.rule] || null;
  const proposal = (extra = {}) => ({ option, set: fx.to, ...extra });

  // Findings that carry no per-definition evidence keep the single-file behaviour: edit the reported line.
  if (!sources.length) {
    const file = source ? source.file : finding.file;
    const line = source ? source.line : finding.line;
    if (typeof files[file] !== 'string') return refuse('blocked', `the defining file ${file} is not in the supplied tree`);
    const r = literalEdit(file, files[file], line, option, fx, bad);
    if (!r.ok) return refuse(/does not parse/.test(r.reason) ? 'blocked' : 'manual', r.reason, { proposal: proposal() });
    if (r.skip) return refuse('manual', `the definition of ${option} at ${file}:${r.line} already holds ${fx.to}`, { proposal: proposal() });
    return optionPlanResult(option, fx, [{ file, before: files[file], after: r.after, from: r.from, to: r.to, line: r.line }], [], bad);
  }

  // Everything that contributes to the effective value: the definitions that win, and those that apply only under a
  // condition. Definitions another one overrides do not contribute and are left alone.
  const live = sources.filter((s) => s.role === 'winner' || s.role === 'conditional');
  const shadowed = sources.filter((s) => s.role === 'shadowed');
  const override = () => overrideSuggestion(option, fx, sources, files, opts);
  if (!live.length) return refuse('manual', `no contributing definition of ${option} could be identified`, { proposal: proposal({ override: override() }) });

  // The caller chose a definition that another one overrides: changing it cannot change the effective value.
  if (source) {
    const chosen = sources.find((s) => s.file === source.file && s.line === source.line);
    if (chosen && chosen.role === 'shadowed') {
      const by = live.map((w) => `${w.file}:${w.line} (${w.priorityLabel || w.priority})`).join(', ');
      return refuse('blocked', `${source.file}:${source.line} is overridden by ${by}: editing it would leave the effective value of ${option} unchanged`, { proposal: proposal({ editInstead: live.map((w) => ({ file: w.file, line: w.line })), override: override() }) });
    }
  }

  // Every contributing definition must be editable: inside the project, present, a single literal. Several definitions at the
  // winning priority agree today and the module system rejects a mix, so they are all changed or none is. A conditional
  // branch is edited only where it holds the weak literal; the verification then proves every branch is safe.
  const working = { ...files };
  const edits = [];
  for (const w of live) {
    if (!isRootRelativePath(w.file)) return refuse('manual', `the winning definition of ${option} is in ${w.file}, outside the project root, so it is not edited`, { proposal: proposal({ outsideRoot: w.file, override: override() }) });
    if (typeof working[w.file] !== 'string') return refuse('manual', `the winning definition of ${option} is in ${w.file}, which is not in the supplied tree`, { proposal: proposal({ override: override() }) });
    const r = literalEdit(w.file, working[w.file], w.line, option, fx, bad);
    if (!r.ok) return refuse(/does not parse/.test(r.reason) ? 'blocked' : 'manual', r.reason, { proposal: proposal({ override: override() }) });
    if (r.skip || (w.role === 'conditional' && bad && r.literal !== bad)) continue;
    const prior = edits.find((e) => e.file === w.file);
    if (prior) prior.after = r.after; else edits.push({ file: w.file, before: working[w.file], after: r.after, from: r.from, to: r.to, line: r.line });
    working[w.file] = r.after;
  }
  if (!edits.length) return refuse('manual', `no contributing definition of ${option} holds the weak value, so there is nothing to edit`, { proposal: proposal({ override: override() }) });
  return optionPlanResult(option, fx, edits, shadowed, bad);
}

function optionPlanResult(option, fx, edits, shadowed, bad = null) {
  const first = edits[0];
  const where = edits.map((e) => `${e.file}:${e.line}`).join(', ');
  const multi = edits.length > 1;
  const notes = [...fx.consequences];
  if (shadowed.length) notes.push(`Weaker definitions of ${option} remain at ${shadowed.map((s) => `${s.file}:${s.line}`).join(', ')}; they are overridden and unchanged.`);
  if (multi) notes.push(`${edits.length} files are edited together (${edits.map((e) => e.file).join(', ')}) because each holds a definition at the winning priority; undo restores all of them.`);
  return {
    ok: true, file: first.file, before: first.before, after: first.after,
    edits: edits.map((e) => ({ file: e.file, before: e.before, after: e.after })),
    ruleId: `nix-set-${option}`, label: 'FULL',
    explanation: `${option} = ${first.from} -> ${first.to} at ${where}, the definition${multi ? 's' : ''} that win${multi ? '' : 's'} by priority.`,
    consequences: notes, tier: TIERS.edit,
    behavior: { kind: 'option', option, from: first.from, to: first.to, files: edits.map((e) => e.file) },
    expectEffective: { option, value: literalValue(fx.to), ...(bad ? { bad: literalValue(bad) } : {}) },
  };
}

function planTransportFix(finding, files) {
  const file = finding.file; const text = files[file];
  if (typeof text !== 'string') return { ok: false, status: 'blocked', tier: TIERS.blocked, reason: `${file} is not in the supplied tree` };
  const lines = text.split('\n'); const ln = (finding.line || 1) - 1;
  const parse = parseNix(text, { file });
  if (!parse.ast) return { ok: false, status: 'blocked', tier: TIERS.blocked, reason: `${file} does not parse` };
  const lineText = lines[ln] || '';
  if (!/"http:\/\//.test(lineText) && !/'http:\/\//.test(lineText)) return { ok: false, status: 'manual', tier: TIERS.guidance, reason: 'the insecure URL is not a literal on the reported line' };
  let off = 0; for (let i = 0; i < ln; i++) off += lines[i].length + 1;
  const next = lineText.replace(/(["'])http:\/\//g, '$1https://');
  return { ok: true, file, before: text, after: splice(text, off, off + lineText.length, next), ruleId: 'nix-https-transport', label: 'MITIGATION', explanation: `Upgraded the cache URL on line ${finding.line} from http:// to https://.`, consequences: ['The cache must serve TLS on the same host; if it does not, substitution from it will fail (builds fall back to other substituters or to building locally).'], tier: TIERS.edit, behavior: { kind: 'transport' } };
}

// ── shell escaping ───────────────────────────────────────────────────────────
function topFormals(ast) {
  let n = ast; let node = null;
  while (n && (n.type === 'lambda' || n.type === 'paren')) { if (n.type === 'paren') { n = n.expr; continue; } node = n; n = n.body; break; }
  const names = new Set(); let pattern = null;
  let cur = ast;
  while (cur && (cur.type === 'lambda' || cur.type === 'paren')) {
    if (cur.type === 'paren') { cur = cur.expr; continue; }
    if (cur.param.kind === 'pattern') { for (const f of cur.param.formals) names.add(f.name); if (!pattern) pattern = cur.param; } else if (cur.param.name) names.add(cur.param.name);
    cur = cur.body;
  }
  return { names, pattern, node };
}

function planShellFix(finding, files) {
  const file = finding.file; const text = files[file];
  const loc = finding.originalLocation;
  if (typeof text !== 'string' || !loc || !Number.isInteger(loc.startOffset)) return { ok: false, status: 'blocked', tier: TIERS.blocked, reason: 'the finding carries no exact source location' };
  const parse = parseNix(text, { file });
  if (!parse.ast) return { ok: false, status: 'blocked', tier: TIERS.blocked, reason: `${file} does not parse` };
  const open = text.lastIndexOf('${', loc.startOffset);
  let close = text.indexOf('}', loc.endOffset);
  if (open < 0 || close < 0 || text.slice(open + 2, loc.startOffset).trim() !== '' || text.slice(loc.endOffset, close).trim() !== '') return { ok: false, status: 'manual', tier: TIERS.guidance, reason: 'could not delimit the interpolation exactly' };
  const expr = text.slice(loc.startOffset, loc.endOffset);
  const before = text[open - 1]; const after = text[close + 1];
  const quoted = (before === '"' || before === "'") && before === after;
  const wordBoundary = (c) => c === undefined || /[\s;|&()]/.test(c);
  const isWholeWord = quoted && wordBoundary(text[open - 2]) && wordBoundary(text[close + 2]);
  const ctx = finding.sink && finding.sink.context;
  const { names, pattern } = topFormals(parse.ast);
  let fn = null; let addLib = false;
  if (names.has('lib')) fn = 'lib.escapeShellArg';
  else if (pattern && pattern.ellipsis) { fn = 'lib.escapeShellArg'; addLib = true; }
  else if (names.has('pkgs')) fn = 'pkgs.lib.escapeShellArg';
  else return { ok: false, status: 'blocked', tier: TIERS.blocked, reason: 'lib is not in scope and the function takes a closed parameter list: adding it changes the interface of this file (manual step)', proposal: { wrap: 'lib.escapeShellArg' } };
  let rangeStart = open; let rangeEnd = close + 1; let replacement;
  if (finding.rule === 'nix-escape-wrong-context') {
    if (!isWholeWord) return { ok: false, status: 'manual', tier: TIERS.guidance, reason: 'the escaped value shares its quotes with other text: removing them needs a human decision', proposal: { removeQuotes: true } };
    rangeStart = open - 1; rangeEnd = close + 2; replacement = text.slice(open, close + 1);
  } else if (finding.rule === 'nix-shell-injection') {
    const wrapped = SIMPLE.test(expr.trim()) ? `${fn} ${expr.trim()}` : `${fn} (${expr.trim()})`;
    if (ctx === 'double' || ctx === 'single') {
      if (!isWholeWord) return { ok: false, status: 'manual', tier: TIERS.guidance, reason: `the value is inside ${ctx} quotes together with other text: it cannot be escaped without restructuring the string`, proposal: { wrap: fn } };
      rangeStart = open - 1; rangeEnd = close + 2;
    } else if (ctx !== 'unquoted') return { ok: false, status: 'manual', tier: TIERS.guidance, reason: `the shell context "${ctx}" has no deterministic escape` };
    replacement = `\${${wrapped}}`;
  } else return { ok: false, status: 'unsupported', tier: TIERS.guidance, reason: `rule ${finding.rule} has no shell fixer` };
  let next = splice(text, rangeStart, rangeEnd, replacement);
  if (addLib) {
    // the formal list is earlier in the file, so its offsets are unaffected by the edit above
    const ps = pattern.span; const head = text.slice(ps.startOffset, ps.endOffset);
    next = splice(next, ps.startOffset, ps.endOffset, head.replace(/^\{\s*/, (m) => `${m}lib, `));
  }
  return { ok: true, file, before: text, after: next, ruleId: finding.rule === 'nix-escape-wrong-context' ? 'nix-unquote-escaped' : 'nix-escape-shell-arg', label: 'FULL', tier: TIERS.edit, explanation: finding.rule === 'nix-escape-wrong-context' ? 'Removed the quotes around an already escaped value: lib.escapeShellArg supplies its own.' : `Wrapped the interpolation in ${fn}${isWholeWord ? ' and dropped the surrounding quotes' : ''}.`, consequences: addLib ? ['`lib` was added to this file\'s function arguments (it is already provided to NixOS modules).'] : [], behavior: { kind: 'shell-escape', fn, quotesRemoved: isWholeWord && (ctx === 'double' || ctx === 'single' || finding.rule === 'nix-escape-wrong-context') } };
}

function planEnvQuoteFix(finding, files) {
  const file = finding.file; const text = files[file]; const loc = finding.originalLocation;
  if (typeof text !== 'string' || !loc || !Number.isInteger(loc.startOffset)) return { ok: false, status: 'blocked', tier: TIERS.blocked, reason: 'the finding carries no exact source location' };
  const seg = text.slice(loc.startOffset, loc.endOffset);
  if (!/^\$(?:\{[A-Za-z_]\w*\}|[A-Za-z_]\w*)$/.test(seg)) return { ok: false, status: 'manual', tier: TIERS.guidance, reason: 'the expansion is not a plain $NAME or ${NAME}' };
  const prev = text[loc.startOffset - 1]; const next = text[loc.endOffset];
  if (prev === '"' || prev === "'") return { ok: false, status: 'manual', tier: TIERS.guidance, reason: 'the expansion is already inside quotes' };
  const quoted = `"${seg}"`;
  return { ok: true, file, before: text, after: splice(text, loc.startOffset, loc.endOffset, quoted), ruleId: 'nix-quote-expansion', label: 'MITIGATION', tier: TIERS.edit, explanation: `Quoted the shell expansion ${seg}: it is no longer word-split or globbed. A value that starts with "-" can still be read as an option by the command.`, consequences: [], behavior: { kind: 'quote-expansion', variable: seg, adjacentText: next } };
}

// ── planning ─────────────────────────────────────────────────────────────────
/**
 * @returns {{ok:true,...}|{ok:false,status:'blocked'|'manual'|'unsupported',tier:string,reason:string,proposal?:object}}
 */
export function planNixFix(finding, files, opts = {}) {
  if (!finding || !finding.rule) return { ok: false, status: 'unsupported', tier: TIERS.guidance, reason: 'the finding names no rule' };
  const r = finding.rule;
  if (r === 'nix-shell-injection' || r === 'nix-escape-wrong-context') return planShellFix(finding, files);
  if (r === 'nix-service-env-shell') return planEnvQuoteFix(finding, files);
  if (OPTION_FIXES[r]) return planOptionFix(finding, files, OPTION_FIXES[r], opts.source || null, opts);
  if (TRANSPORT_RULES.has(r)) return planTransportFix(finding, files);
  if (MANUAL[r]) return { ok: false, status: 'manual', tier: TIERS.guidance, reason: 'moving a secret out of the store changes where the credential lives and who can read it: it needs a human migration, never an automatic rewrite', proposal: { steps: MANUAL[r], rotate: r !== 'nix-secret-log', manager: 'sops-nix or agenix' } };
  if (HASH_MANUAL.has(r)) return { ok: false, status: 'manual', tier: TIERS.blocked, reason: 'the correct hash or revision can only be obtained by fetching the source, which a scan never does; a placeholder hash would be a fabricated value', proposal: { steps: ['Run `nix-prefetch-url` / `nix store prefetch-file` (or build once with lib.fakeHash and read the reported hash) from a trusted machine.', 'Pin a full revision, not a branch.', 'Paste the real hash.'], neverDo: 'insert a made-up or all-zero hash' } };
  return { ok: false, status: 'unsupported', tier: TIERS.guidance, reason: `no deterministic fix exists for ${r}` };
}

// ── rescan ───────────────────────────────────────────────────────────────────
/** The Nix analyses over an in-memory tree: the same rule sets a scan runs, nothing evaluated. */
export async function rescanNix(files) {
  const nix = {};
  for (const [p, t] of Object.entries(files)) if (typeof t === 'string' && (/\.nix$/i.test(p) || /(^|\/)flake\.lock$/.test(p))) nix[p] = t;
  const entry = nix['configuration.nix'] !== undefined ? 'configuration.nix' : undefined;
  const out = [];
  const nixOnly = Object.fromEntries(Object.entries(nix).filter(([p]) => /\.nix$/.test(p)));
  out.push(...analyzeNixScripts({ files: nixOnly }).findings);
  out.push(...analyzeNixSecrets({ files }).findings);
  try { out.push(...analyzeNixBuildTrust({ files: nix, ...(entry ? { entry } : {}) }).findings); } catch { /* reported as a gap by the scan; the fix gate treats absence as no finding */ }
  if (entry) { try { out.push(...analyzeNixosHardening({ entry, files: nixOnly }).findings); } catch { /* same */ } }
  return out;
}
const matchKey = (f) => `${f.rule || f.cwe}|${f.subject || f.attrPath || ''}|${f.file}`;
const syntaxGate = (plan) => {
  const edits = Array.isArray(plan.edits) && plan.edits.length ? plan.edits : [{ file: plan.file, before: plan.before, after: plan.after }];
  let na = 0; let nb = 0; let ok = true;
  for (const e of edits) {
    const a = parseNix(e.before, { file: e.file }); const b = parseNix(e.after, { file: e.file });
    na += (a.errors || []).length; nb += (b.errors || []).length;
    if (!b.ast || (b.errors || []).length > (a.errors || []).length) ok = false;
  }
  return { ok, errorsBefore: na, errorsAfter: nb, detail: ok ? 'no new syntax errors' : `${nb - na} new syntax error(s)` };
};

/**
 * The effective-configuration gate of an option fix. The rescan only proves a finding stopped being REPORTED, and an edit that
 * leaves two equal-priority definitions disagreeing does that too (the module system then rejects the configuration). So the
 * option is resolved again over the patched tree and must be a decided `set` value equal to the intended one.
 */
function makeEffectiveCheck(entry) {
  return (plan, patched) => {
    const want = plan.expectEffective;
    if (!want) return { ok: true, ran: false, detail: 'not an option fix' };
    const multi = Array.isArray(plan.edits) && plan.edits.length > 1;
    if (!entry) return multi ? { ok: false, ran: false, detail: `no entry configuration was found to resolve ${want.option} over the patched tree, and ${plan.edits.length} files were edited` } : { ok: true, ran: false, detail: 'no entry configuration to resolve; the single definition was edited in place' };
    const nixOnly = Object.fromEntries(Object.entries(patched).filter(([p, t]) => /\.nix$/.test(p) && typeof t === 'string'));
    let res;
    try { res = resolveNixosConfig({ entry, files: nixOnly }).lookup(want.option); } catch (e) { return { ok: false, ran: true, detail: `the patched configuration could not be resolved (${e.message})` }; }
    // A value that depends on a condition has no single answer; the fix holds when NO branch can still produce the weak value.
    if (res && res.status === 'conditional' && Array.isArray(res.possibleValues) && res.possibleValues.length && want.bad !== undefined) {
      if (res.possibleValues.includes(want.bad)) return { ok: false, ran: true, option: want.option, detail: `${want.option} can still be ${JSON.stringify(want.bad)} under some condition after the patch` };
      return { ok: true, ran: true, option: want.option, possibleValues: res.possibleValues, detail: `${want.option} is conditional and no branch can produce ${JSON.stringify(want.bad)} (possible: ${res.possibleValues.map((v) => JSON.stringify(v)).join(', ')})` };
    }
    if (!res || res.status !== 'set') return { ok: false, ran: true, option: want.option, status: res && res.status, detail: `${want.option} is "${res && res.status}" after the patch${res && res.reason ? ` (${res.reason})` : ''}, not a decided value` };
    if (res.value !== want.value) return { ok: false, ran: true, option: want.option, detail: `${want.option} is ${JSON.stringify(res.value)} after the patch, not ${JSON.stringify(want.value)}` };
    return { ok: true, ran: true, option: want.option, value: res.value, detail: `${want.option} resolves to ${JSON.stringify(res.value)} over the patched tree` };
  };
}

/** Validate (and optionally apply) a fix through the shared lifecycle. */
export async function validateNixFix(finding, o) {
  const plan = planNixFix(finding, o.files, o);
  if (!plan.ok) return { status: plan.status || 'unsupported', applied: false, tier: plan.tier, reason: plan.reason, proposal: plan.proposal || null, ...plan };
  const res = await runFixLifecycle({ plan, files: o.files, finding, matchKey, rescan: o.rescan || rescanNix, syntax: syntaxGate, behaviorCheck: o.behaviorCheck, effectiveCheck: makeEffectiveCheck(entryOf(o.files, o)), writeFile: o.writeFile, witness: o.witness, requireWitness: o.requireWitness, apply: o.apply, root: o.root });
  return { ...res, consequences: plan.consequences || [], tier: res.status === 'blocked' ? TIERS.blocked : plan.tier, explanation: plan.explanation };
}

/** Verify a patch SUPPLIED BY SOMEONE ELSE through the same gates as a deterministic Nix fix. Nothing is written. */
export async function verifyNixProposal(finding, { files, file, proposal, rescan }) {
  const before = files[file];
  const plan = { file, before: typeof before === 'string' ? before : '', after: proposal, label: 'WORKAROUND', tier: TIERS.edit };
  return runFixLifecycle({ plan, files, finding, matchKey, rescan: rescan || rescanNix, syntax: syntaxGate, apply: false });
}

// ── flake input upgrade ──────────────────────────────────────────────────────
/** Compare two lock texts: only the named input's node (and nodes only it reaches) may differ. */
export function lockDiff(beforeText, afterText, inputName) {
  const a = parseFlakeLock(beforeText); const b = parseFlakeLock(afterText);
  if (a.status !== 'ok' || b.status !== 'ok') return { ok: false, reason: `a lock does not parse (${a.error || b.error || a.status})`, changed: [] };
  const A = JSON.parse(beforeText).nodes; const B = JSON.parse(afterText).nodes;
  const root = (a.root);
  const target = (A[root].inputs || {})[inputName];
  const targetKey = typeof target === 'string' ? target : null;
  // nodes reachable ONLY through the target input
  const reach = (nodes, from) => { const seen = new Set(); const q = [from]; while (q.length) { const k = q.pop(); if (!k || seen.has(k) || !nodes[k]) continue; seen.add(k); for (const v of Object.values(nodes[k].inputs || {})) if (typeof v === 'string') q.push(v); } return seen; };
  const allowed = new Set();
  if (targetKey) { const rest = new Set(); for (const [n, k] of Object.entries(A[root].inputs || {})) if (n !== inputName && typeof k === 'string') for (const x of reach(A, k)) rest.add(x); for (const x of reach(A, targetKey)) if (!rest.has(x)) allowed.add(x); }
  const changed = [];
  for (const k of new Set([...Object.keys(A), ...Object.keys(B)])) {
    if (JSON.stringify(A[k]) !== JSON.stringify(B[k]) && !allowed.has(k) && !(B[k] && allowed.has(k))) changed.push(k);
  }
  const rootChanged = JSON.stringify(Object.fromEntries(Object.entries(A[root].inputs || {}).filter(([n]) => n !== inputName))) !== JSON.stringify(Object.fromEntries(Object.entries(B[root].inputs || {}).filter(([n]) => n !== inputName)));
  return { ok: changed.length === 0 && !rootChanged, changed, rootChanged, reason: changed.length ? `unrelated lock node(s) changed: ${changed.join(', ')}` : (rootChanged ? 'the root inputs of other inputs changed' : '') };
}

/**
 * Plan a targeted flake input upgrade. Edits flake.nix only. flake.lock is never fabricated: without a
 * relocked lock supplied by the caller the result is `relock-required`, and a supplied lock is accepted only
 * if nothing outside the upgraded input changed.
 */
export function planNixUpgrade({ files, flake = 'flake.nix', lock = 'flake.lock', input, toRef, relock = null } = {}) {
  const text = files[flake];
  const blocked = (reason, extra = {}) => ({ ok: false, status: 'blocked', tier: TIERS.blocked, reason, ...extra });
  if (typeof text !== 'string') return blocked(`${flake} is not in the supplied tree`);
  if (!input || !toRef || !/^[\w.\-/]+$/.test(toRef)) return blocked('an input name and a plain target ref are required');
  const parse = parseNix(text, { file: flake });
  if (!parse.ast) return blocked(`${flake} does not parse`);
  const ir = buildNixIR(parse, { file: flake, source: text });
  const b = ir.bindings.find((x) => x.pathText === `inputs.${input}.url` && x.valueSpan);
  if (!b) return blocked(`no literal url for input "${input}" in ${flake}`);
  const vs = b.valueSpan; const cur = text.slice(vs.startOffset, vs.endOffset);
  const m = /^"(github|gitlab|sourcehut):([^/"]+)\/([^/"?]+)(?:\/([^"?]+))?(\?[^"]*)?"$/.exec(cur);
  if (!m) return blocked(`the url ${cur.slice(0, 60)} is not a plain github:/gitlab:/sourcehut: reference this planner can rewrite`);
  const next = `"${m[1]}:${m[2]}/${m[3]}/${toRef}${m[5] || ''}"`;
  const edits = [{ file: flake, before: text, after: splice(text, vs.startOffset, vs.endOffset, next) }];
  const base = { ok: true, input, from: m[4] || '(default branch)', to: toRef, edits, preview: unifiedDiff(flake, text, edits[0].after), lockTouched: false, consequences: [`Input ${input} will track ${toRef}: its content, and everything that follows it, changes at the next lock update.`] };
  const lockText = files[lock];
  if (!relock) return { ...base, status: 'relock-required', tier: TIERS.relock, note: `${lock} was NOT modified and no hash was invented: run \`nix flake update ${input}\` (an isolated resolution, or by hand) and re-scan`, instructions: [`nix flake update ${input}`] };
  let relocked;
  try { relocked = relock({ ...files, [flake]: edits[0].after }); } catch (e) { return { ...base, status: 'relock-required', tier: TIERS.relock, note: `the relock step failed (${e.message}); ${lock} is unchanged` }; }
  if (!relocked || typeof relocked.lockText !== 'string') return { ...base, status: 'relock-required', tier: TIERS.relock, note: `the relock step produced no lock; ${lock} is unchanged` };
  if (typeof lockText !== 'string') return { ...base, status: 'blocked', tier: TIERS.blocked, ok: false, reason: `there is no ${lock} to compare against` };
  const d = lockDiff(lockText, relocked.lockText, input);
  if (!d.ok) return { ...base, ok: false, status: 'blocked', tier: TIERS.blocked, reason: `the relocked ${lock} is rejected: ${d.reason}`, lockDiff: d };
  edits.push({ file: lock, before: lockText, after: relocked.lockText });
  return { ...base, status: 'verified-relock', tier: TIERS.edit, lockTouched: true, lockDiff: d, edits, preview: edits.map((e) => unifiedDiff(e.file, e.before, e.after)).join('\n') };
}
