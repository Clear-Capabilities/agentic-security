// CLI flags for the scan scope (PRD FR 01 / FR 09). Pure: argv in, plain
// object out. Repeatable flags (`--include-path a --include-path b`) are why
// this is not read from the CLI's generic last-one-wins flag map.

const VALUE_FLAGS = new Set(['--include-path', '--exclude-path', '--include-ignored-path', '--ignore-source']);
const BOOL_FLAGS = new Set(['--explain-scope', '--respect-gitignore', '--no-respect-gitignore']);

export function parseScopeFlags(argv) {
  const out = { active: false, explain: false, errors: [], scope: { respectGitignore: true, ignoreSource: 'local', includePaths: [], excludePaths: [], includeIgnoredPaths: [] } };
  for (let i = 0; i < argv.length; i++) {
    let [k, v] = argv[i].startsWith('--') ? argv[i].split(/=(.*)/s, 2) : [argv[i]];
    if (BOOL_FLAGS.has(k)) {
      out.active = true;
      if (k === '--explain-scope') out.explain = true;
      else out.scope.respectGitignore = k === '--respect-gitignore';
    } else if (VALUE_FLAGS.has(k)) {
      out.active = true;
      if (v === undefined) v = argv[++i];
      if (v === undefined || v.startsWith('--')) { out.errors.push(`${k} needs a value`); continue; }
      if (k === '--ignore-source') {
        if (v === 'all') out.scope.ignoreSource = 'local';
        else if (v === 'repository') out.scope.ignoreSource = 'repository';
        else out.errors.push(`--ignore-source must be "all" or "repository", got "${v}"`);
      } else if (k === '--include-path') out.scope.includePaths.push(v);
      else if (k === '--exclude-path') out.scope.excludePaths.push(v);
      else out.scope.includeIgnoredPaths.push(v);
    }
  }
  return out;
}

/** Human-readable scope preview: included paths, excluded subtrees, reasons, overrides, policy. */
export function renderScopePreview(inv, { maxLines = 40 } = {}) {
  const L = [];
  const p = inv.policy;
  L.push(`Scope mode: ${p.mode}${p.respectGitignore ? '' : ' (git ignore rules disabled)'}; tracked-file semantics: ${p.trackedFileSemantics ? 'yes' : 'no'}`);
  if (p.ruleDigest) L.push(`Effective ignore-rule digest: ${p.ruleDigest}`);
  if (inv.digest) L.push(`Inventory digest: ${inv.digest}`);
  for (const d of p.disclosures) L.push(`Disclosure: ${d}`);
  L.push(`Included: ${inv.included.length} file(s)`);
  for (const f of inv.included.slice(0, maxLines)) L.push(`  + ${f}`);
  if (inv.included.length > maxLines) L.push(`  ... ${inv.included.length - maxLines} more`);
  const byReason = new Map();
  for (const s of inv.skipped) (byReason.get(s.reason) || byReason.set(s.reason, []).get(s.reason)).push(s);
  L.push(`Skipped: ${inv.skipped.length} entr${inv.skipped.length === 1 ? 'y' : 'ies'}`);
  for (const [reason, items] of [...byReason].sort()) {
    L.push(`  ${reason}: ${items.length}`);
    for (const s of items.slice(0, 5)) L.push(`    - ${s.path}${s.segment ? ` (segment ${s.segment})` : ''}`);
    if (items.length > 5) L.push(`    ... ${items.length - 5} more`);
  }
  if (inv.overrides.length) {
    L.push(`Overrides: ${inv.overrides.length}`);
    for (const o of inv.overrides) L.push(`  ! ${o.path} overrode ${o.overrode}`);
  }
  return L.join('\n') + '\n';
}
