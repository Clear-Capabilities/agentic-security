#!/usr/bin/env node
// Release gate: dependency currency — check 11 of the release gate.
//
// GOAL
// ----
// Every dependency this project ships or builds with should be on the newest
// published version, so that a vulnerability disclosed against an old release
// cannot reach us simply because nobody bumped anything. Two package trees
// carry that risk — scanner/ (what is published) and ide/vscode/ (what the
// extension is built from) — so both are checked, always.
//
// TWO HALVES, DELIBERATELY UNEQUAL
// --------------------------------
//  Half A — known advisories. Any advisory at moderate severity or above, in
//  either tree, FAILS. There is no opt-out, no hold, no flag. A dependency
//  with a published vulnerability is never an acceptable release state, and
//  the moment this half acquires an escape hatch it stops being a gate.
//
//  Half B — outdated dependencies. Anything behind its latest published
//  version fails UNLESS it is listed in .dependency-holds.json at the repo
//  root. The hold list exists because "always latest" is occasionally the
//  wrong answer: web-tree-sitter is pinned at 0.20.8 because the newer
//  runtime cannot load any grammar in the newest published prebuilt grammar
//  bundle (older grammar ABI), which silently drops six long-tail languages.
//  See scanner/src/ir/tree-sitter-loader.js. Without a hold mechanism this
//  gate would either block every release forever or pressure someone into
//  shipping that regression.
//
// THREE ANTI-ROT RULES — because a hold list nobody revisits is how
// "temporarily pinned" becomes permanent:
//   1. A hold whose `reviewBy` date has passed FAILS. Re-test the upgrade and
//      either clear the hold or extend it with fresh justification.
//   2. A hold for a package that is no longer outdated FAILS as stale. Delete
//      it, so the list only ever describes live exceptions.
//   3. A hold with a missing or empty `reason` FAILS. "Held because it's
//      held" is not a reason.
// The same instinct applies to the file itself: a hold file that exists but
// cannot be parsed FAILS rather than being treated as "no holds", which would
// turn a typo into a silently narrower gate.
//
// UNVERIFIED IS NOT PASSED
// ------------------------
// Both halves need the registry. If it cannot be reached — offline, proxy
// down, registry erroring — the check FAILS with a remedy, exactly as the
// hosted-CI check does. A gate that degrades to a pass under adverse
// conditions is decoration.
//
// SLOW BY CLASSIFICATION
// ----------------------
// Both halves are network round-trips against four manifests, so this is
// registered as a slow check and `--fast` skips it, matching checks 6-8. That
// costs nothing at publish time: `prepublishOnly` invokes the release gate
// with no flags, so the full set — this check included — always runs before
// anything is published.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

/** The package trees whose dependencies this gate governs. */
export const DEPENDENCY_TREES = [
  { id: 'scanner', rel: 'scanner' },
  { id: 'ide/vscode', rel: path.join('ide', 'vscode') },
];

export const HOLDS_FILE = '.dependency-holds.json';

/** Advisory severities that fail the gate outright. */
const BLOCKING_SEVERITIES = ['moderate', 'high', 'critical'];
const ADVISORY_SEVERITIES = ['info', 'low', ...BLOCKING_SEVERITIES];

const REQUIRED_HOLD_FIELDS = ['package', 'tree', 'heldAt', 'reason', 'addedAt', 'reviewBy'];

function result(errors = [], warnings = [], extra = {}) {
  return { ok: errors.length === 0, errors, warnings, ...extra };
}

// ---------------------------------------------------------------------------
// Fact normalisation. Pure — these take raw strings/objects, never do I/O.
// ---------------------------------------------------------------------------

/** Parse a JSON document from a registry command, or null if it is not JSON. */
export function parseNpmJson(stdout) {
  if (typeof stdout !== 'string' || stdout.trim() === '') return null;
  try {
    const parsed = JSON.parse(stdout);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

/** Which manifest section a package is declared in — a stale build tool and a
 *  stale shipped library are not equal risks, and the reader needs to see it. */
export function classifyDependencyKind(manifest, name) {
  if (!manifest || typeof manifest !== 'object') return 'unknown';
  if (manifest.dependencies?.[name]) return 'runtime';
  if (manifest.devDependencies?.[name]) return 'dev';
  if (manifest.optionalDependencies?.[name]) return 'optional';
  return 'unknown';
}

/**
 * Normalise the registry's outdated report into rows, or null when any row is
 * unusable. A row with no `latest` means the registry did not answer for that
 * package; reporting the rest as "everything else is current" would present a
 * partial answer as a complete one.
 */
export function normalizeOutdated(raw, manifest) {
  if (!raw || typeof raw !== 'object') return null;
  const rows = [];
  for (const [name, info] of Object.entries(raw)) {
    if (!info || typeof info !== 'object') return null;
    const { current, wanted, latest } = info;
    if (typeof latest !== 'string' || !latest) return null;
    if (typeof current !== 'string' || !current) return null;
    if (current === latest) continue;
    rows.push({
      package: name,
      current,
      wanted: typeof wanted === 'string' ? wanted : current,
      latest,
      kind: classifyDependencyKind(manifest, name),
    });
  }
  return rows.sort((a, b) => a.package.localeCompare(b.package));
}

/** Normalise the advisory counts, or null when they could not be established. */
export function normalizeAudit(raw) {
  const counts = raw?.metadata?.vulnerabilities;
  if (!counts || typeof counts !== 'object') return null;
  const out = {};
  for (const sev of ADVISORY_SEVERITIES) {
    const n = counts[sev];
    if (typeof n !== 'number' || !Number.isFinite(n)) return null;
    out[sev] = n;
  }
  out.total = typeof counts.total === 'number'
    ? counts.total
    : ADVISORY_SEVERITIES.reduce((a, s) => a + out[s], 0);
  return out;
}

// ---------------------------------------------------------------------------
// The decision. Pure: every fact is handed in already gathered.
// ---------------------------------------------------------------------------

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function endOfDay(dateStr) {
  if (!DATE_RE.test(dateStr)) return null;
  const t = Date.parse(`${dateStr}T23:59:59.999Z`);
  return Number.isFinite(t) ? t : null;
}

/**
 * @param trees  [{ id, audit: counts|null, outdated: rows|null }]
 * @param holdsDoc  parsed .dependency-holds.json, or null when absent
 * @param holdsReadError  non-null when the file exists but could not be used
 * @param now  Date used for reviewBy expiry
 */
export function evaluateDependencyCurrency({ trees, holdsDoc, holdsReadError, now = new Date() }) {
  const errors = [];
  const warnings = [];
  const nowMs = now.getTime();

  // ---- the hold list itself -------------------------------------------------
  let holds = [];
  if (holdsReadError) {
    errors.push(`${HOLDS_FILE} exists but could not be used (${holdsReadError}). An unreadable ` +
      'hold list is not an empty hold list. Remedy: fix the file so it parses as ' +
      '`{ "holds": [ … ] }`.');
  } else if (holdsDoc) {
    if (!Array.isArray(holdsDoc.holds)) {
      errors.push(`${HOLDS_FILE} has no \`holds\` array. Remedy: make the document ` +
        '`{ "holds": [ … ] }`, using [] when there are no live exceptions.');
    } else {
      holds = holdsDoc.holds;
    }
  }

  const knownTreeIds = new Set(trees.map(t => t.id));
  const holdIndex = new Map(); // `${tree} ${package}` -> hold

  for (const [i, hold] of holds.entries()) {
    const where = hold && typeof hold === 'object' && hold.package
      ? `${HOLDS_FILE} hold for ${hold.package}`
      : `${HOLDS_FILE} hold #${i + 1}`;
    if (!hold || typeof hold !== 'object') {
      errors.push(`${where} is not an object. Remedy: delete or rewrite the entry.`);
      continue;
    }
    const missing = REQUIRED_HOLD_FIELDS.filter(f => typeof hold[f] !== 'string' || !hold[f].trim());
    if (missing.length) {
      const reasonNote = missing.includes('reason')
        ? ' A hold with no `reason` is not a hold — "held because it\'s held" is not a reason;' +
          ' state what upgrading breaks.'
        : '';
      errors.push(`${where} is missing required field(s): ${missing.join(', ')}.${reasonNote} ` +
        `Remedy: supply every field (${REQUIRED_HOLD_FIELDS.join(', ')}) or delete the entry.`);
      continue;
    }
    if (!knownTreeIds.has(hold.tree)) {
      errors.push(`${where} names tree "${hold.tree}", which is not a checked package tree ` +
        `(${[...knownTreeIds].join(', ')}). Remedy: correct the tree, or delete the entry.`);
      continue;
    }
    const key = `${hold.tree} ${hold.package}`;
    if (holdIndex.has(key)) {
      errors.push(`${where} is a duplicate for tree ${hold.tree}. Remedy: keep one entry.`);
      continue;
    }
    holdIndex.set(key, hold);

    const reviewMs = endOfDay(hold.reviewBy);
    if (reviewMs === null) {
      errors.push(`${where} has an unparseable \`reviewBy\` ("${hold.reviewBy}"). ` +
        'Remedy: use a YYYY-MM-DD date by which the upgrade will be re-tested.');
    } else if (reviewMs < nowMs) {
      // Anti-rot rule 1.
      errors.push(`${where} passed its \`reviewBy\` of ${hold.reviewBy} — the hold is overdue ` +
        'for review. Remedy: re-test the upgrade now; if it is safe, take the upgrade and delete ' +
        'the hold; if it still regresses, extend `reviewBy` with a fresh, dated justification in ' +
        '`reason`.');
    }
    if (!DATE_RE.test(hold.addedAt)) {
      errors.push(`${where} has an unparseable \`addedAt\` ("${hold.addedAt}"). ` +
        'Remedy: use a YYYY-MM-DD date.');
    }
  }

  // ---- per-tree facts -------------------------------------------------------
  const heldSeen = new Set();
  for (const t of trees) {
    // An uninstalled tree answers "nothing outdated, nothing vulnerable" for
    // the same reason an empty room is quiet. Name that cause specifically —
    // "the registry did not answer" would send the reader after the wrong fault.
    if (t.uninstalled) {
      errors.push(`${t.id}: dependencies are not installed, so both advisories and ` +
        'outdated versions are UNVERIFIED — the registry commands only report on what ' +
        'is on disk, and an empty answer here is indistinguishable from a clean one. ' +
        'Remedy: install this tree\'s dependencies, then re-run.');
      continue;
    }
    // Half A — advisories. No opt-out, by design.
    if (!t.audit) {
      errors.push(`${t.id}: the advisory query did not return usable results, so known ` +
        'vulnerabilities are UNVERIFIED — which is not the same as none. Remedy: restore ' +
        'registry access and re-run; there is no opt-out for this half of the check.');
    } else {
      const blocking = BLOCKING_SEVERITIES.filter(s => t.audit[s] > 0);
      if (blocking.length) {
        const counts = blocking.map(s => `${s}=${t.audit[s]}`).join(' ');
        errors.push(`${t.id}: ${blocking.reduce((a, s) => a + t.audit[s], 0)} known ` +
          `vulnerabilit${t.audit.total === 1 ? 'y' : 'ies'} at moderate or above (${counts}). ` +
          'A vulnerable dependency is never an acceptable release state and there is no opt-out ' +
          'for this — a hold cannot suppress it. Remedy: upgrade the affected packages until ' +
          'the advisory count at moderate and above is zero.');
      }
      const informational = ['info', 'low'].filter(s => t.audit[s] > 0);
      if (informational.length) {
        warnings.push(`${t.id}: ${informational.map(s => `${s}=${t.audit[s]}`).join(' ')} ` +
          'advisories below the moderate gate — not blocking, worth clearing.');
      }
    }

    // Half B — currency, modulo the hold list.
    if (!t.outdated) {
      errors.push(`${t.id}: dependency versions could not be compared against the registry, so ` +
        'currency is UNVERIFIED — which is not the same as current. Remedy: restore registry ' +
        'access and re-run.');
      continue;
    }
    for (const row of t.outdated) {
      const hold = holdIndex.get(`${t.id} ${row.package}`);
      if (!hold) {
        errors.push(`${t.id}: ${row.package} [${row.kind}] is on ${row.current}, behind the ` +
          `latest published ${row.latest}. Remedy: upgrade it — or, if upgrading is verifiably ` +
          `unsafe, add an entry to ${HOLDS_FILE} recording why, at what version, and by when it ` +
          'will be re-tested.');
        continue;
      }
      heldSeen.add(`${t.id} ${row.package}`);
      if (hold.heldAt !== row.current) {
        errors.push(`${t.id}: ${row.package} is held at \`heldAt\` ${hold.heldAt} but the tree ` +
          `has ${row.current} — the hold no longer describes reality. Remedy: re-test at ` +
          `${row.current} and update or remove the hold.`);
        continue;
      }
      warnings.push(`${t.id}: ${row.package} [${row.kind}] ${row.current} is held back from ` +
        `${row.latest} until ${hold.reviewBy} — ${hold.reason}`);
    }
  }

  // Anti-rot rule 2: a hold whose package is not actually outdated any more.
  for (const [key, hold] of holdIndex) {
    if (heldSeen.has(key)) continue;
    const tree = trees.find(t => t.id === hold.tree);
    if (!tree || !tree.outdated) continue; // unverified tree — already reported above
    errors.push(`${HOLDS_FILE} hold for ${hold.package} (${hold.tree}) is stale: that package is ` +
      'not behind its latest published version any more, so the hold is exempting nothing and ' +
      'only hides future drift. Remedy: delete the entry.');
  }

  return result(errors, warnings);
}

// ---------------------------------------------------------------------------
// I/O layer. Gathers facts, makes no pass/fail decision of its own.
// ---------------------------------------------------------------------------

function readTextOrNull(absPath) {
  // Single read inside try/catch rather than existsSync-then-read: the
  // check-then-use form is a TOCTOU pattern this project's own engine flags.
  try {
    return fs.readFileSync(absPath, 'utf8');
  } catch {
    return null;
  }
}

// A registry that accepts connections but never answers would otherwise hang
// the release gate indefinitely, and the default retry policy multiplies that
// wait by every package. Retries are disabled, each request is bounded, and
// the whole invocation is bounded again as a backstop — a timeout kills the
// process, the partial output does not parse, and the check reports the honest
// result: unverified, which fails.
const REGISTRY_FLAGS = ['--fetch-retries=0', '--fetch-timeout=20000'];
const NPM_TIMEOUT_MS = 90_000;

function npmJson(args, cwd) {
  // Always argv-array, never a shell string.
  const r = spawnSync('npm', [...args, ...REGISTRY_FLAGS], {
    cwd,
    encoding: 'utf8',
    shell: false,
    maxBuffer: 32 * 1024 * 1024,
    timeout: NPM_TIMEOUT_MS,
    killSignal: 'SIGKILL',
  });
  if (r.error) return null;
  return parseNpmJson(r.stdout);
}

/** Gather the registry + manifest facts for one package tree. */
/**
 * Is this tree actually installed? `npm outdated`/`audit` only see installed
 * packages, so without node_modules they report an empty document that reads
 * exactly like a clean bill of health. Requiring one declared dependency to be
 * present on disk distinguishes "nothing is outdated" from "nothing was looked
 * at". A manifest with no dependencies at all is legitimately verifiable.
 */
export function dependenciesInstalled(cwd, manifest) {
  const declared = [
    ...Object.keys(manifest?.dependencies || {}),
    ...Object.keys(manifest?.devDependencies || {}),
    ...Object.keys(manifest?.optionalDependencies || {}),
  ];
  if (declared.length === 0) return true;
  return declared.some((name) => {
    try {
      return fs.statSync(path.join(cwd, 'node_modules', name)).isDirectory();
    } catch {
      return false;
    }
  });
}

export function gatherTreeFacts({ id, rel }, repo = REPO) {
  const cwd = path.join(repo, rel);
  const manifest = parseNpmJson(readTextOrNull(path.join(cwd, 'package.json')));
  // Both registry commands report on INSTALLED packages. With no install
  // present they answer "{}" — indistinguishable from "everything is current".
  // That is the gate's worst failure mode: a silent pass on a tree nobody
  // checked. An uninstalled tree is unverified, so say so and let the
  // evaluator fail it, exactly as an unreachable registry does.
  if (!dependenciesInstalled(cwd, manifest)) {
    return { id, audit: null, outdated: null, uninstalled: true };
  }
  // Both commands exit non-zero in ordinary success cases (npm outdated exits
  // 1 when anything is outdated; the advisory command exits non-zero when it
  // finds something), so the exit code says nothing useful here — the presence
  // of a parseable JSON document is what distinguishes an answer from a
  // failure, and an unparseable one is treated as unverified downstream.
  return {
    id,
    audit: normalizeAudit(npmJson(['audit', '--json'], cwd)),
    outdated: normalizeOutdated(npmJson(['outdated', '--json'], cwd), manifest),
  };
}

/** Gather every fact this check needs. */
export function gatherDependencyCurrencyFacts(repo = REPO) {
  const raw = readTextOrNull(path.join(repo, HOLDS_FILE));
  let holdsDoc = null;
  let holdsReadError = null;
  if (raw !== null) {
    try {
      holdsDoc = JSON.parse(raw);
    } catch (e) {
      holdsReadError = e.message;
    }
  }
  return {
    trees: DEPENDENCY_TREES.map(t => gatherTreeFacts(t, repo)),
    holdsDoc,
    holdsReadError,
    now: new Date(),
  };
}

/** Run the whole check end to end. Used by the release gate. */
export function runDependencyCurrencyCheck(repo = REPO) {
  return evaluateDependencyCurrency(gatherDependencyCurrencyFacts(repo));
}

// Standalone use: `node scripts/dependency-currency.mjs` (exit 0 pass / 1 fail).
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const r = runDependencyCurrencyCheck();
  for (const w of r.warnings) process.stderr.write(`  ⚠ ${w}\n`);
  for (const e of r.errors) process.stderr.write(`  ✗ ${e}\n`);
  process.stderr.write(r.ok ? '\n✓ Dependency currency check passed.\n'
    : `\n✗ Dependency currency check FAILED (${r.errors.length}).\n`);
  process.exit(r.ok ? 0 : 1);
}
