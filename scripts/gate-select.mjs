// Which unit-test files a change can affect, for the local pre-push gate.
//
// WHY. The full suite is the dominant cost of a push (about 12 of 19 minutes) and the hosted pull-request CI runs all of it again in four
// shards. The local push only has to answer "did THIS change break anything it can reach", so it runs the test files that can see the change
// and leaves the whole suite to the pull request. A wrong selection costs a red pull request, never a bad release: the full suite is a blocking
// hosted check, and the release gate repeats it.
//
// HOW. A test file is selected when ANY of these holds, each deliberately conservative (a false inclusion costs seconds, a false exclusion
// costs a red PR):
//   1. it imports (transitively, through relative imports) a changed code file;
//   2. its text names a changed file by repo-relative path, by scanner-relative path, by a distinctive file name, or by a containing directory;
//   3. it is a structural test that reads the whole tree (the orphan, drift, ledger, gate and release tests) and always runs.
// A change this module cannot reason about (the test runner itself, the package manifest beyond its version line, an unreadable diff)
// selects the FULL suite, as does a selection larger than `maxFraction` of it.
//
// WHAT IT IS NOT. It is not a proof that the unselected tests pass. It never says "safe"; it says which tests to run now.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

/** Roots whose JavaScript participates in the import graph. */
const GRAPH_ROOTS = ['scanner/src', 'scanner/test', 'scanner/bin', 'scripts', 'bench', 'hooks', 'frontend'];
const SKIP_DIR = /(^|\/)(node_modules|\.cache|\.agentic-security|dist|pre|post|\.git)(\/|$)/;
/** Structural tests that read the whole tree: always selected. */
const ALWAYS = /(no-orphan|ci-parity|pre-push-gate|gate-select|ship\.test|release-check|release-workflow|doc-drift|capability-ledger|dataset-provenance)/;
/** Changes whose effect on the suite cannot be bounded here. */
const FULL_TRIGGERS = [/^scripts\/run-unit-tests\.mjs$/, /^scripts\/gate-/, /^scripts\/pre-push-gate\.mjs$/];

const IMPORT_RE = /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)['"](\.{1,2}\/[^'"\n]+)['"]/g;

/** The tracked JavaScript files under the graph roots, from git (the gate tests the committed tree, so untracked files are not part of it). */
function trackedScripts(repo) {
  const r = spawnSync('git', ['ls-files', '-z', '--', ...GRAPH_ROOTS], { cwd: repo, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  if (r.status !== 0) throw new Error('git ls-files failed');
  return r.stdout.split('\0').filter((f) => /\.(m?js|cjs)$/.test(f) && !SKIP_DIR.test(f)).map((f) => path.join(repo, f));
}

function resolveImport(fromFile, spec, exists) {
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), spec.replace(/[?#].*$/, '')));
  for (const cand of [base, `${base}.js`, `${base}.mjs`, `${base}.cjs`, `${base}/index.js`, `${base}/index.mjs`]) if (exists(cand)) return cand;
  return null;
}

/** Reverse import graph and file texts for the roots. `read` and `list` are injectable for tests. */
export async function buildGraph({ repo, list = null, read = null }) {
  const rd = read || ((rel) => fs.promises.readFile(path.join(repo, rel), 'utf8'));
  const files = (list || trackedScripts(repo)).map((p) => path.relative(repo, p).split(path.sep).join('/'));
  const set = new Set(files);
  const exists = (c) => set.has(c);
  const importers = new Map(); // file -> Set of files that import it
  const text = new Map();
  const read1 = async (f) => { try { return await rd(f); } catch { return null; } };
  const sources = await Promise.all(files.map(read1));
  for (const [i, f] of files.entries()) {
    const src = sources[i];
    if (src === null) continue;
    text.set(f, src);
    for (const m of src.matchAll(IMPORT_RE)) {
      const to = resolveImport(f, m[1], exists);
      if (!to) continue;
      if (!importers.has(to)) importers.set(to, new Set());
      importers.get(to).add(f);
    }
  }
  return { files, importers, text };
}

/** Every file that (transitively) imports any of `seeds`. */
export function transitiveImporters(importers, seeds) {
  const seen = new Set(seeds);
  const queue = [...seeds];
  while (queue.length) {
    const f = queue.pop();
    for (const up of importers.get(f) || []) if (!seen.has(up)) { seen.add(up); queue.push(up); }
  }
  return seen;
}

/** Names a test's text could use to refer to a changed file: path, scanner-relative path, distinctive basename, containing directories. */
export function mentionTokens(changedFile) {
  const t = new Set([changedFile]);
  if (changedFile.startsWith('scanner/')) t.add(changedFile.slice('scanner/'.length));
  const base = path.posix.basename(changedFile);
  if (base.length >= 10 && base.includes('.')) t.add(base);
  const parts = changedFile.split('/');
  for (let n = parts.length - 1; n >= 2; n--) t.add(parts.slice(0, n).join('/'));
  return [...t];
}

/**
 * @param {{changed: string[], tests: string[], graph: {importers: Map, text: Map}, versionOnly?: boolean, maxFraction?: number}} p
 *   `tests` are repo-relative paths of the candidate test files (the files `npm test` runs).
 * @returns {{mode: 'full'|'subset', files: string[], total: number, reason: string}}
 */
export function selectTests({ changed, tests, graph, versionOnly = false, maxFraction = 0.6 }) {
  // `versionOnly`: the manifest and lock files differ from base only in their "version" lines, which tests read, not depend on.
  const total = tests.length;
  const full = (reason) => ({ mode: 'full', files: tests.slice(), total, reason });
  if (!Array.isArray(changed) || changed.length === 0) return full('no changed files could be determined, so nothing is excluded');
  const relevant = changed.filter((f) => !(versionOnly && (f === 'scanner/package.json' || f === 'scanner/package-lock.json')));
  for (const f of relevant) if (FULL_TRIGGERS.some((re) => re.test(f))) return full(`${f} can change how every test runs`);
  if (relevant.some((f) => f === 'scanner/package.json' || f === 'scanner/package-lock.json')) return full(`${relevant.find((f) => f.startsWith('scanner/package'))} changed beyond its version line (scripts and dependencies decide which tests exist and how they run)`);

  const codeChanged = relevant.filter((f) => graph.text.has(f));
  const affected = transitiveImporters(graph.importers, codeChanged);
  const tokens = relevant.flatMap(mentionTokens);
  const picked = new Set();
  for (const t of tests) {
    if (ALWAYS.test(t) || affected.has(t)) { picked.add(t); continue; }
    const src = graph.text.get(t) || '';
    if (tokens.some((tok) => src.includes(tok))) picked.add(t);
  }
  const files = tests.filter((t) => picked.has(t));
  if (files.length > maxFraction * total) return full(`${files.length} of ${total} test files can see this change, which is over ${Math.round(maxFraction * 100)}%: running them all costs the same`);
  return { mode: 'subset', files, total, reason: `${files.length} of ${total} test files can see ${relevant.length} changed file(s)` };
}

const git = (repo, args) => spawnSync('git', args, { cwd: repo, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

/** True when every change to the scanner manifest and lock between base and HEAD is a `"version"` line. */
export function onlyVersionLineChanged(repo, base) {
  const r = git(repo, ['diff', '-U0', base, 'HEAD', '--', 'scanner/package.json', 'scanner/package-lock.json']);
  if (r.status !== 0) return false;
  const lines = r.stdout.split('\n').filter((l) => /^[+-]/.test(l) && !/^(\+\+\+|---)/.test(l));
  // A script line (its value starts with a command) changes which test files a scope lists, not how any other test behaves; a dependency line does.
  return lines.every((l) => /^[+-]\s*"version"\s*:/.test(l) || /^[+-]\s*"[^"]+"\s*:\s*"(node|npm|ncc|bash|sh|cd|cp|rm|mkdir|AGENTIC_SECURITY_\w+=)/.test(l));
}

/** The files changed between `base` and HEAD (committed), or null when git cannot say. */
export function changedFiles(repo, base) {
  const r = git(repo, ['diff', '--name-only', base, 'HEAD']);
  return r.status === 0 ? r.stdout.split('\n').filter(Boolean) : null;
}

/** The test files `npm test` runs, as repo-relative paths. */
export async function candidateTests(repo) {
  const mod = await import(path.join(repo, 'scripts/run-unit-tests.mjs'));
  const pkg = JSON.parse(await fs.promises.readFile(path.join(repo, 'scanner/package.json'), 'utf8'));
  return mod.unionFiles(pkg).map((f) => `scanner/${f}`);
}

/** The whole decision for a push: which tests to run against `base`. Never throws; any failure selects the full suite. */
export async function selectForPush({ repo, base, maxFraction = 0.6 }) {
  try {
    const tests = await candidateTests(repo);
    const changed = changedFiles(repo, base);
    if (!changed) return { mode: 'full', files: tests, total: tests.length, reason: 'git could not list the changed files' };
    const graph = await buildGraph({ repo });
    return selectTests({ changed, tests, graph, versionOnly: onlyVersionLineChanged(repo, base), maxFraction });
  } catch (e) {
    return { mode: 'full', files: [], total: 0, reason: `selection failed (${String(e.message || e).slice(0, 120)}), so the full suite runs` };
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  const repo = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
  const base = process.argv[2] || 'origin/main';
  const t0 = Date.now();
  const sel = await selectForPush({ repo, base });
  process.stdout.write(`${sel.mode}: ${sel.reason} (${Date.now() - t0} ms)\n`);
  if (sel.mode === 'subset') for (const f of sel.files.slice(0, 40)) process.stdout.write(`  ${f}\n`);
}
