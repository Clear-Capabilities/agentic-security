// Orphan-script guard (Stage 0, S0.3).
//
// no-dead-modules.test.js checks exported SYMBOLS under scanner/src/. It never
// walks `bench/` or `scripts/` at all — neither as scan targets nor as call-site
// sources — so a standalone script under either directory is invisible to it in
// both directions. That gap is how scripts/check-bench-shas.mjs (a complete,
// passing gate) and 16 of 18 bench/cve-replay/generate-corpus*.mjs scripts sat
// with zero callers, undetected, per the capability audit.
//
// A SCRIPT is reachable a different way than a module's export: not by another
// file importing a named symbol, but by something actually being able to RUN it —
// an npm script, a CI workflow step, or another script that shells out to it.
// This guard checks reachability by that definition, not by import-graph
// membership.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

// Directories whose scripts are deliberately not run FROM this repo:
//   - ci-templates: copied INTO a consumer repo; the consumer runs them, not us.
//   - fixtures/results/corpus data dirs: not scripts, or test-only inputs.
const SKIP_DIR = /(?:^|\/)(?:node_modules|\.bench-cache|dist|build|\.git|coverage|ci-templates|fixtures|results|corpus|\.agentic-security|bench\/independent\/cache)(?:$|\/)/;

// Each entry needs a reason. This is the same contract as no-dead-modules.js's
// ALLOWLIST: small, reviewed, justified.
const ALLOWLIST = new Set([
  // One-shot corpus-authoring tools. Each is an operator-invoked generator that
  // WROTE a batch of now-committed corpus entries; re-running one is a rare,
  // deliberate act (extending the corpus), not part of any ongoing pipeline.
  // Documented at bench/cve-replay/CONTRIBUTING.md. Grouped by glob rather than
  // named individually because the count grows with each corpus expansion.
  { glob: /^bench\/cve-replay\/generate-corpus.*\.mjs$/, reason: 'one-shot corpus-authoring tool, operator-invoked' },
  { glob: /^bench\/cve-replay\/verify-tier5\.mjs$/, reason: 'one-shot corpus-authoring tool, operator-invoked' },

  // ── Stage 0 (S0.2/S0.3) resolution of the capability-audit orphan list ──────
  // Each entry below was individually investigated (not carried over from the
  // audit's guess) before being allowlisted.
  { glob: /^scripts\/apply-command-trim\.mjs$/,
    reason: 'one-shot rewrite (its own header: "Run once; the lint script keeps it [in check]"); historical, not re-run' },
  { glob: /^scripts\/calibration-expand\.mjs$/,
    reason: 'operator tool requiring a manually-downloaded OWASP Benchmark corpus not present in CI; run by hand when expanding calibration-seed.json' },
  { glob: /^scripts\/resolve-bench-shas\.mjs$/,
    reason: 'network-touching operator tool (its own header: "Requires network access and git"); sibling of check-bench-shas.mjs which IS gated' },
  { glob: /^scripts\/ghsa-to-hints\.mjs$/,
    reason: "operator tool; its own header says \"runs nightly in CI\" but no such workflow currently exists — real gap, tracked, not silently wired to a no-op" },
  { glob: /^scripts\/detector-fuzz-runner\.mjs$/,
    reason: 'NON-FUNCTIONAL against the current fixture layout: discoverFixtures() only recognises family-named dirs (sql-injection, xss, ssrf, …) with a vulnerable/ subfolder, and scanner/test/fixtures/ uses different names throughout (xss-dom-sink, ssrf-static-url, …) — a real run finds 0 fixtures and would exit 0 as a silent, vacuous pass. Its own header says it was designed to run on every release as a CI gate; wiring it before fixing discovery would ship exactly the silent-pass defect class this repo has been hardened against elsewhere. Needs repair, not wiring, as its own item.' },
  { glob: /^scripts\/validator\/(history|junit|refusal-classes|run-test)\.mjs$/,
    reason: 'agents/security-poc-generator.md wires detect-framework.mjs and risk-context.mjs (both now correctly referenced — see the .js→.mjs fix in the same commit) but never references run-test.mjs, junit.mjs, history.mjs or refusal-classes.mjs. This looks like an incompletely-wired PoC-verification pipeline, not four accidental leftovers: the directory name and the four files together imply a designed flow (run the generated PoC, classify a refusal, emit JUnit, record history) that the agent doc never invokes. Real gap for a dedicated remediation-pipeline pass.' },
]);

function listScripts(dir, scanRoot) {
  // SKIP_DIR is checked against the path relative to `scanRoot` — the root this
  // particular scan was asked to cover — not the module-level REPO_ROOT. Using
  // REPO_ROOT unconditionally was a real bug: it made every path under this
  // guard's OWN fixture directory (scanner/test/fixtures/orphan-script-guard/…)
  // match the `fixtures` skip pattern relative to the real repo root, so the
  // fixture's scripts were silently excluded and the "should be flagged" case
  // could never fail — a guard that cannot fail is not a guard.
  const out = [];
  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      const rel = path.relative(scanRoot, p);
      if (e.isDirectory()) {
        if (SKIP_DIR.test(rel)) continue;
        walk(p);
        continue;
      }
      if (e.isFile() && /\.(?:mjs|cjs)$/.test(e.name) && !SKIP_DIR.test(rel)) out.push(p);
    }
  }
  walk(dir);
  return out;
}

function isAllowlisted(rel) {
  for (const entry of ALLOWLIST) if (entry.glob.test(rel)) return true;
  return false;
}

/**
 * A script is reachable if:
 *  (a) its basename appears as a value in any package.json "scripts" entry,
 *  (b) another script or src file imports/requires it by relative path, or
 *  (c) a GitHub Actions workflow step references its path.
 * Matching is by basename/path substring, deliberately looser than the
 * symbol-exact matcher in no-dead-modules.js: a script is invoked by shell
 * command line, not by a language-level identifier, so "the string naming this
 * file appears in an invoking context" is the right-shaped check here.
 */
export function findOrphanScripts({ repoRoot = REPO_ROOT } = {}) {
  const scriptDirs = [path.join(repoRoot, 'scripts'), path.join(repoRoot, 'bench')];
  const allScripts = scriptDirs.flatMap((d) => listScripts(d, repoRoot));

  const haystacks = [];
  for (const pkgPath of [path.join(repoRoot, 'package.json'), path.join(repoRoot, 'scanner', 'package.json')]) {
    if (fs.existsSync(pkgPath)) haystacks.push(fs.readFileSync(pkgPath, 'utf8'));
  }
  const workflowDir = path.join(repoRoot, '.github', 'workflows');
  if (fs.existsSync(workflowDir)) {
    for (const f of fs.readdirSync(workflowDir)) {
      if (/\.ya?ml$/.test(f)) haystacks.push(fs.readFileSync(path.join(workflowDir, f), 'utf8'));
    }
  }
  // agents/*.md and commands/*.md are real invocation sources — a sub-agent
  // system prompt or slash-command doc can literally instruct `node
  // scripts/foo.mjs` as part of its documented workflow. no-dead-modules.js's
  // loadAllSources() already treats commands/*.md this way for module exports;
  // this guard needs the same precedent for scripts, and needs agents/*.md too
  // (missing it here first misclassified the scripts/validator/ cluster as dead
  // — they are invoked from agents/security-poc-generator.md).
  for (const sub of ['agents', 'commands']) {
    const dir = path.join(repoRoot, sub);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir)) {
      if (/\.md$/.test(f)) haystacks.push(fs.readFileSync(path.join(dir, f), 'utf8'));
    }
  }
  for (const f of allScripts) haystacks.push(fs.readFileSync(f, 'utf8'));
  const combined = haystacks.join('\n');

  const orphans = [];
  for (const f of allScripts) {
    const rel = path.relative(repoRoot, f);
    if (isAllowlisted(rel)) continue;
    const base = path.basename(f);
    // Look for the basename referenced anywhere OTHER than the file's own
    // first line (a shebang doesn't count as a reference to itself).
    const selfContent = fs.readFileSync(f, 'utf8');
    const withoutSelf = combined.replace(selfContent, '');
    const re = new RegExp(base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    if (!re.test(withoutSelf)) orphans.push(rel);
  }
  return orphans;
}

test('every script under scripts/ and bench/ is reachable from an npm script, a workflow, or another script', () => {
  const orphans = findOrphanScripts();
  assert.equal(orphans.length, 0,
    `Orphan scripts detected (Stage 0 S0.3 — bench/ and scripts/ were previously unchecked):\n  ` +
    orphans.join('\n  ') +
    `\n\nFix: wire it into an npm script or another caller, add it to ALLOWLIST in ` +
    `test/no-orphan-scripts.test.js with a reason, or delete it.`);
});

test('guard fixture: a script referenced only by a deliberately unreferenced file is flagged', () => {
  const fixtureRoot = path.join(__dirname, 'fixtures', 'orphan-script-guard');
  // Build an isolated repoRoot view: only the fixture's own scripts/ dir plus a
  // package.json whose "scripts" section names the LIVE one, proving both
  // outcomes from one fixture tree.
  const orphans = findOrphanScripts({ repoRoot: fixtureRoot });
  const rels = orphans.map(p => p.replace(/\\/g, '/'));
  assert.ok(rels.some(r => r.endsWith('dead/unused.mjs')),
    `expected dead/unused.mjs to be flagged, got: ${rels.join(', ') || '(none)'}`);
});

test('guard fixture: a script named in package.json "scripts" is not flagged', () => {
  const fixtureRoot = path.join(__dirname, 'fixtures', 'orphan-script-guard');
  const orphans = findOrphanScripts({ repoRoot: fixtureRoot });
  const rels = orphans.map(p => p.replace(/\\/g, '/'));
  assert.ok(!rels.some(r => r.endsWith('live/runner.mjs')),
    `live/runner.mjs must not be flagged, got: ${rels.join(', ')}`);
});
