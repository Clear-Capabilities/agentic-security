// Adversarial premortem Q2 (2026-09-07) — writer-existence, not just
// self-reference-by-name.
//
// `test/compliance-mapping-liveness.test.js`'s self-referential-module test
// (P2.8) catches a `module:` mapping whose artifact evidences THIS SCANNER
// rather than the target. It has no mechanism for a structurally different
// defect: an artifact that evidences NOTHING, because no code path anywhere
// ever writes it. That was live in this codebase — `module:verifier` (→
// `verifier-runs/`) and `module:sigstore-verify` (→ `sigstore-attestations/`)
// both sat in the ARTIFACT table, referenced by real controls in
// nist-800-171-r3.json, nist-csf-2.json, hipaa-security-rule.json and
// nist-ai-600-1.json, and neither path was ever created by any writer in
// scanner/src/ — a worse failure than the self-referential class, because a
// self-referential mapping can at least clear (dishonestly); a dead one can
// NEVER clear, on any project, permanently, with no disclosure anywhere.
//
// This test closes that gap mechanically: for every entry in
// `MODULE_ARTIFACTS` (auditor-walkthrough.js, hoisted and exported
// specifically so this file can read the canonical table instead of keeping
// a second, driftable copy), it either finds a real writer/reference
// elsewhere in scanner/src or bin/ (for generated, per-scan artifacts), or
// confirms the literal file exists in the repo (for the `.../`-prefixed
// fixed source assets — this scanner's own hook/agent/tool files, which are
// never "written", only ever present or absent). A module with neither is a
// name in the vocabulary evidencing nothing, exactly the defect class this
// test exists to catch mechanically rather than by luck on the next
// premortem pass.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MODULE_ARTIFACTS } from '../src/posture/auditor-walkthrough.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const REPO = path.resolve(SCANNER, '..');
const SEARCH_ROOTS = ['src', 'bin'].map((d) => path.join(SCANNER, d));
// The table's own definition site names every artifact in prose (this file's
// own header does too) — neither is "a writer."
const EXEMPT_FILES = new Set([
  path.join(SCANNER, 'src', 'posture', 'auditor-walkthrough.js'),
]);

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

const ALL_FILES = SEARCH_ROOTS.flatMap((r) => walk(r)).filter((f) => !EXEMPT_FILES.has(f));

// Cache file contents once — this test reads every .js file under src/ and
// bin/, and re-reading per module entry would multiply that by the table
// size for no reason.
const CONTENTS = new Map(ALL_FILES.map((f) => [f, fs.readFileSync(f, 'utf8')]));

function hasRealWriter(searchTerm) {
  for (const [file, src] of CONTENTS) {
    if (src.includes(searchTerm)) return file;
  }
  return null;
}

function checkOneArtifact(rawPath) {
  if (rawPath.startsWith('.../')) {
    // A fixed, repo-relative source asset (this tool's own hook/agent/tool
    // file) — never "written" per scan, only ever present or absent in the
    // checkout. Existence IS the correct liveness check here. `.../` is
    // resolved against `scanRoot` in the real evaluator (auditor-walkthrough
    // .js's `_resolve`), which for a self-scan of this repository IS the
    // repo root, not scanner/ — matching that, not SCANNER, is what makes
    // this check test the same path the real evaluator would.
    const rel = rawPath.slice(4);
    const abs = path.join(REPO, rel);
    return fs.existsSync(abs) ? { ok: true, via: `file exists: ${rel}` } : { ok: false, reason: `${rel} does not exist under the repo root` };
  }
  // A generated, per-scan artifact — strip the trailing slash (directories)
  // so the search term matches both `'sbom-history/'`-shaped literals and
  // `'sbom-history'`-shaped ones (e.g. a HISTORY_DIR constant used with
  // path.join rather than a bare trailing-slash string).
  const term = rawPath.replace(/\/$/, '');
  const writer = hasRealWriter(term);
  return writer
    ? { ok: true, via: path.relative(REPO, writer) }
    : { ok: false, reason: `no reference to '${term}' anywhere outside auditor-walkthrough.js` };
}

test('every MODULE_ARTIFACTS entry is either a real writer or a real repo file, never a name evidencing nothing', () => {
  const dead = [];
  for (const [mod, target] of Object.entries(MODULE_ARTIFACTS)) {
    const candidates = Array.isArray(target) ? target : [target];
    const results = candidates.map(checkOneArtifact);
    // An array means "any of these satisfies it" in the real evaluator too
    // (auditor-walkthrough.js's own comment on `scan-history`) — so the
    // liveness bar matches: at least one candidate must be real.
    if (!results.some((r) => r.ok)) {
      dead.push(`module:${mod} → ${JSON.stringify(candidates)} — ${results.map((r) => r.reason).join('; ')}`);
    }
  }
  assert.deepEqual(dead, [],
    `module: artifact(s) with no real writer and no real repo file — a control mapped to ` +
    `any of these can never read 'present', on any project, permanently:\n${dead.join('\n')}`);
});

test('the completeness guard itself finds a non-trivial number of source files to search (sanity — proves it is not silently searching nothing)', () => {
  assert.ok(ALL_FILES.length > 50, `expected to search more than 50 files under src/+bin/, found ${ALL_FILES.length}`);
});

test('MODULE_ARTIFACTS is non-empty and every framework module: mapping resolves to a key in it', () => {
  // The complement of the liveness check above: a mapsTo entry naming a
  // module NOT in the table at all is a silent typo, not evidenced at all
  // and not even reachable by the checks in this file.
  assert.ok(Object.keys(MODULE_ARTIFACTS).length > 10, 'MODULE_ARTIFACTS looks emptied out — the hoist may have dropped entries');
  const FRAMEWORK_DIR = path.join(SCANNER, 'src', 'posture', 'compliance-frameworks');
  const unknown = [];
  for (const file of fs.readdirSync(FRAMEWORK_DIR).filter((f) => f.endsWith('.json'))) {
    const fw = JSON.parse(fs.readFileSync(path.join(FRAMEWORK_DIR, file), 'utf8'));
    for (const c of fw.controls || []) {
      for (const m of c.mapsTo || []) {
        if (!m.startsWith('module:')) continue;
        const mod = m.slice('module:'.length);
        if (!(mod in MODULE_ARTIFACTS)) unknown.push(`${file}:${c.id} maps to module:${mod}, which is not in MODULE_ARTIFACTS at all`);
      }
    }
  }
  assert.deepEqual(unknown, [], 'module: mapping(s) referencing a name absent from the vocabulary table');
});
