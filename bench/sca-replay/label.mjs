#!/usr/bin/env node
// PRD F3.1 — the LABEL side of the SCA replay bench.
//
// ── Why this file duplicates work the engine already does ────────────────────
//
// The obvious way to build this bench is to ask the engine what packages a
// repo depends on and then ask the advisory database which of them are
// vulnerable. That measures nothing: the engine would be scored against its
// own component list, so its recall would be 100% by construction — the
// identical defect `scripts/corpus-provenance-check.mjs` already reports about
// `bench/cve-replay` ("its detection rate is at the ceiling by construction").
//
// So the labeller enumerates dependencies with its OWN readers, written here,
// sharing no code with `scanner/src`. Both sides then ask the same public
// advisory database about the versions they found. Where they disagree, one of
// them read the lockfile wrong — and that is the entire measurement.
//
// ── What this bench does and does not measure ────────────────────────────────
//
// MEASURED: dependency enumeration (direct AND transitive), version
// extraction, ecosystem attribution, and whether an advisory that applies to a
// pinned version is reported.
//
// NOT MEASURED: whether the advisory database is right. Both sides read the
// same public source, so a wrong advisory is wrong on both sides and cancels.
// Stating this plainly matters more than the number: an SCA result is the one
// thing a customer can check independently in minutes, and a bench that
// implied more than it measured would not survive that check.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readManifest, entryDir, entryComplete } from './fetch.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LABELS = path.join(HERE, 'labels.json');
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';

// ─── Independent readers, one per format ─────────────────────────────────────
// Each returns [{ ecosystem, name, version }]. Deliberately small and literal:
// this code is a measuring instrument, so it should be obviously correct rather
// than clever, and it must never grow a dependency on the thing it measures.

function readPackageLock(text) {
  const out = [];
  let j; try { j = JSON.parse(text); } catch { return out; }
  // lockfileVersion 2/3: a flat `packages` map keyed by install path.
  for (const [key, val] of Object.entries(j.packages || {})) {
    if (!key) continue;                                   // the root project itself
    // A key with no `node_modules/` segment is a WORKSPACE (npm/cli's lock has
    // `docs`, `smoke-tests`, …). Those are folders in this repo, not registry
    // packages, and no advisory database has ever heard of them.
    if (!key.includes('node_modules/')) continue;
    const name = key.split('node_modules/').pop();
    if (!name || !val || !val.version) continue;
    if (val.link) continue;                               // workspace symlink, not a registry package
    out.push({ ecosystem: 'npm', name, version: val.version });
  }
  // lockfileVersion 1: a recursive `dependencies` tree.
  const walk = (deps) => {
    for (const [name, val] of Object.entries(deps || {})) {
      if (val && val.version) out.push({ ecosystem: 'npm', name, version: val.version });
      if (val && val.dependencies) walk(val.dependencies);
    }
  };
  if (!j.packages) walk(j.dependencies);
  return out;
}

// package.json, EXACT pins only.
//
// Most projects write ranges here and a range has no single version for an
// advisory to apply to. But some — express is the well-known one — pin every
// dependency exactly, and for those the manifest IS a lockfile. Reading only
// the exact pins keeps the label honest in both directions: express stops
// being an artificial zero, and no range is ever invented into a version.
function readPackageJson(text) {
  const out = [];
  let j; try { j = JSON.parse(text); } catch { return out; }
  for (const group of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const [name, spec] of Object.entries(j[group] || {})) {
      if (typeof spec !== 'string') continue;
      if (!/^\d+\.\d+\.\d+[\w.+-]*$/.test(spec.trim())) continue;   // exact pin only
      out.push({ ecosystem: 'npm', name, version: spec.trim() });
    }
  }
  return out;
}

function readPnpmLock(text) {
  const out = [];
  // pnpm keys look like `/name/1.2.3` (v5/v6) or `/name@1.2.3` (v9), with
  // peer-suffixes after `_` or `(`. Scoped names carry a leading `@`.
  for (const line of text.split('\n')) {
    const m = line.match(/^\s{2}\/(@?[^\s:]+?)[@/](\d[^\s:(_]*)[^:]*:\s*$/);
    if (!m) continue;
    out.push({ ecosystem: 'npm', name: m[1], version: m[2] });
  }
  return out;
}

function readRequirementsTxt(text) {
  const out = [];
  for (const raw of text.split('\n')) {
    const line = raw.split('#')[0].trim();
    if (!line || line.startsWith('-')) continue;
    // Only `==` pins a version. `>=` and `~=` name a range, and a range has no
    // single version to match an advisory against — counting it either way
    // would be a guess, so it is excluded from the denominator entirely.
    const m = line.match(/^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;,]*)/);
    if (m) out.push({ ecosystem: 'PyPI', name: m[1], version: m[2] });
  }
  return out;
}

function readPoetryLock(text) {
  const out = [];
  let name = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line === '[[package]]') { name = null; continue; }
    const n = line.match(/^name\s*=\s*"([^"]+)"/);
    if (n) { name = n[1]; continue; }
    const v = line.match(/^version\s*=\s*"([^"]+)"/);
    if (v && name) { out.push({ ecosystem: 'PyPI', name, version: v[1] }); name = null; }
  }
  return out;
}

function readGemfileLock(text) {
  const out = [];
  let inSpecs = false;
  for (const raw of text.split('\n')) {
    if (/^\s{2}specs:\s*$/.test(raw)) { inSpecs = true; continue; }
    if (/^\S/.test(raw)) { inSpecs = false; continue; }
    if (!inSpecs) continue;
    // Four-space indent is a gem with its version; six is a dependency OF that
    // gem, listed with a constraint rather than a resolved version.
    const m = raw.match(/^\s{4}([A-Za-z0-9._-]+) \(([0-9][^)]*)\)\s*$/);
    // A platform-specific gem is listed once per platform:
    //   nokogiri (1.12.5-arm64-darwin)
    //   nokogiri (1.12.5-x86_64-linux)
    // Those are three builds of ONE version with one advisory between them.
    // Counting each as a separate vulnerable component inflated the
    // denominator and scored the engine as missing two things that do not
    // separately exist.
    if (m) out.push({ ecosystem: 'RubyGems', name: m[1], version: m[2].replace(/-[a-z0-9_]+-[a-z0-9_]+$/i, '') });
  }
  return out;
}

// go.sum carries TWO kinds of line per module and they mean different things:
//
//   example.com/m v1.2.3 h1:…          the module SOURCE was downloaded
//   example.com/m v1.2.3/go.mod h1:…   only its go.mod was read
//
// The second kind is a version that minimal version selection CONSIDERED. Its
// code was never fetched and is not in the binary, so calling it a shipped
// dependency is wrong.
//
// The first version of this reader counted both, and it mattered enormously:
// prometheus 2.30.0 went from 1828 "dependencies" to 187 real ones, and the
// Go recall this bench published on its first run — 2.73%, then 5.28% after an
// engine fix — was an artefact of THIS FILE, not a property of the engine.
// Recorded rather than quietly corrected, because a measuring instrument that
// hides its own errors is worth less than one that does not.
function readGoSum(text) {
  const seen = new Set(), out = [];
  for (const raw of text.split('\n')) {
    const t = raw.trim();
    if (!t || t.includes('/go.mod ')) continue;
    const m = t.match(/^(\S+)\s+(v\S+)\s+h1:/);
    if (!m) continue;
    const name = m[1];
    const version = m[2];
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ecosystem: 'Go', name, version: version.replace(/^v/, '') });
  }
  return out;
}

function readComposerLock(text) {
  const out = [];
  let j; try { j = JSON.parse(text); } catch { return out; }
  for (const group of ['packages', 'packages-dev']) {
    for (const p of j[group] || []) {
      if (!p || !p.name || !p.version) continue;
      out.push({ ecosystem: 'Packagist', name: p.name, version: String(p.version).replace(/^v/, '') });
    }
  }
  return out;
}

function readCargoLock(text) {
  const out = [];
  let name = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line === '[[package]]') { name = null; continue; }
    const n = line.match(/^name\s*=\s*"([^"]+)"/);
    if (n) { name = n[1]; continue; }
    const v = line.match(/^version\s*=\s*"([^"]+)"/);
    if (v && name) { out.push({ ecosystem: 'crates.io', name, version: v[1] }); name = null; }
  }
  return out;
}

function readPomXml(text) {
  const out = [];
  // Properties first, because a Maven version is very often `${some.version}`.
  const props = new Map();
  const propBlock = text.match(/<properties>([\s\S]*?)<\/properties>/);
  if (propBlock) {
    for (const m of propBlock[1].matchAll(/<([\w.-]+)>([^<]+)<\/\1>/g)) props.set(m[1], m[2].trim());
  }
  for (const m of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const block = m[1];
    const g = block.match(/<groupId>([^<]+)<\/groupId>/);
    const a = block.match(/<artifactId>([^<]+)<\/artifactId>/);
    const v = block.match(/<version>([^<]+)<\/version>/);
    if (!g || !a || !v) continue;
    let version = v[1].trim();
    const ref = version.match(/^\$\{([^}]+)\}$/);
    if (ref) version = props.get(ref[1]) || '';
    // An unresolved property is not a version. Dropping it keeps the label
    // honest; a Maven build resolves these from a parent POM this bench does
    // not fetch, and guessing would put fiction in the denominator.
    if (!/^\d/.test(version)) continue;
    out.push({ ecosystem: 'Maven', name: `${g[1].trim()}:${a[1].trim()}`, version });
  }
  return out;
}

const READERS = {
  'package.json': readPackageJson,
  'package-lock.json': readPackageLock,
  'pnpm-lock.yaml': readPnpmLock,
  'requirements.txt': readRequirementsTxt,
  'dev.txt': readRequirementsTxt,
  'poetry.lock': readPoetryLock,
  'Gemfile.lock': readGemfileLock,
  'go.sum': readGoSum,
  'composer.lock': readComposerLock,
  'Cargo.lock': readCargoLock,
  'pom.xml': readPomXml,
};

/** Enumerate the pinned dependencies of a materialised entry. */
export function enumerate(entry) {
  const dir = entryDir(entry.id);
  const comps = [];
  for (const rel of entry.lockfiles || []) {
    const base = rel.split('/').pop();
    const reader = READERS[base];
    if (!reader) continue;
    const p = path.join(dir, rel);
    if (!fs.existsSync(p)) continue;
    comps.push(...reader(fs.readFileSync(p, 'utf8')));
  }
  const seen = new Set(), out = [];
  for (const c of comps) {
    if (!c.name || !c.version) continue;
    const key = `${c.ecosystem}|${c.name}|${c.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
  }
  return out;
}

/** Ask the advisory database, in batches, which of these versions are affected. */
async function queryAdvisories(components) {
  const vulnerable = new Map(); // "eco|name|version" → [advisory ids]
  const CHUNK = 500;
  for (let i = 0; i < components.length; i += CHUNK) {
    const chunk = components.slice(i, i + CHUNK);
    const body = {
      queries: chunk.map((c) => ({ version: c.version, package: { name: c.name, ecosystem: c.ecosystem } })),
    };
    let data;
    try {
      const resp = await fetch(OSV_BATCH, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      data = await resp.json();
    } catch (e) {
      // A failed batch is UNKNOWN, never "no advisories". Silently labelling a
      // network error as clean would manufacture false positives on the engine
      // side and quietly inflate its measured precision problem.
      throw new Error(`advisory query failed at offset ${i}: ${e.message}`);
    }
    (data.results || []).forEach((r, idx) => {
      const ids = (r.vulns || []).map((v) => v.id).filter(Boolean);
      if (!ids.length) return;
      const c = chunk[idx];
      vulnerable.set(`${c.ecosystem}|${c.name}|${c.version}`, ids.sort());
    });
  }
  return vulnerable;
}

async function main() {
  const manifest = readManifest();
  const out = { generatedAt: new Date().toISOString().slice(0, 10), source: 'osv.dev querybatch', entries: {} };

  for (const e of manifest.entries) {
    if (!entryComplete(e)) {
      out.entries[e.id] = { status: 'UNSCORED', reason: 'not materialised — run fetch.mjs' };
      process.stderr.write(`  – ${e.id}: UNSCORED (not materialised)\n`);
      continue;
    }
    const comps = enumerate(e);
    let vulnerable;
    try { vulnerable = await queryAdvisories(comps); }
    catch (err) {
      out.entries[e.id] = { status: 'UNSCORED', reason: err.message };
      process.stderr.write(`  – ${e.id}: UNSCORED (${err.message})\n`);
      continue;
    }
    out.entries[e.id] = {
      status: 'OK',
      componentsEnumerated: comps.length,
      vulnerable: [...vulnerable.entries()]
        .map(([k, ids]) => { const [ecosystem, name, version] = k.split('|'); return { ecosystem, name, version, advisories: ids }; })
        .sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`)),
    };
    process.stderr.write(`  ✓ ${e.id}: ${comps.length} components, ${vulnerable.size} vulnerable\n`);
  }

  fs.writeFileSync(LABELS, JSON.stringify(out, null, 2) + '\n');
  process.stderr.write(`\nwrote ${path.relative(process.cwd(), LABELS)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { process.stderr.write(`label failed: ${e.message}\n`); process.exit(1); });
}
