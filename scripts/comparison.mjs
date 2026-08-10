#!/usr/bin/env node
// PRD Epic 7.2 — the head-to-head comparison driver.
//
// Runs this engine and any number of OPERATOR-SUPPLIED participants over the
// CVE-replay corpus and scores them all identically. This repository ships the
// harness and the answer key; it does not ship, name, or default to any
// participant. There is no bundled list to edit — the config is yours, it lives
// outside the repo, and the report renders the labels you chose.
//
// Usage:
//   node scripts/comparison.mjs --tools <config.json> [options]
//
//   --tools <path>   Participant config (see the shape below). REQUIRED.
//   --limit <n>      Score only the first n corpus entries (a smoke run).
//   --tier <name>    Restrict to one corpus tier (capability | regression | deep).
//   --json <path>    Write the full result set.
//   --md <path>      Write the markdown report.
//   --timeout <ms>   Per-participant per-tree budget (default 120000).
//
// Config shape — one entry per participant:
//   {
//     "participants": [
//       { "id": "<your label>", "command": "<binary>", "args": ["scan", "{dir}"],
//         "format": "sarif" }
//     ]
//   }
//
//   {dir} is replaced with the absolute path of the tree to scan. `format` is
//   `sarif` (read from stdout) or `json-findings` (an array, or {findings:[]},
//   with `cwe` on each). This engine is added automatically as a participant
//   under the id "this-engine" and is scored by exactly the same rules.
//
// Exit codes: 0 the comparison was produced, 2 usage/config/IO error.
// NOTE: the exit code says whether a COMPARISON happened, never who won. A
// harness that failed the run when it lost would be an advertisement.

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const CORPUS = path.join(REPO, 'bench', 'cve-replay');

const { compareParticipants, renderComparison } =
  await import(path.join(REPO, 'scanner', 'src', 'posture', 'comparison.js'));
const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));

// STATE_SEAM_COMPLETION_PRD M3 — placed immediately after the runScan import,
// BEFORE anything can scan. Inserting it after the last top-level statement
// (the first attempt) put it after the scan in attest-fixture.mjs, so the
// fixture was still littered. Placement, not presence, is what matters.
const { disableStateWrites } = await import('../bench/_lib/tree-integrity.mjs');
await disableStateWrites();
const { normalizeFindings } = await import(path.join(REPO, 'scanner', 'src', 'report', 'index.js'));

const VALUED = new Set(['tools', 'limit', 'tier', 'json', 'md', 'timeout']);
const argv = process.argv.slice(2);
const flags = new Map();
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (!a.startsWith('--')) continue;
  const name = a.slice(2);
  if (VALUED.has(name)) flags.set(name, argv[++i] ?? null); else flags.set(name, true);
}
const arg = (n, d = null) => (flags.has(n) ? flags.get(n) : d);

const toolsPath = arg('tools');
if (!toolsPath) {
  process.stderr.write('usage: comparison.mjs --tools <config.json> [--tier capability] [--md out.md]\n\n'
    + 'No participants ship with this repository. Supply your own config; see the header\n'
    + 'of this file for its shape.\n');
  process.exit(2);
}
let config;
try { config = JSON.parse(fs.readFileSync(toolsPath, 'utf8')); }
catch (e) { process.stderr.write(`could not read --tools ${toolsPath}: ${e.message}\n`); process.exit(2); }
const participants = Array.isArray(config?.participants) ? config.participants : [];
if (!participants.length) {
  process.stderr.write('the config declares no participants — nothing to compare against.\n');
  process.exit(2);
}

// ── the corpus ──────────────────────────────────────────────────────────────

const TIERS = ['regression', 'capability', 'deep'];
const wantTier = arg('tier');
if (wantTier && !TIERS.includes(wantTier)) {
  process.stderr.write(`unknown --tier ${wantTier} (expected one of ${TIERS.join(', ')})\n`);
  process.exit(2);
}

function loadCorpus() {
  const out = [];
  for (const tier of TIERS) {
    if (wantTier && tier !== wantTier) continue;
    const dir = path.join(CORPUS, tier);
    let names;
    try { names = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const d of names) {
      if (!d.isDirectory()) continue;
      const entryDir = path.join(dir, d.name);
      let manifest = null;
      for (const f of fs.readdirSync(entryDir)) {
        if (!f.endsWith('.json')) continue;
        try { manifest = JSON.parse(fs.readFileSync(path.join(entryDir, f), 'utf8')); } catch {}
        if (manifest) break;
      }
      if (!manifest?.cwe) continue;
      const pre = path.join(entryDir, 'pre');
      const post = path.join(entryDir, 'post');
      if (!fs.existsSync(pre) || !fs.existsSync(post)) continue;
      out.push({ id: `${tier}/${d.name}`, cwe: String(manifest.cwe).toUpperCase(), pre, post });
    }
  }
  return out.sort((a, b) => a.id.localeCompare(b.id));
}

let entries = loadCorpus();
const limit = Number(arg('limit', '0')) || 0;
if (limit > 0) entries = entries.slice(0, limit);
if (!entries.length) { process.stderr.write('no corpus entries found\n'); process.exit(2); }

// Scan state accumulates inside the trees and can mask a result. Cleared before
// anything runs, for every participant equally — and again at the end, because
// a scan WRITES state into the tree it scanned and leaving it behind both
// dirties the repository and poisons the next run.
function wipeScanState() {
  for (const e of entries) {
    for (const tree of [e.pre, e.post]) {
      fs.rmSync(path.join(tree, '.agentic-security'), { recursive: true, force: true });
    }
  }
}
wipeScanState();
process.on('exit', wipeScanState);

process.stderr.write(`comparison: ${entries.length} corpus entr(y/ies), `
  + `${participants.length + 1} participant(s)\n`);

// ── running a participant ───────────────────────────────────────────────────

const timeoutMs = Number(arg('timeout', '120000')) || 120000;

function parseOutput(text, format) {
  const j = JSON.parse(text);
  if (format === 'sarif') {
    const out = [];
    for (const run of j.runs || []) {
      for (const r of run.results || []) {
        // A SARIF rule carries its CWE either in the result's ruleId or in the
        // rule descriptor's taxa/tags. Both are read; neither is invented.
        const rule = (run.tool?.driver?.rules || []).find((x) => x.id === r.ruleId);
        const tags = rule?.properties?.tags || [];
        out.push({ ruleId: `${r.ruleId || ''} ${tags.join(' ')}`, message: r.message?.text || '' });
      }
    }
    return out;
  }
  return Array.isArray(j) ? j : (j.findings || []);
}

function runExternal(p, dir) {
  const args = (p.args || []).map((a) => a.replaceAll('{dir}', dir));
  let r;
  try {
    r = spawnSync(p.command, args, { encoding: 'utf8', timeout: timeoutMs, cwd: dir, maxBuffer: 64 * 1024 * 1024 });
  } catch (e) { return { error: `spawn failed: ${e.message}` }; }
  if (r.error) return { error: `spawn failed: ${r.error.message}` };
  if (r.status === null) return { error: 'timed out' };
  // A non-zero exit is normal for a scanner that found something, so the exit
  // code is not treated as failure — unparseable output is.
  try { return { findings: parseOutput(r.stdout || '', p.format || 'sarif') }; }
  catch (e) { return { error: `unparseable ${p.format || 'sarif'} output: ${e.message}` }; }
}

async function runThisEngine(dir) {
  try {
    const { scan } = await runScan(dir);
    return { findings: normalizeFindings(scan) };
  } catch (e) { return { error: String(e?.message || e) }; }
}

// ── the run ─────────────────────────────────────────────────────────────────

const all = [{ id: 'this-engine', internal: true }, ...participants];
const collected = [];

for (const p of all) {
  const results = {};
  let done = 0;
  for (const e of entries) {
    const pre = p.internal ? await runThisEngine(e.pre) : runExternal(p, e.pre);
    const post = p.internal ? await runThisEngine(e.post) : runExternal(p, e.post);
    if (pre.error || post.error) {
      results[e.id] = { error: pre.error || post.error };
    } else {
      results[e.id] = { pre: pre.findings, post: post.findings };
      done++;
    }
    process.stderr.write(`\r  ${p.id}: ${done}/${entries.length} completed`);
  }
  process.stderr.write('\n');
  collected.push({ id: p.id, results });
}

const cmp = compareParticipants(entries, collected);
const md = renderComparison(cmp);
process.stdout.write('\n' + md);

const mdOut = arg('md');
if (mdOut) {
  fs.mkdirSync(path.dirname(path.resolve(mdOut)), { recursive: true });
  fs.writeFileSync(mdOut, md);
  process.stderr.write(`wrote ${mdOut}\n`);
}
const jsonOut = arg('json');

if (jsonOut) {
  fs.mkdirSync(path.dirname(path.resolve(jsonOut)), { recursive: true });
  fs.writeFileSync(jsonOut, JSON.stringify({ comparison: cmp, raw: collected }, null, 2));
  process.stderr.write(`wrote ${jsonOut}\n`);
}

if (!cmp.ok) { process.stderr.write(`\nno comparison was produced: ${cmp.reason}\n`); process.exit(2); }
process.exit(0);
