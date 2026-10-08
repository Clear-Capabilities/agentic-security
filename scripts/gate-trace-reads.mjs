#!/usr/bin/env node
// Run one pre-push check under the read tracer and report what it touched.
//
//   node scripts/gate-trace-reads.mjs <check-id> [--verify] [--raw <file>] [--from <recorded trace>]
//
// Without --verify it prints the repo-relative top-level areas the check read.
// With --verify it compares every observed read against the check's declared
// input scope (scripts/gate-check-scopes.mjs) and exits 1 when the check read a
// tracked file the scope does not cover, or ran git against this repository
// while the scope says it does not depend on history. Exit 0 means the scope
// covered everything this run observed; it is evidence, not proof (see the
// limits in gate-trace-preload.mjs).
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { CHECKS } from './pre-push-gate.mjs';
import { scopeFor, pathInScope } from './gate-check-scopes.mjs';
import { wipeIgnoredState } from './gate-verdict-cache.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const SCANNER = path.join(REPO, 'scanner');

/** Pure: reduce trace lines to the verdict against a scope. */
export function analyseTrace(lines, scope, repo = REPO) {
  const outside = new Set();
  const repoGit = [];
  const writes = new Set();
  const stateReads = new Set();
  const areas = new Set();
  const root = repo.endsWith(path.sep) ? repo : repo + path.sep;
  for (const l of lines) {
    let r;
    try { r = JSON.parse(l); } catch { continue; }
    if (r.kind === 'spawn') {
      const isGit = path.basename(String(r.cmd)) === 'git';
      const cwd = r.cwd || '';
      // `clone` and `init` build a NEW repository from a path given as an argument; they do not read this repository's history.
      const buildsNew = (r.args || []).some((a) => a === 'clone' || a === 'init');
      if (isGit && !buildsNew && (cwd === repo || cwd.startsWith(root))) repoGit.push(`${r.cmd} ${(r.args || []).join(' ')}`.slice(0, 120));
      continue;
    }
    if (!r.path || !r.path.startsWith(root)) continue;
    const rel = r.path.slice(root.length);
    if (r.kind === 'write') { if (!rel.startsWith('.git/')) writes.add(rel); continue; }
    if (rel.startsWith('.git/') || rel.startsWith('node_modules/') || rel.startsWith('scanner/node_modules/')) continue;
    if (/(^|\/)\.agentic-security(\/|$)/.test(rel)) {
      // Scan state is an input the file digest cannot see (it is gitignored). A check may read it only under a root the gate wipes
      // before keying (scope.cleanState); a read anywhere else is a hidden input and fails the verification.
      if (!(scope.cleanState || []).some((c) => rel.startsWith(c))) stateReads.add(rel);
      continue;
    }
    areas.add(rel.split('/').slice(0, 2).join('/'));
    if (!pathInScope(scope, rel)) outside.add(rel);
  }
  // With a cleanState root declared, every write inside the repo must be under it: a write elsewhere mutates an input the next run reads.
  const writesOutside = (scope.cleanState || []).length ? [...writes].filter((w) => !scope.cleanState.some((c) => w.startsWith(c))) : [];
  return { areas: [...areas].sort(), outside: [...outside].sort(), repoGit, writes: [...writes].sort(), stateReads: [...stateReads].sort(), writesOutside: writesOutside.sort() };
}

function main(argv) {
  const id = argv[0];
  const check = CHECKS.find((c) => c.id === id && c.npmScript);
  if (!check) { process.stderr.write(`unknown or non-npm check: ${id}\n`); return 2; }
  const fromIdx = argv.indexOf('--from');
  let out;
  if (fromIdx >= 0) {
    // Re-judge an earlier recorded trace against the CURRENT scope without re-running the check (the long benches take far
    // longer under the tracer than without it).
    out = argv[fromIdx + 1];
  } else {
    const rawIdx = argv.indexOf('--raw');
    out = rawIdx >= 0 ? argv[rawIdx + 1] : path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gate-trace-')), 'trace.jsonl');
    fs.rmSync(out, { force: true });
    const preload = path.join(HERE, 'gate-trace-preload.mjs');
    // Exactly what the gate does before it keys and runs this check, so the trace describes the gate's run and not a dirtier one.
    const wiped = wipeIgnoredState(REPO, scopeFor(id).cleanState || []);
    if (wiped === null) { process.stderr.write('could not prepare scan state; refusing to trace\n'); return 1; }
    const r = spawnSync('npm', ['run', check.npmScript], {
      cwd: SCANNER, stdio: ['ignore', 'ignore', 'inherit'],
      env: { ...process.env, GATE_TRACE_OUT: out, NODE_OPTIONS: `${process.env.NODE_OPTIONS || ''} --import=${preload}`.trim() },
    });
    process.stderr.write(`check ${id}: exit ${r.status}\n`);
    if (r.status !== 0) { process.stderr.write('the check itself failed; a trace of a failing run proves nothing\n'); return 1; }
  }
  const lines = fs.existsSync(out) ? fs.readFileSync(out, 'utf8').split('\n').filter(Boolean) : [];
  if (lines.length === 0) { process.stderr.write('empty trace: the tracer did not engage, so nothing is verified\n'); return 1; }
  const scope = scopeFor(id);
  const a = analyseTrace(lines, scope);
  process.stdout.write(`${lines.length} trace records\nareas read:\n  ${a.areas.join('\n  ')}\n`);
  if (a.repoGit.length) process.stdout.write(`git run in this repo (${a.repoGit.length}):\n  ${[...new Set(a.repoGit)].slice(0, 8).join('\n  ')}\n`);
  process.stdout.write(`writes inside the repo (${a.writes.length}):\n  ${a.writes.slice(0, 25).join('\n  ')}\n`);
  if (!argv.includes('--verify')) return 0;
  let bad = 0;
  if (a.outside.length) { bad = 1; process.stdout.write(`NOT COVERED by scope (${a.outside.length}):\n  ${a.outside.slice(0, 40).join('\n  ')}\n`); }
  if (a.repoGit.length && !scope.usesHistory) { bad = 1; process.stdout.write('check ran git in this repo but scope.usesHistory is false\n'); }
  if (a.writes.length && scope.writesRepo === false) { bad = 1; process.stdout.write(`scope says writesRepo:false but the check wrote ${a.writes.length} path(s) inside the repo\n`); }
  if (a.stateReads.length) { bad = 1; process.stdout.write(`read scan state the digest cannot see (${a.stateReads.length}):\n  ${a.stateReads.slice(0, 20).join('\n  ')}\n`); }
  if (a.writesOutside.length) { bad = 1; process.stdout.write(`wrote inside the repo outside its cleanState roots (${a.writesOutside.length}):\n  ${a.writesOutside.slice(0, 20).join('\n  ')}\n`); }
  process.stdout.write(bad ? 'VERIFY FAILED\n' : 'VERIFY OK: every observed read is inside the declared scope\n');
  return bad;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
