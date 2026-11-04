#!/usr/bin/env node
// The shipped-surface inventory for the GA programme (GA-01.1): every public entry point a user or an agent can reach, read from the
// source that ships it, so the acceptance ledger (docs/ga-program/ledger.json) can map each one to a registry capability and the check
// can refuse an unmapped one. Deterministic: no timestamps and no commit, so the committed docs/ga-program/inventory.json compares equal
// to a fresh generation on an unchanged tree.
//
//   node scripts/ga-program/inventory.mjs            print the inventory as JSON
//   node scripts/ga-program/inventory.mjs --write    write docs/ga-program/inventory.json
//   node scripts/ga-program/inventory.mjs --check    exit 1 when the committed file differs from a fresh generation
//
// Surfaces are {kind, id, name, source} with the key `kind:id`. Environment variables are counted and listed, not mapped: they are
// configuration of a surface, not a surface, and the ledger says so.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { atomicWriteFile } from '../loop-engineering/lib/util.mjs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(HERE, '..', '..');
export const INVENTORY_FILE = 'docs/ga-program/inventory.json';

const read = (repo, rel) => readFileSync(path.join(repo, rel), 'utf8');
const exists = (repo, rel) => existsSync(path.join(repo, rel));
const frontmatter = (text, key) => { const m = new RegExp(`^${key}:\\s*(.*)$`, 'm').exec(text.split(/^---\s*$/m)[1] || ''); return m ? m[1].trim().replace(/^"(.*)"$/, '$1') : null; };

/** The CLI commands: the `case '...'` labels of the main dispatch switch in the CLI entry, not of any other switch in the file. */
export function cliCommands(repo = REPO) {
  const src = read(repo, 'scanner/bin/agentic-security.js');
  const at = src.indexOf('switch (cmd)');
  if (at < 0) throw new Error('scanner/bin/agentic-security.js: the main `switch (cmd)` was not found');
  const body = src.slice(at);
  const names = [];
  for (const m of body.matchAll(/^ {6}case '([a-z][a-z0-9-]*)'\s*:/gm)) if (!names.includes(m[1])) names.push(m[1]);
  return names;
}

/** A `const NAME = new Set([...])` literal of string values in the CLI entry. */
function stringSet(src, name) {
  const m = new RegExp(`const ${name} = new Set\\(\\[([^\\]]*)\\]\\)`).exec(src);
  if (!m) throw new Error(`scanner/bin/agentic-security.js: ${name} was not found`);
  return [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
}

/** The tools the MCP server registers, read by loading ALL_TOOLS in a child process; a load failure is an error, never an empty list. */
export function mcpTools(repo = REPO) {
  const mod = path.join(repo, 'scanner', 'src', 'mcp', 'tools.js');
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', `import(${JSON.stringify(`file://${mod}`)}).then((m) => console.log(JSON.stringify(m.ALL_TOOLS.map((t) => ({ name: t.name, description: String(t.description || '').slice(0, 160) })))))`], { cwd: path.join(repo, 'scanner'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000 });
  return JSON.parse(out.trim().split('\n').pop());
}

export function collectSurfaces(repo = REPO) {
  const bin = read(repo, 'scanner/bin/agentic-security.js');
  const surfaces = [];
  const add = (kind, id, name, source, extra = {}) => surfaces.push({ kind, id, name, source, ...extra });

  for (const c of cliCommands(repo)) add('cli-command', c, `agentic-security ${c}`, 'scanner/bin/agentic-security.js');
  for (const f of stringSet(bin, 'SCAN_FORMATS')) add('report-format', f, `--format ${f}`, 'scanner/bin/agentic-security.js (SCAN_FORMATS)');
  for (const f of stringSet(bin, 'DATAFLOW_EXPORT_FORMATS')) add('dataflow-export-format', f, `dataflow export --format ${f}`, 'scanner/bin/agentic-security.js (DATAFLOW_EXPORT_FORMATS)');

  for (const t of mcpTools(repo)) add('mcp-tool', t.name, t.name, 'scanner/src/mcp/tools.js (ALL_TOOLS)');

  for (const f of readdirSync(path.join(repo, 'commands')).filter((x) => x.endsWith('.md')).sort()) {
    const id = f.replace(/\.md$/, '');
    add('slash-command', id, `/${id}`, `commands/${f}`, { description: frontmatter(read(repo, `commands/${f}`), 'description') });
  }
  const hooks = JSON.parse(read(repo, 'hooks/hooks.json'));
  for (const [event, entries] of Object.entries(hooks.hooks || {})) {
    for (const entry of entries) for (const h of entry.hooks || []) {
      const script = (/hooks\/([a-z0-9-]+\.js)/.exec(h.command || '') || [])[1] || h.command;
      add('hook', `${event}:${script}`, `${event}${entry.matcher ? ` (${entry.matcher})` : ''} ${script}`, 'hooks/hooks.json');
    }
  }
  for (const f of readdirSync(path.join(repo, 'agents')).filter((x) => x.endsWith('.md')).sort()) {
    const name = frontmatter(read(repo, `agents/${f}`), 'name');
    if (name) add('agent', name, name, `agents/${f}`);
  }
  for (const d of readdirSync(path.join(repo, 'skills'), { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort()) {
    if (exists(repo, `skills/${d}/SKILL.md`)) add('skill', d, d, `skills/${d}/SKILL.md`);
  }

  const integrations = read(repo, 'scanner/src/integrations/index.js');
  const targets = new Map();
  for (const m of integrations.matchAll(/^export (?:async )?function (build|post)([A-Z][A-Za-z]+)\(/gm)) {
    const target = m[2].replace(/(Digest|Issue|Incident|Event|Card|Comment)$/, '');
    if (!targets.has(target)) targets.set(target, new Set());
    targets.get(target).add(m[1]);
  }
  for (const [target, verbs] of [...targets.entries()].sort()) add('integration', target.toLowerCase(), target, 'scanner/src/integrations/index.js', { verbs: [...verbs].sort() });
  const tickets = read(repo, 'scanner/src/integrations/tickets.js');
  for (const m of new Set([...tickets.matchAll(/provider === '([a-z]+)'/g)].map((x) => x[1]))) add('ticket-provider', m, `tickets sync --provider ${m}`, 'scanner/src/integrations/tickets.js');

  const distributions = [
    ['npm-package', 'scanner/package.json', 'the published npm package and its bin aliases'],
    ['claude-plugin', '.claude-plugin/plugin.json', 'the Claude Code plugin manifest'],
    ['claude-marketplace', '.claude-plugin/marketplace.json', 'the Claude Code marketplace entry'],
    ['codex-plugin', '.codex-plugin/plugin.json', 'the Codex plugin manifest'],
    ['cursor-plugin', '.cursor-plugin/plugin.json', 'the Cursor plugin manifest'],
    ['gemini-extension', 'gemini-extension.json', 'the Gemini extension manifest'],
    ['vscode-extension', 'ide/vscode/package.json', 'the VS Code extension'],
    ['jetbrains-plugin', 'ide/jetbrains/build.gradle.kts', 'the JetBrains plugin'],
    ['nvim-plugin', 'ide/nvim/plugin/agentic-security.lua', 'the Neovim plugin'],
    ['nix-flake', 'flake.nix', 'the Nix flake'],
    ['pre-commit-hook', '.pre-commit-hooks.yaml', 'the pre-commit hook definition'],
  ];
  for (const [id, file, name] of distributions) if (exists(repo, file)) add('distribution', id, name, file);

  surfaces.sort((a, b) => (a.kind === b.kind ? (a.id < b.id ? -1 : 1) : (a.kind < b.kind ? -1 : 1)));
  return surfaces;
}

/** Every AGENTIC_SECURITY_* name the code reads or sets: a `process.env.` or `env.` member, an `env[...]` key, a quoted name, or a shell `$NAME`. A bare mention in prose is not one. */
export function environmentVariables(repo = REPO) {
  const names = new Set();
  const re = /(?:process\.env\.|\benv\.|env\[['"]|['"`]|\$\{?)(AGENTIC_SECURITY_[A-Z0-9_]+)/g;
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'node_modules' || e.name === 'dist' || e.name.startsWith('.')) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(?:m?js|cjs|py|sh|ya?ml|json)$/.test(e.name)) for (const m of readFileSync(p, 'utf8').matchAll(re)) if (!m[1].endsWith('_')) names.add(m[1]);
    }
  };
  for (const root of ['scanner/src', 'scanner/bin', 'scripts', 'hooks']) if (exists(repo, root)) walk(path.join(repo, root));
  return [...names].sort();
}

export function buildInventory(repo = REPO) {
  const surfaces = collectSurfaces(repo);
  const env = environmentVariables(repo);
  const byKind = {};
  for (const s of surfaces) byKind[s.kind] = (byKind[s.kind] || 0) + 1;
  return {
    schema: 'agentic-security/ga-program-inventory@1',
    note: 'Generated by scripts/ga-program/inventory.mjs from the source that ships each surface. Do not edit by hand. Environment variables are listed and counted, never mapped: they configure a surface, they are not one.',
    counts: { surfaces: surfaces.length, byKind, environmentVariables: env.length },
    surfaces,
    environmentVariables: env,
  };
}

export const surfaceKey = (s) => `${s.kind}:${s.id}`;

export function main(argv = process.argv.slice(2)) {
  const inv = buildInventory(REPO);
  const text = JSON.stringify(inv, null, 2).concat('\n');   // a data file, serialised whole; nothing from a scanned source is spliced into code
  if (argv.includes('--write')) {
    atomicWriteFile(path.join(REPO, INVENTORY_FILE), text, 0o644);
    console.log('wrote', INVENTORY_FILE + ':', inv.counts.surfaces, 'surfaces,', inv.counts.environmentVariables, 'environment variables');
    return 0;
  }
  if (argv.includes('--check')) {
    const committed = exists(REPO, INVENTORY_FILE) ? read(REPO, INVENTORY_FILE) : null;
    if (committed === text) {
      console.log(INVENTORY_FILE, 'is current:', inv.counts.surfaces, 'surfaces');
      return 0;
    }
    console.error(INVENTORY_FILE, committed === null ? 'is missing:' : 'is stale:', 'run node scripts/ga-program/inventory.mjs --write');
    return 1;
  }
  process.stdout.write(text);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(main());
