// PRD F11.1 remainder — the IDE distributions, gated.
//
// "The engine is gated heavily; the surfaces that carry it to users are not
// gated at all. The consequence is asymmetric: a detection regression is caught
// by four benches, while a broken IDE extension ships silently."
//
// It had. `ide/vscode/src/extension.ts` looked for the scanner bundle under
//
//     ~/.claude/plugins/cache/clearcapabilities/agentic-security/0.1.0/scanner/dist/…
//
// and Claude Code caches a plugin under its PLUGIN version — 0.128.2, 0.136.9,
// 0.139.1 on the machine this was found on, never 0.1.0. `0.1.0` is the VS Code
// extension's own version from its package.json, pasted into the wrong path. So
// the fallback could not resolve on ANY install and every user got "scanner not
// found. Set agenticSecurity.scannerPath in settings." Nothing tested it,
// because the function read `vscode.workspace` and could not be imported
// outside a VS Code host.
//
// Three kinds of check live here, and the split is deliberate:
//
//   1. BEHAVIOUR — the resolver is now a pure function and is driven directly.
//   2. WIRING — the things a distribution promises the outside world (a command
//      id, a binary name, a factory class) must exist on the other side. Every
//      one of these is a real user-visible break and none needs a running IDE.
//   3. FRESHNESS — the committed VS Code bundle must reflect the source.
//
// What is NOT here, stated so the gap is visible rather than implied: no
// gradle build of the JetBrains plugin (needs a JDK and network), no `vsce
// package`, no Neovim host. Those belong in a packaging job, not the unit gate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveScanner } from '../../ide/vscode/src/resolve-scanner.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const IDE = path.join(REPO, 'ide');
const VSCODE = path.join(IDE, 'vscode');

const BUNDLE_TAIL = path.join('scanner', 'dist', 'agentic-security.mjs');

// A fake filesystem: the set of paths that "exist", plus directory listings.
// Injected rather than written to disk so these run in microseconds and cannot
// be perturbed by whatever the developer happens to have installed.
function fakeFs(paths, dirs = {}) {
  const set = new Set(paths);
  return {
    exists: (p) => set.has(p),
    readdir: (p) => { if (!dirs[p]) throw new Error('ENOENT'); return dirs[p]; },
  };
}

// ─── 1. Resolver behaviour ───────────────────────────────────────────────────

test('resolveScanner: an explicit setting wins over every heuristic', () => {
  const explicit = '/opt/custom/agentic-security.mjs';
  const home = '/home/u';
  const cached = path.join(home, '.claude', 'plugins', 'cache', 'clearcapabilities', 'agentic-security', '0.140.0', BUNDLE_TAIL);
  const hit = resolveScanner({
    explicit, home,
    ...fakeFs([explicit, cached], { [path.join(home, '.claude', 'plugins', 'cache', 'clearcapabilities', 'agentic-security')]: ['0.140.0'] }),
  });
  assert.equal(hit.path, explicit);
  assert.equal(hit.source, 'setting');
});

test('resolveScanner: an explicit setting that does not exist falls through', () => {
  const home = '/home/u';
  const cacheDir = path.join(home, '.claude', 'plugins', 'cache', 'clearcapabilities', 'agentic-security');
  const cached = path.join(cacheDir, '0.140.0', BUNDLE_TAIL);
  const hit = resolveScanner({
    explicit: '/opt/typo/nope.mjs', home,
    ...fakeFs([cached], { [cacheDir]: ['0.140.0'] }),
  });
  assert.equal(hit.path, cached);
});

test('resolveScanner: CLAUDE_PLUGIN_ROOT needs no version guess at all', () => {
  const root = '/plugins/agentic-security';
  const p = path.join(root, BUNDLE_TAIL);
  const hit = resolveScanner({ pluginRoot: root, ...fakeFs([p]) });
  assert.equal(hit.path, p);
  assert.equal(hit.source, 'plugin-root');
});

test('resolveScanner: the plugin cache version is DISCOVERED, and the newest wins', () => {
  const home = '/home/u';
  const cacheDir = path.join(home, '.claude', 'plugins', 'cache', 'clearcapabilities', 'agentic-security');
  // The real layout observed on a long-lived install: several versions side by
  // side. 0.140.0 must beat 0.99.0 — a lexical sort gets that backwards, which
  // would pin every user to whichever old version sorted highest as a string.
  const versions = ['0.99.0', '0.128.2', '0.140.0', '0.136.9'];
  const present = versions.map((v) => path.join(cacheDir, v, BUNDLE_TAIL));
  const hit = resolveScanner({ home, ...fakeFs(present, { [cacheDir]: versions }) });
  assert.equal(hit.path, path.join(cacheDir, '0.140.0', BUNDLE_TAIL));
  assert.equal(hit.source, 'plugin-cache@0.140.0');
});

test('resolveScanner: a cache entry with no bundle is skipped, not returned', () => {
  const home = '/home/u';
  const cacheDir = path.join(home, '.claude', 'plugins', 'cache', 'clearcapabilities', 'agentic-security');
  const versions = ['0.140.0', '0.139.1'];
  // The newest directory exists but was interrupted mid-unpack — no bundle.
  const hit = resolveScanner({
    home,
    ...fakeFs([path.join(cacheDir, '0.139.1', BUNDLE_TAIL)], { [cacheDir]: versions }),
  });
  assert.equal(hit.path, path.join(cacheDir, '0.139.1', BUNDLE_TAIL));
});

test('resolveScanner: falls back to an ordinary npm install in the workspace', () => {
  const ws = '/w/proj';
  const p = path.join(ws, 'node_modules', 'agentic-security', 'dist', 'agentic-security.mjs');
  const hit = resolveScanner({ workspace: ws, ...fakeFs([p]) });
  assert.equal(hit.source, 'workspace-node-modules');
});

test('resolveScanner: returns null when nothing is installed', () => {
  assert.equal(resolveScanner({ home: '/home/u', workspace: '/w', ...fakeFs([]) }), null);
});

test('resolveScanner: an unreadable cache directory is not fatal', () => {
  // readdir throws (no such dir / no permission). The resolver must fall
  // through to the next strategy rather than take the extension down.
  const ws = '/w';
  const p = path.join(ws, 'node_modules', 'agentic-security', 'dist', 'agentic-security.mjs');
  const hit = resolveScanner({ home: '/nope', workspace: ws, ...fakeFs([p]) });
  assert.equal(hit.path, p);
});

// ─── 2. Wiring: what each distribution promises the outside world ────────────

test('no IDE source hardcodes a plugin-cache version segment', () => {
  // The regression pin for the defect above. Any literal version between the
  // `agentic-security` cache segment and `scanner/dist` is wrong by
  // construction — the cache is keyed by whatever version is installed, which
  // this repo cannot know at build time.
  const offenders = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'node_modules' || e.name === 'dist' || e.name === '.agentic-security') continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { walk(p); continue; }
      if (!/\.(ts|js|mjs|lua|kt|json|xml)$/.test(e.name)) continue;
      const body = fs.readFileSync(p, 'utf8');
      if (/agentic-security['"\/\\,\s]+[^\n]{0,20}\b\d+\.\d+\.\d+\b[^\n]{0,20}scanner/.test(body)) {
        offenders.push(path.relative(REPO, p));
      }
    }
  };
  walk(IDE);
  assert.deepEqual(offenders, [], `hardcoded plugin-cache version in: ${offenders.join(', ')}`);
});

test('every VS Code command declared in package.json is registered in the source', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(VSCODE, 'package.json'), 'utf8'));
  const declared = (pkg.contributes?.commands || []).map((c) => c.command);
  assert.ok(declared.length > 0, 'the extension should contribute at least one command');
  const src = fs.readFileSync(path.join(VSCODE, 'src', 'extension.ts'), 'utf8');
  for (const id of declared) {
    // A declared-but-unregistered command is not a silent failure: VS Code
    // shows it in the palette and then errors "command not found" on use.
    assert.ok(src.includes(`'${id}'`), `command "${id}" is contributed but never registered`);
  }
  // And the reverse — a registered command nobody can invoke is dead weight.
  for (const m of src.matchAll(/registerCommand\(\s*'([^']+)'/g)) {
    assert.ok(declared.includes(m[1]), `command "${m[1]}" is registered but not contributed in package.json`);
  }
});

test('every activationEvent onCommand refers to a contributed command', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(VSCODE, 'package.json'), 'utf8'));
  const declared = new Set((pkg.contributes?.commands || []).map((c) => c.command));
  for (const ev of pkg.activationEvents || []) {
    if (!ev.startsWith('onCommand:')) continue;
    const id = ev.slice('onCommand:'.length);
    assert.ok(declared.has(id), `activationEvent "${ev}" names a command that is not contributed`);
  }
});

test('the LSP command the Neovim and JetBrains plugins launch is a declared bin', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner', 'package.json'), 'utf8'));
  // Both distributions spawn a bare command name and rely entirely on it being
  // on PATH after `npm i -g`. If the bin is renamed or dropped, both plugins
  // fail at startup with nothing in this repo noticing.
  const nvim = fs.readFileSync(path.join(IDE, 'nvim', 'lua', 'agentic-security', 'init.lua'), 'utf8');
  const kotlin = fs.readFileSync(path.join(IDE, 'jetbrains', 'src', 'main', 'kotlin', 'AgenticSecurityServerFactory.kt'), 'utf8');

  const names = new Set();
  for (const m of nvim.matchAll(/"(agentic-security[a-z-]*)"/g)) names.add(m[1]);
  for (const m of kotlin.matchAll(/"(agentic-security[a-z-]*)"/g)) names.add(m[1]);
  assert.ok(names.has('agentic-security-lsp'), 'expected both plugins to launch agentic-security-lsp');

  for (const name of names) {
    assert.ok(pkg.bin[name], `${name} is launched by an IDE plugin but is not a declared bin`);
    const target = path.join(REPO, 'scanner', pkg.bin[name]);
    assert.ok(fs.existsSync(target), `bin ${name} → ${pkg.bin[name]} does not exist`);
  }
});

test('the npm package the IDE READMEs tell users to install is this package', () => {
  const pkgName = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner', 'package.json'), 'utf8')).name;
  for (const dist of ['nvim', 'jetbrains', 'vscode']) {
    const readme = path.join(IDE, dist, 'README.md');
    if (!fs.existsSync(readme)) continue;
    const body = fs.readFileSync(readme, 'utf8');
    for (const m of body.matchAll(/npm i(?:nstall)? -g\s+(\S+)/g)) {
      assert.equal(m[1], pkgName, `${dist}/README.md tells users to install "${m[1]}"`);
    }
  }
});

test('the JetBrains plugin.xml factory class exists in the Kotlin source', () => {
  const xml = fs.readFileSync(path.join(IDE, 'jetbrains', 'src', 'main', 'resources', 'META-INF', 'plugin.xml'), 'utf8');
  const m = xml.match(/factoryClass="([^"]+)"/);
  assert.ok(m, 'plugin.xml must declare a factoryClass');
  const fqcn = m[1];
  const pkgName = fqcn.slice(0, fqcn.lastIndexOf('.'));
  const className = fqcn.slice(fqcn.lastIndexOf('.') + 1);
  const kt = fs.readFileSync(path.join(IDE, 'jetbrains', 'src', 'main', 'kotlin', 'AgenticSecurityServerFactory.kt'), 'utf8');
  // A factoryClass that does not resolve makes the plugin fail to load with a
  // ClassNotFoundException at IDE startup — the loudest possible break, and
  // one nothing here would otherwise catch.
  assert.ok(kt.includes(`package ${pkgName}`), `plugin.xml names package ${pkgName}, Kotlin declares something else`);
  assert.ok(new RegExp(`class\\s+${className}\\b`).test(kt), `plugin.xml names class ${className}, not found in the Kotlin source`);
});

// ─── 3. Freshness of the committed VS Code bundle ────────────────────────────

test('the committed VS Code bundle reflects the current resolution logic', () => {
  const bundle = fs.readFileSync(path.join(VSCODE, 'dist', 'extension.js'), 'utf8');
  // A byte-exact rebuild comparison lives in CI, where `npm install` has run
  // in ide/vscode and esbuild is available. This is the part that can be
  // asserted from the scanner's own test suite with no extra dependency: the
  // shipped bundle must contain the resolution strategies the source
  // introduces, and must not contain the dead path it replaced.
  assert.ok(bundle.includes('CLAUDE_PLUGIN_ROOT'), 'bundle is stale — rebuild with `npm run build` in ide/vscode');
  assert.ok(!/agentic-security["'\/\\,\s]+[^\n]{0,20}0\.1\.0/.test(bundle), 'bundle still carries the dead 0.1.0 cache path');
  const pkg = JSON.parse(fs.readFileSync(path.join(VSCODE, 'package.json'), 'utf8'));
  for (const c of pkg.contributes?.commands || []) {
    assert.ok(bundle.includes(c.command), `bundle does not register "${c.command}" — rebuild it`);
  }
});
