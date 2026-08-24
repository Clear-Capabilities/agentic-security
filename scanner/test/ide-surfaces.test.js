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

// ─── 3. The source carries the current resolution logic ─────────────────────

test('no dead resolution path survives in the VS Code source', () => {
  // NOT the built bundle. `ide/vscode/dist/` is gitignored on purpose — the
  // extension is packaged by `vsce`, not committed like `scanner/dist/` is.
  //
  // The first version of this test read `dist/extension.js`, passed locally
  // because the file happened to exist on this machine, and failed in CI with
  // ENOENT. Worse, the CI job it was paired with ran
  // `git diff --exit-code dist/extension.js` on an UNTRACKED file, which can
  // never report a difference — a vacuous gate that looked like coverage.
  //
  // So the source is what is asserted here, and the CI job now builds the
  // extension and inspects the BUILT output. Each half checks the thing it can
  // actually see.
  const resolver = fs.readFileSync(path.join(VSCODE, 'src', 'resolve-scanner.mjs'), 'utf8');
  const ext = fs.readFileSync(path.join(VSCODE, 'src', 'extension.ts'), 'utf8');

  assert.ok(ext.includes('CLAUDE_PLUGIN_ROOT'), 'the extension must pass CLAUDE_PLUGIN_ROOT to the resolver');
  assert.ok(resolver.includes('CLAUDE_PLUGIN_ROOT') || resolver.includes('pluginRoot'),
    'the resolver must accept a plugin root');
  // The version segment is discovered, never written down.
  assert.ok(/readdir/.test(resolver), 'the resolver must enumerate the cache directory rather than guess a version');
  // The "is a version hardcoded" question is NOT re-asked here — the dedicated
  // test above enforces it across all of `ide/`, with a pattern tight enough to
  // ignore prose. A looser second copy of that check matched this file's own
  // explanatory comment, which is how an over-broad assertion earns its keep as
  // a lesson rather than a test.
});

// ─── 4. The JetBrains build configuration agrees with itself ────────────────
//
// The `jetbrains-plugin` CI job is INFORMATIONAL — it downloads a full IntelliJ
// distribution, so a red result there is more often JetBrains' CDN than this
// code. The cost of that classification showed up on 2026-08-24: the job had
// been failing on a REAL defect (`Plugin 'com.redhat.devtools.lsp4ij:0.19.4' is
// not compatible to: IC-233.15026.9` — LSP4IJ dropped IC-233 at 0.18.0) and
// nothing was blocked by it, so it stayed red.
//
// The answer is not to make a network-bound build a release blocker. It is to
// move everything that can be checked WITHOUT the network into the blocking
// offline gate. These are those checks.

const JETBRAINS = path.join(IDE, 'jetbrains');
const readJb = (...p) => fs.readFileSync(path.join(JETBRAINS, ...p), 'utf8');

test('the JDK CI provisions is the JDK the JetBrains build asks for', () => {
  // The exact bug class this exists for: the build compiled against Java 17 for
  // an IntelliJ Platform that requires 21, produced a distribution zip, and
  // exited 0. Only `verifyPluginProjectConfiguration` said the artifact was
  // wrong, and only in text nothing was reading.
  const gradle = readJb('build.gradle.kts');
  const toolchain = gradle.match(/jvmToolchain\((\d+)\)/);
  assert.ok(toolchain, 'build.gradle.kts must pin a jvmToolchain');

  const ci = fs.readFileSync(path.join(REPO, '.github', 'workflows', 'ci.yml'), 'utf8');
  const job = ci.slice(ci.indexOf('  jetbrains-plugin:'));
  const end = job.indexOf('\n  ', job.indexOf('steps:'));
  const jobBody = end === -1 ? job : job.slice(0, job.indexOf('\n\n  '));
  const javaVersion = jobBody.match(/java-version:\s*'?(\d+)'?/);
  assert.ok(javaVersion, 'the jetbrains-plugin job must pin a java-version');
  assert.equal(
    javaVersion[1], toolchain[1],
    `CI provisions JDK ${javaVersion[1]} but the build asks for ${toolchain[1]} — `
    + 'the build will either fail on a missing toolchain or silently compile for the wrong platform',
  );
});

test('the JetBrains plugin does not resurrect the superseded Gradle plugin', () => {
  const gradle = readJb('build.gradle.kts');
  // `org.jetbrains.intellij` 1.x cannot be applied by Gradle 9 at all
  // (`Type DefaultArtifactPublicationSet not present`), which is why CI used to
  // pin Gradle 8.10. The 2.x plugin has a different id; matching on the bare
  // old id must not also match the new one.
  assert.ok(!/id\("org\.jetbrains\.intellij"\)/.test(gradle),
    'org.jetbrains.intellij (1.x) is superseded and forces a Gradle version pin — use org.jetbrains.intellij.platform');
  assert.match(gradle, /id\("org\.jetbrains\.intellij\.platform"\)/);
});

test('the Gradle wrapper is committed and pins its distribution by checksum', () => {
  // The README told people to run `./gradlew` for a long time while no wrapper
  // existed, so CI pinned a Gradle version in the workflow instead and the two
  // could drift. A wrapper that downloads an unverified distribution is a
  // supply-chain hole in a security tool's own build.
  for (const f of ['gradlew', 'gradle/wrapper/gradle-wrapper.jar', 'gradle/wrapper/gradle-wrapper.properties']) {
    assert.ok(fs.existsSync(path.join(JETBRAINS, f)), `${f} is missing — README tells contributors to run ./gradlew`);
  }
  const props = readJb('gradle', 'wrapper', 'gradle-wrapper.properties');
  assert.match(props, /^distributionSha256Sum=[0-9a-f]{64}$/m,
    'the wrapper must verify the Gradle distribution it downloads');
  assert.ok((fs.statSync(path.join(JETBRAINS, 'gradlew')).mode & 0o111) !== 0,
    'gradlew must be executable, or ./gradlew fails with permission denied');
});

test('the compatibility floor is the same number in the build and the README', () => {
  const since = readJb('build.gradle.kts').match(/sinceBuild\s*=\s*"(\d+)"/);
  assert.ok(since, 'build.gradle.kts must declare a sinceBuild');
  const readme = readJb('README.md');
  assert.ok(
    readme.includes(`build ${since[1]}`),
    `build.gradle.kts declares sinceBuild ${since[1]}; README.md does not say so. `
    + 'A support floor users read and a support floor the artifact declares must be one number.',
  );
});

test('the LSP4IJ dependency is not pinned below the platform floor', () => {
  // LSP4IJ 0.18.0 is the first release requiring 242. Pairing a >=0.18 LSP4IJ
  // with a sinceBuild under 242 is the precise configuration that broke the
  // build, and it fails at dependency resolution — after the download, in CI,
  // not here.
  const gradle = readJb('build.gradle.kts');
  const dep = gradle.match(/plugin\("com\.redhat\.devtools\.lsp4ij:(\d+)\.(\d+)\.(\d+)"\)/);
  assert.ok(dep, 'build.gradle.kts must pin an LSP4IJ version');
  const [, major, minor] = dep.map(Number);
  const since = Number(gradle.match(/sinceBuild\s*=\s*"(\d+)"/)[1]);
  if (major > 0 || minor >= 18) {
    assert.ok(since >= 242,
      `LSP4IJ ${dep[1]}.${dep[2]}.${dep[3]} requires platform 242+, but sinceBuild is ${since}`);
  }
});

test('no CI step pipes into tee without pipefail', () => {
  // Not an IDE assertion, but it is here because this file's job is "the
  // surfaces are gated" and it was introduced BY a gate added in this file's
  // name. `run:` steps default to `bash -e {0}`, which has no pipefail, so the
  // exit status of `cmd | tee log` is TEE's — always 0. Both pipe-to-tee steps
  // in this workflow had it: the JetBrains build (a failed build reporting
  // success) and determinism-attest, a BLOCKING job that would have uploaded an
  // empty attestation for determinism-compare to compare against.
  //
  // Demonstrated, not assumed: `bash -e -c 'false | tee /dev/null'` exits 0.
  const ci = fs.readFileSync(path.join(REPO, '.github', 'workflows', 'ci.yml'), 'utf8');
  // Deliberately a text scan rather than a YAML parse: no yaml dependency is
  // available here, and the pattern is unambiguous in the raw file.
  const offenders = [];
  const lines = ci.split('\n');
  for (const [i, line] of lines.entries()) {
    // A comment is neither a pipeline nor an offender. This one bit twice: the
    // check first matched `pipefail` inside a comment and passed when it should
    // have failed, then matched `| tee` inside a comment and failed when it
    // should have passed. Both directions had to be exercised to find both.
    if (/^\s*#/.test(line)) continue;
    if (!/\|\s*tee\s/.test(line)) continue;
    // Look back over the enclosing `run:` block for a pipefail. A single-line
    // `run: cmd | tee x` has no room for one, so it is an offender by shape.
    // COMMENTS ARE STRIPPED FIRST, and that is the whole trick. The first
    // version of this check searched the raw window, and the step it guards
    // carries a comment explaining why `set -o pipefail` is there — so deleting
    // the actual pipefail line left the comment behind, the regex matched it,
    // and the negative control passed. A guard fooled by its own documentation
    // is worse than no guard: it reads as coverage.
    const window = lines.slice(Math.max(0, i - 8), i + 1)
      .filter((l) => !/^\s*#/.test(l))
      .join('\n');
    if (!/set -o pipefail/.test(window)) offenders.push(`line ${i + 1}: ${line.trim()}`);
  }
  assert.deepEqual(offenders, [],
    `these CI steps pipe into tee without pipefail, so a failing command reports success:\n  ${offenders.join('\n  ')}`);
});
