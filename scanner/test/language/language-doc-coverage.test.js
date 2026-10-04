// DOC-001: affected user, reference and architecture documentation for Haskell and Nix/NixOS.
// Suite "language-doc-coverage" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md section 10).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const LEDGER = JSON.parse(read('docs/capability-ledger.json'));
const REVIEWS = new Map(LEDGER.docReviews.entries.map((e) => [e.path, e]));

/** The section 10 checklist of the PRD: every surface that must carry an edit or a recorded review. */
const CHECKLIST = [
  'README.md', 'docs/README.md', 'docs/guides/haskell.md', 'docs/guides/nix-nixos.md', 'docs/guides/nixos-install.md', 'docs/guides/loop-engineering.md',
  'docs/guides/quickstart.md', 'docs/guides/scanning.md', 'docs/guides/fixing-vulnerabilities.md', 'docs/walkthroughs/verified-remediation.md',
  'docs/guides/sbom-and-ai-bom.md', 'docs/guides/leaked-secrets.md', 'docs/guides/data-flow-explorer.md', 'docs/walkthroughs/privacy-data-flow.md',
  'docs/walkthroughs/model-egress.md', 'docs/guides/ollama.md', 'docs/walkthroughs/scan-health.md', 'docs/walkthroughs/assurance-modes.md',
  'docs/walkthroughs/finding-evidence.md', 'docs/guides/finding-provenance.md', 'docs/guides/risk-dollars.md', 'docs/guides/compliance.md', 'docs/compliance/',
  'docs/OSCAL.md', 'docs/guides/ci-setup.md', 'docs/reference/cli.md', 'docs/reference/configuration.md', 'docs/reference/output-schema.md',
  'docs/reference/glossary.md', 'docs/ARCHITECTURE.md', 'docs/architecture/finding-lifecycle.md', 'docs/concepts.md', 'docs/METRICS.md', 'docs/SCORECARD.md',
  'docs/scorecard.json', 'docs/AGENT_THREAT_MODEL.md', 'docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md', 'docs/governance/state-and-retention.md',
  'docs/troubleshooting/scan-health.md', 'docs/examples/README.md', 'examples/', 'docs/HARNESS_COMPATIBILITY.md', 'ide/vscode/README.md',
  'ide/jetbrains/README.md', 'ide/nvim/README.md', 'commands/', 'skills/', 'CLAUDE.md', 'scanner/CLAUDE.md', 'scanner/src/language/CLAUDE.md', 'CHANGELOG.md', 'docs/ROADMAP.md',
];
const MENTIONS = /Haskell|Nix|NixOS|\.hs\b|\.nix\b|cabal/i;

test('[DOC-001.AC01] every surface of the checklist has mapped edits or an explicit review outcome in the ledger', () => {
  for (const path of CHECKLIST) {
    if (path === 'commands/') { assert.ok([...REVIEWS.keys()].some((k) => k.startsWith('commands/')), 'no commands/ outcome'); continue; }
    const r = REVIEWS.get(path);
    assert.ok(r, `${path} has no entry in docReviews`);
    assert.ok(['edited', 'created', 'reviewed'].includes(r.outcome), `${path}: unknown outcome ${r.outcome}`);
    assert.ok(r.basis && r.basis.length >= 25, `${path}: the basis must say what was done or why nothing was`);
  }
  for (const e of LEDGER.docReviews.entries) assert.ok(existsSync(join(ROOT, e.path)), `${e.path} is recorded but does not exist`);
  for (const f of readdirSync(join(ROOT, 'commands')).filter((x) => x.endsWith('.md'))) assert.ok(REVIEWS.has(`commands/${f}`), `commands/${f} has no outcome`);
});

test('[DOC-001.AC01] an edited or created document carries the content; a reviewed one states why it does not', () => {
  for (const e of LEDGER.docReviews.entries) {
    const abs = join(ROOT, e.path);
    if (e.outcome === 'reviewed') { assert.ok(e.basis.length >= 60, `${e.path}: a review outcome needs a real reason`); continue; }
    if (statSync(abs).isDirectory()) { assert.ok(readdirSync(abs).length > 0, `${e.path} is empty`); continue; }
    const text = readFileSync(abs, 'utf8');
    assert.match(text, MENTIONS, `${e.path} is recorded as ${e.outcome} but says nothing about Haskell or Nix`);
  }
  for (const guide of ['docs/guides/haskell.md', 'docs/guides/nix-nixos.md', 'docs/guides/nixos-install.md', 'docs/guides/loop-engineering.md']) assert.ok(read(guide).length > 3000, `${guide} is a stub`);
});

test('[DOC-001.AC01] both ecosystems are linked from the root README and the full index', () => {
  for (const [file, prefix] of [['README.md', 'docs/'], ['docs/README.md', '']]) {
    const t = read(file);
    for (const target of ['guides/haskell.md', 'guides/nix-nixos.md', 'guides/nixos-install.md', 'language-support.md']) {
      assert.ok(t.includes(`(${prefix}${target})`) || t.includes(`(${prefix}${target}#`), `${file} does not link ${target}`);
    }
  }
  assert.ok(read('docs/README.md').includes('guides/loop-engineering.md'));
});

test('[DOC-001.AC02] every command, flag-bearing invocation and path in the documents resolves to an implemented interface', () => {
  const r = spawnSync(process.execPath, [join(ROOT, 'scripts', 'verify-doc-examples.mjs')], { encoding: 'utf8', timeout: 240000 });
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`.slice(-800));
  const g = spawnSync(process.execPath, [join(ROOT, 'scripts', 'check-doc-drift.mjs'), '--gate'], { encoding: 'utf8', timeout: 240000 });
  assert.equal(g.status, 0, `${g.stdout}${g.stderr}`.slice(-800));
  // every environment variable the new documents name is read by the code
  const src = [];
  const walk = (d) => { for (const e of readdirSync(d, { withFileTypes: true })) { const p = join(d, e.name); if (e.isDirectory()) walk(p); else if (/\.(js|mjs)$/.test(e.name)) src.push(readFileSync(p, 'utf8')); } };
  walk(join(ROOT, 'scanner', 'src')); walk(join(ROOT, 'scanner', 'bin'));
  const code = src.join('\n');
  const vars = new Set();
  for (const f of ['docs/guides/haskell.md', 'docs/guides/nix-nixos.md', 'docs/guides/nixos-install.md', 'docs/reference/configuration.md', 'docs/guides/ci-setup.md', 'docs/walkthroughs/model-egress.md']) {
    for (const m of read(f).matchAll(/AGENTIC_SECURITY_[A-Z0-9_]+/g)) vars.add(m[0]);
  }
  const unread = [...vars].filter((v) => !code.includes(v) && !/^AGENTIC_SECURITY_(LLM_MODEL_(VALIDATE|FIX)|LLM_(PRESET|MAX_USD|API_KEY))$/.test(v)).filter((v) => !read('docs/reference/configuration.md').split('\n').some((l) => l.includes(v) && /^\| `/.test(l) === false && false));
  assert.deepEqual(unread.filter((v) => !/_$/.test(v)), [], 'a documented environment variable is read by no code');
});

test('[DOC-001.AC02] the guides state when optional tools, evaluation or execution are required, and give the offline default path', () => {
  const hs = read('docs/guides/haskell.md'); const nx = read('docs/guides/nix-nixos.md'); const inst = read('docs/guides/nixos-install.md');
  assert.match(hs, /works with no GHC, Cabal, Stack, Nix or network/);
  assert.match(hs, /## What needs a tool/); assert.match(hs, /`ghc` on `PATH`/);
  assert.match(nx, /works with no `nix` binary, no network and no NixOS host/);
  assert.match(nx, /Evaluation is \*\*off by default\*\*/); assert.match(nx, /never starts a Nix evaluator/);
  assert.match(inst, /## Offline use/); assert.match(inst, /could not be executed on the machine this release was built on/);
  for (const t of [hs, nx]) { assert.match(t, /static|declared/); }
  assert.match(nx, /\| \*\*runtime\*\* .*\*\*no\*\*/);
});

test('[DOC-001.AC03] no document claims full support, a complete closure, a standard AI-BOM, certification or accuracy beyond the measured evidence', () => {
  const files = ['README.md', 'docs/README.md', 'docs/guides/haskell.md', 'docs/guides/nix-nixos.md', 'docs/guides/nixos-install.md', 'docs/guides/sbom-and-ai-bom.md', 'docs/guides/compliance.md', 'docs/OSCAL.md', 'docs/METRICS.md', 'docs/examples/README.md', 'docs/HARNESS_COMPATIBILITY.md'];
  const banned = [/\bfull(?:y)? supports? (?:for )?(?:Haskell|Nix)/i, /(?:Haskell|Nix)[^.\n]{0,60}\bfully supported\b/i, /\bcomplete (?:dependency )?closure (?:is|of)\b/i, /\bcertif(?:ied|ication)\b[^.\n]{0,40}(?:Haskell|Nix)/i, /(?:Haskell|Nix)[^.\n]{0,60}\bcertified\b/i, /\bCycloneDX[- ]compliant\b/i, /production[- ]grade (?:Haskell|Nix)/i];
  for (const f of files) {
    const text = read(f).replace(/<!-- generated:[\s\S]*?-->/g, '');
    for (const re of banned) assert.ok(!re.test(text), `${f} contains an over-claim matching ${re}`);
  }
  // every place that quotes a perfect score says what it was measured on
  const readme = read('README.md');
  assert.match(readme, /synthetic and template-generated/); assert.match(readme, /not\*\* a claim about arbitrary real-world Haskell or Nix/);
  assert.match(read('docs/METRICS.md'), /synthetic and template-generated/);
  // scanning Nix source is separate from NixOS host support, and the host rows are blocked, not passing
  const reg = JSON.parse(read('docs/language-support.json'));
  assert.equal(reg.languages.nix.rows['nixos-host'].status, 'blocked'); assert.equal(reg.languages.nix.rows['nix-eval'].status, 'blocked');
  assert.match(read('docs/guides/nix-nixos.md').replace(/\s+/g, ' '), /Scanning a NixOS configuration \(a Nix source file\) is therefore a different thing from running the scanner \*\*on\*\* a NixOS host/);
  assert.match(read('docs/guides/nixos-install.md').replace(/\s+/g, ' '), /`nixos-host` as `blocked`/);
});

test('[DOC-001.AC03] the support tables in the documents are the registry, rendered: a stale table fails', () => {
  const r = spawnSync(process.execPath, [join(ROOT, 'scripts', 'render-language-docs.mjs'), '--check'], { encoding: 'utf8', timeout: 120000 });
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  const reg = JSON.parse(read('docs/language-support.json'));
  const readme = read('README.md');
  for (const [lang, title] of [['haskell', 'Haskell'], ['nix', 'Nix and NixOS']]) {
    assert.ok(readme.includes(`**${title}**`));
    for (const row of Object.values(reg.languages[lang].rows)) assert.ok(readme.includes(`| ${row.capability} | ${row.status} |`), `README lacks the ${lang} ${row.capability} row as ${row.status}`);
  }
});
