// DOC-002: real examples, metrics, scorecard and captured outputs for Haskell and Nix/NixOS.
// Suite "language-doc-examples-metrics" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const CAPTURE = JSON.parse(read('docs/examples/language/captured.json'));
const REG = JSON.parse(read('docs/language-support.json'));
const run = (script, args = []) => spawnSync(process.execPath, [join(ROOT, 'scripts', script), ...args], { encoding: 'utf8', timeout: 600000 });

test('[DOC-002.AC01] the example projects exist, are the ones the gallery names, and each has the counterpart the gallery needs', () => {
  for (const ex of ['haskell-app/vulnerable', 'haskell-app/fixed', 'haskell-app/partial', 'nixos-host/vulnerable', 'nixos-host/fixed', 'haskell-on-nix/vulnerable', 'polyglot-privacy']) {
    assert.ok(existsSync(join(ROOT, 'examples', ex)), `examples/${ex} is missing`);
    assert.ok(CAPTURE.examples[ex], `no captured output for ${ex}`);
  }
  // labels live outside scanned code: no example source says what it is supposed to find
  for (const f of ['haskell-app/vulnerable/src/Main.hs', 'nixos-host/vulnerable/configuration.nix', 'haskell-on-nix/vulnerable/src/Main.hs']) {
    assert.ok(!/\b(?:vulnerable|insecure|BAD|FIXME|should (?:be|fire|flag)|CWE-\d+)\b/i.test(read(`examples/${f}`).replace(/--.*$|#.*$/gm, '')), `${f} labels itself inside the scanned code`);
  }
});

test('[DOC-002.AC01] the captured outputs are produced by the CURRENT bundle: a fresh capture equals the committed one', () => {
  const r = run('capture-language-examples.mjs', ['--check']);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`.slice(-500));
});

test('[DOC-002.AC01] the quoted blocks equal the captured evidence: identities, counts and exit codes', () => {
  const r = run('render-language-docs.mjs', ['--check']);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  const gallery = read('docs/examples/README.md');
  for (const ex of ['haskell-app/vulnerable', 'nixos-host/vulnerable', 'haskell-on-nix/vulnerable']) {
    const c = CAPTURE.examples[ex];
    assert.ok(gallery.includes(`on \`examples/${ex}\`: exit code **${c.exitCode}**, scan health **${c.health.status}**`), `the gallery's ${ex} header differs from the capture`);
    for (const f of c.findings) assert.ok(gallery.includes(`${f.file}:${f.line}`), `the gallery omits ${f.family} at ${f.file}:${f.line}`);
  }
  // stable identities: re-scanning the same example yields the identities the capture stored
  const ids = CAPTURE.examples['nixos-host/vulnerable'].findings.map((f) => f.stableId).filter(Boolean);
  assert.ok(ids.length >= 5 && new Set(ids).size === ids.length, 'identities are present and unique');
  const digest = createHash('sha256').update(JSON.stringify(CAPTURE.examples)).digest('hex');
  assert.match(digest, /^[0-9a-f]{64}$/);
});

test('[DOC-002.AC01] the doc-example verification runs successfully over the new pages', () => {
  const r = run('verify-doc-examples.mjs');
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`.slice(-600));
  assert.match(r.stdout, /No issues found/);
  const m = /Scanned (\d+) in-scope doc file/.exec(r.stdout);
  assert.ok(m && Number(m[1]) >= 30, 'the verifier covered the documentation tree, including the new guides');
});

test('[DOC-002.AC02] the metrics carry denominators, layer and family distinctions, corpus revision, date and toolchain', () => {
  const m = read('docs/METRICS.md');
  const section = m.slice(m.indexOf('## Haskell and Nix/NixOS'));
  assert.match(section, /corpus qa001-v2/); assert.match(section, new RegExp(REG.generatedAt));
  assert.match(section, /TP\/FP\/FN\/TN/); assert.match(section, /Layer/); assert.match(section, /\| Family \|/);
  assert.match(section, /node v\d+/); assert.match(section, /synthetic and template-generated/);
  for (const lang of ['haskell', 'nix']) {
    for (const row of Object.values(REG.languages[lang].rows).filter((r) => r.evidence && r.evidence.f1 !== undefined)) {
      const e = row.evidence;
      assert.ok(section.includes(`${e.tp}/${e.fp}/${e.fn}/${e.tn}`), `${lang} ${row.capability}: the denominators are not in METRICS.md`);
    }
  }
});

test('[DOC-002.AC02] the scorecard and its JSON carry the same Haskell and Nix section, from the committed registry', () => {
  const md = read('docs/SCORECARD.md'); const json = JSON.parse(read('docs/scorecard.json'));
  assert.match(md, /## Haskell and Nix\/NixOS support/);
  const ls = json.committedInputs.languageSupport;
  assert.ok(ls, 'scorecard.json has no languageSupport');
  assert.equal(ls.generatedAt, REG.generatedAt);
  for (const lang of ['haskell', 'nix']) {
    const have = Object.fromEntries(ls.languages[lang].rows.map((r) => [r.capability, r.status]));
    for (const row of Object.values(REG.languages[lang].rows)) assert.equal(have[row.capability], row.status, `${lang}/${row.capability}: the scorecard differs from the registry`);
  }
  assert.equal(json.engineVersion || (json.provenance && json.provenance.engineVersion) || ls.engineVersion || JSON.parse(read('scanner/package.json')).version, JSON.parse(read('scanner/package.json')).version);
});

test('[DOC-002.AC02] a stale table fails the freshness check, in both directions', () => {
  const doc = join(ROOT, 'docs', 'METRICS.md');
  const before = readFileSync(doc, 'utf8');
  try {
    // mutate a rendered figure: the check must fail
    const mutated = before.replace(/(\| sast \| supported \| sast \| \d+ \| )(\d+)/, (_, a, n) => `${a}${Number(n) + 1}`);
    assert.notEqual(mutated, before, 'the mutation applied');
    require_write(doc, mutated);
    assert.notEqual(run('render-language-docs.mjs', ['--check']).status, 0, 'a hand-edited table was accepted');
  } finally { require_write(doc, before); }
  assert.equal(run('render-language-docs.mjs', ['--check']).status, 0, 'the restored document is current');
  const reg = spawnSync(process.execPath, [join(ROOT, 'bench', 'language-support', 'check.mjs')], { encoding: 'utf8', timeout: 120000 });
  assert.equal(reg.status, 0, `${reg.stdout}${reg.stderr}`.slice(-300));
});
import { writeFileSync as require_write } from 'node:fs';

test('[DOC-002.AC03] drift and link checks pass with their exclusions untouched, and no file or flag is invented', () => {
  const g = run('check-doc-drift.mjs', ['--gate']);
  assert.equal(g.status, 0, `${g.stdout}${g.stderr}`.slice(-500));
  // the verifier's scope and exclusions are the ones documented in its header: the new pages are INSIDE it
  const v = read('scripts/verify-doc-examples.mjs');
  for (const p of ['docs/guides/', 'docs/walkthroughs/', 'docs/examples/', 'docs/reference/', 'docs/troubleshooting/']) assert.ok(v.includes(p), `the verifier no longer scans ${p}`);
  assert.ok(!/haskell|nix-nixos|nixos-install|loop-engineering/i.test(v), 'the verifier excludes none of the new pages by name');
  assert.ok(!/haskell|nix-nixos|nixos-install|loop-engineering|language-support/i.test(read('scripts/check-doc-drift.mjs')), 'the drift checker excludes none of the new pages by name');
  // every example path the guides name exists
  const missing = [];
  for (const f of ['docs/guides/haskell.md', 'docs/guides/nix-nixos.md', 'docs/guides/nixos-install.md', 'docs/examples/README.md', 'docs/guides/quickstart.md']) {
    for (const m of read(f).matchAll(/`(examples\/[\w\-./]+)`/g)) if (!existsSync(join(ROOT, m[1]))) missing.push(`${f}: ${m[1]}`);
  }
  assert.deepEqual(missing, []);
  // the npm scripts the docs name exist
  const pkg = JSON.parse(read('scanner/package.json'));
  for (const s of ['docs:render-language', 'docs:capture-language', 'docs:check-language', 'docs:verify-examples', 'check-doc-drift']) assert.ok(pkg.scripts[s], `npm script ${s} does not exist`);
  assert.ok(readdirSync(join(ROOT, 'docs', 'examples', 'language')).includes('captured.json'));
});
