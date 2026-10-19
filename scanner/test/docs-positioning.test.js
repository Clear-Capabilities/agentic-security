// Positioning-docs gate (autonomous-assurance docs repositioning, PRD sections 5, 18 and 22).
//
// Every rule is proved in BOTH directions: it passes on a good input and fails on a deliberately bad one, because a
// gate that "looks like it ran" and never fails is worthless. The last group runs the real checkout through the
// same functions and the real CLI (exit code captured), so the committed docs are held to the committed registry.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  MATURITIES, STAGES, CANONICAL_CHAIN,
  parseRegistry, loadRegistry, validateRegistry, renderTable, renderLifecycleTable, renderCounts, checkTables,
  checkMaturityConsistency, checkOverclaims, checkCommands, checkLifecycleOrder, checkStyle, checkLinks,
  checkVisuals, checkNavigation, checkReadmeHero, checkPositioningDocs, slug,
  checkGaBar, checkLimitsFreshness, sectionByAnchor, LIMITS_MAX_AGE_DAYS,
} from '../../scripts/check-positioning-docs.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const SCRIPT = path.join(REPO, 'scripts', 'check-positioning-docs.mjs');

function mkRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'positioning-'));
  for (const [rel, body] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, body);
  }
  return dir;
}
const rules = fs => fs.map(f => f.rule);

const STAGE_YAML = STAGES.map(s => `  - id: ${s}\n    question: Q ${s}?\n    page: docs/${s}/README.md`).join('\n');
function registryYaml(caps) {
  return `lifecycle:\n${STAGE_YAML}\n\ncapabilities:\n${caps}\n`;
}
const GOOD_CAP = `  - id: alpha-scan
    name: Alpha scan
    lifecycleStages: [discover]
    maturity: GA
    establishes: A candidate at a location.
    docs:
      - docs/alpha.md
    evidence:
      - src/alpha.js
`;
const baseFiles = () => ({
  'docs/alpha.md': '# Alpha\n',
  'src/alpha.js': '// impl\n',
  ...Object.fromEntries(STAGES.map(s => [`docs/${s}/README.md`, `# ${s}\n`])),
});

// ---------------------------------------------------------------------------------------------------------- reader

test('registry reader: parses scalars, inline lists and block lists', () => {
  const r = parseRegistry(registryYaml(GOOD_CAP));
  assert.equal(r.lifecycle.length, 10);
  assert.equal(r.capabilities.length, 1);
  const c = r.capabilities[0];
  assert.equal(c.id, 'alpha-scan');
  assert.deepEqual(c.lifecycleStages, ['discover']);
  assert.deepEqual(c.docs, ['docs/alpha.md']);
  assert.deepEqual(c.evidence, ['src/alpha.js']);
});

test('registry reader: refuses a line it cannot read instead of guessing', () => {
  assert.throws(() => parseRegistry('capabilities:\n  - id: a\n      weird indent: x\n'), /cannot read/);
  assert.throws(() => parseRegistry('stray: line\n'), /./);
});

// ------------------------------------------------------------------------------------------------ registry rules

test('registry: a well-formed registry passes', () => {
  const dir = mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(GOOD_CAP) });
  assert.deepEqual(validateRegistry(loadRegistry(dir), dir), []);
});

test('registry: an invalid maturity value fails', () => {
  const bad = GOOD_CAP.replace('maturity: GA', 'maturity: Stable');
  const dir = mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(bad) });
  const f = validateRegistry(loadRegistry(dir), dir);
  assert.ok(f.some(x => /maturity "Stable"/.test(x.message)), JSON.stringify(f));
});

test('registry: GA and Preview and Labs require implementation evidence', () => {
  for (const m of ['GA', 'Preview', 'Labs']) {
    const noEv = GOOD_CAP.replace('maturity: GA', `maturity: ${m}`).replace(/    evidence:\n      - src\/alpha.js\n/, '');
    const dir = mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(noEv) });
    const f = validateRegistry(loadRegistry(dir), dir);
    assert.ok(f.some(x => /requires implementation evidence/.test(x.message)), `${m}: ${JSON.stringify(f)}`);
  }
});

test('registry: evidence that does not exist fails', () => {
  const bad = GOOD_CAP.replace('src/alpha.js', 'src/missing.js');
  const dir = mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(bad) });
  assert.ok(validateRegistry(loadRegistry(dir), dir).some(x => /does not exist/.test(x.message)));
});

test('registry: a Roadmap capability must not list evidence, and may list none', () => {
  const withEv = GOOD_CAP.replace('maturity: GA', 'maturity: Roadmap');
  const d1 = mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(withEv) });
  assert.ok(validateRegistry(loadRegistry(d1), d1).some(x => /Roadmap capability must not list implementation evidence/.test(x.message)));
  const noEv = withEv.replace(/    evidence:\n      - src\/alpha.js\n/, '');
  const d2 = mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(noEv) });
  assert.deepEqual(validateRegistry(loadRegistry(d2), d2), []);
});

test('registry: unknown stage, duplicate id, missing docs path and a wrong stage order all fail', () => {
  const unknownStage = GOOD_CAP.replace('[discover]', '[discover, sideways]');
  let dir = mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(unknownStage) });
  assert.ok(validateRegistry(loadRegistry(dir), dir).some(x => /unknown lifecycle stage "sideways"/.test(x.message)));

  dir = mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(GOOD_CAP + GOOD_CAP) });
  assert.ok(validateRegistry(loadRegistry(dir), dir).some(x => /duplicate capability id/.test(x.message)));

  const missingDoc = GOOD_CAP.replace('docs/alpha.md', 'docs/nowhere.md');
  dir = mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(missingDoc) });
  assert.ok(validateRegistry(loadRegistry(dir), dir).some(x => /docs path docs\/nowhere.md does not exist/.test(x.message)));

  const swapped = registryYaml(GOOD_CAP).replace('id: prove', 'id: TEMP').replace('id: learn', 'id: prove').replace('id: TEMP', 'id: learn');
  dir = mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': swapped });
  assert.ok(validateRegistry(loadRegistry(dir), dir).some(x => /lifecycle must list exactly/.test(x.message)));
});

// -------------------------------------------------------------------------------------- generated tables

function tableRepo(readme) {
  return mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(GOOD_CAP), 'README.md': readme });
}
const BLOCK = body => `<!-- generated:capabilities:start -->\n${body}\n<!-- generated:capabilities:end -->`;

test('tables: a fresh generated table passes', () => {
  const reg = parseRegistry(registryYaml(GOOD_CAP));
  const dir = tableRepo(`# R\n\n${BLOCK(renderTable(reg, { fromDir: '.' }))}\n`);
  assert.deepEqual(checkTables(loadRegistry(dir), dir), []);
});

test('tables: a stale committed table fails, and --write repairs it', () => {
  const dir = tableRepo(`# R\n\n${BLOCK('| old | table |')}\n`);
  const reg = loadRegistry(dir);
  const stale = checkTables(reg, dir);
  assert.deepEqual(rules(stale), ['table'], JSON.stringify(stale));
  assert.deepEqual(checkTables(reg, dir, { write: true }), []);
  assert.deepEqual(checkTables(reg, dir), [], 'after --write the table is fresh');
  assert.match(fs.readFileSync(path.join(dir, 'README.md'), 'utf8'), /\| \[Alpha scan\]\(\.\/docs\/alpha\.md\) \| Discover \| \*\*GA\*\*/);
});

test('tables: changing the registry maturity makes the committed table stale', () => {
  const reg = parseRegistry(registryYaml(GOOD_CAP));
  const dir = tableRepo(`# R\n\n${BLOCK(renderTable(reg, { fromDir: '.' }))}\n`);
  fs.writeFileSync(path.join(dir, 'docs/capabilities.yaml'), registryYaml(GOOD_CAP.replace('maturity: GA', 'maturity: Preview')));
  assert.deepEqual(rules(checkTables(loadRegistry(dir), dir)), ['table']);
});

test('tables: --write on EMPTY adjacent blocks fills each block and never swallows the prose between them', () => {
  const md = '# R\n\n## One\n\nfirst prose\n\n<!-- generated:capabilities:discover:start -->\n<!-- generated:capabilities:discover:end -->\n\n## Two\n\nsecond prose\n\n<!-- generated:capabilities:fix:start -->\n<!-- generated:capabilities:fix:end -->\n\n## Three\n\nthird prose\n';
  const dir = tableRepo(md);
  assert.deepEqual(checkTables(loadRegistry(dir), dir, { write: true }), []);
  const out = fs.readFileSync(path.join(dir, 'README.md'), 'utf8');
  for (const keep of ['## One', 'first prose', '## Two', 'second prose', '## Three', 'third prose']) assert.ok(out.includes(keep), `lost: ${keep}`);
  assert.match(out, /discover:start -->\n\| Capability/);
  assert.deepEqual(checkTables(loadRegistry(dir), dir), []);
});

test('tables: no generated block at all fails closed', () => {
  const dir = tableRepo('# R\n\nNo table here.\n');
  assert.ok(checkTables(loadRegistry(dir), dir).some(f => /no generated capability block/.test(f.message)));
});

test('tables: a stage-scoped block lists only that stage and the lifecycle table is generated', () => {
  const reg = parseRegistry(registryYaml(GOOD_CAP));
  assert.match(renderTable(reg, { stage: 'discover' }), /Alpha scan/);
  assert.doesNotMatch(renderTable(reg, { stage: 'fix' }), /Alpha scan/);
  const life = renderLifecycleTable(reg, { fromDir: '.' });
  assert.match(life, /\| 1\. Discover \| Q discover\? \| \*\*GA\*\* \|/);
  assert.match(life, /\| 10\. Detect .* \(none registered\)/);
  assert.deepEqual(renderCounts(reg), { GA: 1, Preview: 0, Labs: 0, Roadmap: 0 });
});

// -------------------------------------------------------------------------------------------- consistency

const TWO_CAPS = `${GOOD_CAP}  - id: beta-fleet
    name: Beta fleet scanning
    lifecycleStages: [scale]
    maturity: Labs
    establishes: Many repositories.
    docs:
      - docs/beta.md
    evidence:
      - src/alpha.js
`;
function consistencyRepo(page, extra = {}) {
  return mkRepo({ ...baseFiles(), 'docs/beta.md': '# Beta\n', 'docs/capabilities.yaml': registryYaml(TWO_CAPS), 'docs/page.md': page, ...extra });
}

test('consistency: a badge that matches the registry passes; one that contradicts it fails', () => {
  let dir = consistencyRepo('Beta fleet scanning is [Labs] and Alpha scan is [GA].\n');
  assert.deepEqual(checkMaturityConsistency(loadRegistry(dir), dir, ['docs/page.md']), []);
  dir = consistencyRepo('| Beta fleet scanning | [GA] |\n');
  const f = checkMaturityConsistency(loadRegistry(dir), dir, ['docs/page.md']);
  assert.deepEqual(rules(f), ['consistency']);
  assert.match(f[0].message, /\[GA\].*contradicts.*Labs/);
});

test('consistency: a line naming two capabilities is ambiguous and is not guessed at', () => {
  const dir = consistencyRepo('Alpha scan and Beta fleet scanning are both [Preview].\n');
  assert.deepEqual(checkMaturityConsistency(loadRegistry(dir), dir, ['docs/page.md']), []);
});

test('consistency: a page-level Maturity line on the primary doc must match', () => {
  let dir = consistencyRepo('x', { 'docs/beta.md': '# Beta\n\n**Maturity:** Labs.\n' });
  assert.deepEqual(checkMaturityConsistency(loadRegistry(dir), dir, ['docs/beta.md']), []);
  dir = consistencyRepo('x', { 'docs/beta.md': '# Beta\n\n**Maturity:** GA.\n' });
  const f = checkMaturityConsistency(loadRegistry(dir), dir, ['docs/beta.md']);
  assert.deepEqual(rules(f), ['consistency']);
  assert.match(f[0].message, /beta-fleet=Labs/);
});

test('consistency: a badge inside a code fence is example text and is ignored', () => {
  const dir = consistencyRepo('```\nBeta fleet scanning [GA]\n```\n');
  assert.deepEqual(checkMaturityConsistency(loadRegistry(dir), dir, ['docs/page.md']), []);
});

// ------------------------------------------------------------------------------------------------ overclaim

const ROAD = `${GOOD_CAP}  - id: live-watch
    name: Live runtime watch
    aliases: [production watching]
    lifecycleStages: [observe]
    maturity: Roadmap
    establishes: Not shipped.
    docs:
      - docs/alpha.md
`;
function overclaimRepo(page) {
  return mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(ROAD), 'docs/page.md': page });
}

test('overclaim: a Roadmap capability described as shipped fails; hedged or badged text passes', () => {
  let dir = overclaimRepo('Live runtime watch monitors production and detects exploitation.\n');
  assert.deepEqual(rules(checkOverclaims(loadRegistry(dir), dir, ['docs/page.md'])), ['overclaim']);
  dir = overclaimRepo('Live runtime watch would monitor production once implemented.\n');
  assert.deepEqual(checkOverclaims(loadRegistry(dir), dir, ['docs/page.md']), []);
  dir = overclaimRepo('Live runtime watch is [Roadmap] and monitors nothing yet.\n');
  assert.deepEqual(checkOverclaims(loadRegistry(dir), dir, ['docs/page.md']), []);
  dir = overclaimRepo('Production watching generates alerts.\n');
  assert.deepEqual(rules(checkOverclaims(loadRegistry(dir), dir, ['docs/page.md'])), ['overclaim'], 'aliases count');
});

test('overclaim: a documented suppression with a reason silences one line, and only that line', () => {
  const dir = overclaimRepo('<!-- positioning-ignore: quoting a competitor claim -->\nLive runtime watch monitors production.\n\nLive runtime watch monitors production.\n');
  const f = checkOverclaims(loadRegistry(dir), dir, ['docs/page.md']);
  assert.equal(f.length, 1);
  assert.equal(f[0].line, 4);
});

test('overclaim: a suppression with no reason does not suppress', () => {
  const dir = overclaimRepo('<!-- positioning-ignore: -->\nLive runtime watch monitors production.\n');
  assert.equal(checkOverclaims(loadRegistry(dir), dir, ['docs/page.md']).length, 1);
});

test('overclaim: a Labs capability called production-ready fails', () => {
  const dir = mkRepo({ ...baseFiles(), 'docs/beta.md': '# B\n', 'docs/capabilities.yaml': registryYaml(TWO_CAPS), 'docs/page.md': 'Beta fleet scanning is production-ready.\n' });
  assert.deepEqual(rules(checkOverclaims(loadRegistry(dir), dir, ['docs/page.md'])), ['overclaim']);
});

// -------------------------------------------------------------------------------------------------- commands

function commandRepo(page) {
  return mkRepo({
    'scanner/bin/agentic-security.js': "switch (cmd) {\n case 'scan': break;\n case 'ci': break;\n case 'image': break;\n case 'fleet': break;\n}\n",
    'commands/scan.md': '# scan\n',
    'docs/page.md': page,
  });
}

test('commands: real commands and subcommands pass', () => {
  const dir = commandRepo('Run `agentic-security scan .` then `agentic-security image scan x.tar`, `npx @clear-capabilities/agentic-security-scanner ci .` and `/agentic-security:scan`.\n');
  assert.deepEqual(checkCommands(dir, ['docs/page.md']), []);
});

test('commands: an invented command, subcommand, slash command and `scan --assurance` all fail', () => {
  for (const [text, re] of [
    ['`agentic-security teleport .`', /"agentic-security teleport" does not exist/],
    ['`agentic-security image explode x.tar`', /not a image subcommand/],
    ['`/agentic-security:nonsense`', /no commands\/nonsense\.md/],
    ['`agentic-security scan . --assurance strict`', /`--assurance` exists only on `ci`/],
  ]) {
    const dir = commandRepo(`${text}\n`);
    const f = checkCommands(dir, ['docs/page.md']);
    assert.equal(f.length, 1, `${text}: ${JSON.stringify(f)}`);
    assert.match(f[0].message, re);
  }
});

test('commands: prose is not parsed as a command, but code spans and fenced lines are', () => {
  let dir = commandRepo('The agentic-security under test, and agentic-security watches the repo.\n');
  assert.deepEqual(checkCommands(dir, ['docs/page.md']), []);
  dir = commandRepo('Run:\n\n```bash\n$ agentic-security teleport .\n```\n');
  assert.equal(checkCommands(dir, ['docs/page.md']).length, 1);
  dir = commandRepo('Try `agentic-security teleport .` now.\n');
  assert.equal(checkCommands(dir, ['docs/page.md']).length, 1);
});

// ---------------------------------------------------------------------------------------------- lifecycle

test('lifecycle: the canonical chain passes; any other ordering of the ten stages fails', () => {
  const ok = mkRepo({ 'docs/p.md': `${CANONICAL_CHAIN}\n` });
  assert.deepEqual(checkLifecycleOrder(ok, ['docs/p.md']), []);
  const swapped = 'Discover → Prove → Corroborate → Learn → Scale → Observe → Trace → Fix → Verify → Detect ↻';
  const bad = mkRepo({ 'docs/p.md': `${swapped}\n` });
  assert.deepEqual(rules(checkLifecycleOrder(bad, ['docs/p.md'])), ['lifecycle']);
});

test('lifecycle: the seven-step operational workflow and prose that mentions stages are not flagged', () => {
  const dir = mkRepo({ 'docs/p.md': 'Find → Prove → Hunt → Scope → Fix → Verify → Detect\n\nIn Learn, Scale, Observe and Trace we go → somewhere, then Discover, Fix, Verify and Detect again.\n' });
  assert.deepEqual(checkLifecycleOrder(dir, ['docs/p.md']), []);
});

// ------------------------------------------------------------------------------------------------- style

test('style: em-dashes and unqualified avoid-list words fail; negated, quoted and coded uses pass', () => {
  const dir = mkRepo({ 'docs/p.md': [
    'This is fine, truly.',
    'An em-dash — in prose.',
    'We offer zero false positives.',
    'The result is certified.',
    'It is not certified and never compliant.',
    'Use `guarantee` in code spans.',
    '<!-- positioning-ignore: quoting the avoid list -->',
    'We guarantee nothing here, honestly guarantees.',
    '```',
    'a code block — with an em-dash, guarantees and certified',
    '```',
  ].join('\n') });
  const f = checkStyle(dir, ['docs/p.md']);
  const lines = f.map(x => x.line).sort((a, b) => a - b);
  assert.deepEqual(lines, [2, 3, 4], JSON.stringify(f));
});

// ------------------------------------------------------------------------------------------------- links

test('links: a broken file link and a missing heading anchor fail; good ones pass', () => {
  const dir = mkRepo({
    'docs/a.md': '# A\n\n[ok](b.md) [ok2](b.md#real-heading) [self](#top-of-a) [bad](missing.md) [badanchor](b.md#nope)\n\n## Top of A\n',
    'docs/b.md': '# B\n\n## Real heading\n',
  });
  const f = checkLinks(dir, ['docs/a.md']);
  assert.equal(f.length, 2, JSON.stringify(f));
  assert.ok(f.some(x => /broken link missing\.md/.test(x.message)));
  assert.ok(f.some(x => /anchor #nope/.test(x.message)));
});

test('links: heading slugs follow the GitHub rules for punctuation and spaces', () => {
  assert.equal(slug('The honesty model — why this won\'t inflate your score'), 'the-honesty-model--why-this-wont-inflate-your-score');
  assert.equal(slug('Deterministic vs. model-assisted'), 'deterministic-vs-model-assisted');
  assert.equal(slug('`scan` --all'), 'scan---all');
});

// ---------------------------------------------------------------------------------------------- visuals

const goodSvg = (extra = '') => `<svg viewBox="0 0 10 10" xmlns="http://www.w3.org/2000/svg"><title>A descriptive title</title><desc>A long description of the picture for screen readers.</desc>${extra}</svg>`;
const matText = '<text>GA</text><text>Preview</text><text>Labs</text><text>Roadmap</text>';

test('visuals: all six present with alt text and written-out maturity passes', () => {
  const files = {};
  for (const n of ['assurance-lifecycle', 'security-graph', 'one-finding-journey', 'platform-architecture']) files[`docs/assets/positioning/${n}.svg`] = goodSvg(matText);
  for (const n of ['traditional-vs-agentic', 'evidence-model']) files[`docs/assets/positioning/${n}.svg`] = goodSvg();
  assert.deepEqual(checkVisuals(mkRepo(files)), []);
});

test('visuals: missing file, no alt text, a percentage, or colour-only maturity each fail', () => {
  const dir = mkRepo({
    'docs/assets/positioning/assurance-lifecycle.svg': '<svg viewBox="0 0 1 1"><text>GA</text><text>Preview</text><text>51 %</text></svg>',
  });
  const f = checkVisuals(dir);
  assert.ok(f.some(x => /required SVG is missing/.test(x.message)), 'missing files');
  assert.ok(f.some(x => /no <title>/.test(x.message)));
  assert.ok(f.some(x => /no <desc>/.test(x.message)));
  assert.ok(f.some(x => /percentage/.test(x.message)));
  assert.ok(f.some(x => /maturity "Labs" is not spelled out/.test(x.message)));
});

// ------------------------------------------------------------------------------------------- navigation

test('navigation: a role page needs a docs-home link and an existing Core workflow link', () => {
  const roles = ['developer', 'appsec', 'ciso', 'platform-engineering', 'ai-engineering', 'privacy', 'compliance', 'detection-engineering'];
  const files = { 'docs/README.md': roles.map(r => `[${r}](roles/${r}.md)`).join('\n'), 'docs/w.md': '# W\n' };
  for (const r of roles) files[`docs/roles/${r}.md`] = `# ${r}\n\n**Core workflow:** [w](../w.md)\n`;
  assert.deepEqual(checkNavigation(mkRepo(files)), []);

  const broken = { ...files, 'docs/roles/ciso.md': '# ciso\n\nno core workflow line\n', 'docs/roles/privacy.md': '# p\n\n**Core workflow:** [x](../gone.md)\n', 'docs/README.md': files['docs/README.md'].replace('roles/appsec.md', 'roles/other.md') };
  const f = checkNavigation(mkRepo(broken));
  assert.ok(f.some(x => /does not link to roles\/appsec\.md/.test(x.message)));
  assert.ok(f.some(x => x.file === 'docs/roles/ciso.md' && /no "\*\*Core workflow:\*\*/.test(x.message)));
  assert.ok(f.some(x => x.file === 'docs/roles/privacy.md' && /does not resolve/.test(x.message)));
});

// -------------------------------------------------------------------------------------------- README hero

test('readme: the hero, the canonical chain and the trust statement are required', () => {
  const good = `# Agentic Security\n\n## Autonomous Security Assurance for the AI Software Era\n\n**Discover vulnerabilities. Prove what's exploitable. Understand what's exposed. Fix it safely. Learn from every finding.**\n\n> **Evidence, not magic.** x\n\n${CANONICAL_CHAIN}\n`;
  assert.deepEqual(checkReadmeHero(mkRepo({ 'README.md': good })), []);
  const old = '# agentic-security\n\nBuild faster with an Agentic Workforce.\n';
  assert.ok(checkReadmeHero(mkRepo({ 'README.md': old })).length >= 4);
});

// -------------------------------------------------------------------------- the real checkout, both directions

test('real checkout: the registry is valid and every maturity is one of the four', () => {
  const reg = loadRegistry(REPO);
  assert.deepEqual(validateRegistry(reg, REPO), []);
  for (const c of reg.capabilities) assert.ok(MATURITIES.includes(c.maturity), c.id);
  assert.deepEqual(reg.lifecycle.map(s => s.id), STAGES, 'one canonical ten-stage ordering');
});

test('real checkout: no Roadmap capability lists evidence; every GA capability names evidence that exists', () => {
  const reg = loadRegistry(REPO);
  for (const c of reg.capabilities.filter(x => x.maturity === 'Roadmap')) assert.equal((c.evidence || []).length, 0, c.id);
  for (const c of reg.capabilities.filter(x => x.maturity === 'GA')) {
    assert.ok((c.evidence || []).length > 0, c.id);
    for (const e of c.evidence) assert.ok(fs.existsSync(path.join(REPO, e)), `${c.id}: ${e}`);
  }
});

test('real checkout: conservative assignments hold (nothing promoted because the positioning would benefit)', () => {
  const by = Object.fromEntries(loadRegistry(REPO).capabilities.map(c => [c.id, c.maturity]));
  assert.equal(by['rule-compiler'], 'Preview');
  assert.equal(by['fleet-scan'], 'Preview');
  assert.equal(by['exploit-proof'], 'Preview');
  assert.equal(by['runtime-corroboration'], 'Preview');
  assert.equal(by['live-runtime-observation'], 'Roadmap');
  assert.equal(by['detection-and-response'], 'Preview');
  assert.equal(by['connected-production-detection'], 'Roadmap');
  assert.equal(by['eval-lab'], 'Preview');
  assert.equal(by['release-assurance'], 'Preview');
  assert.equal(by['security-learning-rate'], 'Roadmap');
  assert.equal(by['verified-remediation'], 'GA');
  assert.equal(by['scan-health'], 'GA');
});

test('real checkout: every rule passes against the committed docs', () => {
  const f = checkPositioningDocs(REPO);
  assert.deepEqual(f, [], f.map(x => `[${x.rule}] ${x.file}:${x.line} ${x.message}`).join('\n'));
});

test('real checkout: the CLI exits 0 on the checkout and non-zero on a checkout with the registry corrupted', () => {
  const ok = spawnSync(process.execPath, [SCRIPT], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /positioning-docs: ok\./);

  // a minimal checkout with a bad maturity must fail closed (exit 1, finding on stderr)
  const dir = mkRepo({ ...baseFiles(), 'docs/capabilities.yaml': registryYaml(GOOD_CAP.replace('maturity: GA', 'maturity: Stable')), 'README.md': '# old\n' });
  const bad = spawnSync(process.execPath, [SCRIPT, '--root', dir], { encoding: 'utf8' });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /maturity "Stable"/);
});

test('real checkout: the release doc-links gate runs the positioning checks', () => {
  const src = fs.readFileSync(path.join(REPO, 'scripts', 'check-doc-drift.mjs'), 'utf8');
  assert.match(src, /checkPositioningDocs\(REPO\)/);
  const r = spawnSync(process.execPath, [path.join(REPO, 'scripts', 'check-doc-drift.mjs'), '--gate'], { encoding: 'utf8' });
  assert.match(r.stdout + r.stderr, /positioning-docs:/, 'the gate reports on positioning docs');
});

test('real checkout: the README states the maturity labels it renders and never an unlabeled Roadmap claim', () => {
  const readme = fs.readFileSync(path.join(REPO, 'README.md'), 'utf8');
  for (const m of MATURITIES) assert.match(readme, new RegExp(`\\*\\*${m}\\*\\*`));
  assert.match(readme, /<!-- generated:capabilities:start -->/);
  assert.match(readme, /<!-- generated:lifecycle:start -->/);
});


// ------------------------------------------------------------------------------------------------ the GA bar

const BAR_CAP = (extra = '') => `  - id: alpha-scan
    name: Alpha scan
    lifecycleStages: [discover]
    maturity: GA
    since: 0.178.0
    contract: docs/ref/alpha.md
    contractTest: scanner/test/alpha.test.js
    gate: corpus-gate
    platforms: [linux:test-shard, macos:determinism-attest]
    limits: docs/alpha.md#what-alpha-does-not-do
    establishes: A candidate at a location.
    docs:
      - docs/alpha.md
    evidence:
      - src/alpha.js
${extra}`;
const barFiles = () => ({
  ...baseFiles(),
  'docs/alpha.md': '# Alpha\n\n## What alpha does not do\n\n<!-- limits-verified: 2026-10-19 -->\n\n- a limit\n\n## Other\n',
  'docs/ref/alpha.md': '# Alpha reference\n',
  'scanner/test/alpha.test.js': '// test\n',
  'scanner/package.json': JSON.stringify({ scripts: { 'test:alpha': 'node --test test/alpha.test.js' } }),
  'scripts/release-check.mjs': "evaluate('corpus-gate', () => 1);\nevaluate('mutation-gate', () => 1);\n",
  '.github/workflows/ci.yml': 'name: ci\non: push\njobs:\n  test-shard:\n    runs-on: ubuntu-latest\n  determinism-attest:\n    runs-on: macos-latest\n',
});
const barRepo = (overrides = {}, cap = BAR_CAP()) => {
  const files = { ...barFiles(), ...overrides, 'docs/capabilities.yaml': registryYaml(cap) };
  for (const k of Object.keys(files)) if (files[k] === null) delete files[k];
  return mkRepo(files);
};
const barFindings = (dir) => checkGaBar(loadRegistry(dir), dir);

test('GA bar: a GA capability that names every piece of evidence passes', () => {
  assert.deepEqual(barFindings(barRepo()), []);
});

test('GA bar: each missing field fails, naming the field', () => {
  for (const k of ['since', 'contract', 'contractTest', 'gate', 'platforms', 'limits']) {
    const cap = BAR_CAP().split('\n').filter(l => !l.startsWith(`    ${k}:`)).join('\n');
    const f = barFindings(barRepo({}, cap));
    assert.ok(f.some(x => x.rule === 'bar' && x.message.includes(`\`${k}\``)), `${k}: ${JSON.stringify(f)}`);
  }
});

test('GA bar: a contract page, a contract test or a limits page that does not exist fails', () => {
  assert.ok(barFindings(barRepo({ 'docs/ref/alpha.md': null })).some(x => /contract page/.test(x.message)));
  assert.ok(barFindings(barRepo({ 'scanner/test/alpha.test.js': null })).some(x => /contract test .* does not exist/.test(x.message)));
  assert.ok(barFindings(barRepo({ 'docs/alpha.md': null })).some(x => /limits must be an existing/.test(x.message)));
});

test('GA bar: a contract test that no scanner script runs is not evidence', () => {
  const f = barFindings(barRepo({ 'scanner/package.json': JSON.stringify({ scripts: { 'test:alpha': 'node --test test/other.test.js' } }) }));
  assert.ok(f.some(x => /not run by any scanner test script/.test(x.message)), JSON.stringify(f));
});

test('GA bar: a gate that release-check does not evaluate fails, one it does passes', () => {
  const f = barFindings(barRepo({ 'scripts/release-check.mjs': "evaluate('mutation-gate', () => 1);\n" }));
  assert.ok(f.some(x => /gate "corpus-gate" is not a check/.test(x.message)), JSON.stringify(f));
  assert.deepEqual(barFindings(barRepo()), []);
});

test('GA bar: platforms need os:job pairs, a job that exists, and a linux job', () => {
  const swap = (pl) => BAR_CAP().replace('[linux:test-shard, macos:determinism-attest]', pl);
  assert.ok(barFindings(barRepo({}, swap('[linux:no-such-job]'))).some(x => /not a job in \.github\/workflows/.test(x.message)));
  assert.ok(barFindings(barRepo({}, swap('[windows:test-shard]'))).some(x => /must be os:job/.test(x.message)));
  assert.ok(barFindings(barRepo({}, swap('[test-shard]'))).some(x => /must be os:job/.test(x.message)));
  assert.ok(barFindings(barRepo({}, swap('[macos:determinism-attest]'))).some(x => /needs a linux job/.test(x.message)));
});

test('GA bar: a limits anchor that is not a heading, or has no verified marker, fails', () => {
  assert.ok(barFindings(barRepo({}, BAR_CAP().replace('#what-alpha-does-not-do', '#nope'))).some(x => /is not a heading/.test(x.message)));
  const noMarker = { 'docs/alpha.md': '# Alpha\n\n## What alpha does not do\n\n- a limit\n' };
  assert.ok(barFindings(barRepo(noMarker)).some(x => /no <!-- limits-verified/.test(x.message)));
});

test('GA bar: a marker in a different section does not satisfy the anchor', () => {
  const f = barFindings(barRepo({ 'docs/alpha.md': '# Alpha\n\n<!-- limits-verified: 2026-10-19 -->\n\n## What alpha does not do\n\n- a limit\n' }));
  assert.ok(f.some(x => /no <!-- limits-verified/.test(x.message)), JSON.stringify(f));
});

test('GA bar: Preview needs a contract page or a contractNote; Labs and Roadmap are not held to it', () => {
  const preview = (extra) => `  - id: beta\n    name: Beta\n    lifecycleStages: [discover]\n    maturity: Preview\n${extra}    establishes: x\n    docs:\n      - docs/alpha.md\n    evidence:\n      - src/alpha.js\n`;
  assert.ok(barFindings(barRepo({}, preview(''))).some(x => /Preview needs a `contract`/.test(x.message)));
  assert.deepEqual(barFindings(barRepo({}, preview('    contractNote: may still change; reviewed 2026-10-19.\n'))), []);
  const labs = preview('').replace('Preview', 'Labs');
  assert.deepEqual(barFindings(barRepo({}, labs)), []);
});

test('GA bar: sectionByAnchor stops at the next heading of the same or a higher level', () => {
  const t = '# A\n\n## One\n\nbody one\n\n### Sub\n\nsub body\n\n## Two\n\nbody two\n';
  assert.match(sectionByAnchor(t, 'one'), /sub body/);
  assert.doesNotMatch(sectionByAnchor(t, 'one'), /body two/);
  assert.equal(sectionByAnchor(t, 'missing'), null);
});

test('limits freshness: a recent marker passes; a stale or future one fails; an unreadable HEAD date is a finding', () => {
  const dir = barRepo();
  const reg = loadRegistry(dir);
  assert.deepEqual(checkLimitsFreshness(reg, dir, { headDate: '2026-10-19' }), []);
  assert.deepEqual(checkLimitsFreshness(reg, dir, { headDate: '2026-12-01' }), []);
  const stale = checkLimitsFreshness(reg, dir, { headDate: '2027-03-01' });
  assert.ok(stale.some(x => /more than 90 days/.test(x.message)), JSON.stringify(stale));
  const future = checkLimitsFreshness(reg, dir, { headDate: '2026-09-01' });
  assert.ok(future.some(x => /after the HEAD commit/.test(x.message)), JSON.stringify(future));
  assert.equal(LIMITS_MAX_AGE_DAYS, 90);
  assert.ok(checkLimitsFreshness(reg, dir, { headDate: 'nonsense' }).some(x => x.rule === 'limits'));
});

test('GA bar: the real registry meets its own bar, and every GA capability names a gate release-check evaluates', () => {
  const reg = loadRegistry(REPO);
  assert.deepEqual(checkGaBar(reg, REPO), []);
  const ga = reg.capabilities.filter(c => c.maturity === 'GA');
  assert.ok(ga.length >= 12);
  for (const c of ga) for (const k of ['contract', 'contractTest', 'gate', 'limits', 'since']) assert.ok(c[k], `${c.id} lacks ${k}`);
});

test('contract-conformance runs exactly the tests the registry names for GA and Preview, and none for Labs', async () => {
  const { contractTests } = await import('../../scripts/check-ga-contracts.mjs');
  const reg = parseRegistry(registryYaml(BAR_CAP() + BAR_CAP().replace('alpha-scan', 'lab-thing').replace('maturity: GA', 'maturity: Labs').replace('scanner/test/alpha.test.js', 'scanner/test/lab.test.js')));
  assert.deepEqual(contractTests(reg), ['scanner/test/alpha.test.js']);
  assert.deepEqual(contractTests({ capabilities: [] }), []);
  const real = contractTests(loadRegistry(REPO));
  assert.ok(real.length >= 12);
  for (const t of real) assert.ok(fs.existsSync(path.join(REPO, t)), `${t} is named by the registry but does not exist`);
});
