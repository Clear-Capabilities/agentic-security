// DOC-001.AC03: the documentation drift check verifies that every command, npm script, schema, environment variable and fixture
// path a page names still exists, and prohibits universal "safe" and "fully covered" claims. Each rule is tested in both
// directions: a deliberately bad page is caught with the right finding, and a good page (and every real page) passes.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  checkAssuranceDoc, checkAllAssuranceDocs, universalClaimsIn, splitMarkdown, ASSURANCE_DOCS, REPO,
} from '../../../scripts/check-assurance-docs.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** A small repository the check can resolve against: one script, one CLI command, one schema, one env variable, one fixture. */
function miniRepo() {
  const root = fs.realpathSync(mkTestTmp('doc-drift-'));
  const w = (rel, text) => { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), text); };
  w('scanner/package.json', JSON.stringify({ scripts: { 'real:script': 'node ../scripts/real.mjs', test: 'node x' } }));
  w('scanner/bin/agentic-security.js', "switch (cmd) {\n  case 'scan': break;\n  case 'portfolio': break;\n}\nconst usage = `\n  portfolio progress --store <file>\n`;\n");
  w('scanner/src/schema.js', "export const S = 'agentic-security/real-schema'; const e = process.env.AGENTIC_SECURITY_REAL_VAR;\n");
  w('scanner/src/posture/assurance/config.js', "export const FEATURES = { 'real-feature': {} };\n");
  w('scripts/real.mjs', '// real\n');
  w('scanner/test/fixtures/real/a.json', '{}');
  w('docs/other.md', '# other\n');
  const doc = (body) => { w('docs/guides/page.md', body); return path.join(root, 'docs/guides/page.md'); };
  return { root, doc };
}
const kinds = (fs_) => fs_.map((f) => f.kind).sort();
const GOOD = [
  '# Page', '',
  'Run `npm run real:script` or the script itself:', '', '```', 'node scripts/real.mjs', 'node ../scripts/real.mjs', 'agentic-security scan --json', 'agentic-security portfolio progress --store s.json',
  'AGENTIC_SECURITY_REAL_VAR=1 agentic-security scan', '```', '',
  'The contract is `agentic-security/real-schema`. The fixture is `scanner/test/fixtures/real/a.json` and [the other page](../other.md).',
  'Set `AGENTIC_SECURITY_ASSURANCE_REAL_FEATURE=1` and `AGENTIC_SECURITY_REAL_VAR`.',
  'This does not mean the software is safe, and it is not certified by anyone.', '',
  '```text', 'npm run output-only-not-checked', 'see scanner/test/fixtures/nowhere.json', '```', '',
].join('\n');

describe('[DOC-001.AC03] the drift check verifies referenced commands, scripts, schemas, variables and paths', () => {
  test('[DOC-001.AC03] a page whose every reference exists passes (output fences are not read as commands)', async () => {
    const { root, doc } = miniRepo();
    const found = await checkAssuranceDoc(doc(GOOD), { repo: root });
    assert.deepEqual(found, [], JSON.stringify(found));
  });

  const bad = [
    ['unknown-npm-script', 'Run `npm run nonexistent:script` now.'],
    ['missing-script-path', 'Run `node scripts/ghost.mjs` now.'],
    ['unknown-cli-command', '```\nagentic-security frobnicate --now\n```'],
    ['unknown-cli-command', '```\nagentic-security portfolio vanish --store s\n```'],
    ['unknown-schema', 'The contract is `agentic-security/ghost-schema`.'],
    ['unknown-env', 'Set `AGENTIC_SECURITY_GHOST_VAR=1`.'],
    ['missing-path', 'See `scanner/test/fixtures/real/missing.json`.'],
    ['missing-path', 'See [the page](../ghost.md).'],
    ['missing-path', '```\nnode scripts/real.mjs --fixture scanner/test/fixtures/real/missing-dir\n```'],
    ['em-dash', 'A sentence — with a dash.'],
  ];
  for (const [kind, body] of bad) {
    test(`[DOC-001.AC03] a deliberately bad page is caught: ${kind} (${body.replace(/\n/g, ' ').slice(0, 50)})`, async () => {
      const { root, doc } = miniRepo();
      const found = await checkAssuranceDoc(doc(`# Page\n\n${body}\n`), { repo: root });
      assert.ok(found.some((f) => f.kind === kind), `expected ${kind}, got ${JSON.stringify(found)}`);
      assert.ok(found.every((f) => f.line >= 1 && f.ref), 'every finding names a line and the offending reference');
    });
  }

  test('[DOC-001.AC03] a reference inside an output fence is not checked, and one outside it is (same text, both directions)', async () => {
    const { root, doc } = miniRepo();
    assert.deepEqual(await checkAssuranceDoc(doc('```text\nnpm run ghost\n```\n'), { repo: root }), []);
    assert.deepEqual(kinds(await checkAssuranceDoc(doc('```\nnpm run ghost\n```\n'), { repo: root })), ['unknown-npm-script']);
  });

  test('[DOC-001.AC03] an environment variable derived from a feature name is accepted, a lookalike is not', async () => {
    const { root, doc } = miniRepo();
    assert.deepEqual(await checkAssuranceDoc(doc('`AGENTIC_SECURITY_ASSURANCE_REAL_FEATURE=1` and `AGENTIC_SECURITY_NO_REAL_FEATURE=1`\n'), { repo: root }), []);
    assert.deepEqual(kinds(await checkAssuranceDoc(doc('`AGENTIC_SECURITY_ASSURANCE_REAL_FEATURES=1`\n'), { repo: root })), ['unknown-env']);
  });
});

describe('[DOC-001.AC03] the drift check prohibits universal safe and full-coverage claims', () => {
  const claims = [
    'Your code is safe to deploy.', 'The release is secure.', 'The scope is fully covered.', 'This gives full coverage of the codebase.',
    'The result is guaranteed.', 'We guarantee the outcome.', 'The build is certified.', 'The software is vulnerability-free.',
    'The service is free of vulnerabilities.', 'Every path is completely verified.', 'This is 100% secure.',
  ];
  for (const c of claims) {
    test(`[DOC-001.AC03] a page that says "${c}" is caught`, async () => {
      const { root, doc } = miniRepo();
      const found = await checkAssuranceDoc(doc(`# Page\n\n${c}\n`), { repo: root });
      assert.ok(found.some((f) => f.kind === 'universal-claim'), JSON.stringify(found));
    });
  }

  const allowed = [
    'This does not mean the software is safe or free of vulnerabilities.', 'A signature is not independent certification.',
    'Nothing here is guaranteed.', 'The page never says the scope is fully covered.', 'No result is certified.',
    'It cannot be called safe to deploy.', 'Coverage is bounded: it is not full coverage.',
  ];
  for (const a of allowed) {
    test(`[DOC-001.AC03] a negated statement is allowed: "${a}"`, () => {
      assert.deepEqual(universalClaimsIn(a), []);
    });
  }

  test('[DOC-001.AC03] a negation AFTER the claim does not excuse it, and a claim in an inline code span or output fence is not prose', async () => {
    assert.equal(universalClaimsIn('The release is secure, and nothing else matters.').length, 1);
    const { root, doc } = miniRepo();
    assert.deepEqual(await checkAssuranceDoc(doc('The phrase `fully covered` is shown as code.\n\n```text\nsafe to deploy\n```\n'), { repo: root }), []);
  });

  test('[DOC-001.AC03] a table cell is judged on its own: a negation in another cell does not excuse a claim', () => {
    assert.equal(universalClaimsIn('| not a claim | fully covered |').length, 1);
  });
});

describe('[DOC-001.AC03] the check is wired into the documentation gate and owns every assurance page', () => {
  test('[DOC-001.AC03] every assurance page exists, passes the check, and is linked from the index', async () => {
    for (const rel of ASSURANCE_DOCS) assert.ok(fs.existsSync(path.join(REPO, rel)), `${rel} is listed but missing`);
    const found = await checkAllAssuranceDocs(REPO);
    assert.deepEqual(found, [], found.map((f) => `${path.relative(REPO, f.file)}:${f.line} ${f.kind} ${f.ref}`).join('\n'));
    const hub = fs.readFileSync(path.join(REPO, 'docs/guides/assurance-documentation-index.md'), 'utf8');
    for (const rel of ASSURANCE_DOCS.filter((r) => r !== 'docs/guides/assurance-documentation-index.md')) {
      const base = path.basename(rel);
      assert.ok(hub.includes(`(${base})`) || hub.includes(`/${base})`), `the index does not link ${rel}`);
    }
  });

  test('[DOC-001.AC03] a listed page that is missing is a finding, not a skip', async () => {
    const { root } = miniRepo();
    const found = await checkAllAssuranceDocs(root);
    assert.ok(found.length === ASSURANCE_DOCS.length && found.every((f) => f.kind === 'missing-doc'));
  });

  test('[DOC-001.AC03] the check is part of the existing doc-links gate (check-doc-drift.mjs --gate) and of npm run docs:check-assurance', () => {
    const gate = fs.readFileSync(path.join(REPO, 'scripts/check-doc-drift.mjs'), 'utf8');
    assert.match(gate, /check-assurance-docs\.mjs/);
    assert.match(gate, /checkAllAssuranceDocs/);
    const pkg = JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', 'package.json'), 'utf8'));
    assert.match(pkg.scripts['docs:check-assurance'], /check-assurance-docs\.mjs/);
    assert.match(pkg.scripts['test:documentation'], /test\/documentation\/drift-check\.test\.js/);
  });

  test('[DOC-001.AC03] the gate exits 0 on the real pages', () => {
    const r = spawnSync(process.execPath, [path.join(REPO, 'scripts/check-doc-drift.mjs'), '--gate'], { encoding: 'utf8', timeout: 120000 });
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
  });

  test('[DOC-001.AC03] the standalone check exits 1 on a bad page and 0 on the real pages', async () => {
    const ok = spawnSync(process.execPath, [path.join(REPO, 'scripts/check-assurance-docs.mjs')], { encoding: 'utf8', timeout: 120000 });
    assert.equal(ok.status, 0, ok.stderr);
    const { root, doc } = miniRepo();
    const found = await checkAssuranceDoc(doc('# Page\n\nThe scope is fully covered. Run `npm run ghost`.\n'), { repo: root });
    assert.deepEqual(kinds(found), ['universal-claim', 'unknown-npm-script']);
  });

  test('[DOC-001.AC03] splitMarkdown separates prose, command fences and output fences', () => {
    const s = splitMarkdown('a\n```\ncmd\n```\n```text\nout\n```\nb\n');
    assert.deepEqual(s.prose.map((p) => p.text), ['a', 'b', '']);
    assert.deepEqual(s.commands.map((p) => p.text), ['cmd']);
    assert.deepEqual(s.output.map((p) => p.text), ['out']);
  });
});
