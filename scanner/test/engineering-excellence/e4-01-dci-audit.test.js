// E4-01: the DCI maturity audit is measured, current, and honest about what is absent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO } from './helpers.js';
import { buildContext } from '../../src/context-intelligence/build.js';
import { normalizeConfig } from '../../src/context-intelligence/config.js';
import { capabilityMatrix } from '../../src/context-intelligence/capabilities.js';
import { ABSENT_PROBES, DIMENSIONS, FIXTURES } from '../../../scripts/engineering-excellence/dci-audit.mjs';

const DATA = JSON.parse(fs.readFileSync(path.join(REPO, 'scripts/engineering-excellence/data/dci-maturity.json'), 'utf8'));

test('the committed audit and its document match a fresh measurement', () => {
  const r = spawnSync(process.execPath, [path.join(REPO, 'scripts/engineering-excellence/dci-audit.mjs'), '--check'], { cwd: REPO, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

test('every language has every dimension, each cell is one of detected/partial/not-detected, and the document names them', () => {
  assert.deepEqual(Object.keys(DATA.languages).sort(), Object.keys(FIXTURES).sort());
  for (const [lang, v] of Object.entries(DATA.languages)) for (const d of DIMENSIONS) assert.ok(['detected', 'partial', 'not-detected'].includes(v.cells[d]), `${lang}/${d}`);
  const doc = fs.readFileSync(path.join(REPO, 'docs/engineering-excellence/DCI_MATURITY.md'), 'utf8');
  for (const lang of Object.keys(FIXTURES)) assert.ok(doc.includes(`| ${lang} |`), lang);
  for (const w of ['Dimensions with no deterministic extractor', 'Model-assisted question packs', 'Limitations']) assert.ok(doc.includes(w), w);
});

test('JavaScript and TypeScript detect every dimension, and no control is reported on the unguarded route in any language', () => {
  for (const lang of ['javascript', 'typescript']) for (const d of DIMENSIONS) assert.equal(DATA.languages[lang].cells[d], 'detected', `${lang}/${d}`);
  for (const [lang, v] of Object.entries(DATA.languages)) assert.deepEqual(v.detail.controlsOnUnguardedRoute || [], [], `${lang}: a control on the open route is a false positive`);
});

test('the dimensions with no deterministic extractor are reported absent, not detected, and the packs that cover them are model-assisted', () => {
  for (const k of Object.keys(ABSENT_PROBES)) assert.equal(DATA.absent[k].state, 'absent', k);
  const packs = DATA.questionPacks.map((p) => p.pack);
  for (const p of ['transaction-integrity', 'business-invariant', 'cross-route-consistency']) assert.ok(packs.includes(p), p);
  assert.ok(DATA.questionPacks.every((p) => p.status === 'experimental'), 'no pack claims more than experimental');
});

test('the capability matrix agrees with the measurement: a language marked unsupported found no entry point, and PHP is experimental, not verified', () => {
  const rows = capabilityMatrix();
  const unsupported = rows.find((r) => /java\/kotlin\/c#\/go\/ruby\/rust/.test(r.language));
  assert.equal(unsupported.status, 'unsupported');
  for (const lang of ['java-spring', 'go', 'csharp-aspnet', 'ruby-rails']) assert.equal(DATA.languages[lang].cells['entry-point'], 'not-detected', lang);
  const php = rows.find((r) => r.language === 'php');
  assert.equal(php.status, 'experimental'); assert.equal(DATA.languages['php-laravel'].cells['entry-point'], 'detected');
  for (const r of rows) for (const e of r.evidence) assert.ok(fs.existsSync(path.join(REPO, 'scanner', e)), `${r.language}: evidence ${e} exists`);
});

test('regression: a one-line handler is its own declaration line, and the sensitive operation and the owner scope inside it are still seen', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e4a-'));
  try {
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"p","version":"1.0.0"}');
    fs.writeFileSync(path.join(root, 'app.js'), "const app = require('express')();\napp.get('/own/:id', requireUser, async (req, res) => { res.json(await db.docs.findOne({ id: req.params.id, ownerId: req.user.id })); });\nfunction requireUser(req, res, next) { if (!req.user) return res.sendStatus(401); next(); }\n");
    const r = await buildContext(root, { config: normalizeConfig({}).config });
    const kinds = new Set(r.bundles.flatMap((b) => (b.reach?.facts || []).map((f) => `${f.category}:${f.kind}`)));
    assert.ok(kinds.has('sensitive:data-read'), [...kinds].join());
    assert.ok(kinds.has('control:ownership'), [...kinds].join());
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('the measured gaps are listed as gaps: Python, FastAPI same-file dependencies and the unsupported languages are not claimed', () => {
  assert.equal(DATA.languages['python-fastapi'].cells['authentication'], 'not-detected');
  assert.equal(DATA.languages['python-flask'].cells['ownership'], 'not-detected');
  assert.equal(DATA.languages['python-flask'].cells['sensitive-operation'], 'not-detected');
});
