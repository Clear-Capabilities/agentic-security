// The frozen Haskell measurement splits (bench/language-support/corpora/unseen-v4, unseen-v5, ...) load only when their sources
// and labels still match the digests frozen in their manifests, and the shared builder reproduces those digests from the authoring
// files. A split whose role is `development` must say since when (its USE-LOG records the use that changed it).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORPORA = path.resolve(HERE, '..', '..', '..', 'bench', 'language-support', 'corpora');
const { build, rollup, loadFrozen, FAMILIES, ecosystemOf, PER_FAMILY } = await import(path.join(CORPORA, 'frozen-split.mjs'));

// unseen-v4, unseen-v5, ... (Haskell) and unseen-nix-v1, ... (Nix): one ecosystem per split, recorded in its manifest
const SPLITS = fs.readdirSync(CORPORA).filter((d) => /^unseen-(?:nix-)?v\d+$/.test(d) && fs.existsSync(path.join(CORPORA, d, 'manifest.json')));

test('at least one frozen split exists', () => { assert.ok(SPLITS.length >= 1, 'no frozen split with a manifest under bench/language-support/corpora'); });

for (const split of SPLITS) {
  const dir = path.join(CORPORA, split);
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const eco = ecosystemOf(manifest);
  const CWE = FAMILIES[eco];

  test(`${split}: loads with its frozen digests and has ${PER_FAMILY} vulnerable and ${PER_FAMILY} safe forms per family`, () => {
    assert.ok(CWE, `ecosystem ${eco} has a family table`);
    const cases = loadFrozen({ dir, split });
    assert.equal(cases.length, manifest.cases);
    const counts = {};
    for (const c of cases) { assert.equal(c.split, split); assert.equal(c.ecosystem, eco); assert.equal(c.cwe, CWE[c.family]); counts[`${c.family}|${c.label}`] = (counts[`${c.family}|${c.label}`] || 0) + 1; }
    for (const fam of Object.keys(CWE)) for (const lab of ['vulnerable', 'safe']) assert.equal(counts[`${fam}|${lab}`], PER_FAMILY, `${fam} ${lab}`);
    for (const c of cases) assert.ok(Number.isInteger(c.label === 'vulnerable' ? c.flawLine : c.safeSinkLine), `${c.id} has no labelled line`);
  });

  test(`${split}: the shared builder reproduces the frozen digests from the authoring files`, () => {
    const { cases, sources } = build({ dir, split, idPrefix: cases0IdPrefix(dir), eco });
    const roll = rollup(cases, sources);
    assert.equal(roll.sourcesSha256, manifest.sourcesSha256);
    assert.equal(roll.labelsSha256, manifest.labelsSha256);
  });

  test(`${split}: a modified source refuses to load`, () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'frozen-split-'));
    try {
      fs.cpSync(dir, tmp, { recursive: true });
      const c = JSON.parse(fs.readFileSync(path.join(tmp, 'labels.json'), 'utf8'))[0];
      fs.appendFileSync(path.join(tmp, 'sources', eco, c.id, c.path), eco === 'nix' ? '# changed after freezing\n' : '-- changed after freezing\n');
      assert.throws(() => loadFrozen({ dir: tmp, split }), /digest mismatch/);
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  test(`${split}: the manifest's role is stated and a development role names its date`, () => {
    const role = manifest.role || 'generalisation';
    assert.ok(['generalisation', 'development'].includes(role), `role ${role}`);
    if (role === 'development') assert.match(String(manifest.developmentSince), /^\d{4}-\d{2}-\d{2}$/, 'a development split records since when');
    assert.ok(fs.existsSync(path.join(dir, 'USE-LOG.md')), 'USE-LOG.md exists');
  });
}

function cases0IdPrefix(dir) {
  const first = JSON.parse(fs.readFileSync(path.join(dir, 'labels.json'), 'utf8'))[0];
  return first.id.replace(/[0-9a-f]{10}$/, '');
}
