// Gate for framework provenance and scope (PRD F10.1 + F10.4).
//
// A compliance artifact is read by auditors and regulators who will not
// re-derive it, so two things must be impossible:
//
//   1. IMPLYING COVERAGE THAT DOES NOT EXIST. `gdpr.json` carries 6 controls;
//      GDPR has 99 articles. `ccpa.json` carries 4. Nothing in those files said
//      they were subsets, so a reader could reasonably take a clean run as
//      "GDPR: clean". Every framework must now state its scope, in prose, and
//      say what is NOT represented.
//
//   2. SILENT DRIFT. The control set can be edited — a mapping added, an id
//      renamed — with no signal. `controlsDigest` pins the id+mapsTo structure
//      of the catalogue, so a change to what is claimed forces a deliberate
//      digest update rather than sliding in with an unrelated edit.
//
// The digest deliberately covers ONLY control ids and their mapsTo lists, not
// the whole file: fixing a typo in a summary should not trip the gate, but
// adding a control or re-pointing a mapping must.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.join(HERE, '..', 'src', 'posture', 'compliance-frameworks');
const FILES = fs.readdirSync(DIR).filter((f) => f.endsWith('.json'));

const load = (f) => JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8'));

function digestOf(fw) {
  const rows = (fw.controls || [])
    .map((c) => `${c.id || ''}\t${(c.mapsTo || []).slice().sort().join('|')}`)
    .sort();
  return crypto.createHash('sha256').update(rows.join('\n')).digest('hex').slice(0, 16);
}

test('there are frameworks to check', () => {
  assert.ok(FILES.length >= 9, `expected the bundled frameworks, found ${FILES.length}`);
});

for (const file of FILES) {
  test(`${file} declares publisher, license and source url`, () => {
    const fw = load(file);
    for (const k of ['id', 'name', 'publisher', 'license', 'url']) {
      assert.ok(fw[k] && String(fw[k]).trim(), `${file} is missing ${k}`);
    }
    assert.match(fw.url, /^https?:\/\//, `${file} url must point at the published source`);
  });

  test(`${file} states its scope and what it does NOT cover`, () => {
    const fw = load(file);
    assert.ok(
      typeof fw.scope === 'string' && fw.scope.trim().length >= 80,
      `${file} needs a real scope statement — a reader must be able to tell a subset from a full catalogue`,
    );
    // The whole point is disclosing the negative space. A scope note that only
    // describes what IS covered is the failure mode being prevented.
    assert.match(
      fw.scope,
      /NOT represented|not represented|full|FULL/,
      `${file} scope must say what is not covered (or state that it IS the full catalogue)`,
    );
  });

  test(`${file} pins its control catalogue with a matching digest`, () => {
    const fw = load(file);
    assert.ok(fw.controlsDigest, `${file} has no controlsDigest`);
    assert.equal(
      digestOf(fw),
      fw.controlsDigest,
      `${file} controls changed without updating controlsDigest — if the change is intended, recompute it deliberately`,
    );
  });

  test(`${file} controlCount matches the controls actually present`, () => {
    const fw = load(file);
    assert.equal(fw.controlCount, (fw.controls || []).length, `${file} controlCount is stale`);
  });
}

test('the digest reacts to a changed mapping, not to prose', () => {
  // Proves the pin actually bites, and that it is scoped to the claim rather
  // than to the wording — a gate that fired on every typo would be turned off.
  const fw = load(FILES[0]);
  const base = digestOf(fw);

  const proseEdit = JSON.parse(JSON.stringify(fw));
  proseEdit.controls[0].summary = `${proseEdit.controls[0].summary || ''} (clarified)`;
  assert.equal(digestOf(proseEdit), base, 'editing a summary must not trip the drift gate');

  const claimEdit = JSON.parse(JSON.stringify(fw));
  claimEdit.controls[0].mapsTo = [...(claimEdit.controls[0].mapsTo || []), 'family:something-else'];
  assert.notEqual(digestOf(claimEdit), base, 'changing what a control claims MUST trip the gate');

  const added = JSON.parse(JSON.stringify(fw));
  added.controls.push({ id: 'NEW-1', summary: 'x', mapsTo: ['family:x'] });
  assert.notEqual(digestOf(added), base, 'adding a control MUST trip the gate');
});
