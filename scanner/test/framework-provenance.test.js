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

  // Adversarial premortem P0.3/P2.7 (2026-09-07): a `url` field was carried
  // by every framework since the beginning, but nothing ever actually fetched
  // it — the PRD for nist-800-171-r3 explicitly said "verify it resolves
  // before committing" and that verification silently never ran. Every
  // bundled framework was live-checked once (WebFetch, or curl when WebFetch
  // was itself bot-blocked) and got exactly one of three outcomes:
  //
  //   sourceDoi + sourcePdfSha256   — a fixed, hashable publication (NIST SPs)
  //   sourceVerifiedAt              — confirmed live, but a living-law page or
  //                                   a navigation hub, so no hash is meaningful
  //   sourceVerificationAttempted   — checked and NOT confirmed (bot-blocked);
  //                                   recorded honestly rather than faked
  //
  // A framework that claims ANY of these three must claim it completely and
  // consistently — a half-present hash, or a note with no timestamp, is worse
  // than no claim at all, because a reader trusts it.
  test(`${file} — if source verification is claimed, it is claimed completely`, () => {
    const fw = load(file);
    const hasDoi = 'sourceDoi' in fw;
    const hasHash = 'sourcePdfSha256' in fw;
    const hasVerifiedAt = 'sourceVerifiedAt' in fw;
    const hasAttempted = 'sourceVerificationAttempted' in fw;
    const hasNote = 'sourceVerificationNote' in fw;
    if (!hasDoi && !hasHash && !hasVerifiedAt && !hasAttempted && !hasNote) {
      return; // not yet instrumented — tracked separately (P2.7 follow-up), not a failure here
    }
    assert.ok(hasNote && typeof fw.sourceVerificationNote === 'string' && fw.sourceVerificationNote.length >= 40,
      `${file} claims source verification but has no real sourceVerificationNote explaining what was checked`);
    // Exactly one confirmation tier, never both a confirmed and an
    // unconfirmed claim on the same framework.
    assert.ok(!(hasVerifiedAt && hasAttempted),
      `${file} carries both sourceVerifiedAt and sourceVerificationAttempted — pick one, they mean different things`);
    if (hasDoi || hasHash) {
      assert.ok(hasDoi && hasHash,
        `${file} claims partial hash-pinned verification (sourceDoi:${hasDoi}, sourcePdfSha256:${hasHash}) — both or neither`);
      assert.match(fw.sourceDoi, /^https:\/\/doi\.org\//, `${file}.sourceDoi must be a real DOI URL`);
      assert.match(fw.sourcePdfSha256, /^[0-9a-f]{64}$/, `${file}.sourcePdfSha256 must be a 64-hex-char SHA-256`);
    }
    if (hasVerifiedAt) {
      assert.match(fw.sourceVerifiedAt, /^\d{4}-\d{2}-\d{2}$/, `${file}.sourceVerifiedAt must be an ISO date`);
    }
    if (hasAttempted) {
      assert.match(fw.sourceVerificationAttempted, /^\d{4}-\d{2}-\d{2}$/, `${file}.sourceVerificationAttempted must be an ISO date`);
    }
  });
}

// This is the actual, whole-population check the per-file loop above can't
// express: every CURRENTLY bundled framework has been through the P2.7 sweep
// at least once. If a new framework is added later without running the same
// check, this fails loudly rather than silently letting an unverified `url`
// sit in the bundle indefinitely (the exact failure mode this whole test
// exists to prevent).
test('every bundled framework has at least attempted source verification', () => {
  const unverified = FILES.filter((file) => {
    const fw = load(file);
    return !('sourceDoi' in fw) && !('sourceVerifiedAt' in fw) && !('sourceVerificationAttempted' in fw);
  });
  assert.deepEqual(unverified, [],
    `these bundled frameworks have never had their source url checked: ${unverified.join(', ')}`);
});

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
