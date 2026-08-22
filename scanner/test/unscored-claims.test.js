// PRD F3.5 — a capability with no measured accuracy must SAY it is unscored.
//
// `sca-malware-analyst` emits CLEAN / SUSPICIOUS / MALICIOUS with no labelled
// corpus behind it. F3.5 gives two options — score it, or downgrade it to
// advisory — and there is no labelled malicious-package set here, so it is
// labelled.
//
// Why this needs a TEST rather than just a doc edit: the banner is the only
// thing standing between a reader and an assumed accuracy claim, and prose with
// nothing enforcing it is exactly what this project has been bitten by twice
// already (the compliance "engine-gap" treatment that nothing implemented, and
// the AI-BOM's unverified `cyclonedxCompatible`). A claim that is only in a
// comment is a claim that quietly disappears on the next edit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..');
const AGENT = path.join(REPO, 'agents', 'sca-malware-analyst.md');

test('the malware analyst declares itself advisory and unscored', () => {
  const body = fs.readFileSync(AGENT, 'utf8');
  assert.match(body, /ADVISORY ONLY/, 'the unscored banner must be present');
  assert.match(body, /never been scored|unscored/i);
});

test('its one-line description carries the caveat too', () => {
  // The frontmatter description is what a host surfaces when offering the
  // agent. A banner buried in the body is invisible at the point of choosing.
  const body = fs.readFileSync(AGENT, 'utf8');
  const desc = /^description:\s*(.+)$/m.exec(body);
  assert.ok(desc, 'the agent must have a description');
  assert.match(desc[1], /ADVISORY|unscored/i,
    'the caveat must travel with the description, not only in the body');
});

test('the banner states the cost of being wrong in BOTH directions', () => {
  // A caveat that only warns about false positives implies false negatives are
  // safe. For malware the false CLEAN is the one that ships a compromised
  // package through a gate the team believed had checked it.
  const body = fs.readFileSync(AGENT, 'utf8');
  assert.match(body, /false MALICIOUS/i, 'must state the cost of a false positive');
  assert.match(body, /false CLEAN/i, 'must state the cost of a false negative');
});

test('the banner says what would REMOVE it', () => {
  // Without an exit condition a caveat becomes permanent furniture. Same rule
  // as the dependency holds and the calibration waiver: state what clears it.
  const body = fs.readFileSync(AGENT, 'utf8');
  assert.match(body, /What would remove this banner/i);
  assert.match(body, /precision\/recall|\{n, d\}/i, 'the exit condition must be a measurement, not a promise');
});

test('no shipped agent claims a measured accuracy it does not have', () => {
  // The general rule this item is an instance of. An agent asserting a rate
  // must cite where the rate came from; a bare percentage in a system prompt is
  // an accuracy claim a reader will believe.
  const dir = path.join(REPO, 'agents');
  const offenders = [];
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.md'))) {
    const body = fs.readFileSync(path.join(dir, f), 'utf8');
    // A percentage presented as this tool's own accuracy, with no denominator
    // and no citation anywhere in the file.
    const claims = body.match(/\b\d{1,3}(?:\.\d+)?%\s*(?:precision|recall|accuracy|f1)/gi) || [];
    for (const c of claims) {
      const cited = /bench\/|docs\/SCORECARD|\{n,\s*d\}|n\s*=\s*\d+/i.test(body);
      if (!cited) offenders.push(`${f}: "${c}" with no cited source`);
    }
  }
  assert.deepEqual(offenders, [], 'agents asserting an uncited accuracy figure');
});

// ── PRD F4.4 — container scope, stated ──────────────────────────────────────
//
// `scanContainer` reads Dockerfiles. It does not read a built image: no
// base-image CVE lookup, no layer secret extraction, no digest verification of
// something pulled from a registry. The README listed "containers" among twelve
// pillars with no qualification, and a reader reasonably infers image scanning
// from that word.
//
// F4.4's options were "scan images" or "say it is out of scope". Building image
// scanning is a feature, not a disclosure fix; the scope is therefore stated.
// The silence was the problem — an unqualified pillar name reads as coverage.

test('the README does not imply built-image scanning', () => {
  const readme = fs.readFileSync(path.join(REPO, 'README.md'), 'utf8');
  assert.match(readme, /Built images are NOT scanned/i,
    'the container pillar must state that images are out of scope');
  assert.match(readme, /base-image CVE|layer secret/i,
    'it must name what is absent, not just gesture at a limitation');
});

test('the container scope note names an alternative rather than leaving a hole', () => {
  // A limitation with no suggested path leaves the reader stuck. Naming the
  // alternative is what turns a gap into a boundary.
  const readme = fs.readFileSync(path.join(REPO, 'README.md'), 'utf8');
  assert.match(readme, /dedicated image scanner/i);
});
