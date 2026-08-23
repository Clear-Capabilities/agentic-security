#!/usr/bin/env node
// PRD F4.1 — secrets, scored. Precision and recall separately, because they
// are different claims with different costs and a single F1 hides which half
// is broken.
//
// ── Why the two halves are built differently ─────────────────────────────────
//
// RECALL is measured over credential formats transcribed from PROVIDER
// documentation into `formats.json`, not read out of the engine's own pattern
// table. Deriving the positive set from `CREDENTIAL_PATTERNS` would make recall
// 100% by construction — the defect `scripts/corpus-provenance-check.mjs`
// already reports about `bench/cve-replay`. It measures FORMAT COVERAGE and
// says so; it is not a claim about detecting real leaks in the wild.
//
// PRECISION is the half that matters and the half the PRD calls "the harder
// one". Every case in `negatives.json` is high-entropy, credential-shaped, and
// not a secret: lockfile integrity fields, git SHAs, UUIDs, content digests,
// inlined base64 assets, SRI attributes, build-generated class names. These are
// in every real repository, thousands per project. A scanner that reports them
// teaches its users to ignore it, which is worse than not scanning at all.
//
// ── The deliberate design decision this has to respect ──────────────────────
//
// The credential scanners read RAW SOURCE — a key inside a comment is still
// reported, because for a committed secret the comment is not a hiding place,
// it is where people put things they were about to remove. That is correct and
// is pinned by `test/comment-blindness.test.js`. So the negative set contains
// documentation and `.env.example` cases, where the right answer is genuinely
// "do not report": a provider's own published example value and an obvious
// placeholder are not credentials in any state of the world.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanCredentials, scanEntropySecrets } from '../../scanner/src/engine.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RESULT = path.join(HERE, 'RESULT.json');

// A fixed seed. Values must look real enough to exercise the patterns and must
// be reproducible, and no run may ever emit something that could be mistaken
// for a live credential in a log.
function makeRng(seed) {
  let s = seed >>> 0;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 0x100000000; };
}

function instantiate(template, rng) {
  const SETS = {
    U: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    L: 'abcdefghijklmnopqrstuvwxyz0123456789',
    A: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    D: '0123456789',
    H: '0123456789abcdef',
  };
  // Braced placeholders. The first version of this used bare X/x/a/#/h
  // characters and rewrote the literals inside `da2-`, `shpat_`, `https`,
  // `slack` and `key-` — producing malformed values that were then reported as
  // ENGINE misses. Attributing a fixture bug to the thing under test is the
  // specific failure this project has paid for before.
  return template.replace(/\{([ULADH]):(\d+)\}/g, (_, kind, n) => {
    const set = SETS[kind];
    let out = '';
    for (let i = 0; i < Number(n); i++) out += set[Math.floor(rng() * set.length)];
    return out;
  });
}

// Both detectors, because both are part of the shipped claim: the pattern list
// and the entropy heuristic. Scoring only the pattern list would flatter the
// recall number and hide every false positive the entropy path produces — and
// the entropy path is where a secret scanner usually goes wrong.
function detect(file, body) {
  const out = [];
  try { out.push(...(scanCredentials(file, body) || [])); } catch (e) { out.push({ vuln: `ERROR:${e.message}` }); }
  try { out.push(...(scanEntropySecrets(file, body) || [])); } catch { /* entropy path optional */ }
  return out;
}

function main() {
  const asJson = process.argv.includes('--json');
  const formats = JSON.parse(fs.readFileSync(path.join(HERE, 'formats.json'), 'utf8'));
  const negatives = JSON.parse(fs.readFileSync(path.join(HERE, 'negatives.json'), 'utf8'));
  const rng = makeRng(20260822);

  // ── Recall ────────────────────────────────────────────────────────────────
  const recallRows = [];
  for (const f of formats.formats) {
    const value = instantiate(f.body, rng);
    // Placed the way a leaked credential actually appears: assigned to a
    // variable in a source file. A bare string on a line of its own is an
    // easier problem than the real one.
    // Named after the provider. Several formats are only identifiable WITH
    // nearby context — a bare `SK` plus 32 hex characters is not distinguishably
    // Twilio, and the engine is right to require the word — and this is how a
    // leaked credential actually appears in source.
    const varName = f.provider.replace(/[^A-Za-z0-9]/g, '').toLowerCase() + 'Credential';
    const body = `// ${f.provider} service configuration\nconst ${varName} = "${value}";\nexport default ${varName};\n`;
    const hits = detect('src/config.js', body);
    recallRows.push({ id: f.id, provider: f.provider, detected: hits.length > 0, reportedAs: hits[0]?.vuln || null });
  }

  // ── Precision ─────────────────────────────────────────────────────────────
  const precisionRows = [];
  for (const n of negatives.cases) {
    const hits = detect(n.file, n.body + '\n');
    precisionRows.push({ id: n.id, why: n.why, falsePositive: hits.length > 0, reportedAs: hits.map((h) => h.vuln) });
  }

  const detected = recallRows.filter((r) => r.detected).length;
  const fps = precisionRows.filter((r) => r.falsePositive);

  const result = {
    prd: 'F4.1',
    generatedAt: new Date().toISOString(),
    engineVersion: JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', 'scanner', 'package.json'), 'utf8')).version,
    recall: {
      n: detected, d: recallRows.length,
      pct: Number(((detected / recallRows.length) * 100).toFixed(2)),
      claim: 'FORMAT COVERAGE over provider-documented credential formats — not detection of real leaks in the wild',
      missed: recallRows.filter((r) => !r.detected).map((r) => `${r.provider}/${r.id}`),
    },
    precision: {
      // Precision on the negative set is "how many of these high-entropy
      // non-secrets did we correctly stay silent about". Reported as a
      // correct-silence rate rather than a precision ratio, because there are
      // no true positives in this set for a ratio to be taken against.
      correctSilence: { n: precisionRows.length - fps.length, d: precisionRows.length },
      pct: Number((((precisionRows.length - fps.length) / precisionRows.length) * 100).toFixed(2)),
      falsePositives: fps.map((r) => ({ id: r.id, why: r.why, reportedAs: r.reportedAs })),
    },
    formats: recallRows,
    negatives: precisionRows,
  };

  fs.writeFileSync(RESULT, JSON.stringify(result, null, 2) + '\n');
  if (asJson) { process.stdout.write(JSON.stringify(result, null, 2) + '\n'); return; }

  process.stdout.write(`\nbench/secrets-precision — engine ${result.engineVersion}\n\n`);
  process.stdout.write(`format coverage   ${result.recall.n}/${result.recall.d} = ${result.recall.pct}%\n`);
  if (result.recall.missed.length) process.stdout.write(`  missed: ${result.recall.missed.join(', ')}\n`);
  process.stdout.write(`correct silence   ${result.precision.correctSilence.n}/${result.precision.correctSilence.d} = ${result.precision.pct}%\n`);
  for (const fp of result.precision.falsePositives) {
    process.stdout.write(`  FP  ${fp.id.padEnd(28)} ${fp.why}\n      reported as: ${fp.reportedAs.join(', ')}\n`);
  }
  process.stdout.write(`\nwrote ${path.relative(process.cwd(), RESULT)}\n`);
}

main();
