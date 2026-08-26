#!/usr/bin/env node
// FR-403 step 3 (assurance-hardening PRD, D-0047's plan): before/after
// recall comparison between the existing shallow annotatePrivacyTaint
// (privacy-taint.js — a per-file, name-in-text regex matcher) and the new
// opt-in intra-procedural walker (dataflow/privacy-deep-walker.js, gated by
// AGENTIC_SECURITY_PRIVACY_DEEP=1).
//
// bench/layer-recall is NOT reusable here: it always forces deep mode on
// with no on/off diff axis, and it scores against the CVE-replay corpus,
// which has no privacy-shaped fixtures. This is a new, small, purpose-built
// harness instead.
//
// A single scan per fixture, with BOTH AGENTIC_SECURITY_DEEP=1 and
// AGENTIC_SECURITY_PRIVACY_DEEP=1 set, is enough to measure both sides: the
// shallow annotator always runs whenever deep mode is on (it's not gated by
// the privacy-deep flag at all), and the new walker's findings are
// distinguishable by parser:'IR-PRIVACY-TAINT'. Partitioning one scan's
// output is simpler and faster than two separate scans, and avoids any risk
// of the two runs disagreeing on unrelated grounds (timing, ordering).

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { disableStateWrites, purgeScanState } from '../_lib/tree-integrity.mjs';
import { runScan } from '../../scanner/src/runScan.js';

await disableStateWrites();

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = path.join(HERE, 'fixtures');

// D-0009 (this codebase's own documented precedent): disableStateWrites()
// does not cover every writer (e.g. threat-model/sbom-history annotators) —
// purge before AND after every run so the fixtures never accumulate real
// scan state, matching bench/layer-recall's own established pattern.
purgeScanState(FIXTURES_DIR);

function listFixtures() {
  return fs.readdirSync(FIXTURES_DIR, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

async function measureFixture(name) {
  const dir = path.join(FIXTURES_DIR, name);
  const saved = {
    DEEP: process.env.AGENTIC_SECURITY_DEEP,
    DEEP_IN_CI: process.env.AGENTIC_SECURITY_DEEP_IN_CI,
    PRIVACY_DEEP: process.env.AGENTIC_SECURITY_PRIVACY_DEEP,
  };
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  process.env.AGENTIC_SECURITY_PRIVACY_DEEP = '1';
  try {
    const { scan } = await runScan(dir, { network: false });
    const pii = (scan.findings || []).filter((f) => f.family === 'pii-exposure');
    const deep = pii.filter((f) => f.parser === 'IR-PRIVACY-TAINT');
    const shallow = pii.filter((f) => f.parser !== 'IR-PRIVACY-TAINT');
    return { shallowCount: shallow.length, deepCount: deep.length };
  } finally {
    for (const [k, envKey] of [['DEEP', 'AGENTIC_SECURITY_DEEP'], ['DEEP_IN_CI', 'AGENTIC_SECURITY_DEEP_IN_CI'], ['PRIVACY_DEEP', 'AGENTIC_SECURITY_PRIVACY_DEEP']]) {
      if (saved[k] === undefined) delete process.env[envKey];
      else process.env[envKey] = saved[k];
    }
  }
}

export async function measure() {
  const results = {};
  for (const name of listFixtures()) {
    results[name] = await measureFixture(name);
  }
  purgeScanState(FIXTURES_DIR);
  return results;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const jsonOut = process.argv.includes('--json');
  const results = await measure();
  if (jsonOut) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    for (const [name, r] of Object.entries(results)) {
      console.log(`${name}: shallow=${r.shallowCount} deep=${r.deepCount}`);
    }
  }
}
