#!/usr/bin/env node
// A bounded local replay (X-208.AC03): replay the pinned positive fixture of one oracle twice and show that the verdict and the
// verification record id reproduce.
//
//   node scripts/verification-replay-example.mjs [oracle-id]      (default: injection-execution)
//
// WHAT IS BOUNDED. The target is the repository's own fixture (scanner/test/fixtures/oracles/<id>/positive). It runs through
// the trust boundary only, with no network, a workspace-only write scope, the oracle's own time and output budgets, and a
// process tree that is torn down before the verdict is read. The `verification-oracles` feature is OFF by default for every
// scan and every CLI path; this script turns it on in this one process, by an explicit operator action, and nothing else.
//
// Exit: 0 the verdict reproduced / 1 it did not / 3 this host cannot run the trust boundary (stated, never reported as a pass).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCANNER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'scanner');
const mod = (rel) => import(pathToFileURL(path.join(SCANNER, 'src', rel)).href);
const { createReplayManifest, replayManifest } = await mod('posture/replay/replay.js');
const { resolveAssuranceConfig } = await mod('posture/assurance/config.js');

const oracleId = process.argv[2] || 'injection-execution';
const dir = path.join(SCANNER, 'test', 'fixtures', 'oracles', oracleId);
if (!fs.existsSync(path.join(dir, 'positive', 'target.mjs'))) { console.error(`no pinned fixture for oracle '${oracleId}'`); process.exit(2); }

const fixtureFiles = { 'target.mjs': fs.readFileSync(path.join(dir, 'positive', 'target.mjs'), 'utf8') };
const inputs = JSON.parse(fs.readFileSync(path.join(dir, 'scenario.json'), 'utf8'));
const manifest = createReplayManifest({
  hypothesisId: `replay-example-${oracleId}`, commit: 'a'.repeat(40), fixtureFiles, oracleId, entry: 'target.mjs', inputs,
  expected: { outcome: 'confirmed' },
  // the parser oracle's positive case is ended by the supervisor deadline; keep the example short
  ...(oracleId === 'parser-resource' ? { budgets: { timeoutMs: 2500 } } : {}),
});
const config = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } });

const first = await replayManifest({ manifest, fixtureFiles }, { config });
if (first.status !== 'completed') {
  console.log(`not executed: ${first.status}${first.prerequisites?.length ? ` (${first.prerequisites.map((p) => `${p.kind}:${p.id} ${p.state}`).join(', ')})` : ''}`);
  console.log('this host cannot run the trust boundary, so nothing was verified; this is not a pass');
  process.exit(3);
}
const second = await replayManifest({ manifest, fixtureFiles }, { config });
const same = second.status === 'completed' && second.outcome === first.outcome && second.record?.id === first.record?.id;
console.log(`manifest ${manifest.id} pins commit ${manifest.repository.commit.slice(0, 12)}, fixture ${manifest.fixture.digest.slice(0, 19)}, oracle ${manifest.oracle.id}@${manifest.oracle.version}`);
console.log(`first run:  outcome ${first.outcome}, reproduced expected: ${first.reproduced}, record ${first.record.id}`);
console.log(`second run: outcome ${second.outcome}, reproduced expected: ${second.reproduced}, record ${second.record?.id}`);
console.log(`replay ${same && first.reproduced ? 'reproduced the verdict and the record id' : 'did NOT reproduce'}`);
process.exit(same && first.reproduced ? 0 : 1);
