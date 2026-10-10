#!/usr/bin/env node
// A local migration example (DOC-001.AC02): move three legacy verification shapes to the version-1 record and read them back through
// the legacy view a not-yet-migrated consumer would use.
//
//   node scripts/migration-example.mjs
//
// The inputs are small SYNTHETIC objects shaped like the three older vocabularies (a boolean, a proof-tier object and a status
// string). Nothing runs, nothing is read from disk and nothing touches a network. The point it shows is the rule of the migration:
// evidence can be lost, never invented, so no legacy shape reaches `confirmed` or `refuted` on its own.
//
// Exit: 0 every legacy shape migrated as described / 1 one did not.
import { fromLegacyVerification, toLegacyVerificationView } from '../scanner/src/posture/assurance/migrations.js';

const COMMIT = 'a'.repeat(40);
const cases = [
  { name: 'a boolean `true`', legacy: { verified: true } },
  { name: 'a proof-tier object (ran, tier execution-proven)', legacy: { tier: 'execution-proven', ran: true, backend: 'userspace' } },
  { name: 'a status string "skipped"', legacy: { status: 'skipped' } },
];
let failed = 0;
for (const c of cases) {
  const m = fromLegacyVerification(c.legacy, { hypothesisId: `example-${cases.indexOf(c)}`, commit: COMMIT });
  if (!m.ok) { console.log(`${c.name}: refused (${m.errors?.[0]?.code})`); failed++; continue; }
  const view = toLegacyVerificationView(m.record);
  console.log(`${c.name}`);
  console.log(`  version-1 outcome: ${m.record.outcome}; reason: ${m.record.reason}`);
  console.log(`  legacy view: verified ${JSON.stringify(view.verified)}, status ${view.status}`);
  if (m.record.outcome === 'confirmed' || m.record.outcome === 'refuted') { console.log('  UNEXPECTED: a legacy shape reached a decided outcome'); failed++; }
}
const missing = fromLegacyVerification({ verified: true }, {});
console.log(`no hypothesis id supplied: ${missing.ok ? 'migrated (UNEXPECTED)' : `refused (${missing.errors?.[0]?.code})`}`);
if (missing.ok) failed++;
console.log(failed ? `${failed} migration(s) did not behave as described` : 'every migration behaved as described: undecided stays undecided, and a missing id is refused rather than guessed');
process.exit(failed ? 1 : 0);
