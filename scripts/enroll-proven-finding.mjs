#!/usr/bin/env node
// R2 — enrol execution-proven findings from a scan into the CVE-replay corpus.
//
// Reads `.agentic-security/last-scan.json` from a scanned project, takes every
// finding the pipeline PROVED by execution, and offers each to
// `posture/corpus-enroll.js`. Entries are written only after being scored
// `pre:TP post:TN` with the corpus gate's own matcher; anything else is
// reported with its reason and nothing is written.
//
// A fix is required for `post/`, so a finding is enrollable only when the scan
// carries fixed content for it (`finding.fix.patch`, the shape
// `deterministic-fix.js` and the MCP synthesise path produce). A proven
// finding with no fix is reported as skipped, not silently dropped: it is a
// real candidate waiting on a fix, and it should stay visible.
//
// Usage:
//   node scripts/enroll-proven-finding.mjs <scanned-project-dir> [--dry-run]
//
// After a successful enrolment the corpus baseline must be refreshed:
//   cd scanner && npm run bench:cve-replay:update-baseline
// The gate reports a new passing entry as a nudge rather than a failure, so
// skipping that step does not break the build — it just leaves the baseline
// incomplete.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..');
const CORPUS = path.join(REPO, 'bench', 'cve-replay');

const target = process.argv[2];
const dryRun = process.argv.includes('--dry-run');
if (!target) {
  console.error('usage: enroll-proven-finding.mjs <scanned-project-dir> [--dry-run]');
  process.exit(2);
}

const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
const { enrollProvenFinding, isEnrollable } = await import(
  path.join(REPO, 'scanner', 'src', 'posture', 'corpus-enroll.js')
);
const { proveFinding } = await import(path.join(REPO, 'scanner', 'src', 'posture', 'execution-proof.js'));

// A finding reaches `execution-proven` only by running its PoC in the sandbox.
// The scan pipeline does not do this today — nothing attaches a `poc` to a
// finding automatically, so `last-scan.json` never contains a proven one. This
// step is what makes the script usable now: a finding that carries a PoC (from
// the PoC-generator agent, or hand-attached) is proved here, and the sandbox
// decides the tier. A finding with no PoC is left exactly as it was.
async function ensureProven(finding, projectRoot) {
  if (isEnrollable(finding).ok) return finding;
  if (!finding.poc?.code) return finding;
  let files;
  try {
    files = { [path.basename(finding.file)]: fs.readFileSync(path.resolve(projectRoot, finding.file), 'utf8') };
  } catch { return finding; }
  return proveFinding(finding, { files });
}

const scanFile = path.join(path.resolve(target), '.agentic-security', 'last-scan.json');
let scan;
try {
  scan = JSON.parse(fs.readFileSync(scanFile, 'utf8'));
} catch (e) {
  console.error(`could not read ${scanFile}: ${e.message}`);
  console.error('run a scan over the project first.');
  process.exit(2);
}

const all = [...(scan.findings || []), ...(scan.logicVulns || [])];
const withPoc = all.filter(f => f.poc?.code || isEnrollable(f).ok);

console.log(`${all.length} findings in ${scanFile}`);
console.log(`${withPoc.length} carry a proof-of-concept or an existing execution proof`);

const candidates = [];
for (const f of withPoc) candidates.push(await ensureProven(f, path.resolve(target)));
const proven = candidates.filter(f => isEnrollable(f).ok);
console.log(`${proven.length} are execution-proven and eligible to enrol\n`);

for (const f of candidates) {
  if (!isEnrollable(f).ok && f.proofEvidence) {
    console.log(`UNPROVEN  ${f.file}: ${f.proofEvidence.reason || 'the PoC did not demonstrate the predicted effect'}`);
  }
}

if (!proven.length) {
  console.log('\nNothing to enrol. A finding must carry a proof-of-concept that the sandbox');
  console.log('runs to the predicted effect — see posture/execution-proof.js. Note that the');
  console.log('scan pipeline does not attach PoCs itself; they come from the PoC-generator.');
  process.exit(0);
}

let enrolled = 0, skipped = 0, refused = 0;
for (const f of proven) {
  const abs = path.resolve(target, f.file);
  let preContent;
  try {
    preContent = fs.readFileSync(abs, 'utf8');
  } catch (e) {
    console.log(`SKIP  ${f.file}: could not read the vulnerable file (${e.message})`);
    skipped++;
    continue;
  }

  const rel = path.basename(f.file);
  const postContent = f.fix?.patch?.[f.file] ?? f.fix?.patch?.[rel] ?? null;
  if (!postContent) {
    console.log(`SKIP  ${f.file}: proven, but no fixed content is attached — an entry needs a post/ that scores TN`);
    skipped++;
    continue;
  }

  const r = await enrollProvenFinding(f, {
    corpusRoot: CORPUS,
    preFiles: { [rel]: preContent },
    postFiles: { [rel]: postContent },
    runScan,
    dryRun,
  });

  if (r.ok) {
    enrolled++;
    console.log(`${dryRun ? 'WOULD ENROL' : 'ENROLLED'}  ${r.id}  (${r.status})`);
  } else {
    refused++;
    console.log(`REFUSE  ${r.id || f.file}: ${r.reason}`);
  }
}

console.log(`\n${enrolled} enrolled, ${skipped} skipped (no fix), ${refused} refused.`);
if (enrolled && !dryRun) {
  console.log('\nNext: cd scanner && npm run bench:cve-replay:update-baseline');
  console.log('then commit the regenerated corpus-baseline.json alongside the new entries.');
}
