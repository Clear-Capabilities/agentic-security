// Child-process entry for ONE repository's scan inside a fleet run (PRD 4, requirement 4: one hung repository must not stop the
// fleet). `node scan-child.js <repoPath>`. It exists as its own process so the controller can kill a scan that does not finish,
// together with everything the scan started; an in-process scan cannot be interrupted.
//
// It runs the scan through the existing `runFleet` for a single repository, so the per-repository entry (finding counts, owners
// from CODEOWNERS, scan health, policy drift, provenance debt) is exactly what a fleet entry has always been, and prints that entry
// plus a slim copy of the findings between markers. Scan state writes are disabled (`AGENTIC_SECURITY_NO_STATE=1`, set by the
// controller): scanning a repository for the fleet must not change that repository.
import { runFleet } from '../fleet.js';
import { runScan } from '../../runScan.js';

export const BEGIN = '@@FLEET-SCAN-BEGIN@@';
export const END = '@@FLEET-SCAN-END@@';
const MAX_FINDINGS = 5000;

const slim = (f) => ({ id: f.id ?? null, stableId: f.stableId ?? null, severity: f.severity ?? null, cwe: f.cwe ?? null, family: f.family ?? null, vuln: f.vuln ?? null, file: f.file ?? null, line: Number.isInteger(f.line) ? f.line : null, parser: f.parser ?? null });

async function main(repoPath) {
  let captured = null;
  const res = await runFleet({ repos: [repoPath], concurrency: 1, resume: false, runScan: async (p) => { const r = await runScan(p, { provenance: false }); captured = r.scan; return r; } });
  const entry = res.results?.[0];
  if (!entry) throw new Error('the scan produced no entry');
  const findings = (captured?.findings ?? []).slice(0, MAX_FINDINGS).map(slim);
  process.stdout.write(`${BEGIN}${JSON.stringify({ entry, findings, findingsTruncated: (captured?.findings?.length ?? 0) > MAX_FINDINGS })}${END}`);
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main(process.argv[2]).then(() => process.exit(0), (e) => { process.stderr.write(String(e?.stack || e).slice(0, 4000)); process.exit(1); });
}
