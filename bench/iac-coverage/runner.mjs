#!/usr/bin/env node
// PRD F4.3 — IaC coverage, scored end to end and by verdict flip.
//
// ── Why this runs a real scan instead of calling detectors ───────────────────
//
// IaC support in this engine has failed at ADMISSION twice, not at detection.
// `k8s-admission` was fully implemented, wired into the dispatch and covered by
// unit tests while returning zero findings through an actual scan, because the
// walker never kept the file. `install-script` was the same story. A bench that
// imports `scanIaC` and passes it a string would have scored both as working.
//
// So every case here is written to a temp directory at the path a project would
// really use — `deploy/app.yaml`, `charts/app/values.yaml`, `infra/main.bicep` —
// and scanned through `runScan`. What is measured is the product, not a module.
//
// ── Verdict flip, not detection count ───────────────────────────────────────
//
// Every control ships a vulnerable and a hardened variant, and a control only
// counts as covered when the vulnerable one fires AND the hardened one does
// not. A detector that reports both is not detecting the control, it is
// reporting the resource — and a recall-only bench cannot tell the difference.
// That is the same doctrine as `bench/mutation`, and it is what stops coverage
// being bought by matching on `kind: Deployment`.

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../scanner/src/runScan.js';
import { disableStateWrites } from '../_lib/tree-integrity.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RESULT = path.join(HERE, 'RESULT.json');

// Any finding at all on the file under test counts. Matching on this engine's
// own rule names would grade it against vocabulary it chose itself — the same
// reason `bench/independent` matches on CWE only — and the control text here
// comes from published hardening baselines that name no rule ids.
async function scanOne(relFile, body) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'iac-cov-'));
  try {
    const abs = path.join(dir, relFile);
    await fsp.mkdir(path.dirname(abs), { recursive: true });
    await fsp.writeFile(abs, body);
    // A project marker, so the scan behaves like a repository rather than a
    // loose directory.
    await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"iac-fixture","version":"1.0.0"}');
    // `runScan` returns { scan, meta } — a wrapper, not the scan. The first
    // version of this runner read `.findings` off the wrapper, got undefined
    // everywhere, and reported 0/14 including Terraform and Dockerfile, which
    // the regression corpus proves work. Recorded because a bench that reports
    // total failure is the one most likely to be believed.
    const { scan } = await runScan(dir, { noNetwork: true });
    const all = [
      ...(scan.findings || []),
      ...(scan.secrets || []),
      ...(scan.logicVulns || []),
    ];
    const onFile = all.filter((f) => String(f.file || '').replace(/\\/g, '/').endsWith(relFile));
    return { count: onFile.length, vulns: [...new Set(onFile.map((f) => f.vuln || f.title))].slice(0, 4) };
  } finally {
    await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

function pct(n, d) { return d === 0 ? null : Number(((n / d) * 100).toFixed(2)); }

async function main() {
  // A scan writes `.agentic-security/` into the tree it reads. These trees are
  // temporary, so nothing here would be corrupted — but the guard in
  // test/tree-integrity.test.js is unconditional on purpose, because the two
  // corpora this project polluted were both 'obviously fine' at the time.
  await disableStateWrites();
  const { controls } = JSON.parse(fs.readFileSync(path.join(HERE, 'controls.json'), 'utf8'));
  const rows = [];

  for (const c of controls) {
    const vuln = await scanOne(c.file, c.vulnerable);
    const hard = await scanOne(c.file, c.hardened);
    // Three distinct outcomes, and collapsing them would hide the interesting
    // one. SILENT means no rule exists. NO-FLIP means a rule fires on the
    // resource regardless of its configuration, which is worse than silence:
    // it looks like coverage and carries no information.
    const outcome = vuln.count === 0 ? 'SILENT'
      : hard.count === 0 ? 'COVERED'
        : 'NO-FLIP';
    rows.push({
      id: c.id, format: c.format, control: c.control, outcome,
      vulnerableFindings: vuln.count, hardenedFindings: hard.count,
      reportedAs: vuln.vulns, stillReportedWhenHardened: hard.vulns,
    });
    process.stderr.write(`  ${outcome.padEnd(8)} ${c.format.padEnd(15)} ${c.id}\n`);
  }

  const byFormat = {};
  for (const r of rows) {
    const b = (byFormat[r.format] ||= { covered: 0, noFlip: 0, silent: 0, d: 0 });
    b.d++;
    if (r.outcome === 'COVERED') b.covered++;
    else if (r.outcome === 'NO-FLIP') b.noFlip++;
    else b.silent++;
  }
  for (const b of Object.values(byFormat)) b.pct = pct(b.covered, b.d);

  const covered = rows.filter((r) => r.outcome === 'COVERED').length;
  const result = {
    prd: 'F4.3',
    generatedAt: new Date().toISOString(),
    engineVersion: JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', 'scanner', 'package.json'), 'utf8')).version,
    scoring: 'verdict flip — the vulnerable variant must fire AND the hardened variant must not',
    configuration: 'runScan on a temp tree, --no-network, files at realistic project paths',
    coverage: { n: covered, d: rows.length, pct: pct(covered, rows.length) },
    byFormat, controls: rows,
  };
  fs.writeFileSync(RESULT, JSON.stringify(result, null, 2) + '\n');

  if (process.argv.includes('--json')) { process.stdout.write(JSON.stringify(result, null, 2) + '\n'); return; }
  process.stdout.write(`\nbench/iac-coverage — engine ${result.engineVersion}\n\n`);
  process.stdout.write(`covered (verdict flips)  ${covered}/${rows.length} = ${result.coverage.pct}%\n\n`);
  for (const [fmt, b] of Object.entries(byFormat)) {
    process.stdout.write(`  ${fmt.padEnd(16)} covered ${b.covered}/${b.d}   no-flip ${b.noFlip}   silent ${b.silent}\n`);
  }
  const silent = rows.filter((r) => r.outcome === 'SILENT');
  if (silent.length) {
    process.stdout.write(`\nSILENT — no rule fires at all:\n`);
    for (const r of silent) process.stdout.write(`  ${r.format.padEnd(15)} ${r.id}: ${r.control}\n`);
  }
  const noFlip = rows.filter((r) => r.outcome === 'NO-FLIP');
  if (noFlip.length) {
    process.stdout.write(`\nNO-FLIP — fires on the hardened variant too, so it is not detecting the control:\n`);
    for (const r of noFlip) process.stdout.write(`  ${r.format.padEnd(15)} ${r.id}: still reports ${JSON.stringify(r.stillReportedWhenHardened)}\n`);
  }
  process.stdout.write(`\nwrote ${path.relative(process.cwd(), RESULT)}\n`);
}

main().catch((e) => { process.stderr.write(`runner failed: ${e.stack}\n`); process.exit(1); });
