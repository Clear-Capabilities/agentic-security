// Fix safety (PRD 9.2): every proposal that is a real fix must be ACCEPTED by the same gates a deterministic fix goes through
// (path, syntax, the original finding gone, nothing new at medium or above), and every intentionally bad proposal must be
// REJECTED. Also measured: the engine's own advertised deterministic fixes, which must all verify.
import { readJson, source, scanFiles, answers, actionable } from '../lib.mjs';
import { verifyHaskellProposal, planHaskellFix, validateHaskellFix } from '../../../scanner/src/language/haskell-fix.js';
import { verifyNixProposal, planNixFix, validateNixFix } from '../../../scanner/src/language/nix-fix.js';

export async function runFixes({ eco }) {
  const fixes = readJson('labels/fixes.json').filter((c) => c.ecosystem === eco);
  const cwes = Object.fromEntries(readJson('labels/cases.json').filter((c) => c.ecosystem === eco).map((c) => [c.family, c.cwe]));
  const out = { accept: { total: 0, correct: 0, wrong: [] }, reject: { total: 0, correct: 0, wrong: [] }, reasons: {} };
  for (const c of fixes) {
    const escape = /\.\./.test(c.targetPath);
    const rel = escape ? (eco === 'haskell' ? 'src/Svc.hs' : 'configuration.nix') : c.targetPath;
    const before = source(`fix-${eco}`, c.id, escape ? 'before/target' : `before/${c.targetPath}`);
    const proposal = source(`fix-${eco}`, c.id, 'after/proposal');
    const files = { [rel]: before };
    const scan = await scanFiles(files);
    const finding = scan.findings.find((f) => f.file === rel && actionable(f) && answers(eco, c.family, cwes[c.family], f));
    let verdict;
    if (!finding) verdict = { status: 'blocked', reason: 'no in-family finding to verify the patch against' };
    else {
      const o = { files, file: c.targetPath, proposal };
      verdict = eco === 'haskell' ? await verifyHaskellProposal(finding, o) : await verifyNixProposal(finding, o);
    }
    const accepted = verdict.status === 'verified';
    const bucket = c.expected.accepted ? out.accept : out.reject;
    bucket.total++;
    const reasonClass = String(verdict.reason || '').split(':')[0];
    out.reasons[reasonClass || (accepted ? 'verified' : 'none')] = (out.reasons[reasonClass || (accepted ? 'verified' : 'none')] || 0) + 1;
    if (accepted === c.expected.accepted) bucket.correct++; else bucket.wrong.push({ id: c.id, family: c.family, tag: c.tag, engine: verdict.status, reason: String(verdict.reason || '').slice(0, 120) });
  }

  // The engine's OWN advertised deterministic fixes, planned for each vulnerable case of a family it claims to fix.
  const vuln = readJson('labels/cases.json').filter((c) => c.ecosystem === eco && c.label === 'vulnerable' && c.split !== 'holdout-excluded');
  const advertised = { planned: 0, verified: 0, notVerified: [], unsupported: 0 };
  const seenFamilyShape = new Set();
  for (const c of vuln) {
    const text = source(eco, c.id, c.path);
    const shape = `${c.family}|${c.group.split('|')[3]}`;      // one case per template shape: the fixers are shape-based
    if (seenFamilyShape.has(shape)) continue;
    seenFamilyShape.add(shape);
    const scan = await scanFiles({ [c.path]: text });
    const finding = scan.findings.find((f) => f.file === c.path && actionable(f) && answers(eco, c.family, c.cwe, f));
    if (!finding) continue;
    const files = { [c.path]: text };
    const plan = eco === 'haskell' ? planHaskellFix(finding, files) : planNixFix(finding, files);
    if (!plan || plan.ok === false) { advertised.unsupported++; continue; }
    advertised.planned++;
    const res = eco === 'haskell' ? await validateHaskellFix(finding, { files }) : await validateNixFix(finding, { files });
    if (res.status === 'verified') advertised.verified++; else advertised.notVerified.push({ id: c.id, family: c.family, status: res.status, reason: String(res.reason || '').slice(0, 120) });
  }
  return { proposals: fixes.length, ...out, advertised };
}
