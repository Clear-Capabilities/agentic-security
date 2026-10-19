// `agentic-security release-package build|verify`: assembles a signed release assurance package from the last scan and checks one offline.
//
//   release-package build [path] --private-key <pem> [--output <file>] [--fix-records <file>] [--public-key-out <file>]
//   release-package verify <package.json> --public-key <pem> [--require kind,kind]
//
// `io.git(root, ...args)` answers a read-only git query (or null); the caller supplies it so this layer never spawns a process itself.
// Exit codes: 0 built or verified; 1 the scan state failed its integrity check, or a package was rejected; 2 a usage problem or unreadable input.
//
// What goes in: the scan's health record and one record per finding (and, with --fix-records, one verification record per fix claimed). The proof tier of a
// finding is whatever the scan recorded; a finding that recorded none is `taint-proven` when the taint engine found its path and `unproven` otherwise. An
// executed counterexample is never inferred here. The verdict is computed from the package's own contents and recorded as a policy decision, so the stated
// verdict can always be recomputed by anyone holding the package.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { statePath } from '../state-dir.js';
import { verifyLastScan } from '../integrity.js';
import { buildSnapshotRef } from './evidence-registry.js';
import { buildReleasePackage, signReleasePackage } from './release-package.js';
import { releaseVerdict, verifyStatedVerdict } from './release-verdict.js';
import { verifyReleasePackage } from './release-package-verify.js';

const USAGE = 'Usage: agentic-security release-package build [path] --private-key <pem> [--output <file>] [--fix-records <file>] [--public-key-out <file>]\n       agentic-security release-package verify <package.json> --public-key <pem> [--require kind,kind]';
const DEFAULT_OUT = 'release-package.json';


function proofTierOf(f) {
  if (typeof f.proofTier === 'string') return f.proofTier;
  return f.parser === 'IR-TAINT' ? 'taint-proven' : 'unproven';
}

function findingPayload(f) {
  return {
    id: f.id, stableId: f.stableId ?? null, severity: f.severity, vuln: f.vuln, file: f.file, line: f.line ?? null,
    parser: f.parser, family: f.family, cwe: f.cwe ?? null, proofTier: proofTierOf(f),
    ...(f.triage ? { triage: f.triage } : {}),
  };
}

async function build(args, say, git) {
  const root = path.resolve(args._[2] || '.');
  const keyFile = args.flags['private-key'];
  if (!keyFile) { say.err(USAGE); return 2; }
  let privateKey;
  try { privateKey = fs.readFileSync(path.resolve(String(keyFile)), 'utf8'); } catch { say.err(`Could not read the private key at ${keyFile}.`); return 2; }

  const file = statePath(root, 'last-scan.json');
  let body;
  try { body = fs.readFileSync(file, 'utf8'); } catch { say.err(`No scan found at ${file}. Run a scan first.`); return 2; }
  const sig = verifyLastScan(body, file + '.sig');
  if (sig !== true) { say.err(sig === null ? 'The last scan has no signature, so it is not used as evidence. Run a scan again.' : 'The last scan failed its integrity check, so it is not used as evidence.'); return 1; }
  let scan;
  try { scan = JSON.parse(body); } catch { say.err('The last scan is not valid JSON.'); return 1; }
  if (!scan.scanHealth || typeof scan.scanHealth !== 'object') { say.err('The last scan carries no scan health record, which a release package requires.'); return 1; }

  let fixes = [];
  if (args.flags['fix-records']) {
    try { fixes = JSON.parse(fs.readFileSync(path.resolve(String(args.flags['fix-records'])), 'utf8')); } catch (e) { say.err(`Could not read the fix records: ${e.message}`); return 2; }
    if (!Array.isArray(fixes)) { say.err('The fix records file must hold a list.'); return 2; }
  }

  const findings = (scan.findings || []).filter(f => f && typeof f === 'object');
  const evidence = [{ kind: 'scan-health', payload: scan.scanHealth }];
  for (const f of findings) evidence.push({ kind: 'finding', payload: findingPayload(f) });
  for (const rec of fixes) {
    const at = findings.findIndex(f => f.id === rec.findingId || (rec.findingStableId && f.stableId === rec.findingStableId));
    evidence.push({ kind: 'fix-verification', payload: rec, ...(at >= 0 ? { restsOn: [at + 1] } : {}) });
  }

  const commit = git(root, 'rev-parse', 'HEAD');
  const dirty = commit ? (git(root, 'status', '--porcelain') || '').length > 0 : false;
  const snapshot = buildSnapshotRef({ commit, dirty, engineVersion: scan.engineVersion || null });
  let pkg;
  try {
    const draft = buildReleasePackage({ snapshot, evidence });
    const v = releaseVerdict(draft);
    pkg = signReleasePackage(buildReleasePackage({ snapshot, evidence, policyDecisions: [{ id: 'release-verdict', outcome: v.verdict, reason: v.statement, policyVersion: '1' }] }), privateKey);
  } catch (e) { say.err(`Could not build the package: ${e.message}`); return 1; }

  const out = path.resolve(String(args.flags.output || path.join(root, DEFAULT_OUT)));
  fs.writeFileSync(out, JSON.stringify(pkg, null, 2) + '\n');
  if (args.flags['public-key-out']) {
    const { createPublicKey } = await import('node:crypto');
    fs.writeFileSync(path.resolve(String(args.flags['public-key-out'])), createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }));
  }
  const v = releaseVerdict(pkg);
  say.out(`release package written to ${out}: ${pkg.evidence.length} evidence records, ${pkg.findings.length} findings, scan ${pkg.completeness.scanStatus}`);
  say.out(`verdict: ${v.verdict}. ${v.statement}`);
  if (!snapshot.immutable) say.out('The snapshot is not immutable: the working tree has uncommitted changes or there is no commit, and the package says so.');
  return 0;
}

async function verify(args, say) {
  const file = args._[2];
  const keyFile = args.flags['public-key'];
  if (!file || !keyFile) { say.err(USAGE); return 2; }
  let pkg; let key;
  try { pkg = JSON.parse(fs.readFileSync(path.resolve(file), 'utf8')); key = fs.readFileSync(path.resolve(String(keyFile)), 'utf8'); } catch (e) { say.err(`Could not read the input: ${e.message}`); return 2; }
  const r = verifyReleasePackage(pkg, key, { require: String(args.flags.require || '').split(',').filter(Boolean) });
  const stated = r.ok ? verifyStatedVerdict(pkg) : null;
  if (r.ok && stated && stated.ok) { say.out(`release package verified: scan ${r.completeness}, ${pkg.evidence.length} records, ${pkg.findings.length} findings`); return 0; }
  for (const e of (r.errors || [])) say.err(`${e.code}: ${e.message}`);
  if (r.ok && stated && stated.ok === false) say.err(`verdict-mismatch: ${stated.message}`);
  say.err('release package REJECTED');
  return 1;
}

export async function cmdReleasePackage(args, io = {}) {
  const say = { out: io.out || ((s) => console.log(s)), err: io.err || ((s) => console.error(s)) };
  const sub = args._[1];
  if (sub === 'build') return build(args, say, io.git || (() => null));
  if (sub === 'verify') return verify(args, say);
  say.err(USAGE);
  return 2;
}
