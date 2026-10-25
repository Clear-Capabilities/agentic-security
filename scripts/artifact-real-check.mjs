#!/usr/bin/env node
// Hosted evidence for source-to-artifact provenance, against the REAL tools: a container engine (docker), a registry (the registry
// image, run locally), and a signing tool (cosign). Nothing here is a stand-in. It is meant to run on a hosted Linux runner and exits
// non-zero, with the reason, when any tool is missing: a leg that could not run its tools is a failure, never a skip.
//
//   node scripts/artifact-real-check.mjs [--out <evidence.json>]
//
// What it builds: two tiny images (a manifest naming lodash 4.17.4, and one naming 4.17.21) with the revision label set, pushed to a
// registry on localhost, with only the first signed. Then, each asserted in BOTH directions:
//   scan      the archive (`docker save`), the local engine and the registry reference report the same advisories for the same image;
//             the clean image reports strictly fewer
//   verify    the signed image verifies with its key; the same image does not verify with another key; the unsigned image does not verify
//   mismatch  source patched to 4.17.21 against the image still on 4.17.4 is reported as "fixed in source, vulnerable in production";
//             source on 4.17.4, the same as the image, is not flagged
//
// The advisory lookups go to the real advisory database, so this needs the network. The tamper direction is a source that no longer
// matches its artifact, which is the case this feature exists to catch.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(REPO, 'scanner', 'bin', 'agentic-security.js');
const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i === -1 ? d : process.argv[i + 1]; };
const OUT = arg('out', null);
const REGISTRY = 'localhost:5000';
const NAME = 'agsec-registry-' + process.pid;
const VULN = '4.17.4';
const CLEAN = '4.17.21';
const COMMIT = 'c0ffee'.repeat(6) + 'abcd';

const evidence = { schema: 'agentic-security/artifact-real-evidence', generatedAt: new Date().toISOString(), host: { platform: process.platform, arch: process.arch, node: process.version }, tools: {}, checks: [] };
const failures = [];
const check = (name, ok, detail = null) => { evidence.checks.push({ name, ok: !!ok, ...(detail ? { detail } : {}) }); if (!ok) failures.push(detail ? `${name}: ${detail}` : name); };
const sh = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: 'utf8', timeout: opts.timeout ?? 300000, cwd: opts.cwd, env: { ...process.env, ...(opts.env || {}) } });
const must = (cmd, args, opts) => { const r = sh(cmd, args, opts); if (r.status !== 0) { fail(`${cmd} ${args.slice(0, 3).join(' ')} exited ${r.status}: ${String(r.stderr || r.stdout).trim().slice(0, 400)}`); } return r; };
const cli = (cwd, args, env) => sh(process.execPath, [CLI, ...args], { cwd, env, timeout: 600000 });
const ids = (report) => [...new Set((report.vulnerabilities || []).filter((v) => v.type === 'vulnerable_dep').map((v) => v.osvId))].sort();

function fail(msg) { cleanup(); console.error(`artifact-real: ${msg}`); process.exit(1); }
let work = null;
function cleanup() {
  try { sh('docker', ['rm', '-f', NAME], { timeout: 30000 }); } catch { /* best effort */ }
  if (work) { try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* best effort */ } }
}

// ---- the tools must exist: a missing one is a failure, not a skip
for (const [tool, args] of [['docker', ['version', '--format', '{{.Server.Version}}']], ['cosign', ['version']]]) {
  const r = sh(tool, args, { timeout: 30000 });
  if (r.error || r.status !== 0) fail(`${tool} is not available on this runner (${r.error ? r.error.code : `exit ${r.status}`}); this leg proves nothing without it`);
  evidence.tools[tool] = String(r.stdout || r.stderr).trim().split('\n').find((l) => /\d+\.\d+/.test(l))?.trim() ?? 'present';
}

work = fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-real-'));
must('docker', ['run', '-d', '--rm', '--name', NAME, '-p', '5000:5000', 'registry:2']);
for (let i = 0; i < 30; i++) { const r = sh('curl', ['-fsS', '--max-time', '3', `http://${REGISTRY}/v2/`], { timeout: 10000 }); if (r.status === 0) break; if (i === 29) fail('the local registry did not become ready'); sh('sleep', ['1'], { timeout: 5000 }); }

function build(tag, version) {
  const dir = path.join(work, tag);
  fs.mkdirSync(path.join(dir, 'app'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'app', 'package.json'), JSON.stringify({ name: tag, version: '1.0.0', dependencies: { lodash: version } }));
  fs.writeFileSync(path.join(dir, 'Dockerfile'), `FROM scratch\nLABEL org.opencontainers.image.revision=${COMMIT}\nCOPY app/package.json /app/package.json\n`);
  const ref = `${REGISTRY}/agsec/${tag}:1`;
  must('docker', ['build', '--provenance=false', '-t', ref, dir]);
  must('docker', ['push', ref]);
  const repoDigest = must('docker', ['inspect', '--format', '{{index .RepoDigests 0}}', ref]).stdout.trim();
  return { tag, ref, repository: `${REGISTRY}/agsec/${tag}`, digest: repoDigest.split('@')[1], version };
}
const vuln = build('vuln', VULN);
const clean = build('clean', CLEAN);
evidence.images = { vuln: { ref: vuln.ref, digest: vuln.digest }, clean: { ref: clean.ref, digest: clean.digest } };

// ---- keys, and a signature on the vulnerable image only
const keys = (name) => { const d = path.join(work, name); fs.mkdirSync(d); must('cosign', ['generate-key-pair'], { cwd: d, env: { COSIGN_PASSWORD: '' } }); return { priv: path.join(d, 'cosign.key'), pub: path.join(d, 'cosign.pub') }; };
const good = keys('good');
const other = keys('other');
must('cosign', ['sign', '--key', good.priv, '--yes', '--tlog-upload=false', '--allow-insecure-registry', `${vuln.repository}@${vuln.digest}`], { env: { COSIGN_PASSWORD: '' } });

// ---- scan three ways
const project = path.join(work, 'project');
fs.mkdirSync(project);
fs.writeFileSync(path.join(project, 'package.json'), '{"name":"scan-host","version":"1.0.0"}');
const tar = path.join(work, 'vuln.tar');
must('docker', ['save', '-o', tar, vuln.ref]);
const byArchive = cli(project, ['image', 'scan', tar]);
const byEngine = cli(project, ['image', 'scan', vuln.ref, '--engine', 'docker']);
const byRegistry = cli(project, ['image', 'scan', '--registry', vuln.ref, '--allow-http-loopback']);
const cleanByRegistry = cli(project, ['image', 'scan', '--registry', clean.ref, '--allow-http-loopback']);
for (const [n, r] of [['archive', byArchive], ['engine', byEngine], ['registry', byRegistry], ['clean via registry', cleanByRegistry]]) check(`scan by ${n} exits 0`, r.status === 0, r.status === 0 ? null : String(r.stderr).trim().slice(0, 300));
let a; let e; let g; let c;
try { a = JSON.parse(byArchive.stdout); e = JSON.parse(byEngine.stdout); g = JSON.parse(byRegistry.stdout); c = JSON.parse(cleanByRegistry.stdout); } catch (err) { fail(`a scan did not print JSON: ${err.message}`); }
const [ia, ie, ig, ic] = [ids(a), ids(e), ids(g), ids(c)];
evidence.advisories = { vulnerable: ig.length, clean: ic.length };
check('the vulnerable image carries real advisories', ig.length >= 7, `${ig.length} advisories`);
check('archive, engine and registry report the same advisories', JSON.stringify(ia) === JSON.stringify(ie) && JSON.stringify(ie) === JSON.stringify(ig), `archive ${ia.length}, engine ${ie.length}, registry ${ig.length}`);
check('the clean image reports strictly fewer advisories', ic.length < ig.length, `clean ${ic.length}, vulnerable ${ig.length}`);
// an image reference is a public content address, not a secret, so a plain comparison is right
const scannedRef = g.inventory.digest;
const pushedRef = vuln.digest;
check('the registry scan is bound to the registry manifest', scannedRef === pushedRef, `scanned ${scannedRef}, pushed ${pushedRef}`);
check('the revision label is read as the source commit', (g.artifactProvenanceGraph?.nodes || []).some((n) => n.kind === 'gitCommit' && n.sha === COMMIT) || JSON.stringify(g).includes(COMMIT), null);

// ---- verify, in both directions
const verify = (digest, pub, repository) => { const r = cli(project, ['image', 'verify', digest, '--cosign', '--repository', repository, '--public-key', pub, '--ignore-tlog']); let o = null; try { o = JSON.parse(r.stdout); } catch { /* reported below */ } return { status: r.status, state: o?.signature?.state ?? null, reason: o?.signature?.reason ?? String(r.stderr).trim().slice(0, 200) }; };
const vOk = verify(vuln.digest, good.pub, vuln.repository);
const vWrongKey = verify(vuln.digest, other.pub, vuln.repository);
const vUnsigned = verify(clean.digest, good.pub, clean.repository);
evidence.verification = { signedWithItsKey: vOk, signedWithAnotherKey: vWrongKey, unsigned: vUnsigned };
check('the signed image verifies with its own key', vOk.state === 'verified', JSON.stringify(vOk));
check('the same image is INVALID, not merely unverified, with another key', vWrongKey.state === 'invalid', JSON.stringify(vWrongKey));
check('an unsigned image is reported as having no signature', vUnsigned.state === 'missing', JSON.stringify(vUnsigned));

// ---- the mismatch detector, in both directions
const source = (name, version) => { const d = path.join(work, name); fs.mkdirSync(d); fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name, version: '1.0.0', dependencies: { lodash: version } })); const s = cli(d, ['scan', '.', '--only', 'sca', '--format', 'json']); if (![0, 1, 2, 3, 4].includes(s.status)) fail(`scanning the ${name} source failed: ${String(s.stderr).trim().slice(0, 300)}`); return d; };
const patched = source('source-patched', CLEAN);
const same = source('source-same', VULN);
const trace = (dir) => { const r = cli(project, ['provenance', 'trace', vuln.digest, '--source', dir]); try { return JSON.parse(r.stdout); } catch { fail(`provenance trace did not print JSON: ${String(r.stderr).trim().slice(0, 300)}`); } };
const mPatched = trace(patched);
const mSame = trace(same);
evidence.mismatch = { patchedSource: { scenarioA: mPatched.mismatch?.scenarioA?.length ?? null }, sameSource: { scenarioA: mSame.mismatch?.scenarioA?.length ?? null } };
check('source patched but image still vulnerable is reported', (mPatched.mismatch?.scenarioA?.length ?? 0) > 0, JSON.stringify(evidence.mismatch.patchedSource));
check('source equal to the image is not flagged', (mSame.mismatch?.scenarioA?.length ?? -1) === 0, JSON.stringify(evidence.mismatch.sameSource));

cleanup();
if (OUT) fs.writeFileSync(path.resolve(OUT), JSON.stringify(evidence, null, 2) + '\n');
for (const c2 of evidence.checks) console.log(`${c2.ok ? 'ok  ' : 'FAIL'} ${c2.name}${c2.detail && !c2.ok ? ` (${c2.detail})` : ''}`);
if (failures.length) { console.error(`artifact-real: ${failures.length} check(s) failed`); process.exit(1); }
console.log(`artifact-real: ${evidence.checks.length} checks passed against docker ${evidence.tools.docker}, a real registry and cosign ${evidence.tools.cosign}`);
