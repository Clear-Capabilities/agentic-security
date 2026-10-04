// X-016: state, retention, governance and federation parity for Haskell and Nix. Tests are tagged [X-016.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ARTIFACT_REGISTRY, isRegisteredArtifact, classificationOf, retentionClassOf, confidentialOf, listArtifactsWithRetentionClass } from '../../src/posture/artifact-registry.js';
import { addLegalHold, loadLegalHolds, isUnderHold } from '../../src/posture/legal-hold.js';
import { findExpiredArtifacts } from '../../src/posture/retention-policy.js';
import { statePath } from '../../src/posture/state-dir.js';
import { writeWithBackup, undoFix } from '../../src/language/fix-lifecycle.js';
import { LANGUAGE_ANALYSIS_FILE, LANGUAGE_BOM_FILE, buildLanguageArtifacts, persistLanguageArtifacts, hasLanguageContent } from '../../src/language/state-artifacts.js';
import { validateCrossRepoLink } from '../../src/lineage/cross-repo-link.js';
import { buildProjectIR } from '../../src/ir/index.js';
import { buildLineageGraph } from '../../src/lineage/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.join(HERE, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');
const FIX = path.join(HERE, '..', 'fixtures');

const HS = 'module A where\nimport System.Process (callCommand)\n\nrun :: IO ()\nrun = getLine >>= \\n -> callCommand ("echo " ++ n)\n';
const CABAL = 'cabal-version: 2.4\nname: app\nversion: 0.1.0.0\nbuild-type: Simple\n\nexecutable app\n  main-is: A.hs\n  build-depends: base, process\n  default-language: Haskell2010\n';
const NIX = '{ ... }:\n{\n  services.openssh.enable = true;\n  services.openssh.settings.PermitRootLogin = "yes";\n}\n';
const mkProject = (files = { 'A.hs': HS, 'app.cabal': CABAL, 'host.nix': NIX }) => {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'x016-')));
  fs.writeFileSync(path.join(d, 'package.json'), '{}');
  for (const [f, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true }); fs.writeFileSync(path.join(d, f), t); }
  return d;
};
const rm = (d) => fs.rmSync(d, { recursive: true, force: true });
const cli = (cwd, args, env = {}) => spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', timeout: 110000, env: { ...process.env, NO_COLOR: '1', AGENTIC_SECURITY_LINEAGE_DEEP: '', ...env } });
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const scanned = (d) => { const r = cli(d, ['scan', '.', '--format', 'json']); assert.ok(r.status <= 3, `scan exit ${r.status}: ${r.stderr}`); return r; };

// ── AC01 ──────────────────────────────────────────────────────────────────────────────────────────────────────
test('[X-016.AC01] a Haskell/Nix scan writes registered, signed, hash-described metadata artifacts with no source text', () => {
  const d = mkProject();
  try {
    scanned(d);
    const af = path.join(d, '.agentic-security', LANGUAGE_ANALYSIS_FILE);
    assert.ok(fs.existsSync(af) && fs.existsSync(`${af}.sig`), 'analysis metadata and its signature exist');
    const body = fs.readFileSync(af, 'utf8');
    const rec = JSON.parse(body);
    assert.equal(rec.classification.containsSourceText, false);
    assert.ok(!body.includes('callCommand') && !body.includes('PermitRootLogin'), 'paths and digests only: no source text');
    const inA = rec.inputs.find((i) => i.path === 'A.hs');
    assert.equal(inA.sha256, sha(HS), 'the input digest matches the file');
    assert.ok(rec.inputs.some((i) => i.path === 'host.nix') && rec.inputs.some((i) => i.path === 'app.cabal'));
    assert.ok(rec.analysis.capabilities.haskell.parser && rec.analysis.capabilities.nix.parser, 'capability status recorded for both languages');
    const bomFile = path.join(d, '.agentic-security', LANGUAGE_BOM_FILE);
    if (rec.bom) { assert.equal(rec.bom.sha256, sha(fs.readFileSync(bomFile, 'utf8')), 'the record carries the BOM hash'); }
    for (const n of [LANGUAGE_ANALYSIS_FILE, `${LANGUAGE_ANALYSIS_FILE}.sig`, LANGUAGE_BOM_FILE, `${LANGUAGE_BOM_FILE}.sig`, 'fix-backups', 'hackage-advisories.json']) assert.ok(isRegisteredArtifact(n), `${n} is registered`);
    assert.equal(classificationOf('hackage-advisories.json'), 'operator-config', 'an operator-supplied snapshot is never deleted by reset');
    assert.equal(retentionClassOf(LANGUAGE_BOM_FILE), 'evidence');
    assert.equal(retentionClassOf('fix-backups'), 'backup');
    assert.ok(confidentialOf('fix-backups'), 'a backup holds customer source');
    assert.ok(!confidentialOf(LANGUAGE_ANALYSIS_FILE), 'metadata holds no customer content');
  } finally { rm(d); }
});

test('[X-016.AC01] a project with no Haskell or Nix leaves no language artifact', () => {
  const d = mkProject({ 'index.js': 'console.log(1)\n' });
  try {
    scanned(d);
    assert.ok(!fs.existsSync(path.join(d, '.agentic-security', LANGUAGE_ANALYSIS_FILE)));
    assert.equal(hasLanguageContent({ scanHealth: { languageCoverage: null } }), false);
    assert.equal(persistLanguageArtifacts(d, {}).skipped, 'no-language-content');
  } finally { rm(d); }
});

test('[X-016.AC01] the metadata record is deterministic and reorders nothing it should not', () => {
  const scan = { scanHealth: { languageCoverage: { totals: { files: 2 }, byKind: {}, conditions: [], limitations: [], capabilities: { haskell: {} }, optionalModes: {} } }, languageBom: { components: [{ name: 'x' }] }, languageBridges: { a: 1 } };
  const a = buildLanguageArtifacts(scan, [{ path: 'b.hs', sha256: '2' }, { path: 'a.hs', sha256: '1' }]);
  const b = buildLanguageArtifacts(scan, [{ path: 'a.hs', sha256: '1' }, { path: 'b.hs', sha256: '2' }]);
  assert.deepEqual(a.record, b.record);
  assert.deepEqual(a.record.inputs.map((i) => i.path), ['a.hs', 'b.hs']);
});

test('[X-016.AC01] legal hold blocks both TTL expiry and a plain reset of the language artifacts; without it they expire', () => {
  const d = mkProject();
  try {
    scanned(d);
    const sd = path.join(d, '.agentic-security');
    const old = new Date(Date.now() - 4000 * 86400000);
    for (const n of [LANGUAGE_ANALYSIS_FILE, LANGUAGE_BOM_FILE]) if (fs.existsSync(path.join(sd, n))) fs.utimesSync(path.join(sd, n), old, old);
    const names = () => findExpiredArtifacts(d).map((a) => a.name);
    assert.ok(names().includes(LANGUAGE_ANALYSIS_FILE), 'an old, unheld artifact expires');
    const h = addLegalHold(d, { artifact: LANGUAGE_ANALYSIS_FILE, owner: 'counsel', reason: 'litigation hold' });
    assert.equal(h.ok, true, h.reason);
    assert.ok(!names().includes(LANGUAGE_ANALYSIS_FILE), 'a held artifact never expires');
    assert.ok(isUnderHold(LANGUAGE_ANALYSIS_FILE, loadLegalHolds(d)));
    const r = cli(d, ['reset', '.', '--yes']);
    assert.ok(fs.existsSync(path.join(sd, LANGUAGE_ANALYSIS_FILE)), `reset kept the held artifact\n${r.stdout}`);
    const report = JSON.parse(fs.readFileSync(path.join(sd, 'deletion-report.json'), 'utf8'));
    assert.match(JSON.stringify(report), /active legal hold/, 'the deletion report says why it was kept');
    assert.ok(listArtifactsWithRetentionClass().some((a) => a.name === LANGUAGE_BOM_FILE));
  } finally { rm(d); }
});

test('[X-016.AC01] fix backups follow the encryption policy: encrypted when configured, refused when required and unavailable', () => {
  const d = mkProject({ 'A.hs': HS });
  try {
    fs.mkdirSync(path.join(d, '.agentic-security'), { recursive: true });
    const after = HS.replace('callCommand', 'putStrLn');
    // no policy: plaintext, as before
    const plain = writeWithBackup(d, 'A.hs', HS, after);
    assert.equal(fs.readFileSync(path.join(plain.dir, 'original'), 'utf8'), HS);
    fs.writeFileSync(path.join(d, 'A.hs'), HS);
    // configured provider: the pre-image is not readable as source, and undo restores it exactly
    fs.writeFileSync(path.join(d, '.agentic-security', 'encryption-policy.yml'), 'provider: local-key\nrequired: true\n');
    const env = { XDG_CONFIG_HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'x016k-')) };
    const saved = process.env.XDG_CONFIG_HOME; process.env.XDG_CONFIG_HOME = env.XDG_CONFIG_HOME;
    try {
      const enc = writeWithBackup(d, 'A.hs', HS, after);
      const stored = fs.readFileSync(path.join(enc.dir, 'original'), 'utf8');
      assert.ok(!stored.includes('callCommand'), 'the stored pre-image is encrypted');
      undoFix(d, enc.id);
      assert.equal(fs.readFileSync(path.join(d, 'A.hs'), 'utf8'), HS, 'undo decrypts and restores the exact original');
    } finally { if (saved === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = saved; fs.rmSync(env.XDG_CONFIG_HOME, { recursive: true, force: true }); }
    // required but no provider: refuse BEFORE touching the source
    fs.writeFileSync(path.join(d, '.agentic-security', 'encryption-policy.yml'), 'required: true\n');
    assert.throws(() => writeWithBackup(d, 'A.hs', HS, after), /encryption/i);
    assert.equal(fs.readFileSync(path.join(d, 'A.hs'), 'utf8'), HS, 'the source was not modified');
  } finally { rm(d); }
});

test('[X-016.AC01] language text that leaves the machine is redacted by the same policy as every other language', () => {
  const reg = ARTIFACT_REGISTRY.filter((a) => /^language-/.test(a.name));
  assert.ok(reg.length >= 4);
  for (const a of reg) assert.ok(a.classification === 'generated' && a.retentionClass, `${a.name} has a classification and a retention class`);
});

// ── AC02 ──────────────────────────────────────────────────────────────────────────────────────────────────────
test('[X-016.AC02] a governance edit is previewed, backed up and audit-logged, and never touches source, scan or proof state', () => {
  const d = mkProject();
  try {
    scanned(d);
    const sd = path.join(d, '.agentic-security');
    const before = { src: sha(fs.readFileSync(path.join(d, 'A.hs'))), scan: sha(fs.readFileSync(path.join(sd, 'last-scan.json'))), meta: sha(fs.readFileSync(path.join(sd, LANGUAGE_ANALYSIS_FILE))) };
    const entry = { provider: 'Acme Analytics', serviceType: 'analytics', legalEntity: 'Acme Inc', processorRole: 'processor', servicePurpose: 'usage analytics', subprocessorChain: [], processingCountries: ['US'], dataResidencyCommitment: null, dpaStatus: 'in_place', transferMechanism: null, transferImpactReviewStatus: null, retentionCommitment: null };
    fs.writeFileSync(statePath(d, 'recipient-profiles.json'), JSON.stringify({ recipients: {} }));
    const patch = path.join(d, 'patch.json'); fs.writeFileSync(patch, JSON.stringify({ recipients: { vendor1: entry } }));
    const preview = cli(d, ['governance', 'propose-edit', d, '--patch', patch]);
    assert.equal(preview.status, 0, preview.stderr);
    assert.ok(!JSON.parse(fs.readFileSync(statePath(d, 'recipient-profiles.json'), 'utf8')).recipients.vendor1, 'a preview writes nothing');
    const r = cli(d, ['governance', 'propose-edit', d, '--patch', patch, '--yes']);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(fs.readdirSync(statePath(d, 'recipient-profiles-backups')).length, 1, 'the previous state is backed up');
    assert.match(fs.readFileSync(statePath(d, 'mcp-audit.log'), 'utf8'), /governance_propose_edit/);
    assert.equal(sha(fs.readFileSync(path.join(d, 'A.hs'))), before.src, 'source is untouched');
    assert.equal(sha(fs.readFileSync(path.join(sd, 'last-scan.json'))), before.scan, 'scan history is untouched');
    assert.equal(sha(fs.readFileSync(path.join(sd, LANGUAGE_ANALYSIS_FILE))), before.meta, 'detector and proof metadata are untouched');
  } finally { rm(d); }
});

test('[X-016.AC02] accepted risk removes the finding from the active list but keeps the acceptance record, the source and the evidence', () => {
  const d = mkProject({ 'A.hs': HS });
  try {
    scanned(d);
    const sd = path.join(d, '.agentic-security');
    const first = JSON.parse(fs.readFileSync(path.join(sd, 'last-scan.json'), 'utf8'));
    const f = first.findings.find((x) => /A\.hs$/.test(x.file) && x.severity !== 'info');
    assert.ok(f, 'the Haskell finding exists');
    const digestBefore = JSON.parse(fs.readFileSync(path.join(sd, LANGUAGE_ANALYSIS_FILE), 'utf8')).inputs.find((i) => i.path === 'A.hs').sha256;
    const acc = cli(d, ['accept', '--finding', f.id, '--accept-critical']);
    assert.equal(acc.status, 0, acc.stderr + acc.stdout);
    scanned(d);
    const second = JSON.parse(fs.readFileSync(path.join(sd, 'last-scan.json'), 'utf8'));
    assert.ok(!second.findings.some((x) => x.id === f.id), 'no longer active');
    const accepted = JSON.parse(fs.readFileSync(path.join(sd, 'accepted.json'), 'utf8')).accepted;
    assert.ok(accepted.some((a) => a.id === f.id && a.expires_at && a.reason), 'the acceptance is recorded with a reason and an expiry');
    assert.equal(fs.readFileSync(path.join(d, 'A.hs'), 'utf8'), HS, 'source is not rewritten');
    const meta = JSON.parse(fs.readFileSync(path.join(sd, LANGUAGE_ANALYSIS_FILE), 'utf8'));
    assert.equal(meta.inputs.find((i) => i.path === 'A.hs').sha256, digestBefore, 'the analysed input digest is unchanged');
    assert.ok(meta.analysis.capabilities.haskell.taint.status === 'ran', 'the detector still ran: acceptance does not switch analysis off');
  } finally { rm(d); }
});

// ── AC03 ──────────────────────────────────────────────────────────────────────────────────────────────────────
function walkTree(dir, ext) { const out = {}; const w = (x) => { for (const e of fs.readdirSync(x, { withFileTypes: true })) { const p = path.join(x, e.name); if (e.isDirectory()) w(p); else if (ext.test(e.name)) out[path.relative(dir, p)] = fs.readFileSync(p, 'utf8'); } }; w(dir); return out; }
function graphOf(files, repository) {
  const { perFile, callGraph } = buildProjectIR(files);
  const r = buildLineageGraph(callGraph, { perFile, fileContents: files, repository, deterministic: true });
  assert.equal(r.status, 'complete', JSON.stringify(r.failure));
  return r.graph;
}

test('[X-016.AC03] a cross-repo link between a Nix config node and a Haskell node keeps canonical ids, scope and limitations, and is a declaration, not an observation', () => {
  const nixGraph = graphOf(walkTree(path.join(FIX, 'nix-secrets', 'store'), /\.nix$/), 'infra');
  const hsGraph = graphOf(walkTree(path.join(FIX, 'language-privacy', 'haskell'), /\.hs$/), 'orders');
  const nixNode = nixGraph.nodes.find((n) => n.analysis && n.analysis.language === 'nix');
  const hsNode = hsGraph.nodes.find((n) => n.kind === 'sink') || hsGraph.nodes[0];
  assert.ok(nixNode && hsNode);
  assert.equal(nixNode.analysis.runtime, false, 'a Nix node is static configuration evidence');
  const nixLimits = nixGraph.flows.filter((f) => f.source === nixNode.id || f.sink === nixNode.id).flatMap((f) => f.limitations || []);
  assert.ok(nixLimits.length, 'and its flows state their limitation');
  const record = {
    id: 'crosslink:abc', version: '1.0.0', provenance: 'manual', relationship: 'data_flow',
    local: { graphId: nixGraph.graphId, graphDigest: 'd1', nodeId: nixNode.id },
    remote: { repository: 'orders', sourceFile: '/x/orders.json', graphId: hsGraph.graphId, graphDigest: 'd2', nodeId: hsNode.id },
    scope: { local: { target: 'hosts.web', config: 'configuration.nix', analysis: nixNode.analysis, limitations: nixLimits }, remote: { target: 'orders-api', config: null, analysis: hsNode.analysis || null, limitations: [] } },
    evidence: { declared: true, observed: false },
    rationale: 'the web host exposes the orders API', declaredBy: 'ops', declaredAt: new Date().toISOString(),
  };
  assert.deepEqual(validateCrossRepoLink(record).errors, []);
  assert.equal(record.local.nodeId, nixNode.id); assert.equal(record.remote.nodeId, hsNode.id);
  // a declaration can never claim to be an observed flow
  assert.equal(validateCrossRepoLink({ ...record, evidence: { declared: true, observed: true } }).valid, false);
  assert.equal(validateCrossRepoLink({ ...record, evidence: { declared: false, observed: false } }).valid, false);
  assert.equal(validateCrossRepoLink({ ...record, scope: { local: { limitations: 'nope' } } }).valid, false);
  // an old record without scope or evidence stays valid
  const { scope, evidence, ...legacy } = record;
  assert.equal(validateCrossRepoLink(legacy).valid, true);
});

test('[X-016.AC03] federate declare/list carry scope, limitations and the declared-not-observed marker end to end (real CLI)', () => {
  const mk = (files) => { const d = mkProject(files); const r = cli(d, ['scan', '.', '--format', 'json'], { AGENTIC_SECURITY_LINEAGE_DEEP: '1' }); assert.ok(r.status <= 3, r.stderr); return d; };
  const tree = Object.fromEntries(Object.entries(walkTree(path.join(FIX, 'language-privacy', 'haskell'), /\.hs$/)).map(([k, v]) => [`src/${k}`, v]));
  const local = mk(tree);
  const remote = mk(tree);
  try {
    const exportPath = path.join(remote, 'remote-export.json');
    const ex = cli(remote, ['dataflow', 'export', '.', '--format', 'json', '--no-redact', '--output', exportPath]);
    assert.equal(ex.status, 0, ex.stderr);
    const remoteNode = JSON.parse(fs.readFileSync(exportPath, 'utf8')).graph.nodes[0];
    const localGraph = JSON.parse(fs.readFileSync(statePath(local, 'lineage-graph.json'), 'utf8'));
    const localNode = localGraph.nodes[0];
    const dec = cli(local, ['federate', 'declare', '.', '--local-node', localNode.id, '--remote-graph', exportPath, '--remote-node', remoteNode.id, '--repository', 'orders', '--local-target', 'billing', '--remote-config', 'orders.cabal', '--yes']);
    assert.equal(dec.status, 0, dec.stderr);
    const rep = JSON.parse(dec.stdout);
    assert.equal(rep.record.local.nodeId, localNode.id, 'canonical node ids are preserved verbatim');
    assert.equal(rep.record.remote.nodeId, remoteNode.id);
    assert.equal(rep.record.remote.repository, 'orders');
    assert.equal(rep.record.scope.local.target, 'billing');
    assert.equal(rep.record.scope.remote.config, 'orders.cabal');
    assert.ok(Array.isArray(rep.record.scope.local.limitations));
    assert.deepEqual(rep.record.evidence, { declared: true, observed: false });
    assert.equal(rep.record.provenance, 'manual');
    const list = JSON.parse(cli(local, ['federate', 'list', '.']).stdout);
    assert.equal(list.links.length, 1);
    assert.deepEqual(list.links[0].evidence, { declared: true, observed: false });
    assert.equal(list.links[0].scope.remote.config, 'orders.cabal');
    // the declaration does not add a data-flow EDGE: observed flows come only from analysis
    const after = JSON.parse(fs.readFileSync(statePath(local, 'lineage-graph.json'), 'utf8'));
    assert.equal(after.edges.length, localGraph.edges.length);
  } finally { rm(local); rm(remote); }
});
