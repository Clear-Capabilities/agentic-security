// X-011: compliance, coverage maps and OSCAL parity for Haskell and Nix evidence. Tests are tagged [X-011.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runFullScan } from '../../src/engine.js';
import { listFrameworks, loadFramework, evaluateFramework, walkthroughToEvidenceJsonLd, renderWalkthrough } from '../../src/posture/auditor-walkthrough.js';
import { resolveFamilyKeys } from '../../src/posture/family-resolve.js';
import { LANGUAGE_COMPLIANCE_FAMILIES, LANGUAGE_FAMILY_ALIASES, languageAnalysisGaps } from '../../src/language/compliance-map.js';
import { toOSCALCompliance, complianceRowsFromEvaluation } from '../../src/report/oscal.js';
import { ensureKeyPair } from '../../src/posture/evidence-bundle.js';
import { signComplianceEvidence, verifyComplianceEvidence } from '../../src/posture/compliance-evidence-signing.js';
import { buildObligationEvidencePack, signObligationEvidencePack, verifyObligationEvidencePack } from '../../src/posture/obligation-evidence-pack.js';
import { buildProjectIR } from '../../src/ir/index.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { mkTestTmp } from '../helpers/tmp.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FRAMEWORK_DIR = path.join(HERE, '..', '..', 'src', 'posture', 'compliance-frameworks');
const LANG_PARSERS = new Set(['IR-TAINT', 'HS-WEB', 'HS-RULES', 'HS-LLM', 'NIX-SCRIPT', 'NIX-SECRET', 'NIX-AGENT', 'nixos-hardening', 'nix-build-trust']);
const isLangFinding = (f) => /\.(?:l?hs|nix)$/i.test(f.file || '') || LANG_PARSERS.has(f.parser);

const HS_BAD = 'module App where\nimport System.Process (callCommand)\nimport Database.PostgreSQL.Simple\n\nrun :: Connection -> IO ()\nrun conn = do\n  name <- getLine\n  callCommand ("echo " ++ name)\n  _ <- execute conn ("SELECT * FROM t WHERE n = \'" ++ name ++ "\'") ()\n  pure ()\n';
const NIX_BAD = `{ config, pkgs, lib, ... }:
let cfg = config.services.mover; in {
  imports = [ ];
  services.openssh.enable = true;
  services.openssh.settings.PermitRootLogin = "yes";
  networking.firewall.allowedTCPPorts = [ 22 ];
  systemd.services.mover = { script = ''
    cp g \${cfg.dest}
  ''; };
  environment.etc."app.conf".text = "password=\${cfg.dbPassword}";
}
`;
const FLAKE = '{ inputs = { nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05"; floating.url = "github:Example/floating"; }; outputs = { self, ... }: { }; }\n';
const scanOf = (fc, dep = {}) => runFullScan({ fileContents: fc, depFileContents: dep, deep: true, scanRoot: null });

let _bad = null;
const badScan = async () => (_bad ||= await scanOf({ 'App.hs': HS_BAD, 'configuration.nix': NIX_BAD }, { 'flake.nix': FLAKE }));
const root = () => { const r = fs.realpathSync(mkTestTmp('x011-')); fs.writeFileSync(path.join(r, 'package.json'), '{}'); return r; };

test('[X-011.AC03] the framework count and the applicable subset are generated from the current catalogs', () => {
  const files = fs.readdirSync(FRAMEWORK_DIR).filter((f) => f.endsWith('.json'));
  const listed = listFrameworks(null).filter((f) => f.source === 'bundled');
  assert.equal(listed.length, files.length, 'every catalog is listed and nothing else');
  const applicable = listed.filter((f) => (loadFramework(null, f.id).controls || []).some((c) => (c.mapsTo || []).some((m) => m.startsWith('family:') && LANGUAGE_COMPLIANCE_FAMILIES.has(m.split(':')[1]))));
  assert.ok(applicable.length > 0 && applicable.length <= listed.length);
  for (const fam of Object.keys(LANGUAGE_FAMILY_ALIASES)) assert.ok(LANGUAGE_COMPLIANCE_FAMILIES.has(fam));
});

test('[X-011.AC01] every applicable framework links Haskell and Nix findings to the right controls, and only those', async () => {
  const scan = await badScan();
  const lang = [...scan.findings, ...scan.supplyChain, ...scan.secrets].filter(isLangFinding);
  assert.ok(lang.length >= 5, `real Haskell/Nix findings exist (${lang.length})`);
  const families = new Set(lang.map((f) => f.family));
  let accepted = 0; const checked = [];
  for (const meta of listFrameworks(null).filter((f) => f.source === 'bundled')) {
    const fw = loadFramework(null, meta.id);
    const ev = evaluateFramework(null, fw, scan);
    let frameworkLinked = false;
    for (const e of ev) {
      const maps = (e.control.mapsTo || []).filter((m) => m.startsWith('family:')).map((m) => m.split(':')[1]);
      const expectIds = new Set();
      for (const fam of maps) for (const key of resolveFamilyKeys(fam, families)) for (const f of lang.filter((x) => x.family === key && ['medium', 'high', 'critical'].includes(x.severity))) expectIds.add(f.id);
      const got = new Set((e.controlRefs || []).filter((id) => lang.some((f) => f.id === id)));
      for (const id of got) assert.ok(expectIds.has(id), `${meta.id} ${e.control.id}: ${id} is linked to a control whose families do not include it`);
      for (const id of expectIds) if (!(maps.length === 0)) { assert.ok(got.has(id), `${meta.id} ${e.control.id}: expected link to ${id} is missing`); }
      if (got.size) { frameworkLinked = true; checked.push(`${meta.id}:${e.control.id}`); assert.notEqual(e.status, 'present', 'a control with an open linked finding is never present'); }
    }
    if (frameworkLinked) accepted++;
  }
  assert.ok(accepted >= 3, `at least three frameworks accept the evidence (${accepted}): ${checked.slice(0, 6).join(', ')}`);
});

test('[X-011.AC01] controls that are process-only or have no automated mapping stay outside tested technical coverage', async () => {
  const scan = await badScan();
  for (const meta of listFrameworks(null).filter((f) => f.source === 'bundled')) {
    const fw = loadFramework(null, meta.id);
    for (const e of evaluateFramework(null, fw, scan)) {
      if ((e.control.mapsTo || []).length === 0) assert.equal(e.status, 'manual', `${meta.id} ${e.control.id} has no mapping`);
      if (e.control.codeTestable === 'no') assert.notEqual(e.status, 'present', `${meta.id} ${e.control.id} is organisational`);
    }
  }
});

test('[X-011.AC02] unknown or incomplete Haskell/Nix analysis cannot read as satisfied; the same scan complete does', async () => {
  const clean = await scanOf({ 'App.hs': 'module App where\nmain :: IO ()\nmain = putStrLn "ok"\n', 'configuration.nix': '{ config, ... }: { services.openssh.enable = false; }\n' });
  assert.equal(languageAnalysisGaps(clean).present, true);
  const complete = { ...clean, scanHealth: { status: 'complete', conditions: [] } };
  const partial = { ...clean, scanHealth: { status: 'partial', conditions: ['1 language adapter exception(s)', 'the effective NixOS configuration for a target is partial: 2 unresolved, 0 truncated'] } };
  assert.equal(languageAnalysisGaps(partial).incomplete, true);
  assert.equal(languageAnalysisGaps(complete).incomplete, false);
  let capped = 0; let cleared = 0;
  for (const meta of listFrameworks(null).filter((f) => f.source === 'bundled')) {
    const fw = loadFramework(null, meta.id);
    const a = evaluateFramework(null, fw, complete); const b = evaluateFramework(null, fw, partial);
    a.forEach((ea, i) => {
      const eb = b[i];
      const langMapped = (ea.control.mapsTo || []).some((m) => m.startsWith('family:') && LANGUAGE_COMPLIANCE_FAMILIES.has(m.split(':')[1]));
      if (ea.status === 'present' && langMapped) {
        cleared++;
        assert.equal(eb.status, 'partial', `${meta.id} ${ea.control.id}: incomplete analysis caps the control`);
        assert.ok(eb.observations.some((o) => /Haskell\/Nix analysis was incomplete/.test(o)));
        capped++;
      } else if (!langMapped) assert.equal(eb.status, ea.status, `${meta.id} ${ea.control.id}: unrelated controls are unaffected`);
    });
  }
  assert.ok(cleared > 0 && capped === cleared, `controls that read present when complete were capped when not (${capped}/${cleared})`);
});

test('[X-011.AC02] OSCAL follows existing policy: an unassessed control gets no finding, and no finding is invented for it', async () => {
  const scan = await badScan();
  const fw = loadFramework(null, 'nist-800-171-r3');
  const ev = evaluateFramework(null, fw, scan);
  const rows = complianceRowsFromEvaluation(ev);
  const doc = toOSCALCompliance(fw, rows, { startedAt: '2026-10-03T00:00:00Z' });
  const result = doc.results[0];
  const manual = ev.filter((e) => e.status === 'manual').map((e) => e.control.id);
  assert.ok(manual.length > 0);
  const findingTargets = new Set((result.findings || []).map((f) => f.props.find((p) => p.name === 'source-control-id').value));
  for (const id of manual) assert.equal(findingTargets.has(id), false, `${id} is unassessed and has no finding`);
  const assessed = ev.filter((e) => e.status !== 'manual').length;
  assert.equal(findingTargets.size, assessed, 'one finding per assessed control, none more');
});

test('[X-011.AC03] positive, negative and unassessed controls produce the right gap and coverage in a signed walkthrough', async () => {
  const bad = await badScan();
  const good = await scanOf({ 'App.hs': 'module App where\nmain :: IO ()\nmain = putStrLn "ok"\n' });
  const fw = loadFramework(null, 'nist-800-171-r3');
  const evBad = evaluateFramework(null, fw, bad);
  const evGood = evaluateFramework(null, fw, { ...good, scanHealth: { status: 'complete', conditions: [] } });
  const evPart = evaluateFramework(null, fw, { ...good, scanHealth: { status: 'partial', conditions: ['2 language file(s) timed out'] } });
  const n = (ev, st) => ev.filter((e) => e.status === st).length;
  assert.ok(n(evBad, 'partial') + n(evBad, 'absent') > n(evGood, 'partial') + n(evGood, 'absent') - 1);
  assert.ok(n(evPart, 'partial') >= n(evGood, 'partial'), 'incomplete analysis never improves coverage');
  assert.ok(n(evGood, 'present') >= n(evPart, 'present'), 'complete analysis can only evidence more');
  const dir = mkTestTmp('x011-key-');
  try {
    const keys = ensureKeyPair(dir);
    const doc = walkthroughToEvidenceJsonLd(fw, evBad, { scan: bad, engineVersion: 'test', generatedAt: '2026-10-03T00:00:00Z' });
    const signed = signComplianceEvidence(doc, keys.privateKeyPem);
    assert.deepEqual(verifyComplianceEvidence(signed, keys.publicKeyPem), { ok: true, reason: null });
    assert.equal(signed.provenance.languageAnalysis.present, true);
    const t = JSON.parse(JSON.stringify(signed));
    const gap = t.controls.find((c) => c.status === 'partial' || c.status === 'absent');
    assert.ok(gap);
    gap.status = 'present';
    assert.equal(verifyComplianceEvidence(t, keys.publicKeyPem).ok, false, 'turning a gap into a pass breaks the signature');
    const partialDoc = walkthroughToEvidenceJsonLd(fw, evPart, { scan: { ...good, scanHealth: { status: 'partial', conditions: ['2 language file(s) timed out'] } } });
    assert.equal(partialDoc.provenance.languageAnalysis.incomplete, true);
    assert.match(partialDoc.provenance.languageAnalysis.reasons[0], /timed out/);
    assert.ok(/not assessed|not evidence/.test(renderWalkthrough(fw, evPart)) || partialDoc.controls.some((c) => c.observations.some((o) => /incomplete/.test(o))));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('[X-011.AC03] a signed obligation pack carries a Haskell graph fact and verifies; tampering is detected', () => {
  const src = 'module A where\nimport Network.HTTP.Simple\nimport Web.Scotty (ActionM, jsonData, liftIO)\n\ndata Patient = Patient { diagnosis :: String }\n\nh :: ActionM ()\nh = do\n  p <- jsonData\n  r0 <- parseRequest "POST http://clinic.example.test/ingest"\n  _ <- liftIO (httpLBS (setRequestBodyJSON (diagnosis p) r0))\n  pure ()\n';
  const files = { 'A.hs': src };
  const { perFile, callGraph } = buildProjectIR(files);
  const lr = buildLineageGraph(callGraph, { perFile, fileContents: files, repository: 'demo', deterministic: true });
  assert.equal(lr.status, 'complete');
  const fw = loadFramework(null, 'hipaa-security-rule');
  const ev = evaluateFramework(null, fw, { findings: [], supplyChain: [], secrets: [], lineageGraph: lr.graph, filesScanned: 1 });
  const pack = buildObligationEvidencePack({ graph: lr.graph, framework: fw, evaluation: ev, engineVersion: 'test' });
  assert.ok(pack.facts.length >= 1, 'the graph: mapping produced an obligation fact');
  assert.ok(pack.graphDigest);
  const dir = mkTestTmp('x011-pack-');
  try {
    const keys = ensureKeyPair(dir);
    const signed = signObligationEvidencePack(pack, keys.privateKeyPem);
    assert.equal(verifyObligationEvidencePack(signed, keys.publicKeyPem).ok, true);
    const t = JSON.parse(JSON.stringify(signed)); t.facts[0].state = 'satisfied';
    assert.equal(verifyObligationEvidencePack(t, keys.publicKeyPem).ok, false);
    const states = pack.facts.map((f) => f.state);
    assert.ok(!states.includes('satisfied'), `a cleartext http PHI flow is never satisfied: ${states}`);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
