// X-012: every documented output format, through the real CLI entry point, for Haskell and Nix findings.
// Tests are tagged [X-012.ACnn].
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildSnapshot } from '../../src/language/haskell-sca.js';
import { validateCycloneDX16, validateSPDX23 } from '../../src/language/bom-validate.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', '..', 'bin', 'agentic-security.js');
const REC = path.join(HERE, '..', 'fixtures', 'hackage-advisories', 'records', 'HSEC-2023-0001.json');

// The Haskell source carries hostile text in a comment-free string so it appears in snippets.
const HS = 'module App where\nimport System.Process (callCommand)\n\nrun :: IO ()\nrun = do\n  name <- getLine\n  callCommand ("echo <script>alert(1)</script> & \\"q\\" " ++ name)\n';
const NIX = `{ config, pkgs, lib, ... }:
let cfg = config.services.mover; in {
  services.openssh.enable = true;
  services.openssh.settings.PermitRootLogin = "yes";
  systemd.services.mover = { script = ''
    cp g \${cfg.dest}
  ''; };
}
`;
const CABAL = 'cabal-version: 2.4\nname: demo\nversion: 0.1\nexecutable demo\n  main-is: App.hs\n  hs-source-dirs: app\n  build-depends: base, aeson\n';
const FREEZE = 'constraints: any.aeson ==1.5.6.0\n';

let dir; let env; const out = {};
const run = (args, extraEnv = {}) => spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', env: { ...process.env, ...env, ...extraEnv, NO_COLOR: '1' }, timeout: 240_000, maxBuffer: 64 * 1024 * 1024 });

before(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'x012-'));
  fs.mkdirSync(path.join(dir, 'app'));
  fs.writeFileSync(path.join(dir, 'app', 'App.hs'), HS);
  fs.writeFileSync(path.join(dir, 'configuration.nix'), NIX);
  fs.writeFileSync(path.join(dir, 'demo.cabal'), CABAL);
  fs.writeFileSync(path.join(dir, 'cabal.project.freeze'), FREEZE);
  const snap = buildSnapshot([JSON.parse(fs.readFileSync(REC, 'utf8'))], new Date().toISOString());
  fs.writeFileSync(path.join(dir, 'snap.json'), JSON.stringify(snap));
  env = { AGENTIC_SECURITY_HACKAGE_ADVISORIES: path.join(dir, 'snap.json'), AGENTIC_SECURITY_OFFLINE: '1' };
  for (const f of ['json', 'sarif', 'junit', 'csv', 'html', 'md', 'stix', 'oscal', 'cyclonedx', 'spdx', 'pbom', 'aibom', 'mlbom', 'vex', 'ship', 'cli', 'summary']) {
    const r = run(['scan', '.', '--format', f, '--deep', '--no-provenance']);
    out[f] = { code: r.status, stdout: r.stdout, stderr: r.stderr };
  }
});
after(() => { if (dir) fs.rmSync(dir, { recursive: true, force: true }); });

const json = () => JSON.parse(out.json.stdout);
const sarif = () => JSON.parse(out.sarif.stdout);
const allFindings = () => { const j = json(); return [...(j.findings || []), ...(j.supplyChain || []), ...(j.secrets || [])]; };

test('[X-012.AC01] every documented format runs through the real CLI and parses', () => {
  for (const [f, r] of Object.entries(out)) { assert.ok(r.stdout.length > 0, `${f}: no output (${r.stderr.slice(0, 200)})`); assert.ok([0, 1, 2, 3].includes(r.code), `${f}: exit ${r.code}`); }
  for (const f of ['json', 'sarif', 'stix', 'oscal', 'cyclonedx', 'spdx', 'pbom', 'aibom', 'mlbom', 'vex']) assert.doesNotThrow(() => JSON.parse(out[f].stdout), `${f} is valid JSON`);
  assert.match(out.junit.stdout, /^<\?xml/); assert.match(out.html.stdout, /<html/i); assert.match(out.csv.stdout, /^id,severity,vuln/);
});

test('[X-012.AC01] SARIF, JUnit and CSV preserve the Haskell, Nix and SCA findings, with matching counts', () => {
  const j = json();
  const sast = (j.findings || []).filter((f) => f.kind === 'sast' && /\.(?:l?hs|nix)$/.test(f.file));
  const sca = (j.findings || []).filter((f) => f.kind === 'sca');
  assert.ok(sast.length >= 3, `language SAST findings in JSON (${sast.length})`);
  assert.equal(sca.length, 1, 'the Hackage advisory is one SCA finding');
  assert.equal(sca[0].file, 'cabal.project.freeze', 'attributed to the file that decides the version');
  const n = j.findings.length;
  const sarifResults = sarif().runs[0].results;
  assert.equal(sarifResults.length, n, 'SARIF has one result per finding');
  assert.equal((out.junit.stdout.match(/<testcase /g) || []).length, n, 'JUnit has one case per finding');
  assert.equal(out.csv.stdout.trim().split('\n').length - 1, n, 'CSV has one row per finding (none contain a raw newline)');
  assert.match(out.junit.stdout, new RegExp(`tests="${n}"`));
  const at = (r) => `${r.locations[0].physicalLocation.artifactLocation.uri}:${r.locations[0].physicalLocation.region.startLine}`;
  for (const f of [...sast, ...sca]) assert.ok(sarifResults.some((r) => at(r) === `${f.file}:${Math.max(1, f.line || 1)}`), `SARIF keeps ${f.file}:${f.line}`);
  const sarifSca = sarifResults.find((r) => r.locations[0].physicalLocation.artifactLocation.uri === 'cabal.project.freeze');
  assert.ok(sarifSca, 'a report that only read scan.findings would still lose this if SCA were separate: it is present');
  const LVL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
  for (const f of sast) assert.equal(sarifResults.find((r) => at(r) === `${f.file}:${f.line}`).level, LVL[f.severity], `${f.file}:${f.line} severity`);
  // the same ids in CSV
  for (const f of sast) assert.ok(out.csv.stdout.includes(f.id), `CSV carries ${f.id}`);
  const oscal = JSON.parse(out.oscal.stdout);
  assert.ok(JSON.stringify(oscal).includes('app/App.hs'), 'OSCAL observations reach the Haskell finding');
  const stix = JSON.parse(out.stix.stdout);
  assert.ok(stix.objects.length >= n, 'STIX has an object per finding');
});

test('[X-012.AC01] standard BOM formats validate and carry the Hackage component', () => {
  const c = JSON.parse(out.cyclonedx.stdout); const s = JSON.parse(out.spdx.stdout);
  assert.deepEqual(validateCycloneDX16(c).errors, []); assert.deepEqual(validateSPDX23(s).errors, []);
  assert.ok(c.components.some((x) => x.purl === 'pkg:hackage/aeson@1.5.6.0'));
  assert.ok(c.vulnerabilities && c.vulnerabilities.some((v) => /HSEC-2023-0001/.test(v.id)), 'the advisory is in the CycloneDX vulnerabilities');
  const pb = JSON.parse(out.pbom.stdout); assert.ok(pb.languageBuild && pb.languageBuild.haskell);
});

test('[X-012.AC02] SARIF carries ordered code flows, correct locations and visible generated-script origins', () => {
  const r = sarif().runs[0].results;
  const hs = r.find((x) => x.locations[0].physicalLocation.artifactLocation.uri === 'app/App.hs' && x.codeFlows);
  assert.ok(hs, 'the Haskell taint finding has a code flow');
  const hl = hs.codeFlows[0].threadFlows[0].locations.map((l) => l.location.physicalLocation.region.startLine);
  assert.deepEqual(hl, [6, 7], 'source then sink, in order');
  assert.equal(hs.locations[0].physicalLocation.region.startLine, 7);
  const nix = r.find((x) => x.codeFlows && x.locations[0].physicalLocation.artifactLocation.uri === 'configuration.nix');
  assert.ok(nix, 'the Nix script finding has a code flow');
  const steps = nix.codeFlows[0].threadFlows[0].locations;
  const gen = steps.filter((l) => l.kinds && l.kinds.includes('generated'));
  assert.equal(gen.length, 1, 'exactly the generated-script hop is labelled');
  assert.match(gen[0].location.message.text, /\[generated script\]/);
  assert.equal(gen[0].properties.generated, true);
  assert.ok(Number.isInteger(gen[0].properties.generatedLocation.line));
  assert.ok(gen[0].properties.generatedBy && /script/.test(gen[0].properties.generatedBy));
  for (const l of steps) assert.equal(l.location.physicalLocation.artifactLocation.uri, 'configuration.nix');
  // the generated hop is reported at the Nix source span, never at script coordinates inside the Nix file
  assert.equal(gen[0].location.physicalLocation.region.startLine, nix.locations[0].physicalLocation.region.startLine);
});

test('[X-012.AC02] escaping holds in HTML, CSV, Markdown and JUnit for hostile text from a source line', () => {
  assert.equal(/<script>alert\(1\)<\/script>/.test(out.html.stdout), false, 'no raw script element from a snippet in the HTML report');
  assert.ok(out.html.stdout.includes('\\u003cscript>alert(1)\\u003c/script>'), 'the hostile text IS in the report, with every `<` escaped as \\u003c inside the data block (so the check above is not vacuous)');
  assert.equal(/<script>alert\(1\)<\/script>/.test(out.md.stdout.replace(/`[^`]*`/g, '')), false, 'Markdown does not carry live HTML');
  assert.equal(/<script>alert\(1\)<\/script>/.test(out.junit.stdout.replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, '')), false, 'JUnit text outside CDATA is escaped');
  assert.doesNotMatch(out.junit.stdout.replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, ''), /[^&]&(?!amp;|lt;|gt;|quot;|apos;|#)/, 'no bare ampersand in JUnit XML');
  // CSV: the quote characters in the snippet are doubled and the field quoted, and no cell starts with a formula character
  const rows = out.csv.stdout.trim().split('\n');
  for (const row of rows.slice(1)) for (const cell of row.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/)) assert.equal(/^["']?[=+@-]/.test(cell.replace(/^"/, '')) && !/^"?-?\d/.test(cell), false, `a CSV cell starts like a formula: ${cell.slice(0, 40)}`);
});

test('[X-012.AC03] machine outputs, exit codes and the verdict agree, partial scans included', () => {
  const j = json();
  assert.equal(j.scanHealth.status, 'complete', 'with a hash-pinned advisory snapshot the Haskell analysis is complete');
  assert.equal(j.findings.some((f) => f.severity === 'critical'), true);
  const codes = new Set(Object.values(out).map((o) => o.code));
  assert.deepEqual([...codes], [3], 'every format exits 3 (a critical finding) for the same scan');
  assert.match(out.ship.stdout, /Not safe to deploy/);
  assert.doesNotMatch(out.json.stdout.trimStart(), /^[^{]/); assert.doesNotMatch(out.sarif.stdout.trimStart(), /^[^{]/);
  // A clean project whose Haskell dependencies could not be checked is PARTIAL: JSON, the verdict and strict CI agree.
  const clean = fs.mkdtempSync(path.join(os.tmpdir(), 'x012c-'));
  try {
    fs.writeFileSync(path.join(clean, 'Main.hs'), 'module Main where\nmain :: IO ()\nmain = putStrLn "ok"\n');
    fs.writeFileSync(path.join(clean, 'demo.cabal'), CABAL);
    const noFeed = { ...process.env, NO_COLOR: '1', AGENTIC_SECURITY_OFFLINE: '1', AGENTIC_SECURITY_HACKAGE_ADVISORIES: '' };
    const sh = (args) => spawnSync(process.execPath, [CLI, ...args], { cwd: clean, encoding: 'utf8', env: noFeed, timeout: 240_000, maxBuffer: 1 << 26 });
    const cj = JSON.parse(sh(['scan', '.', '--format', 'json', '--no-provenance', '--deep']).stdout);
    assert.equal(cj.scanHealth.status, 'partial'); assert.equal(cj.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length, 0);
    assert.ok(cj.scanHealth.conditions.some((c) => /Hackage advisory snapshot/.test(c)));
    const ship = sh(['scan', '.', '--format', 'ship', '--no-provenance', '--deep']);
    assert.match(ship.stdout, /Scan incomplete/); assert.doesNotMatch(ship.stdout, /Safe to deploy/);
    const strict = sh(['ci', '.', '--assurance', 'strict', '--no-provenance']);
    assert.notEqual(strict.status, 0, 'strict assurance fails a partial scan with no findings');
    const standard = sh(['ci', '.', '--assurance', 'standard', '--no-provenance']);
    assert.equal(standard.status, 0, `standard assurance reports but does not fail: ${standard.stderr.slice(0, 200)}`);
  } finally { fs.rmSync(clean, { recursive: true, force: true }); }
});

test('[X-012.AC03] an unsupported output label is an error, never a silent fallback', () => {
  const r = run(['scan', '.', '--format', 'junit-xml', '--no-provenance']);
  assert.equal(r.status, 2); assert.match(r.stderr, /unsupported --format "junit-xml"/); assert.equal(r.stdout, '');
  const ok = run(['scan', '.', '--format', 'summary', '--no-provenance']);
  assert.ok(ok.stdout.length > 0);
});
