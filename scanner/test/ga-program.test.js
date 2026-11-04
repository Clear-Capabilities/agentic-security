// The GA programme's acceptance ledger (docs/ga-program/ledger.json, scripts/ga-program/ledger.mjs, the GA plan PRD sections 4, 5 and 8).
//
// What is pinned: the committed ledger, inventory and status page are consistent; every shipped registry capability has an entry and
// every generated surface is mapped; a mechanical record's status comes from the artifacts, never from the ledger; a manual `passed`
// without its evidence is a finding; a stale manual pass is not counted; an orphan surface is a finding; the milestone is not met today
// and the status page says so. The fabricated defects use the evaluator's overrides, so nothing in the tree is touched.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluate, validateLedger, loadLedger, render, modelCallSites, LEDGER_FILE, STATUS_MD } from '../../scripts/ga-program/ledger.mjs';
import { buildInventory, collectSurfaces, cliCommands, surfaceKey } from '../../scripts/ga-program/inventory.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const clone = (x) => JSON.parse(JSON.stringify(x));
let inventory;
test.before(() => { inventory = buildInventory(REPO); });

test('the committed ledger, inventory and status page are consistent (no finding)', () => {
  const findings = validateLedger(REPO);
  assert.deepEqual(findings, []);
});

test('the inventory reads every shipped surface from its source: the CLI switch, the format sets, the MCP registry, the plugin files', () => {
  const kinds = inventory.counts.byKind;
  assert.ok(kinds['cli-command'] >= 60 && cliCommands(REPO).includes('scan') && cliCommands(REPO).includes('help'));
  assert.ok(kinds['mcp-tool'] >= 17, 'the MCP tools come from ALL_TOOLS, not a document');
  assert.ok(kinds['report-format'] >= 15 && kinds['slash-command'] >= 10 && kinds['hook'] >= 5 && kinds['agent'] >= 5);
  assert.ok(kinds['integration'] >= 5 && kinds['distribution'] >= 5);
  assert.ok(inventory.counts.environmentVariables > 100 && !inventory.environmentVariables.some((v) => v.endsWith('_')));
  const keys = inventory.surfaces.map(surfaceKey);
  assert.equal(new Set(keys).size, keys.length, 'surface keys are unique');
});

test('every registry capability that ships has a ledger entry, the baseline count matches, and no entry invents one', () => {
  const ledger = loadLedger(REPO);
  assert.equal(ledger.capabilities.length, ledger.program.baselineCapabilities);
  assert.equal(ledger.program.promotionCandidates.length, 17);
  for (const c of ledger.capabilities) assert.equal(c.targetMaturity, 'GA');
  for (const c of ledger.capabilities) assert.ok(c.owner.role && c.owner.person === null, `${c.capabilityId}: owners are roles until a person is named`);
});

test('mechanical records are computed from the artifacts: the GA bar passes for a GA row, the independent record is historical, every model path evaluates the policy', () => {
  const model = evaluate(REPO);
  const ds = model.capabilities.find((c) => c.capabilityId === 'deterministic-scan');
  assert.equal(ds.records.find((r) => r.check === 'registry-ga-bar').status, 'passed');
  assert.equal(ds.records.find((r) => r.check === 'independent-accuracy-current').status, 'blocked');
  assert.match(ds.records.find((r) => r.check === 'independent-accuracy-current').detail, /historical/);
  const preview = model.capabilities.find((c) => c.registryMaturity === 'Preview');
  assert.equal(preview.records.find((r) => r.check === 'registry-ga-bar').status, 'not-started');
  const mep = model.capabilities.find((c) => c.capabilityId === 'model-egress-policy');
  const egress = mep.records.find((r) => r.check === 'egress-all-model-paths');
  assert.ok(['passed', 'failed'].includes(egress.status));
  // the sites the check sees: a transport module and a dashboard are exempt with a reason; the two scripts are the finding until release B
  const sites = modelCallSites(REPO, loadLedger(REPO).program.nonModelFetch);
  assert.ok(sites.some((s) => s.file === 'scanner/src/llm-validator/index.js' && s.guarded), 'the validator evaluates the policy');
  // 0.195.21 found two scripts sending a prompt without evaluating the policy; 0.195.22 routed both (the synthesis module through the
  // shared bounded call, the autopilot through the policy and the redactor), so no site is unguarded and the record passes.
  assert.deepEqual(sites.filter((s) => !s.guarded && !s.exempt).map((s) => s.file), []);
  assert.equal(egress.status, 'passed');
  assert.ok(sites.some((s) => s.file === 'scanner/src/discovery/detector-spec-synthesis.js' && s.guarded));
  assert.ok(sites.some((s) => s.file === 'scripts/autopilot.mjs' && s.guarded));
  // 0.195.23: every guarded site also sends through the shared transport (no redirect, capped reply, deadline); a guarded site with a
  // bare fetch fails the record. A file that uses only modelFetch is still a candidate: the transport does not hide a site.
  assert.deepEqual(sites.filter((s) => s.guarded && !s.bounded).map((s) => s.file), []);
  for (const f of ['scanner/src/posture/flow-narration.js', 'scanner/src/posture/adversary-agent.js', 'scanner/src/sca/llm-function-extract.js', 'scanner/src/posture/llm-redteam.js']) {
    assert.ok(sites.some((s) => s.file === f && s.guarded && s.bounded), `${f} is seen, guarded and bounded`);
  }
});

test('a model site that sends through a bare fetch fails the egress record even when it evaluates the policy', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'ga-bare-fetch-'));
  mkdirSync(path.join(dir, 'scanner', 'src', 'x'), { recursive: true });
  writeFileSync(path.join(dir, 'scanner', 'src', 'x', 'bare.js'), "import { evaluateEgress } from '../egress/policy.js';\nexport async function ask(prompt, endpoint) {\n  evaluateEgress({ endpoint });\n  return fetch(endpoint, { body: prompt });\n}\n");
  writeFileSync(path.join(dir, 'scanner', 'src', 'x', 'bounded.js'), "import { evaluateEgress } from '../egress/policy.js';\nimport { modelFetch } from '../egress/transport.js';\nexport async function ask(prompt, endpoint) {\n  evaluateEgress({ endpoint });\n  return modelFetch(endpoint, { body: prompt });\n}\n");
  const sites = modelCallSites(dir, {});
  assert.deepEqual(sites.map((s) => [s.file, s.guarded, s.bounded]), [['scanner/src/x/bare.js', true, false], ['scanner/src/x/bounded.js', true, true]]);
  rmSync(dir, { recursive: true, force: true });
});

test('the headline is honest: verified GA is 0 of 36 until a current-engine independent record exists, and the milestone is not met', () => {
  const model = evaluate(REPO);
  assert.equal(model.program.verifiedGa, 0);
  assert.equal(model.program.registryGa, 19);
  assert.equal(model.milestone.met, false);
  assert.ok(model.milestone.reasons.some((r) => /no current-engine independent accuracy record/.test(r)));
  assert.ok(model.milestone.reasons.some((r) => /owner unassigned/.test(r)));
  const md = readFileSync(path.join(REPO, STATUS_MD), 'utf8');
  assert.match(md, /Verified GA \(every required acceptance record passed\) \| 0 of 36/);
  assert.match(md, /never promotes anything/);
  assert.equal(render(model).md, md, 'the committed page is what the ledger renders');
});

test('an unmapped shipped surface is an orphan: a finding, and a milestone reason', () => {
  const inv = clone(inventory);
  inv.surfaces.push({ kind: 'cli-command', id: 'brand-new-command', name: 'agentic-security brand-new-command', source: 'scanner/bin/agentic-security.js' });
  const findings = validateLedger(REPO, { inventory: inv });
  assert.ok(findings.some((f) => /orphan shipped surface cli-command:brand-new-command/.test(f)), findings.join('\n'));
  const model = evaluate(REPO, { inventory: inv });
  assert.ok(model.milestone.reasons.some((r) => /orphan shipped surface cli-command:brand-new-command/.test(r)));
  // and a mapping whose surface is gone is a finding too
  const ledger = clone(loadLedger(REPO));
  ledger.surfaces['cli-command:removed-command'] = { to: 'deterministic-scan' };
  assert.ok(validateLedger(REPO, { ledger }).some((f) => /removed-command is mapped but no longer shipped/.test(f)));
});

test('a manual record declared passed without evidence is a finding and is not counted; a stale pass is not counted either', () => {
  const ledger = clone(loadLedger(REPO));
  const cap = ledger.capabilities.find((c) => c.capabilityId === 'fleet-scan');
  const rec = cap.acceptance.find((r) => r.kind === 'manual');
  rec.status = 'passed';
  const findings = validateLedger(REPO, { ledger });
  assert.ok(findings.some((f) => new RegExp(`fleet-scan/${rec.id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}: declared passed without evidence`).test(f)), findings.join('\n'));
  const model = evaluate(REPO, { ledger });
  assert.equal(model.capabilities.find((c) => c.capabilityId === 'fleet-scan').records.find((r) => r.id === rec.id).status, 'failed');
  // with evidence, but recorded 45 days ago: stale
  Object.assign(rec, { sourceCommit: 'a'.repeat(40), command: 'npm run test:posture', exitCode: 0, evidencePath: 'docs/ga-program/README.md', recordedAt: new Date(Date.now() - 45 * 86400000).toISOString() });
  const stale = evaluate(REPO, { ledger }).capabilities.find((c) => c.capabilityId === 'fleet-scan').records.find((r) => r.id === rec.id);
  assert.notEqual(stale.status, 'passed'); assert.equal(stale.stale, true);
  // recorded today: counted
  rec.recordedAt = new Date().toISOString();
  assert.equal(evaluate(REPO, { ledger }).capabilities.find((c) => c.capabilityId === 'fleet-scan').records.find((r) => r.id === rec.id).status, 'passed');
  // an evidence path that does not exist is refused
  rec.evidencePath = 'docs/ga-program/does-not-exist.md';
  assert.ok(validateLedger(REPO, { ledger }).some((f) => /does not exist/.test(f)));
});

test('a mechanical record cannot declare its status, an unknown state is refused, and a not-applicable record needs a reviewed reason', () => {
  const ledger = clone(loadLedger(REPO));
  const cap = ledger.capabilities[0];
  cap.acceptance.find((r) => r.kind === 'mechanical').status = 'passed';
  assert.ok(validateLedger(REPO, { ledger }).some((f) => /a mechanical record must not declare a status/.test(f)));
  const ledger2 = clone(loadLedger(REPO));
  ledger2.capabilities[0].acceptance.find((r) => r.kind === 'manual').status = 'unmeasured';
  assert.ok(validateLedger(REPO, { ledger: ledger2 }).some((f) => /status unmeasured is not one of/.test(f)));
  const ledger3 = clone(loadLedger(REPO));
  Object.assign(ledger3.capabilities[0].acceptance.find((r) => r.kind === 'manual'), { status: 'not-applicable', reason: 'short' });
  assert.ok(validateLedger(REPO, { ledger: ledger3 }).some((f) => /needs a reviewed reason/.test(f)));
});

test('the ledger never moves maturity: a baseline that disagrees with the registry, or a missing registry capability, is a finding', () => {
  const ledger = clone(loadLedger(REPO));
  ledger.capabilities.find((c) => c.capabilityId === 'fleet-scan').baselineMaturity = 'GA';
  assert.ok(validateLedger(REPO, { ledger }).some((f) => /fleet-scan: baselineMaturity GA differs from the registry/.test(f)));
  const ledger2 = clone(loadLedger(REPO));
  ledger2.capabilities = ledger2.capabilities.filter((c) => c.capabilityId !== 'scan-health');
  assert.ok(validateLedger(REPO, { ledger: ledger2 }).some((f) => /registry capability scan-health \(GA\) has no ledger entry/.test(f)));
});

test('the inventory is deterministic across two generations', () => {
  assert.deepEqual(collectSurfaces(REPO), inventory.surfaces);
});

test('the ledger file is where the docs say it is', () => {
  assert.equal(LEDGER_FILE, 'docs/ga-program/ledger.json');
});
