// CORE-001: capability inventory and traceability ledger.
// Suite "capability-ledger" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// The checks live in scripts/capability-ledger/check.mjs. They crawl the real
// README / docs index / commands directory and compare against
// docs/capability-ledger.json; the negative tests below prove the check fails
// when a capability is removed, unmapped, or misrepresented.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  REPO_ROOT,
  PRD_PATH,
  PRD_SNAPSHOT_PATH,
  loadLedger,
  parsePrd,
  discoverCapabilities,
  checkCoverage,
  checkAdditionalTasks,
  checkBaselineSeparation,
} from '../../../scripts/capability-ledger/check.mjs';

const prd = parsePrd(REPO_ROOT);
const ledger = loadLedger(REPO_ROOT);
const discover = () => discoverCapabilities(REPO_ROOT, { excludedDocPrefixes: (ledger.excludedDocPrefixes || []).map((x) => x.prefix) });
const clone = (v) => structuredClone(v);
const cloneDiscovered = (d) => ({ ...d, sources: new Map(d.sources), unindexedDocs: [...d.unindexedDocs], brokenLinks: [...d.brokenLinks] });
const fmt = (errors) => errors.join('\n');

test('[CORE-001.AC01] discovery crawls the real README Documentation section, docs index and commands', () => {
  const d = discover();
  for (const k of ['docs/guides/quickstart.md', 'docs/compliance/', 'docs/README.md', 'docs/POSITIONING.md', 'examples/demo-app/', 'CLAUDE.md', 'command:scan', 'command:hunt', 'command:dataflow']) {
    assert.ok(d.sources.has(k), `discovery missed ${k}`);
  }
  assert.deepEqual(d.brokenLinks, [], 'index links must resolve');
  assert.ok(d.modes.scan && d.modes.scan.includes('archaeology'), 'README command modes must be parsed');
  assert.ok(prd.ids.length >= 57, 'PRD requirement headings must be parsed');
});

test('[CORE-001.AC01] every documented capability and link has ledger coverage for Haskell, Nix and NixOS execution', () => {
  const errors = checkCoverage(ledger, discover(), prd, REPO_ROOT);
  assert.equal(errors.length, 0, fmt(errors));
  for (const e of ledger.entries) {
    for (const block of ['haskell', 'nix', 'nixosExecution']) {
      assert.ok(e[block], `${e.id} lacks ${block}`);
    }
  }
});

test('[CORE-001.AC01] a removed ledger entry fails the check as an unmapped capability', () => {
  const mutated = clone(ledger);
  const removed = mutated.entries.find((e) => e.sources.includes('docs/guides/quickstart.md'));
  mutated.entries = mutated.entries.filter((e) => e !== removed);
  const errors = checkCoverage(mutated, discover(), prd, REPO_ROOT);
  assert.ok(errors.some((m) => m.includes('unmapped capability: docs/guides/quickstart.md')), fmt(errors));
});

test('[CORE-001.AC01] a newly documented link or command that the ledger does not map fails the check', () => {
  const d = cloneDiscovered(discover());
  d.sources.set('docs/guides/haskell-example.md', 'docs/README.md');
  d.sources.set('command:brand-new', 'commands');
  const errors = checkCoverage(ledger, d, prd, REPO_ROOT);
  assert.ok(errors.some((m) => m.includes('unmapped capability: docs/guides/haskell-example.md')), fmt(errors));
  assert.ok(errors.some((m) => m.includes('unmapped capability: command:brand-new')), fmt(errors));
});

test('[CORE-001.AC01] a capability removed from the docs leaves a stale ledger source that fails the check', () => {
  const d = cloneDiscovered(discover());
  d.sources.delete('docs/guides/leaked-secrets.md');
  const errors = checkCoverage(ledger, d, prd, REPO_ROOT);
  assert.ok(errors.some((m) => m.includes('no longer documented') && m.includes('leaked-secrets')), fmt(errors));
});

test('[CORE-001.AC01] a missing ecosystem block, unjustified not-applicable or unknown requirement fails the check', () => {
  const noNix = clone(ledger);
  delete noNix.entries[0].nix;
  assert.ok(checkCoverage(noNix, discover(), prd, REPO_ROOT).some((m) => m.includes('missing nix block')));

  const weakNa = clone(ledger);
  weakNa.entries[0].nixosExecution = { applicability: 'not-applicable', justification: 'n/a' };
  assert.ok(checkCoverage(weakNa, discover(), prd, REPO_ROOT).some((m) => m.includes('needs a justification')));

  const badReq = clone(ledger);
  badReq.entries[0].haskell.requirements = ['HS-999'];
  assert.ok(checkCoverage(badReq, discover(), prd, REPO_ROOT).some((m) => m.includes('unknown requirement HS-999')));
});

test('[CORE-001.AC01] every requirement named by PRD section 3 is mapped by at least one ledger entry', () => {
  assert.ok(prd.section3Ids.size > 40, 'section 3 table must be parsed');
  const used = new Set();
  for (const e of ledger.entries) {
    for (const block of ['haskell', 'nix', 'nixosExecution']) for (const r of e[block].requirements || []) used.add(r);
  }
  const missing = [...prd.section3Ids].filter((id) => !used.has(id));
  assert.deepEqual(missing, []);
});

test('[CORE-001.AC02] documents and commands found in the checkout are tracked by required versioned tasks', () => {
  const d = discover();
  const errors = checkAdditionalTasks(ledger, d, prd, REPO_ROOT);
  assert.equal(errors.length, 0, fmt(errors));
  assert.ok(d.unindexedDocs.length > 0, 'the checkout has documents no index links to');
  const tasks = new Map(ledger.additionalRequiredTasks.map((t) => [t.id, t]));
  for (const p of d.unindexedDocs) {
    const task = tasks.get(ledger.unindexedDocs.find((u) => u.path === p).taskId);
    assert.equal(task.required, true);
    assert.ok(task.version);
  }
  assert.equal(ledger.denominator.frozenRequiredScope, prd.ids.length + ledger.additionalRequiredTasks.length);
});

test('[CORE-001.AC02] an untracked discovered document, an optional task or a lowered denominator fails the check', () => {
  const d = cloneDiscovered(discover());
  d.unindexedDocs.push('docs/NEW_CAPABILITY.md');
  assert.ok(checkAdditionalTasks(ledger, d, prd, REPO_ROOT).some((m) => m.includes('docs/NEW_CAPABILITY.md')));

  const optional = clone(ledger);
  optional.additionalRequiredTasks[0].required = false;
  assert.ok(checkAdditionalTasks(optional, discover(), prd, REPO_ROOT).some((m) => m.includes('required: true')));

  const lowered = clone(ledger);
  lowered.denominator.frozenRequiredScope -= 1;
  assert.ok(checkAdditionalTasks(lowered, discover(), prd, REPO_ROOT).some((m) => m.includes('frozenRequiredScope')));

  const dropped = clone(ledger);
  dropped.unindexedDocs.pop();
  assert.ok(checkAdditionalTasks(dropped, discover(), prd, REPO_ROOT).length > 0);
});

test('[CORE-001.AC02] discovery on a scratch checkout finds a new command and an unlinked document', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-'));
  try {
    fs.mkdirSync(path.join(tmp, 'docs'), { recursive: true });
    fs.mkdirSync(path.join(tmp, 'commands'));
    fs.writeFileSync(path.join(tmp, 'README.md'), '## Documentation\n\n- [Index](docs/README.md)\n- [Guide](docs/guide.md)\n\n## Commands\n\n- **`alpha`** - Does a thing. Modes: one / two-x.\n\n## Other\n');
    fs.writeFileSync(path.join(tmp, 'docs', 'README.md'), '# Index\n\n- [Guide](guide.md)\n');
    fs.writeFileSync(path.join(tmp, 'docs', 'guide.md'), '# Guide\n');
    fs.writeFileSync(path.join(tmp, 'docs', 'orphan.md'), '# Orphan\n');
    fs.writeFileSync(path.join(tmp, 'commands', 'beta.md'), '---\ndescription: b\n---\n');
    const d = discoverCapabilities(tmp);
    assert.ok(d.sources.has('docs/guide.md'));
    assert.ok(d.sources.has('command:alpha'));
    assert.ok(d.sources.has('command:beta'));
    assert.deepEqual(d.modes.alpha, ['one', 'two-x']);
    assert.deepEqual(d.unindexedDocs, ['docs/orphan.md']);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('[CORE-001.AC03] existing-behavior observations still hold against the checkout and are separate from proposed support', () => {
  const errors = checkBaselineSeparation(ledger, REPO_ROOT);
  assert.equal(errors.length, 0, fmt(errors));
  const baseIds = new Set(ledger.existingBehavior.map((b) => b.id));
  for (const e of ledger.entries) {
    for (const block of ['haskell', 'nix', 'nixosExecution']) {
      if (e[block].applicability === 'applicable') assert.equal(e[block].status, 'proposed', `${e.id}.${block}`);
      for (const r of e[block].requirements || []) assert.ok(!baseIds.has(r), 'baseline IDs and requirement IDs must not mix');
    }
  }
});

test('[CORE-001.AC03] documented metrics are quoted as not re-measured and never carry fresh-measurement fields', () => {
  const metrics = ledger.existingBehavior.filter((b) => b.kind === 'documented-metric');
  assert.ok(metrics.length >= 1);
  for (const m of metrics) {
    assert.equal(m.measuredThisRun, false);
    assert.equal(m.status, 'documented-not-remeasured');
    assert.ok(m.asOf, 'a metric states the date the source gave it, or that it is undated');
  }
  assert.ok(!JSON.stringify(ledger).includes('measuredAt'));
});

test('[CORE-001.AC03] relabeling a baseline metric as fresh, claiming implemented support, or a stale observation fails the check', () => {
  const fresh = clone(ledger);
  fresh.existingBehavior.find((b) => b.kind === 'documented-metric').measuredThisRun = true;
  assert.ok(checkBaselineSeparation(fresh, REPO_ROOT).length > 0);

  const stamped = clone(ledger);
  stamped.existingBehavior[0].measuredAt = '2026-10-03';
  assert.ok(checkBaselineSeparation(stamped, REPO_ROOT).some((m) => m.includes('fresh-measurement')));

  const claimed = clone(ledger);
  claimed.entries[0].haskell.status = 'implemented';
  assert.ok(checkCoverage(claimed, discover(), prd, REPO_ROOT).some((m) => m.includes('status must be "proposed"')));

  const stale = clone(ledger);
  stale.existingBehavior.find((b) => b.id === 'BASE-002').expect = 'present';
  assert.ok(checkBaselineSeparation(stale, REPO_ROOT).some((m) => m.includes('no longer true')));
});

test('[CORE-001.AC01] the committed PRD snapshot equals the PRD whenever both exist, and a clean checkout parses from the snapshot', () => {
  const snap = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, PRD_SNAPSHOT_PATH), 'utf8'));
  assert.ok(snap.ids.length >= 57 && Object.keys(snap.suiteByRequirement).length >= 57);
  if (fs.existsSync(path.join(REPO_ROOT, PRD_PATH))) {
    const p = parsePrd(REPO_ROOT);
    assert.deepEqual(snap.ids, p.ids, 'the snapshot is stale: run node scripts/capability-ledger/check.mjs --write-snapshot');
    assert.deepEqual(snap.suiteByRequirement, p.suiteByRequirement);
    assert.deepEqual(snap.section3Ids, [...p.section3Ids].sort());
  }
});
