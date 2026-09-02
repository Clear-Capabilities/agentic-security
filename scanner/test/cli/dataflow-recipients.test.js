// dataflow-recipients.test.js — Milestone 4, FR-506 (Third-Party and
// Cross-Border Intelligence), Task 3: real CLI integration tests for
// `agentic-security dataflow export --format recipients`.
//
// Mirrors test/cli/dataflow-export-privacy.test.js's own real-git-fixture +
// real-deep-scan + real-CLI-subprocess pattern — recipients needs a REAL
// sink site reaching a REAL technical-provider-catalog-matched sink (an
// AI-provider SDK call) to produce meaningful content, the same reason
// dpia/ropa need real classified flows.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

// Same real, proven PHI-to-model-provider shape used throughout this
// branch's own M4 sub-projects (bench/data-lineage/fixtures/
// js-ai-model-output-to-ai-model-provider-phi), copied verbatim from
// test/cli/dataflow-export-privacy.test.js's own PHI_SOURCE — a real
// `anthropic.messages.create()` call, the exact fixture shape the task
// brief names for this Task's own recipient-intelligence tests.
const PHI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

// A fixture reaching nothing recipient-worthy at all — an ordinary
// in-process http response, no technical-provider catalog match, no
// operator-declared recipient.
const NOTHING_SOURCE = `function h(req, res){ const pw = req.body.password; res.send(pw); }`;

function _scanWithLineage(fx) {
  return spawnSync(process.execPath, [CLI, 'scan', '.'], {
    cwd: fx.root, encoding: 'utf8', timeout: 60000,
    env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
  });
}

function _exportCli(fx, args) {
  return spawnSync(process.execPath, [CLI, 'dataflow', 'export', '.', ...args], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
}

function _writeRecipientConfig(fx, obj) {
  const dir = path.join(fx.root, '.agentic-security');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'recipient-profiles.json'), JSON.stringify(obj, null, 2));
}

test('dataflow export --format recipients: real AI-provider scan produces a real Markdown table naming the real provider', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'recipients.md');
  const exportR = _exportCli(fx, ['--format', 'recipients', '--output', outFile]);
  assert.equal(exportR.status, 0, `dataflow export --format recipients failed: ${exportR.stderr}\n${exportR.stdout}`);
  assert.ok(fs.existsSync(outFile), 'expected recipients.md to be written');

  const md = fs.readFileSync(outFile, 'utf8');
  assert.match(md, /# Third-Party and Cross-Border Recipient Intelligence/);
  assert.match(md, /\| Provider \|/, 'expected a real Markdown table header');
  assert.match(md, /anthropic/, 'expected the real, catalog-matched provider name to appear');
  assert.match(md, /code_inferred/, 'expected the field-evidence footer to disclose code_inferred provenance');
});

test('dataflow export --format recipients: with NO recipient-profiles.json present, still produces a real catalog-only report', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);
  assert.ok(!fs.existsSync(path.join(fx.root, '.agentic-security', 'recipient-profiles.json')), 'fixture assumption: no recipient config file exists');

  const outFile = path.join(fx.root, 'recipients-catalog-only.md');
  const exportR = _exportCli(fx, ['--format', 'recipients', '--output', outFile]);
  assert.equal(exportR.status, 0, `dataflow export --format recipients failed: ${exportR.stderr}\n${exportR.stdout}`);
  const md = fs.readFileSync(outFile, 'utf8');
  assert.match(md, /anthropic/);
  // No operator-declared fields — every fact-evidence entry for the
  // declared-only fields must read "absent", never fabricated.
  assert.match(md, /Legal Entity: absent/);
});

test('dataflow export --format recipients: a real operator-declared recipient-profiles.json surfaces declared fields, distinguished from code-inferred ones', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');
  _writeRecipientConfig(fx, {
    recipients: {
      anthropic: {
        legalEntity: 'Anthropic PBC',
        processorRole: 'processor',
        dpaStatus: 'in_place',
        processingCountries: ['US'],
      },
    },
  });

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'recipients-declared.md');
  const exportR = _exportCli(fx, ['--format', 'recipients', '--output', outFile]);
  assert.equal(exportR.status, 0, `dataflow export --format recipients failed: ${exportR.stderr}\n${exportR.stdout}`);
  const md = fs.readFileSync(outFile, 'utf8');
  assert.match(md, /Anthropic PBC/);
  assert.match(md, /in_place/);
  assert.match(md, /US/);
  // The declared fields must read "declared" in the footer, distinct from
  // the catalog-derived provider/serviceType, which must read "code_inferred".
  assert.match(md, /Legal Entity: declared/);
  assert.match(md, /Provider: code_inferred/);
});

test('dataflow export --format recipients: a fixture reaching nothing recipient-worthy produces an honest "no recipients" report, not an error', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', NOTHING_SOURCE);
  fx.commit('add ordinary non-recipient flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'recipients-empty.md');
  const exportR = _exportCli(fx, ['--format', 'recipients', '--output', outFile]);
  assert.equal(exportR.status, 0, `dataflow export --format recipients failed: ${exportR.stderr}\n${exportR.stdout}`);
  const md = fs.readFileSync(outFile, 'utf8');
  assert.match(md, /No recipients resolved for this graph/);
});

test('dataflow export --format recipients: --filter genuinely narrows the output by contributingGraphIds', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const graphPath = path.join(fx.root, '.agentic-security', 'lineage-graph.json');
  assert.ok(fs.existsSync(graphPath), 'expected a real persisted lineage graph after a deep scan');
  const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
  assert.ok(Array.isArray(graph.recipientProfiles) && graph.recipientProfiles.length >= 1, 'fixture assumption: at least one real recipient profile');

  // Unfiltered baseline.
  const unfilteredOut = path.join(fx.root, 'recipients-unfiltered.md');
  assert.equal(_exportCli(fx, ['--format', 'recipients', '--output', unfilteredOut]).status, 0);
  const unfilteredMd = fs.readFileSync(unfilteredOut, 'utf8');
  assert.match(unfilteredMd, /anthropic/);

  // A filter naming NONE of the recipient's contributingGraphIds must
  // narrow the recipients report down to zero rows.
  const filterPath = path.join(fx.root, 'filter.json');
  fs.writeFileSync(filterPath, JSON.stringify({ nodeIds: ['node:nonexistent'], edgeIds: [] }));
  const filteredOut = path.join(fx.root, 'recipients-filtered.md');
  const filteredR = _exportCli(fx, ['--format', 'recipients', '--output', filteredOut, '--filter', filterPath]);
  assert.equal(filteredR.status, 0, `filtered export failed: ${filteredR.stderr}`);
  const filteredMd = fs.readFileSync(filteredOut, 'utf8');
  assert.doesNotMatch(filteredMd, /anthropic/, 'expected the filter to narrow the recipient out of the report entirely');
  assert.match(filteredMd, /No recipients survive the given `--filter` scope\./);

  // A filter naming the REAL contributingGraphIds must keep it.
  const realFilterPath = path.join(fx.root, 'filter-real.json');
  fs.writeFileSync(realFilterPath, JSON.stringify({ nodeIds: graph.recipientProfiles[0].contributingGraphIds, edgeIds: [] }));
  const keptOut = path.join(fx.root, 'recipients-kept.md');
  assert.equal(_exportCli(fx, ['--format', 'recipients', '--output', keptOut, '--filter', realFilterPath]).status, 0);
  const keptMd = fs.readFileSync(keptOut, 'utf8');
  assert.match(keptMd, /anthropic/);
});

// fix-round-1, B3 live reproduction: build the filter file from a node id
// derived INDEPENDENTLY from graph.nodes (never copied from
// recipientProfiles[].contributingGraphIds itself) — the prior test above
// used contributingGraphIds to build its own "real" filter, which the
// final whole-branch review flagged as a vacuous construction: it would
// pass even if contributingGraphIds still held a bogus CFG-local counter
// value, since the filter and the field under test came from the exact
// same (possibly-wrong) source. This test instead re-derives the real
// AI-provider sink node id directly from graph.nodes (kind:'external',
// subtype:'ai-model-provider' — sink-registry.js's own CATEGORY_NODE_KIND/
// CWE_MAP mapping for CWE-201), confirms it's actually a MEMBER of
// contributingGraphIds (proving B3's fix genuinely wired the real id
// through), and then proves --filter narrows correctly using that
// independently-derived id.
test('dataflow export --format recipients: --filter narrows using a node id derived independently of contributingGraphIds (fix-round-1, B3)', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const graphPath = path.join(fx.root, '.agentic-security', 'lineage-graph.json');
  const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
  assert.ok(Array.isArray(graph.recipientProfiles) && graph.recipientProfiles.length >= 1, 'fixture assumption: at least one real recipient profile');

  // The node's kind is 'unresolved', not 'external': `anthropic.messages
  // .create()` is a receiver-based SDK call with no literal destination
  // URL to resolve, so FR-203's own unresolved-destination path applies
  // (confirmed live against the real persisted graph, not assumed) —
  // matched on `subtype: 'ai-model-provider'` alone, independent of kind.
  const independentNode = graph.nodes.find((n) => n.subtype === 'ai-model-provider');
  assert.ok(independentNode, 'expected a real ai-model-provider sink node in graph.nodes, derived independently of recipientProfiles');
  assert.match(independentNode.id, /^node:[a-z-]+:[0-9a-f]{12}$/);

  // Real, live proof that B3's fix actually threads the real node id
  // through: the independently-derived node id must be a member of the
  // recipient profile's own contributingGraphIds.
  assert.ok(
    graph.recipientProfiles[0].contributingGraphIds.includes(independentNode.id),
    'expected the independently-derived sink node id to appear in contributingGraphIds',
  );

  const filterPath = path.join(fx.root, 'filter-independent.json');
  fs.writeFileSync(filterPath, JSON.stringify({ nodeIds: [independentNode.id], edgeIds: [] }));
  const filteredOut = path.join(fx.root, 'recipients-filtered-independent.md');
  const filteredR = _exportCli(fx, ['--format', 'recipients', '--output', filteredOut, '--filter', filterPath]);
  assert.equal(filteredR.status, 0, `filtered export failed: ${filteredR.stderr}`);
  const filteredMd = fs.readFileSync(filteredOut, 'utf8');
  assert.match(filteredMd, /anthropic/, 'expected the independently-derived real node id to keep the recipient in the filtered report');

  // A filter naming an unrelated real node (not the sink) must narrow it
  // out entirely — proves the filter genuinely discriminates, not just
  // "any node id passes".
  const otherNode = graph.nodes.find((n) => n.id !== independentNode.id);
  assert.ok(otherNode, 'fixture assumption: at least one other real node exists');
  const negFilterPath = path.join(fx.root, 'filter-independent-neg.json');
  fs.writeFileSync(negFilterPath, JSON.stringify({ nodeIds: [otherNode.id], edgeIds: [] }));
  const negOut = path.join(fx.root, 'recipients-filtered-independent-neg.md');
  const negR = _exportCli(fx, ['--format', 'recipients', '--output', negOut, '--filter', negFilterPath]);
  assert.equal(negR.status, 0);
  const negMd = fs.readFileSync(negOut, 'utf8');
  assert.doesNotMatch(negMd, /anthropic/, 'expected an unrelated real node id to narrow the recipient out entirely');
});

test('dataflow export --format recipients: --view/--no-redact are documented no-ops with a warning', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', PHI_SOURCE);
  fx.commit('add PHI-to-model-provider flow');

  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);

  const outFile = path.join(fx.root, 'recipients-view.md');
  const viewR = _exportCli(fx, ['--format', 'recipients', '--output', outFile, '--view', 'privacy']);
  assert.equal(viewR.status, 0);
  assert.match(viewR.stderr, /--view has no effect on --format recipients/);

  const outFile2 = path.join(fx.root, 'recipients-noredact.md');
  const noRedactR = _exportCli(fx, ['--format', 'recipients', '--output', outFile2, '--no-redact']);
  assert.equal(noRedactR.status, 0);
  assert.match(noRedactR.stderr, /--no-redact has no effect on --format recipients/);
});
