// DOC-001.AC01: the MCP tool contract page and the capability matrix are generated from the code, so they cannot drift from it.
// A test compares each with the generator output, with the registries it was built from, and shows that a stale page, an
// unclassified tool and a Linux "supported" cell would each be caught.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { stalePages, renderMcp, renderMatrix, PAGES } from '../../../scripts/render-assurance-docs.mjs';
import { ALL_TOOLS } from '../../src/mcp/tools.js';
import { TOOL_CAPABILITIES } from '../../src/capabilities/tool-registry.js';
import { oracleManifest } from '../../src/posture/oracles/registry.js';
import { FEATURES } from '../../src/posture/assurance/config.js';
import { platformStatements } from '../../src/capabilities/probes.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..', '..');
const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');

/** Rows of the first markdown table whose header starts with `firstHeader`, as arrays of trimmed cells. */
function tableRows(md, firstHeader) {
  const lines = md.split('\n');
  const i = lines.findIndex((l) => l.startsWith(`| ${firstHeader}`));
  assert.ok(i >= 0, `no table starting with ${firstHeader}`);
  const rows = [];
  for (let j = i + 2; j < lines.length && lines[j].startsWith('|'); j++) rows.push(lines[j].split(/(?<!\\)\|/).slice(1, -1).map((c) => c.trim()));
  return rows;
}

describe('[DOC-001.AC01] the generated pages equal what the code produces', () => {
  test('[DOC-001.AC01] both pages equal the generator output (the same check as `npm run docs:check-assurance`)', async () => {
    assert.deepEqual(await stalePages(), []);
    const r = spawnSync(process.execPath, [path.join(REPO, 'scripts/render-assurance-docs.mjs'), '--check'], { encoding: 'utf8', timeout: 60000 });
    assert.equal(r.status, 0, r.stderr);
  });

  test('[DOC-001.AC01] a stale page is caught: an edited cell, a deleted page and an extra tool row each make the page stale', async () => {
    const mutate = (rel, fn) => (r) => (r === rel ? fn(read(rel)) : read(r));
    assert.deepEqual(await stalePages(mutate(PAGES.mcp, (t) => t.replace('| read |', '| mutating |'))), [PAGES.mcp]);
    assert.deepEqual(await stalePages(mutate(PAGES.matrix, (t) => t.replace('| unverified |', '| supported |'))), [PAGES.matrix]);
    assert.deepEqual(await stalePages((r) => (r === PAGES.matrix ? null : read(r))), [PAGES.matrix]);
    assert.deepEqual(await stalePages(mutate(PAGES.mcp, (t) => `${t}| \`ghost_tool\` | read | | | | |\n`)), [PAGES.mcp]);
  });
});

describe('[DOC-001.AC01] the MCP tool contract lists every tool with its read or mutating classification', () => {
  const md = read(PAGES.mcp);
  const rows = tableRows(md, 'Tool');

  test('[DOC-001.AC01] the page lists exactly the registered tools, each with the classification from the capability table', () => {
    const listed = rows.map((r) => r[0].replace(/`/g, ''));
    assert.deepEqual([...listed].sort(), ALL_TOOLS.map((t) => t.name).sort());
    for (const r of rows) {
      const name = r[0].replace(/`/g, '');
      assert.equal(r[1], TOOL_CAPABILITIES[name].effect, `${name} is classified ${TOOL_CAPABILITIES[name].effect} in the registry`);
    }
  });

  test('[DOC-001.AC01] the two differentiation tools are listed and read-only', () => {
    for (const name of ['invariant_scenario_export', 'portfolio_progress']) {
      const row = rows.find((r) => r[0] === `\`${name}\``);
      assert.ok(row, `${name} is missing from the page`);
      assert.equal(row[1], 'read');
    }
  });

  test('[DOC-001.AC01] mutating and external tools are never shown as read, and the counts add up to the tool total', () => {
    for (const t of ['apply_fix', 'apply_sca_upgrade', 'verify_fix', 'append_scratchpad', 'append_agents_memory']) {
      assert.notEqual(rows.find((r) => r[0] === `\`${t}\``)[1], 'read', `${t} must not read as read-only`);
    }
    const counts = Object.fromEntries(['read', 'mutating', 'external', 'unclassified'].map((k) => [k, Number(new RegExp(`\\| ${k} \\| (\\d+)`).exec(md)[1])]));
    assert.equal(counts.read + counts.mutating + counts.external + counts.unclassified, ALL_TOOLS.length);
    assert.equal(counts.unclassified, 0, 'every registered tool is classified');
    assert.match(md, new RegExp(`registers ${ALL_TOOLS.length} tools`));
  });

  test('[DOC-001.AC01] a tool that is registered but unclassified would be shown as unclassified, not silently listed as read', async () => {
    const extra = { name: 'ghost_tool', description: 'A ghost.', inputSchema: { type: 'object', properties: {} } };
    ALL_TOOLS.push(extra);
    try {
      const page = await renderMcp();
      assert.match(page, /\| `ghost_tool` \| \*\*unclassified\*\* \|/);
      assert.match(page, /\| unclassified \| 1 \(ghost_tool\)/);
    } finally { ALL_TOOLS.pop(); }
    assert.ok(!ALL_TOOLS.some((t) => t.name === 'ghost_tool'));
  });

  test('[DOC-001.AC01] the page states that the classification is policy at the tool boundary, not isolation', () => {
    assert.match(md, /in-process-policy/);
    assert.match(md, /never enforced isolation/);
  });
});

describe('[DOC-001.AC01] the capability matrix is read from the manifests and configuration', () => {
  const md = read(PAGES.matrix);

  test('[DOC-001.AC01] every feature, with its risk class and platforms, is a row', () => {
    const rows = tableRows(md, 'Feature');
    assert.deepEqual(rows.map((r) => r[0].replace(/`/g, '')), Object.keys(FEATURES));
    for (const r of rows) {
      const f = FEATURES[r[0].replace(/`/g, '')];
      assert.equal(r[1], f.risk);
      assert.equal(r[2], f.platforms.join(', '));
    }
  });

  test('[DOC-001.AC01] every oracle is a row with the platform status from its manifest, and Linux is never "supported"', () => {
    const rows = tableRows(md, 'Oracle');
    const man = oracleManifest();
    assert.deepEqual(rows.map((r) => r[0].replace(/`/g, '')), man.oracles.map((o) => o.id));
    for (const r of rows) {
      const o = man.oracles.find((x) => x.id === r[0].replace(/`/g, ''));
      assert.equal(r[4], o.platforms.darwin.status);
      assert.equal(r[5], o.platforms.linux.status);
      assert.equal(r[6], o.platforms.win32.status);
      assert.notEqual(r[5], 'supported', `${o.id}: no Linux outcome may be claimed`);
    }
  });

  test('[DOC-001.AC01] the enforcement table states Linux partially verified, macOS host-proved and Windows unsupported', () => {
    const rows = tableRows(md, 'Platform');
    const by = Object.fromEntries(rows.map((r) => [r[0], r]));
    const ps = platformStatements();
    assert.equal(by.linux[2], `\`${ps.linux.status}\``);
    assert.equal(ps.linux.status, 'partially-verified');
    assert.equal(by.darwin[2], `\`${ps.darwin.status}\``);
    assert.equal(ps.darwin.status, 'host-proved-not-advertised');
    assert.equal(by.win32[2], `\`${ps.win32.status}\``);
    assert.equal(ps.win32.status, 'unsupported');
  });

  test('[DOC-001.AC01] the deployment adapters match the validated-adapter table of the deployment guide', () => {
    const guide = read('docs/guides/deployment-aware-support.md');
    const rows = tableRows(md, 'Adapter');
    for (const r of rows) {
      const name = r[0].replace(/`/g, '');
      const m = new RegExp(`\\| \`${name}\` \\| (validated|not validated) \\|`).exec(guide);
      assert.ok(m, `${name} has no row in the deployment guide`);
      assert.equal(r[1], m[1]);
    }
    assert.deepEqual(rows.filter((r) => r[1] === 'validated').map((r) => r[0].replace(/`/g, '')), ['kubernetes', 'compose']);
  });

  test('[DOC-001.AC01] a matrix that claimed Linux support would differ from the generator output (the claim is not typed by hand)', async () => {
    const page = await renderMatrix();
    assert.equal(page, md);
    const tampered = md.replace(/\| unverified \| unsupported \| `verification-oracles` \||\| unverified \| unsupported \| verification-oracles \|/, '| supported | unsupported | verification-oracles |');
    assert.notEqual(tampered, md);
    assert.deepEqual(await stalePages((r) => (r === PAGES.matrix ? tampered : read(r))), [PAGES.matrix]);
  });
});
