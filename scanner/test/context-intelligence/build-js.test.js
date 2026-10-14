import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tempProject, cleanup, build, byLabel } from './helpers.js';
import { validateManifest } from '../../src/context-intelligence/manifest.js';
import { hashOf } from '../../src/context-intelligence/canonical.js';

test('js fixture: entry points, dispositions and integrity are reported, never assumed', async () => {
  const dir = tempProject('js-app');
  try {
    const built = await build(dir);
    assert.equal(built.ok, true);
    assert.equal(built.entrypoints.length, 7);
    for (const b of built.bundles) {
      assert.ok(b.manifest, `bundle for ${b.entrypoint.label}`);
      assert.deepEqual(validateManifest(b.manifest, { fileContents: built.fileContents }), [], `manifest valid for ${b.entrypoint.label}`);
      assert.ok(['complete', 'partial', 'unavailable'].includes(b.manifest.context.integrity));
    }
    const dynamic = built.bundles.filter(b => b.manifest.context.integrity !== 'complete');
    assert.ok(dynamic.length >= 1, 'a dynamic dispatch route must not be reported complete');
    assert.ok(built.summary.complete >= 1);
  } finally { cleanup(dir); }
});

test('js fixture: a guard that runs after the data access is flagged as ineffective, not as protection', async () => {
  const dir = tempProject('js-app');
  try {
    const built = await build(dir);
    const archive = byLabel(built, '/docs/:id/archive');
    assert.equal(archive.manifest.protection.ownership.state, 'evaluated_and_ineffective');
    assert.equal(archive.manifest.protection.ownership.evidence[0].order, 'after-sensitive');
    assert.equal(archive.manifest.protection.authentication.state, 'present');
    assert.equal(archive.manifest.protection['authorization-role'].state, 'not_present');
  } finally { cleanup(dir); }
});

test('the same snapshot builds byte-identical manifests twice', async () => {
  const dir = tempProject('js-app');
  try {
    const a = await build(dir); const b = await build(dir);
    assert.equal(hashOf(a.bundles.map(x => x.manifest)), hashOf(b.bundles.map(x => x.manifest)));
    assert.equal(a.graph.hash, b.graph.hash);
  } finally { cleanup(dir); }
});

test('every evidence file the capability matrix cites exists', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { capabilityMatrix } = await import('../../src/context-intelligence/capabilities.js');
  const root = path.resolve(import.meta.dirname, '../..');
  for (const row of capabilityMatrix()) {
    if (row.status === 'blocked' || row.status === 'unsupported') assert.deepEqual(row.evidence, [], 'a blocked or unsupported capability cites no evidence');
    else assert.ok(row.evidence.length > 0, `${row.kind} needs evidence`);
    for (const f of row.evidence) assert.ok(fs.existsSync(path.join(root, f)), `${f} exists`);
  }
});
