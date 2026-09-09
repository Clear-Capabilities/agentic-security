// End-to-end proof that a scan's `onProgress` callback (the same callback
// `bin/agentic-security.js`'s CLI entry wires to the stderr `\r[phase]
// current/total` status line) now fires for the previously-silent phases:
// deep interprocedural taint analysis and the Data Flow Explorer lineage
// graph build. Both run as one synchronous call each (see
// dataflow/CLAUDE.md / src/lineage/CLAUDE.md), so this only proves the
// wiring reaches `setProgress` with the right phase — the per-function
// live-updating behavior itself is proven directly against the engines in
// test/dataflow-progress.test.js and test/lineage/driver.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.join(__dirname, 'fixtures', name);

async function scanWithProgress(dir, envOverrides) {
  const prev = {};
  for (const [k, v] of Object.entries(envOverrides)) {
    prev[k] = process.env[k];
    process.env[k] = v;
  }
  const calls = [];
  try {
    await runScan(dir, { onProgress: (p) => calls.push({ ...p }) });
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  return calls;
}

test('scan onProgress: reports an "Annotating" phase with increasing current, no deep mode needed', async () => {
  const calls = await scanWithProgress(FIX('vulnerable-js'), {});
  const annotating = calls.filter(c => c.phase === 'Annotating');
  assert.ok(annotating.length > 1, `expected multiple "Annotating" progress calls, got ${annotating.length} (phases seen: ${[...new Set(calls.map(c => c.phase))].join(', ')})`);
  for (let i = 1; i < annotating.length; i++) {
    assert.ok(annotating[i].current > annotating[i - 1].current,
      `expected current to strictly increase across annotator steps, got ${annotating.map(c => c.current).join(',')}`);
  }
});

test('scan onProgress: reports a "Deep analysis" phase when AGENTIC_SECURITY_DEEP=1', async () => {
  const calls = await scanWithProgress(FIX('ir-taint/interproc'), {
    AGENTIC_SECURITY_DEEP: '1',
    AGENTIC_SECURITY_DEEP_IN_CI: '1',
  });
  const deep = calls.filter(c => c.phase === 'Deep analysis');
  assert.ok(deep.length > 0, `expected at least one "Deep analysis" progress call, got phases: ${[...new Set(calls.map(c => c.phase))].join(', ')}`);
});

test('scan onProgress: reports a "Lineage graph" phase when AGENTIC_SECURITY_LINEAGE_DEEP=1', async () => {
  const calls = await scanWithProgress(FIX('ir-taint/interproc'), {
    AGENTIC_SECURITY_LINEAGE_DEEP: '1',
  });
  const lineage = calls.filter(c => c.phase === 'Lineage graph');
  assert.ok(lineage.length > 0, `expected at least one "Lineage graph" progress call, got phases: ${[...new Set(calls.map(c => c.phase))].join(', ')}`);
});
