// MCP tool-output offloading (harness-anatomy #1).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { signLastScan } from '../src/posture/integrity.js';
import { explain_finding, read_scratchpad } from '../src/mcp/tools.js';
import { mkTestTmp } from './helpers/tmp.js';

function mkRootWithFinding(stagedFinding) {
  const root = mkTestTmp('offload-');
  const stateDir = path.join(root, '.agentic-security');
  fs.mkdirSync(stateDir, { recursive: true });
  const scan = { findings: [stagedFinding] };
  const body = JSON.stringify(scan);
  fs.writeFileSync(path.join(stateDir, 'last-scan.json'), body);
  fs.writeFileSync(path.join(stateDir, 'last-scan.json.sig'), signLastScan(body));
  return root;
}

test('explain_finding returns trace inline when small', async () => {
  const finding = {
    id: 'f1', stableId: 'a', file: 'app.js', line: 1, vuln: 'X',
    trace: [{ step: 1, label: 'src' }, { step: 2, label: 'sink' }],
  };
  const root = mkRootWithFinding(finding);
  const r = await explain_finding.handler({ finding_id: 'f1' }, { sessionRoot: root });
  assert.equal(r.id, 'f1');
  assert.equal(Array.isArray(r.trace), true);
  assert.equal(r.trace.length, 2);
  assert.equal(r.traceOffload, null);
});

test('explain_finding offloads a large trace and returns head/tail + scratchpadPath', async () => {
  const trace = [];
  for (let i = 0; i < 50; i++) trace.push({ step: i, label: 'step-' + i });
  const finding = { id: 'f1', stableId: 'a', file: 'app.js', line: 1, vuln: 'X', trace };
  const root = mkRootWithFinding(finding);
  const r = await explain_finding.handler({ finding_id: 'f1' }, { sessionRoot: root });
  assert.ok(r.traceOffload, 'expected traceOffload metadata');
  assert.equal(r.traceOffload.totalSteps, 50);
  assert.match(r.traceOffload.scratchpadPath, /^\.agentic-security\/agent-scratchpad\/mcp-offload\//);
  // Trimmed trace: head(3) + gap + tail(2) = 6 elements.
  assert.equal(r.trace.length, 6);
  assert.equal(r.trace[0].step, 0);
  assert.equal(r.trace[r.trace.length - 1].step, 49);
  // Verify the scratchpad path actually exists and is readable via the
  // companion MCP tool.
  const read = await read_scratchpad.handler({
    path: r.traceOffload.scratchpadPath, offset: 0, limit: 4096,
  }, { sessionRoot: root });
  assert.equal(read.ok, true);
  assert.match(read.content, /"total":\s*50/);
});

test('offload threshold is honored at the boundary', async () => {
  // 11 entries should offload (> 10 = OFFLOAD_THRESHOLD); 10 should NOT.
  for (const n of [10, 11]) {
    const trace = []; for (let i = 0; i < n; i++) trace.push({ step: i });
    const finding = { id: 'fX', stableId: 'a', file: 'app.js', line: 1, vuln: 'X', trace };
    const root = mkRootWithFinding(finding);
    const r = await explain_finding.handler({ finding_id: 'fX' }, { sessionRoot: root });
    if (n === 10) {
      assert.equal(r.traceOffload, null, 'n=10 should NOT offload');
      assert.equal(r.trace.length, 10);
    } else {
      assert.ok(r.traceOffload, 'n=11 should offload');
      assert.equal(r.traceOffload.totalSteps, 11);
    }
  }
});
