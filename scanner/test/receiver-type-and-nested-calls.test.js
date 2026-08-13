// Covers PRD R6, R10, R11 (docs/DETECTION_GAP_REMEDIATION_PRD.md, Theme B+D).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { buildProjectIR } from '../src/ir/index.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-rcvr-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('CHA is threaded onto callContext during a real deep scan (no throw, scan completes)', () => {
  const fileContents = {
    'app.js': `
class UserRepo {
  save(x) { return x; }
}
const repo = new UserRepo();
repo.save(1);
`,
  };
  const { perFile, callGraph } = buildProjectIR(fileContents);
  // Must not throw — this is the smoke test that CHA wiring didn't break
  // the ordinary per-file analysis loop.
  assert.doesNotThrow(() => runDeepAnalysis(perFile, callGraph, { fileContents }));
});
