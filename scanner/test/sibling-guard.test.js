// PRD F1.1 — the first Go detector written fixture-first from a real advisory.
//
// PROVENANCE. GHSA-95cv-r8x4-vh75 (alist, CWE-22), one of the 12 `NO-FINDINGS`
// Go entries in the root-cause histogram: the vulnerable file produced no
// finding of any kind. The upstream fix is two lines —
//
//     + err = checkRelativePath(renameObject.SrcName)
//     + if err != nil { common.ErrorResp(c, err, 403); return }
//
// added directly above an already-present `checkRelativePath(renameObject.NewName)`.
// Two sibling fields of one request struct reach a filesystem rename; the
// project's OWN guard was applied to one and not the other.
//
// WHY THIS SHAPE IS WORTH A RULE. The detector never has to decide what counts
// as a guard — it OBSERVES one being applied to a sibling field in the same
// function. The claim is "this codebase guards X and forgets Y", which is
// checkable by a reviewer against the same screen of code, and carries the
// evidence with it. That is the same argument Theme 6 makes for project-scoped
// convention mining, applied intra-function where the evidence is strongest.
//
// The bias, matching convention-deviation.test.js: this rule asserts an
// ABSENCE, so most of the cases below prove it REFUSES to fire.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanSiblingGuard } from '../src/sast/sibling-guard.js';
import { runScan } from '../src/runScan.js';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'sibling-guard');
const read = (which) => fs.readFileSync(path.join(FIX, which, 'handler.go'), 'utf8');

test('the real shape fires: a guard applied to one sibling field and not the other', () => {
  const f = scanSiblingGuard('server/handles/fsbatch.go', read('vulnerable'));
  assert.equal(f.length, 1, `expected exactly one finding, got ${JSON.stringify(f.map((x) => x.vuln))}`);
  assert.equal(f[0].cwe, 'CWE-22');
  assert.match(f[0].vuln, /SrcName/);
  assert.match(f[0].description, /checkRelativePath/,
    'the finding must name the guard it observed on the sibling — that is the evidence');
});

test('FIX-DISCRIMINATION: applying the guard to both siblings silences it', () => {
  // This is the upstream fix, verbatim in shape. A finding that survives its
  // own fix has detected an API, not a vulnerability.
  assert.deepEqual(scanSiblingGuard('server/handles/fsbatch.go', read('clean')), []);
});

test('the finding carries checkable evidence: guard, guarded sibling, unguarded field', () => {
  const [f] = scanSiblingGuard('h.go', read('vulnerable'));
  assert.equal(f.checkedFor, 'checkRelativePath');
  assert.equal(f.evidenceGuardedSibling, 'renameObject.NewName');
  assert.equal(f.evidenceUnguardedField, 'renameObject.SrcName');
});

// ───────────────────────────────── precision: it must refuse far more than it fires
test('REFUSES when no guard is applied to any sibling (nothing to deviate from)', () => {
  const src = `package h
func F(req *R, reqPath string) {
	filePath := fmt.Sprintf("%s/%s", reqPath, req.SrcName)
	fsRename(filePath, req.NewName)
}`;
  assert.deepEqual(scanSiblingGuard('h.go', src), [],
    'with no guard anywhere there is no established convention to omit');
});

test('REFUSES when the unguarded sibling never reaches a path-ish operation', () => {
  const src = `package h
func F(req *R) {
	err := checkRelativePath(req.NewName)
	if err != nil { return }
	log.Printf("renaming %s", req.SrcName)
}`;
  assert.deepEqual(scanSiblingGuard('h.go', src), [],
    'a field that is only logged is not a path traversal');
});

test('REFUSES when the field reaching the sink is itself guarded', () => {
  // NOTE ON THIS TEST'S FIRST VERSION. It guarded SrcName and still passed
  // NewName to `fsRename`, then asserted silence. That assertion was wrong:
  // NewName is a filesystem destination reached without the guard its sibling
  // uses, so firing there is the rule working, not a false positive. The test
  // was rewritten rather than the rule weakened to satisfy it — a precision
  // case that encodes a mistaken expectation is worse than no case at all.
  const src = `package h
func F(req *R, reqPath string) {
	err := checkRelativePath(req.SrcName)
	if err != nil { return }
	filePath := fmt.Sprintf("%s/%s", reqPath, req.SrcName)
	writeAudit(req.NewName)
}`;
  assert.deepEqual(scanSiblingGuard('h.go', src), [],
    'the only field reaching a path operation is guarded; there is no omission');
});

test('REFUSES across different receivers — two unrelated structs are not siblings', () => {
  const src = `package h
func F(a *A, b *B, reqPath string) {
	err := checkRelativePath(a.NewName)
	if err != nil { return }
	filePath := fmt.Sprintf("%s/%s", reqPath, b.SrcName)
	fsRename(filePath, a.NewName)
}`;
  assert.deepEqual(scanSiblingGuard('h.go', src), [],
    'a.NewName and b.SrcName belong to different objects and establish no convention');
});

test('REFUSES on a non-Go file', () => {
  assert.deepEqual(scanSiblingGuard('h.js', read('vulnerable')), []);
});

test('the rule is reachable through a real scan, not just when called directly', async () => {
  // The rate-limit.js failure mode: a detector that works in isolation and is
  // never invoked by the pipeline. detector-liveness.test.js enforces this for
  // every fixture; asserting it here too keeps the reason attached to the rule.
  setStateWritesEnabled(false);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sibguard-'));
  try {
    fs.copyFileSync(path.join(FIX, 'vulnerable', 'handler.go'), path.join(dir, 'handler.go'));
    const { scan } = await runScan(dir);
    const hits = (scan.findings || []).filter((f) => f.family === 'sibling-guard-omission');
    assert.ok(hits.length >= 1,
      `expected the rule to fire through runScan, got: ${JSON.stringify((scan.findings || []).map((f) => f.vuln))}`);
  } finally {
    setStateWritesEnabled(true);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
