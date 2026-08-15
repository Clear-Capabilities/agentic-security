import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchAnnotationParams } from '../src/dataflow/catalog.js';

test('matchAnnotationParams: empty/absent input returns an empty Set', () => {
  assert.deepEqual(matchAnnotationParams(undefined, 'App.java'), new Set());
  assert.deepEqual(matchAnnotationParams([], 'App.java'), new Set());
});

test('matchAnnotationParams: a matching Spring decorator taints its param name', () => {
  const result = matchAnnotationParams(
    [{ index: 0, name: 'q', decorator: 'RequestParam' }],
    'UserController.java'
  );
  assert.ok(result.has('q'));
  assert.equal(result.size, 1);
});

test('matchAnnotationParams: multiple annotated params, only catalogued decorators taint', () => {
  const result = matchAnnotationParams(
    [
      { index: 0, name: 'q', decorator: 'RequestParam' },
      { index: 1, name: 'id', decorator: 'PathVariable' },
      { index: 2, name: 'svc', decorator: 'Autowired' },
    ],
    'UserController.java'
  );
  assert.ok(result.has('q'));
  assert.ok(result.has('id'));
  assert.ok(!result.has('svc'), '@Autowired is not a source-shaped annotation and must not taint');
  assert.equal(result.size, 2);
});

test('matchAnnotationParams: language scoping — a Java-only decorator name does not fire on a C# file', () => {
  const result = matchAnnotationParams(
    [{ index: 0, name: 'q', decorator: 'RequestParam' }],
    'Controller.cs'
  );
  assert.equal(result.size, 0, '@RequestParam is Spring/Java-scoped; must not match on a .cs file');
});

test('matchAnnotationParams: ASP.NET Core [FromQuery] taints its param name on a .cs file', () => {
  const result = matchAnnotationParams(
    [{ index: 0, name: 'q', decorator: 'FromQuery' }],
    'Controller.cs'
  );
  assert.ok(result.has('q'));
});

test('matchAnnotationParams: NestJS @Query() taints its param name on a .ts file', () => {
  const result = matchAnnotationParams(
    [{ index: 0, name: 'q', decorator: 'Query' }],
    'app.controller.ts'
  );
  assert.ok(result.has('q'));
});

test('matchAnnotationParams: AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY=1 respects provenance filter (regression guard)', () => {
  // Verify that the function applies filterByProvenance to respect the
  // OFFICIAL_ONLY mode. This guards against a regression where filterByProvenance
  // is accidentally removed from matchAnnotationParams but left in place for
  // matchSource/matchSinkOrSanitizer/matchMemberWriteSink — a silent divergence
  // that would cause non-official (community/inferred) annotation entries to
  // be silently ignored when official-only mode is enabled.
  const oldEnv = process.env.AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY;
  try {
    // Set OFFICIAL_ONLY mode on.
    process.env.AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY = '1';
    // The existing Spring @RequestParam is official (default-stamped) and should
    // still match even with OFFICIAL_ONLY on.
    const result = matchAnnotationParams(
      [{ index: 0, name: 'q', decorator: 'RequestParam' }],
      'UserController.java'
    );
    assert.ok(result.has('q'), '@RequestParam (official entry) must match with OFFICIAL_ONLY=1');
  } finally {
    // Restore the original env var.
    if (oldEnv === undefined) {
      delete process.env.AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY;
    } else {
      process.env.AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY = oldEnv;
    }
  }
});
