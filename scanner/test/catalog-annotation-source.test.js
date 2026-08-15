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
