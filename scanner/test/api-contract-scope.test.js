// A contract file inside one package of a monorepo governs that package's routes only. Found on the servant monorepo, where two example
// swagger.json files produced 78 "implemented but not declared" findings across every other package. A contract at the scan root (or in a
// directory with no package manifest above it) governs every route, as before.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from './helpers/tmp.js';
import { runApiContractScan, contractScope } from '../src/posture/api-contract.js';

const OPENAPI = JSON.stringify({ openapi: '3.0.0', paths: { '/todo': { get: {} } } });
const write = (root, rel, text) => { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), text); };
const undocumented = (fs_) => fs_.filter((f) => f.subfamily === 'undocumented-endpoint').map((f) => f.file);

test('a contract inside a package governs only that package', () => {
  const root = mkTestTmp('contract-scope-');
  write(root, 'pkg-a/pkg-a.cabal', 'name: pkg-a\n');
  write(root, 'pkg-a/example/swagger.json', OPENAPI);
  write(root, 'pkg-b/pkg-b.cabal', 'name: pkg-b\n');
  const routes = [
    { method: 'GET', path: '/todo', file: 'pkg-a/example/Todo.hs', line: 3 },
    { method: 'GET', path: '/other', file: 'pkg-a/src/Other.hs', line: 7 },
    { method: 'GET', path: '/greet', file: 'pkg-b/src/Greet.hs', line: 9 },
  ];
  assert.equal(contractScope(path.join(root, 'pkg-a/example/swagger.json'), root), path.join(root, 'pkg-a'));
  const files = undocumented(runApiContractScan(root, routes));
  assert.deepEqual(files, ['pkg-a/src/Other.hs'], 'pkg-b is not judged by pkg-a\'s contract; pkg-a\'s own undeclared route still is');
});

test('a contract at the scan root, or with no package manifest above it, governs every route', () => {
  const root = mkTestTmp('contract-root-');
  write(root, 'openapi.json', OPENAPI);
  const routes = [
    { method: 'GET', path: '/todo', file: 'a/Todo.hs', line: 3 },
    { method: 'GET', path: '/greet', file: 'b/Greet.hs', line: 9 },
  ];
  assert.equal(contractScope(path.join(root, 'openapi.json'), root), path.resolve(root));
  assert.deepEqual(undocumented(runApiContractScan(root, routes)), ['b/Greet.hs']);
  const deep = mkTestTmp('contract-deep-');
  write(deep, 'docs/api/openapi.json', OPENAPI);   // no manifest anywhere: the contract still describes the whole tree
  assert.equal(contractScope(path.join(deep, 'docs/api/openapi.json'), deep), path.resolve(deep));
  assert.deepEqual(undocumented(runApiContractScan(deep, routes)), ['b/Greet.hs']);
});
