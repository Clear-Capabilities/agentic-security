import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { parseScopeFlags } from '../../src/scope/flags.js';
import { runScan } from '../../src/runScan.js';
import { mkTestTmp } from '../helpers/tmp.js';

const BIN = path.resolve('bin/agentic-security.js');

test('parseScopeFlags: repeatable, validated, inert when absent', () => {
  assert.equal(parseScopeFlags(['scan', '.']).active, false);
  const f = parseScopeFlags(['--include-path', 'a', '--include-path=b', '--exclude-path', 'c', '--include-ignored-path', 'd', '--ignore-source', 'repository', '--no-respect-gitignore']);
  assert.deepEqual(f.scope.includePaths, ['a', 'b']);
  assert.deepEqual(f.scope.excludePaths, ['c']);
  assert.deepEqual(f.scope.includeIgnoredPaths, ['d']);
  assert.equal(f.scope.ignoreSource, 'repository');
  assert.equal(f.scope.respectGitignore, false);
  assert.equal(parseScopeFlags(['--ignore-source', 'x']).errors.length, 1);
});

function proj() {
  const dir = mkTestTmp('as-cli-scope-');
  cp.execFileSync('git', ['init', '-q'], { cwd: dir });
  fs.writeFileSync(path.join(dir, '.gitignore'), 'buck-out/\n');
  fs.mkdirSync(path.join(dir, 'buck-out'));
  fs.writeFileSync(path.join(dir, 'buck-out/G.js'), 'eval(req.query.x)');
  fs.writeFileSync(path.join(dir, 'a.js'), 'const x=1;');
  return dir;
}

test('--explain-scope previews and exits 0 without scanning', () => {
  const dir = proj();
  const r = cp.spawnSync('node', [BIN, 'scan', '--explain-scope', dir], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /buck-out\//);
  assert.match(r.stdout, /\+ a\.js/);
  assert.ok(!fs.existsSync(path.join(dir, '.agentic-security')), 'no scan state written');
});

test('runScan with gitScope records scope and never reports ignored-subtree findings', async () => {
  const dir = proj();
  const { scan } = await runScan(dir, { gitScope: true });
  assert.equal(scan.scope.schema, 1);
  assert.ok(scan.scope.skippedByReason['git-ignored'] >= 1);
  const all = JSON.stringify(scan.findings || []);
  assert.ok(!all.includes('buck-out'));
});
