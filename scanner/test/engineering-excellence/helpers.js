// Shared helpers for the Engineering Excellence tooling tests (not itself a test file).
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(HERE, '../../..');
export const EE = path.join(REPO, 'scripts', 'engineering-excellence');

export function mini(tasks) {
  return {
    schemaVersion: 1, program: 'test-program', source: { file: 'test.prd', sha256: null },
    epics: [{ id: 'E0', title: 'First', priority: 'P0', exitGate: null, taskCount: 0 }, { id: 'E1', title: 'Second', priority: 'P1', exitGate: null, taskCount: 0 }],
    tasks: tasks.map((t) => ({ id: t.id, title: t.title || t.id, epic: t.id.slice(0, 2), priority: t.id.startsWith('E0') ? 'P0' : 'P1', weight: t.id.startsWith('E0') ? 3 : 2, requires: t.requires || [], informedBy: [], description: 'd', acceptance: 'a', expectedTests: [] })),
  };
}

/** A throwaway git repository holding a small manifest, initialised status and one passing and one failing test file. */
export async function makeRoot(tasks = [{ id: 'E0-01' }, { id: 'E0-02', requires: ['E0-01'] }, { id: 'E1-01', requires: ['E0-02'] }]) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-test-'));
  const git = (...a) => execFileSync('git', a, { cwd: root, stdio: 'ignore' });
  git('init', '-q'); git('config', 'user.email', 't@example.com'); git('config', 'user.name', 't');
  const dir = path.join(root, 'scripts', 'engineering-excellence');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'tasks.json'), JSON.stringify(mini(tasks), null, 2));
  fs.mkdirSync(path.join(root, 'tests'), { recursive: true });
  fs.writeFileSync(path.join(root, 'tests', 'pass.test.js'), "import { test } from 'node:test';\ntest('ok', () => {});\n");
  fs.writeFileSync(path.join(root, 'tests', 'fail.test.js'), "import { test } from 'node:test';\nimport assert from 'node:assert/strict';\ntest('bad', () => assert.equal(1, 2));\n");
  fs.writeFileSync(path.join(root, 'tests', 'hang.test.js'), "import { test } from 'node:test';\ntest('hang', () => new Promise(() => setInterval(() => {}, 1000)));\n");
  fs.writeFileSync(path.join(root, 'src.txt'), 'x\n');
  git('add', '-A'); git('commit', '-q', '-m', 'init');
  const store = await import(path.join(EE, 'lib', 'store.mjs'));
  store.initStatus(root);
  return { root, dir, store, git };
}

export function cleanup(root) { try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ } }

export const NODE = process.execPath;
export function runnerArgs(root, task, kind, rest) {
  return [path.join(EE, 'runner.mjs'), '--root', root, '--cwd', root, '--task', task, '--kind', kind, ...rest];
}
