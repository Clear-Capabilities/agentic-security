// annotateGitHistory blames once per file and reads commit messages in one call.
// The batching is only an optimization: it must give the same answer as asking
// git about one line at a time, including a line past the end of the file.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { annotateGitHistory } from '../src/posture/git-history.js';

function git(cwd, ...args) {
  return execFileSync('git', ['-c', 'user.name=Tester', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
}

test('git-history batch: per-file blame equals per-line blame, and a bad line does not lose the others', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-ghb-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  git(dir, 'init', '-q');
  fs.writeFileSync(path.join(dir, 'a.js'), 'one\ntwo\nthree\n');
  fs.writeFileSync(path.join(dir, 'b.js'), 'x\ny\n');
  git(dir, 'add', '.');
  git(dir, 'commit', '-q', '-m', 'first commit');
  fs.writeFileSync(path.join(dir, 'a.js'), 'one\nTWO\nthree\n');
  git(dir, 'add', '.');
  git(dir, 'commit', '-q', '-m', 'second commit\n\nCo-Authored-By: Claude <noreply@anthropic.com>');

  const findings = [
    { file: 'a.js', line: 1 }, { file: 'a.js', line: 2 }, { file: 'a.js', line: 3 },
    { file: 'b.js', line: 2 }, { file: 'b.js', line: 99 },
  ];
  annotateGitHistory(dir, findings);

  const expected = (file, line) => {
    const out = git(dir, 'blame', '-L', `${line},${line}`, '--porcelain', '--', file);
    return out.slice(0, 12);
  };
  for (const f of findings.slice(0, 4)) assert.equal(f.introducedIn, expected(f.file, f.line), `${f.file}:${f.line}`);
  assert.equal(findings[1].introducedInMessage, 'second commit');
  assert.equal(findings[1].aiAuthored, true);
  assert.equal(findings[0].introducedInMessage, 'first commit');
  assert.equal(findings[0].aiAuthored, undefined);
  assert.equal(findings[4].introducedIn, undefined, 'a line past the end of the file is skipped, not guessed');
});
