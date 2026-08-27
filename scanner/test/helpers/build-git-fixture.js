import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFileSync } from 'node:child_process';

function run(cwd, args, env) {
  execFileSync('git', args, { cwd, stdio: 'ignore', env: { ...process.env, ...env } });
}

export function createGitFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-provenance-fixture-'));
  run(root, ['init', '-q']);
  run(root, ['config', 'user.email', 'fixture@example.com']);
  run(root, ['config', 'user.name', 'Fixture Author']);
  return {
    root,
    writeFile(relPath, content) {
      const full = path.join(root, relPath);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    },
    commit(message, { authorName = 'Fixture Author', authorEmail = 'fixture@example.com', date } = {}) {
      run(root, ['add', '-A']);
      const env = {
        GIT_AUTHOR_NAME: authorName, GIT_AUTHOR_EMAIL: authorEmail,
        GIT_COMMITTER_NAME: authorName, GIT_COMMITTER_EMAIL: authorEmail,
      };
      if (date) { env.GIT_AUTHOR_DATE = date; env.GIT_COMMITTER_DATE = date; }
      run(root, ['commit', '-q', '-m', message], env);
      return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
    },
    checkoutBranch(name) { run(root, ['checkout', '-q', '-b', name]); },
    checkout(ref) { run(root, ['checkout', '-q', ref]); },
    merge(ref, message) {
      run(root, ['merge', '--no-ff', '-q', '-m', message, ref]);
      return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
    },
    cleanup() { fs.rmSync(root, { recursive: true, force: true }); },
  };
}
