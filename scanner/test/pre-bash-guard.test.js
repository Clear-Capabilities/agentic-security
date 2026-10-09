// hooks/pre-bash-guard.js: deletion is allowed strictly inside an allowed root (default ~/code) and refused everywhere else.
// The guard parses the command; it does not grep it. These cases pin both directions, because a guard that blocks everything is as
// useless as one that blocks nothing (the old text match refused `docker run --rm -v /abs/path` and any absolute `rm` path).
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, realpathSync, existsSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir, homedir } from 'node:os';
import { join, dirname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK = join(HERE, '..', '..', 'hooks', 'pre-bash-guard.js');
const { analyzeDeletes } = createRequire(import.meta.url)(HOOK);

// The guard's default allowed root is ~/code, and the "outside" cases need a directory that is genuinely outside
// it. The OS temp folder normally is, but a TMPDIR inside the repository (which lives under ~/code) is not, and
// the "blocked" assertions would then fail for a reason unrelated to the guard. So the scratch area is the first
// candidate that is really outside ~/code; the guard itself is not relaxed in any way.
const codeRoot = join(homedir(), 'code');
const insideCode = (d) => { const r = realpathSync(d); return r === codeRoot || r.startsWith(codeRoot + sep); };
const scratchParent = [tmpdir(), '/tmp', '/var/tmp'].find((d) => existsSync(d) && !insideCode(d)) || tmpdir();
const made = [];
const mkScratch = (prefix) => { const d = realpathSync(mkdtempSync(join(scratchParent, prefix))); made.push(d); return d; };
after(() => { for (const d of made) rmSync(d, { recursive: true, force: true }); });

const base = mkScratch('guard-');
const root = join(base, 'code'); const outside = join(base, 'elsewhere');
mkdirSync(join(root, 'proj', 'sub'), { recursive: true }); mkdirSync(outside, { recursive: true });
writeFileSync(join(root, 'proj', 'a.txt'), 'x'); writeFileSync(join(outside, 'keep.txt'), 'x');
symlinkSync(outside, join(root, 'proj', 'escape'));
const cwd = join(root, 'proj');
const bad = (cmd) => analyzeDeletes(cmd, { roots: [root], startCwd: cwd });
const ok = (cmd) => assert.deepEqual(bad(cmd), [], `should be allowed: ${cmd}`);
const no = (cmd) => assert.ok(bad(cmd).length > 0, `should be blocked: ${cmd}`);

test('deleting inside the allowed root is allowed, including recursive and forced', () => {
  ok(`rm ${root}/proj/a.txt`);
  ok(`rm -rf ${root}/proj/sub`);
  ok('rm -f a.txt');
  ok('rm -rf sub ./other');
  ok(`rmdir ${root}/proj/sub`);
  ok(`rm -rf ${root}/proj/*.log`);
  ok(`cd ${root}/proj && rm -rf build`);
  ok(`find ${root}/proj -name '*.tmp' -delete`);
  ok(`sudo rm -rf ${root}/proj/sub`);
});

test('anything outside the allowed root is blocked, however it is spelled', () => {
  no(`rm ${outside}/keep.txt`);
  no(`rm -rf ${outside}`);
  no('rm -rf /');
  no('rm -rf /tmp/anything');
  no('rm -rf ~');
  no('rm -rf ~/Documents');
  no('rm -rf $HOME/.ssh');
  no(`rm -rf ${homedir()}/.claude`);
  no('rm -rf ..');
  no('rm -rf ../../elsewhere');
  ok('rm -rf ../sibling-inside-root');
  no(`rm -rf ${root}/proj/../../elsewhere`);
  no(`find ${outside} -delete`);
  no(`find ${outside} -type f -exec rm {} \\;`);
  no(`unlink ${outside}/keep.txt`);
});

test('the allowed root itself is not something inside it', () => {
  no(`rm -rf ${root}`);
  no(`rm -rf ${root}/`);
  no('rm -rf ../..');
});

test('a symlink inside the root that points outside cannot be used to escape', () => {
  no(`rm -rf ${root}/proj/escape`);
  no(`rm -rf ${root}/proj/escape/keep.txt`);
});

test('a target the guard cannot resolve is refused, not guessed', () => {
  no('rm -rf $TARGET');
  no('rm -rf "$DIR/build"');
  no('rm -rf $(pwd)/..');
  no('rm -rf `echo /`');
  no('ls | xargs rm');
  no('cd "$SOMEWHERE" && rm -rf build');
  no('rm -rf');
  no('echo "$(rm -rf /)"');
  no('x=$(rm -rf ~/Documents)');
  no(`rm -rf ${root}/proj/*/../../../elsewhere/*`);
});

test('cd is followed: the same relative target is judged by where it now points', () => {
  no(`cd ${outside} && rm -rf build`);
  no('cd ~ && rm -rf build');
  no('cd / && rm -rf tmp');
  ok(`cd ${outside} && cd ${root}/proj && rm -rf build`);
});

test('text that merely mentions rm, and docker --rm, are not deletions', () => {
  ok('echo "run rm -rf / to wipe it"');
  ok(`docker run --rm -v ${homedir()}/nixwork:/w nixos/nix sh run.sh`);
  ok('git rm --cached a.txt');
  ok('npm run clean');
  ok(`python3 - <<'PY'\nprint("rm -rf /")\nPY`);
  ok("cat <<'EOF' > notes.txt\nrm -rf ~\nEOF");
  ok(`grep -rn "rm -rf" ${root}`);
  ok('ls -la ~');
});

test('the hook end to end: exit 2 when it blocks, 0 when it allows, and the config can widen the root', () => {
  const run = (command, config) => {
    const proj = mkScratch('guard-proj-');
    if (config) { mkdirSync(join(proj, '.agentic-security')); writeFileSync(join(proj, '.agentic-security', 'destructive-guard.json'), JSON.stringify(config)); }
    return spawnSync(process.execPath, [HOOK], { input: JSON.stringify({ tool_name: 'Bash', tool_input: { command } }), env: { ...process.env, CLAUDE_PROJECT_DIR: proj }, encoding: 'utf8' });
  };
  const allowed = join(homedir(), 'code', 'guard-e2e-scratch');
  assert.equal(run(`rm -rf ${allowed}`, { mode: 'block' }).status, 0, 'inside ~/code is allowed by default');
  const blocked = run(`rm -rf ${outside}`, { mode: 'block' });
  assert.equal(blocked.status, 2); assert.match(blocked.stderr, /outside the allowed root/);
  assert.equal(run(`rm -rf ${outside}`, { mode: 'block', allowedRoots: [base] }).status, 0, 'allowedRoots widens the boundary');
  assert.equal(run(`rm -rf ${outside}`, { mode: 'warn' }).status, 0, 'warn mode reports but does not block');
  assert.equal(run(`rm -rf ${outside}`, { mode: 'off' }).status, 0);
  assert.equal(run('docker run --rm -v /Users/x:/w img sh', { mode: 'block' }).status, 0);
});

test('disposableDirs may be deleted wholesale, and nothing beside them is opened up', () => {
  const scratch = join(outside, 'scratch');
  const d = (cmd) => analyzeDeletes(cmd, { roots: [root], startCwd: cwd, disposable: [scratch] });
  assert.deepEqual(d(`rm -rf ${scratch}`), [], 'the directory itself');
  assert.deepEqual(d(`rm -rf ${scratch}/inner/file`), [], 'inside it');
  assert.ok(d(`rm -rf ${scratch}2`).length > 0, 'a sibling that merely shares the prefix');
  assert.ok(d(`rm -rf ${outside}`).length > 0, 'its parent');
  assert.ok(d(`rm -rf ${scratch}/../keep.txt`).length > 0, 'an escape via ..');
  assert.ok(analyzeDeletes(`rm -rf ${root}`, { roots: [root], startCwd: cwd, disposable: [scratch] }).length > 0, 'allowedRoots stays protected');
});

test('the other destructive patterns still block', () => {
  const r = spawnSync(process.execPath, [HOOK], { input: JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'git push --force origin main' } }), env: { ...process.env, CLAUDE_PROJECT_DIR: base }, encoding: 'utf8' });
  assert.equal(r.status, 2);
});
