// Plugin self-check hook test (post-recommendation #9).
//
// Sets up a tiny fake plugin root with one well-formed command, one
// well-formed agent, and one malformed command. Verifies the hook flags
// only the malformed one and exits 0.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as cp from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const HOOK = path.resolve(__dirname, '..', '..', 'hooks', 'session-start-self-check.js');

function mkPlugin(layout) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'self-check-'));
  for (const [rel, content] of Object.entries(layout)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

function runHook(pluginRoot) {
  const r = cp.spawnSync('node', [HOOK], {
    env: { ...process.env, CLAUDE_PLUGIN_ROOT: pluginRoot },
    // 20s, not 4s: this spawns a real child process, and a busy machine
    // (concurrent test runs, unrelated background load) can starve it well
    // past 4s even though the hook itself normally completes in ~100-300ms.
    // A 4s cap was producing false failures (status:null from the timeout,
    // not a real assertion failure) under ordinary machine contention.
    input: '{}', encoding: 'utf8', timeout: 20000,
  });
  return { code: r.status, stderr: r.stderr || '', stdout: r.stdout || '' };
}

test('self-check stays silent when every surface is well-formed', () => {
  const root = mkPlugin({
    'commands/scan.md':  '---\ndescription: Run the scanner.\n---\n# scan\n',
    'agents/triager.md': '---\nname: triager\ndescription: Triage findings.\ntools: Read, Bash\n---\nbody\n',
  });
  const r = runHook(root);
  assert.equal(r.code, 0);
  assert.equal(r.stderr.trim(), '', `expected silence, got: ${r.stderr}`);
});

test('self-check flags a command missing its description', () => {
  const root = mkPlugin({
    'commands/scan.md':   '---\ndescription: ok\n---\nbody\n',
    'commands/broken.md': '---\nargument-hint: nope\n---\nbody\n',
  });
  const r = runHook(root);
  assert.equal(r.code, 0);
  assert.match(r.stderr, /broken\.md.*missing-description-in-frontmatter/);
});

test('self-check flags a command missing the frontmatter fence', () => {
  const root = mkPlugin({
    'commands/no-fence.md': '# scan\n\nNo frontmatter at all.\n',
  });
  const r = runHook(root);
  assert.equal(r.code, 0);
  assert.match(r.stderr, /no-fence\.md.*missing-frontmatter-fence/);
});

test('self-check flags an agent missing required fields', () => {
  const root = mkPlugin({
    'agents/incomplete.md': '---\ndescription: only description\n---\nbody\n',
  });
  const r = runHook(root);
  assert.equal(r.code, 0);
  assert.match(r.stderr, /incomplete\.md.*missing-name/);
  assert.match(r.stderr, /incomplete\.md.*missing-tools/);
});

test('self-check flags a missing hook referenced in hooks.json', () => {
  const root = mkPlugin({
    'commands/scan.md': '---\ndescription: ok\n---\nbody\n',
    'hooks/hooks.json': JSON.stringify({
      hooks: {
        SessionStart: [{ hooks: [{ type: 'command', command: 'node ${CLAUDE_PLUGIN_ROOT}/hooks/does-not-exist.js' }] }],
      },
    }),
  });
  const r = runHook(root);
  assert.equal(r.code, 0);
  assert.match(r.stderr, /does-not-exist\.js.*missing/);
});

test('self-check ignores underscore-prefixed files (like _CONFINEMENT.md)', () => {
  const root = mkPlugin({
    'agents/_CONFINEMENT.md': '# Confinement schema (no frontmatter — this is a shared doc, not an agent)\n',
    'agents/real-agent.md':   '---\nname: real-agent\ndescription: ok\ntools: Read\n---\nbody\n',
  });
  const r = runHook(root);
  assert.equal(r.code, 0);
  assert.equal(r.stderr.trim(), '', `expected silence, got: ${r.stderr}`);
});
