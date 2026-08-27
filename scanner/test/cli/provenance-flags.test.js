import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseProvenanceFlags } from '../../bin/agentic-security.js';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

test('parseProvenanceFlags: defaults to standard mode, nothing disabled', () => {
  const f = parseProvenanceFlags([]);
  assert.equal(f.mode, 'standard');
  assert.equal(f.disabled, false);
  assert.equal(f.includeEmail, false);
  assert.equal(f.requireProvenance, false);
});

test('parseProvenanceFlags: --no-provenance disables', () => {
  const f = parseProvenanceFlags(['--no-provenance']);
  assert.equal(f.disabled, true);
});

test('parseProvenanceFlags: --provenance deep is accepted but warns and stays standard', () => {
  const f = parseProvenanceFlags(['--provenance', 'deep']);
  assert.equal(f.mode, 'standard');
  assert.match(f.warning, /deep mode ships in a later release/);
});

test('parseProvenanceFlags: --provenance-since, --provenance-timeout, --include-author-email, --require-provenance', () => {
  const f = parseProvenanceFlags(['--provenance-since', 'v1.0.0', '--provenance-timeout', '30000', '--include-author-email', '--require-provenance']);
  assert.equal(f.since, 'v1.0.0');
  assert.equal(f.timeoutMs, 30000);
  assert.equal(f.includeEmail, true);
  assert.equal(f.requireProvenance, true);
});

// Regression for a Critical bug found in review: `bin/agentic-security.js`
// must run its CLI dispatch (main()) when invoked THROUGH A SYMLINK, which
// is exactly how npm/npx run every `bin` entry (`npm install -g`, `npx`,
// `node_modules/.bin/<name>`) — including this package's own published
// `agentic-security`/`as`/`agentic-security-scanner` commands. A guard of
// the form `import.meta.url === file://${process.argv[1]}` is FALSE through
// a symlink (import.meta.url resolves to the realpath; process.argv[1]
// stays the symlink path), so the CLI would silently exit 0 with no output
// for every real installed user. The fix is `import.meta.main`, which
// resolves correctly through a symlink.
test('CLI entry point runs (produces output) when invoked through a symlink', () => {
  const realScript = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
  const dir = mkdtempSync(path.join(tmpdir(), 'as-symlink-test-'));
  const linkPath = path.join(dir, 'agentic-security-link.js');
  try {
    symlinkSync(realScript, linkPath);
    const result = spawnSync(process.execPath, [linkPath, 'version'], { encoding: 'utf8' });
    assert.equal(result.status, 0, `expected exit 0, got ${result.status}; stderr: ${result.stderr}`);
    assert.match(result.stdout, /agentic-security \d+\.\d+\.\d+/, 'symlinked invocation must produce real CLI output, not silently exit with nothing');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
