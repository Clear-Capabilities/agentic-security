// QA-002.AC02: the existing mandatory benchmark gates do not regress.
// Tagged [QA-002.AC02]. Kept in its own file and its own script (npm run test:language-gates) because it runs five benchmark gates
// (about fifteen minutes) and would starve every other test of CPU inside the combined `npm test`. The same gates also run in the
// pre-push gate and the release check, so nothing is left unselected.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.join(HERE, '..', '..');
const gate = (cmd, args, cwd = SCANNER, timeout = 900000) => spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout, env: { ...process.env, NO_COLOR: '1' } });

test('[QA-002.AC02] the existing mandatory benchmark gates do not regress', () => {
  const runs = [
    ['bench:mutation:check', ['../bench/mutation/runner.mjs']],
    ['bench:protection-verdict:check', ['../bench/protection-verdict/runner.mjs']],
    ['bench:layer-recall:check', ['../bench/layer-recall/runner.mjs', '--check']],
    ['bench:provenance-accuracy:check', ['../bench/provenance-accuracy/runner.mjs', '--check']],
    ['bench:cve-replay:check', ['../bench/cve-replay/runner.mjs', '--check-baseline']],
  ];
  for (const [name, args] of runs) {
    const r = gate(process.execPath, args);
    assert.equal(r.status, 0, `${name} exited ${r.status}\n${String(r.stdout).slice(-800)}${String(r.stderr).slice(-400)}`);
  }
});

