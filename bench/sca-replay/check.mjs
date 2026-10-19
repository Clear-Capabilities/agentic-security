#!/usr/bin/env node
// The release-gate form of the SCA replay: fetch the manifests, re-label them against today's advisory data, then score the engine against
// those fresh labels and compare with the committed RESULT.json.
//
// Why the labels are rebuilt here. The engine reads the live advisory database, and labels.json is a snapshot of it. Scored against a
// snapshot that is months old, every advisory published since counts as an engine "false positive" and the gate fails on the calendar, not
// on the code (the hosted release of 0.180.0 failed that way: precision 95.6% against a committed 100%). Labelling and scoring in the
// same run puts both sides on the same data, which is what the bench is meant to compare. The fresh labels go to a temp file; nothing in
// the repository is written.
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sca-replay-check-'));
const labels = path.join(dir, 'labels.json');
const step = (script, args, env = {}) => spawnSync(process.execPath, [path.join(HERE, script), ...args], { stdio: 'inherit', env: { ...process.env, ...env } }).status;
let code = step('fetch.mjs', []);
if (code === 0) code = step('label.mjs', [], { SCA_REPLAY_LABELS_OUT: labels });
if (code === 0) code = step('runner.mjs', ['--check'], { SCA_REPLAY_LABELS: labels });
fs.rmSync(dir, { recursive: true, force: true });
process.exit(code ?? 1);
