#!/usr/bin/env node
// PreToolUse (Edit|Write|MultiEdit) dispatcher (#24 — hook process consolidation).
//
// Runs all three Edit-time PreToolUse hooks in ONE node process instead of three:
//   1. pre-edit-bodyguard   — the SECURITY GATE. Can BLOCK the edit (exit 2).
//                             Runs FIRST and short-circuits: on a block the
//                             dispatcher exits 2 with the guard's stderr message,
//                             byte-for-byte identical to the standalone hook, and
//                             the advisory hooks below never run.
//   2. conversation-context — injects open findings / fix history / pending
//                             fix-plans for the target file (stdout, advisory).
//   3. cache-invalidator    — warns when the edit cold-invalidates the prompt
//                             cache (stderr, advisory).
//
// The block path is the security-critical invariant; test/dispatch-pre-tool.test.js
// asserts a critical edit still exits 2 here. Cuts 3 spawns → 1 on every edit.
'use strict';
const { evaluate } = require('./pre-edit-bodyguard.js');
const { buildContextOutput } = require('./conversation-context.js');
const { buildWarning } = require('./cache-invalidator-guard.js');

function readStdinJSON() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    setTimeout(() => resolve({}), 500).unref?.();
  });
}

async function main() {
  const evt = await readStdinJSON();

  // 1) Security gate FIRST. A block short-circuits everything else — the advisory
  //    hooks must never run after a deny, and the deny signal (stderr + exit 2)
  //    is emitted exactly as the standalone bodyguard would. Fail-open on error,
  //    matching the standalone hook (it never blocks on its own crash).
  let decision = { action: 'allow' };
  try { decision = await evaluate(evt); } catch { decision = { action: 'allow' }; }
  if (decision && decision.action === 'block') {
    process.stderr.write((decision.message || 'agentic-security: edit blocked') + '\n');
    process.exit(2);
  }

  // 2) Advisory-only from here. None of these can block the edit.
  let context = null, warning = null;
  try { context = buildContextOutput(evt); } catch { /* best-effort */ }
  try { warning = buildWarning(evt); } catch { /* best-effort */ }

  if (decision && decision.action === 'warn' && decision.message) {
    process.stderr.write(decision.message + '\n'); // bodyguard warn-mode notice
  }
  if (warning) process.stderr.write(warning);       // cache-invalidation warning
  if (context) process.stdout.write(context + '\n'); // findings/fix context → model
  process.exit(0);
}

if (require.main === module) {
  main();
}
