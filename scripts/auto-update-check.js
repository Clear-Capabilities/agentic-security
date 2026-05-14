#!/usr/bin/env node
// auto-update-check.js — throttle/gate logic for /scan's auto-update step.
//
// Exit codes:
//   0  Update check is DUE. Caller should invoke /plugin marketplace update.
//   1  Auto-update DISABLED by user config.
//   2  Within throttle window. Skip the update.
//   3  IO/parse error reading config (treat as "update is due" — exits 0 to be safe).
//
// Usage:
//   node auto-update-check.js          # check whether an update is due
//   node auto-update-check.js --mark   # record that an update was just performed
//
// Config (.agentic-security/auto-update.json):
//   {
//     "enabled": true,
//     "throttleHours": 4,
//     "lastCheck": 1715688000
//   }
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const cfgPath = path.join(stateDir, 'auto-update.json');

const DEFAULT_CFG = { enabled: true, throttleHours: 4, lastCheck: 0 };

function readCfg() {
  if (!fs.existsSync(cfgPath)) return { ...DEFAULT_CFG };
  try {
    const data = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    return { ...DEFAULT_CFG, ...data };
  } catch {
    // Malformed — surface to caller so they can decide. We return defaults
    // and let the caller proceed (safe default = check for updates).
    return { ...DEFAULT_CFG };
  }
}

function writeCfg(cfg) {
  try {
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
  } catch (e) {
    process.stderr.write(`auto-update-check: failed to write ${cfgPath}: ${e.message}\n`);
  }
}

const mark = process.argv.includes('--mark');

const cfg = readCfg();

if (mark) {
  cfg.lastCheck = Math.floor(Date.now() / 1000);
  writeCfg(cfg);
  process.stdout.write(`auto-update-check: recorded lastCheck=${cfg.lastCheck}\n`);
  process.exit(0);
}

// Gate 1: user disabled it
if (cfg.enabled === false) {
  process.stdout.write('auto-update-check: disabled by config\n');
  process.exit(1);
}

// Gate 2: throttle window
const now = Math.floor(Date.now() / 1000);
const throttleSeconds = Math.max(0, Number(cfg.throttleHours) || 0) * 3600;
const elapsed = now - (Number(cfg.lastCheck) || 0);

if (cfg.lastCheck && elapsed < throttleSeconds) {
  const remainingMin = Math.ceil((throttleSeconds - elapsed) / 60);
  process.stdout.write(
    `auto-update-check: within throttle window (next check in ~${remainingMin}min)\n`
  );
  process.exit(2);
}

// Gate 3: update is due
process.stdout.write(
  `auto-update-check: update check is due (last check: ${
    cfg.lastCheck ? new Date(cfg.lastCheck * 1000).toISOString() : 'never'
  })\n`
);
process.exit(0);
