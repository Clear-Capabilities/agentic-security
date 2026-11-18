const { execSync, execFileSync } = require('child_process');
const fs = require('fs');

function readRoutes(file) {
  return fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.includes('via'));
}

function linkState(iface) {
  return execFileSync('ip', ['link', 'show', iface]).toString();
}

function linkStateChecked(iface) {
  const safe = sanitizeShellString(iface);
  return execSync(`ip link show ${safe}`).toString();
}

function sanitizeShellString(s) {
  return String(s).replace(/[^a-zA-Z0-9_.-]/g, '');
}

module.exports = { readRoutes, linkState, linkStateChecked };
