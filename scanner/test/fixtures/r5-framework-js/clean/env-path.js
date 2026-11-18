const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
function loadConfig() {
  return fs.readFileSync(path.join(process.env.HOME, '.toolrc'), 'utf8');
}
function openEditor(file) {
  spawnSync(process.env.EDITOR, [file], { stdio: 'inherit' });
}
module.exports = { loadConfig, openEditor };
