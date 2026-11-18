const { execSync } = require('child_process');

function readRoutes(file) {
  const cmd = `cat ${file} 2> /dev/null | grep via`;
  return execSync(cmd).toString().split('\n');
}

function linkState(iface) {
  return execSync(`ip link show ${iface}`).toString();
}

module.exports = { readRoutes, linkState };
