function identity(payload) {
  return payload;
}

function emit() {
  const cmd = identity('status: ok');
  require('child_process').exec(cmd);
}

module.exports = { identity, emit };
