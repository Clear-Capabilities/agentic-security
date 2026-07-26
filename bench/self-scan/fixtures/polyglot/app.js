function emit(payload) {
  process.stdout.write(payload);
}

module.exports = { emit };
