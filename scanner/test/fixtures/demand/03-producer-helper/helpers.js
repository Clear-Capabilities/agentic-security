function readInput() {
  return process.env.USER_CMD;
}
function constant() {
  return 'ls';
}
module.exports = { readInput, constant };
