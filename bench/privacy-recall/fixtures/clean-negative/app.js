function logCount(req) {
  const count = req.body.value;
  console.log(count);
}
module.exports = { logCount };
