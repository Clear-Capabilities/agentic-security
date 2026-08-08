// Source side of an interprocedural flow. Split across files on purpose: the
// cross-file taint walk is one of the paths whose iteration order could differ
// between machines, which is exactly what the first determinism fixture failed
// to exercise.
function readTarget(req) {
  return req.query.host;
}
function readName(req) {
  return req.body.name;
}
module.exports = { readTarget, readName };
