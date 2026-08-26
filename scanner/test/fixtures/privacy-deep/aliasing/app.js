function logViaAlias(req) {
  const record = {};
  const a = record;
  const ssn = req.body.value;
  a.value = ssn;
  console.log(record.value);
}

function logCleanViaAlias(req) {
  const record2 = {};
  const b = record2;
  const other = req.body.value;
  b.value = other;
  console.log(record2.value);
}

module.exports = { logViaAlias, logCleanViaAlias };
