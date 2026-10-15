const pool = require('pg').Pool;
const db = new pool();

function logMetric(name, value) {
  metrics.increment(name, value);
}

module.exports = { db, logMetric };
