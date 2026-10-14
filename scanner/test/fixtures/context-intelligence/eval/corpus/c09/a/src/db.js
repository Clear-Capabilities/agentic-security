const { Pool } = require('pg');
const pool = new Pool();

function logMetric(name, value) {
  metrics.increment(name, value);
}

module.exports = { db: pool, logMetric };
