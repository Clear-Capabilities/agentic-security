// SYNTHETIC evaluation fixture. A query that LOOKS dynamic but is built from constants only.
const db = require('./db');
const TABLE = 'audit_log';

function dailyCount(cb) {
  db.query('SELECT COUNT(*) FROM ' + TABLE + ' WHERE day = CURRENT_DATE', cb);
}

module.exports = { dailyCount };
