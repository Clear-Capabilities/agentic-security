const { db } = require('./db');
exports.getReport = function getReport(id) {
  return db.query('SELECT * FROM reports WHERE id = ' + id);
};
