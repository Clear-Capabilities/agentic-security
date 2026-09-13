const mysql = require('mysql');
const config = require('../config');

const pool = mysql.createPool({
  host: config.dbHost,
  user: config.dbUser,
  password: config.dbPassword,
  database: 'tinymart',
});

module.exports = {
  query(sql, paramsOrCb, maybeCb) {
    if (typeof paramsOrCb === 'function') return pool.query(sql, paramsOrCb);
    return pool.query(sql, paramsOrCb, maybeCb);
  },
};
