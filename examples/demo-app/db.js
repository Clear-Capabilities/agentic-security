// demo-app — deliberately vulnerable. See README.md. Never deploy.
const mysql = require('mysql2');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'shop',
  password: process.env.DB_PASSWORD,
  database: 'shop',
});

module.exports = { query: (...args) => pool.query(...args) };
