const express = require('express');
const http = require('http');
const app = express();

app.use(express.json({ limit: '2gb' }));

http.createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
  });
  req.on('end', () => res.end(body.length.toString()));
}).listen(8080);
