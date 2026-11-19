const express = require('express');
const http = require('http');
const app = express();

app.use(express.json({ limit: '1mb' }));

http.createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
    if (body.length > 1e6) {
      res.statusCode = 413;
      req.destroy();
    }
  });
  req.on('end', () => res.end(body.length.toString()));
}).listen(8080);
