const http = require('http');

http.createServer((req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.end('Hello ' + req.headers['x-name']);
}).listen(8080);
