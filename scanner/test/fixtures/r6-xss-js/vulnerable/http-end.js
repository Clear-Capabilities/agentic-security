const http = require('http');

http.createServer((req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.end('<html><body>' + req.headers['x-name'] + '</body></html>');
}).listen(8080);
