const { execFile } = require('child_process');
server.route({ method: 'POST', path: '/run', handler: (request, h) => {
  execFile('git', ['log', '--oneline', request.payload.ref]);
  return 'ok';
} });