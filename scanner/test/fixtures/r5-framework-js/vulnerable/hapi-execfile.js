const { execFile } = require('child_process');
server.route({ method: 'POST', path: '/run', handler: (request, h) => {
  execFile(request.payload.tool, ['--version']);
  return 'ok';
} });