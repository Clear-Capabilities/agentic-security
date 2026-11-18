const fs = require('fs');
const path = require('path');
fastify.get('/doc', async (request, reply) => {
  return fs.readFileSync(path.join('/srv/docs', path.basename(request.query.name)));
});