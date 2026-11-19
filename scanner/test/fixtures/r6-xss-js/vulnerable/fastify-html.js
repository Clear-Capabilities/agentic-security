const fastify = require('fastify')();

fastify.get('/greet', async (request, reply) => {
  const who = request.query.who;
  reply.type('text/html');
  return reply.send('<p>Welcome, ' + who + '</p>');
});

module.exports = fastify;
