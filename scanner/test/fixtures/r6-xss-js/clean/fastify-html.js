const fastify = require('fastify')();

fastify.get('/greet', async (request, reply) => {
  const who = request.query.who;
  return reply.send({ greeting: 'Welcome', who });
});

module.exports = fastify;
