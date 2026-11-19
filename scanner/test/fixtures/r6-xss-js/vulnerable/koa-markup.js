const Koa = require('koa');
const app = new Koa();

app.use(async (ctx) => {
  const name = ctx.query.name;
  ctx.body = '<h1>Hello ' + name + '</h1>';
});

module.exports = app;
