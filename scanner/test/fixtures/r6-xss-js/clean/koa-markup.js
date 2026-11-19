const Koa = require('koa');
const escapeHtml = require('escape-html');
const app = new Koa();

app.use(async (ctx) => {
  const name = escapeHtml(ctx.query.name);
  ctx.body = '<h1>Hello ' + name + '</h1>';
});

module.exports = app;
