import { Hono } from 'hono';

const app = new Hono();

app.get('/search', (c) => {
  const term = c.req.query('term');
  return c.html('<div class="results">No results for ' + term + '</div>');
});

export default app;
