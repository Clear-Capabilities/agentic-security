import { Hono } from 'hono';
import { html } from 'hono/html';

const app = new Hono();

app.get('/search', (c) => {
  const term = c.req.query('term');
  return c.html(html`<div class="results">No results for ${term}</div>`);
});

app.get('/search.txt', (c) => {
  const term = c.req.query('term');
  return c.text('No results for ' + term);
});

export default app;
