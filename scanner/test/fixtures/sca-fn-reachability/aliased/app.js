// POSITIVE (R7): vulnerable lodash.merge invoked via an ALIASED named import.
// The regex reachability pass keys on `lodash.merge` / `_.merge` and MISSES
// `deepMerge(...)`. R7's import-aware pass resolves the alias to lodash.merge,
// so functionReachable should be 'reachable' (the call is in a route handler).
import express from 'express';
import { merge as deepMerge } from 'lodash';

const app = express();

app.post('/profile', (req, res) => {
  const merged = deepMerge({}, req.body);
  res.json(merged);
});

export default app;
