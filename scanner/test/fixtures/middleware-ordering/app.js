const express = require('express');
const adminRouter = require('./admin');
const apiRouter = require('./api');
const publicRouter = require('./public');
const { authMiddleware } = require('./auth');

const app = express();

// VULNERABLE: /admin mounted BEFORE auth middleware is registered.
// Anyone can hit /admin/* without authentication.
app.use('/admin', adminRouter);

// VULNERABLE: same for /api
app.use('/api', apiRouter);

// /public is fine — public-facing route can sit above the auth boundary
app.use('/public', publicRouter);

// Global auth registered too late
app.use(authMiddleware);

// Routes registered AFTER auth are protected — fine
app.use('/dashboard', adminRouter);

app.listen(3000);
