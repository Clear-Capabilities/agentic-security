const express = require('express');
const escapeHtml = require('escape-html');
const { MongoClient } = require('mongodb');

const app = express();
const mongo = new MongoClient(process.env.MONGO_URL);
const db = mongo.db('shop');

app.get('/report', async (req, res) => {
  const rows = await db.collection('orders').find({}).toArray();
  let html = '<ul>';
  for (const o of rows) {
    html += '<li>' + o.note + '</li>';
  }
  res.send(html + '</ul>');
});

app.get('/report/safe', async (req, res) => {
  const rows = await db.collection('orders').find({}).toArray();
  let html = '<ul>';
  for (const o of rows) {
    html += '<li>' + escapeHtml(o.note) + '</li>';
  }
  res.send(html + '</ul>');
});

app.get('/audit', async (req, res) => {
  const rows = await db.collection('audit').find({}).toArray();
  res.send('<pre>' + rows.map((r) => r.line).join('\n') + '</pre>');
});

app.get('/bio', async (req, res) => {
  const doc = await db.collection('profiles').findOne({});
  res.send('<p>' + doc.bio + '</p>');
});

app.listen(3001);
