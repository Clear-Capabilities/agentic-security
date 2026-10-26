const express = require('express');
const { SQSClient, SendMessageCommand } = require('@aws-sdk/client-sqs');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json({ limit: '10kb' }));

const sqs = new SQSClient({ region: 'us-east-1' });
const mongo = new MongoClient(process.env.MONGO_URL);
const db = mongo.db('shop');

const ORDERS_QUEUE = process.env.ORDERS_QUEUE_URL;
const AUDIT_QUEUE = process.env.AUDIT_QUEUE_URL;

app.post('/orders', async (req, res) => {
  const note = req.body.note;
  const qty = Number(req.body.qty);
  await sqs.send(new SendMessageCommand({
    QueueUrl: ORDERS_QUEUE,
    MessageBody: JSON.stringify({ note, qty }),
  }));
  await sqs.send(new SendMessageCommand({
    QueueUrl: AUDIT_QUEUE,
    MessageBody: 'order created',
  }));
  res.status(202).json({ queued: true });
});

app.post('/profile', async (req, res) => {
  await db.collection('profiles').insertOne({ bio: req.body.bio });
  await db.collection('events').insertOne({ at: Date.now(), kind: 'profile' });
  res.status(201).json({ ok: true });
});

app.listen(3000);
