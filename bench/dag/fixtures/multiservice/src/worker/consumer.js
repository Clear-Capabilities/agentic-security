const { SQSClient, ReceiveMessageCommand } = require('@aws-sdk/client-sqs');
const { MongoClient } = require('mongodb');

const sqs = new SQSClient({ region: 'us-east-1' });
const mongo = new MongoClient(process.env.MONGO_URL);
const db = mongo.db('shop');

const ORDERS_QUEUE = process.env.ORDERS_QUEUE_URL;
const AUDIT_QUEUE = process.env.AUDIT_QUEUE_URL;
const PRICE = 12;

async function drainOrders() {
  const out = await sqs.send(new ReceiveMessageCommand({ QueueUrl: ORDERS_QUEUE }));
  for (const m of out.Messages || []) {
    const body = JSON.parse(m.Body);
    await db.collection('orders').insertOne({ note: body.note, total: body.qty * PRICE });
  }
}

async function drainAudit() {
  const out = await sqs.send(new ReceiveMessageCommand({ QueueUrl: AUDIT_QUEUE }));
  for (const m of out.Messages || []) {
    await db.collection('audit').insertOne({ line: m.Body });
  }
}

setInterval(drainOrders, 1000);
setInterval(drainAudit, 1000);
