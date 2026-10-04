const { Kafka } = require('kafkajs');
const kafka = new Kafka({ brokers: ['k:9092'] });
const consumer = kafka.consumer({ groupId: 'g' });
async function run() { await consumer.subscribe({ topic: 'legacy' }); }
