import json
import pika

def handle(ch, method, props, raw):
    body = json.loads(raw)
    print(body['orderId'])

conn = pika.BlockingConnection()
ch = conn.channel()
ch.basic_consume(queue='orders-events', on_message_callback=handle)
