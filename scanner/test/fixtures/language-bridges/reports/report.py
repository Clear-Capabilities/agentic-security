import os
import psycopg2

conn = psycopg2.connect(dbname='shop', host='db')
cur = conn.cursor()
cur.execute("SELECT email FROM customers")
mode = os.environ['SHARED_MODE']
