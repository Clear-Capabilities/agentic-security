import requests
from flask import request

def forward():
    item = request.args['item']
    resp = requests.put('https://api.internal.test/items', json={'item': item})
    return resp.text