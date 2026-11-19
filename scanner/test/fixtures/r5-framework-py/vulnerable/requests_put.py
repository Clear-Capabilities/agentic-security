import requests
from flask import request

def forward():
    target = request.args['target']
    resp = requests.put(target, data=b'x')
    return resp.text