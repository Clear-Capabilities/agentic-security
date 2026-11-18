import os
from flask import request

def delete():
    body = request.get_json()
    os.remove('/srv/uploads/' + body['name'])
    return 'ok'