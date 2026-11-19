import os
import uuid
from flask import request

def delete():
    body = request.get_json()
    os.remove('/srv/uploads/' + str(uuid.uuid4()))
    return body['name']
