import re
from flask import request

def find():
    pattern = request.args['pattern']
    return str(re.search(pattern, 'some text'))