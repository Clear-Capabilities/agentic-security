import re
from flask import request

def find():
    pattern = re.escape(request.args['pattern'])
    return str(re.search(pattern, 'some text'))