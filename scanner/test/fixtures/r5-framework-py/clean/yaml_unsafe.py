import yaml
from flask import request

def load():
    return yaml.safe_load(request.data)