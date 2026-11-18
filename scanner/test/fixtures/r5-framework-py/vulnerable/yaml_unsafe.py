import yaml
from flask import request

def load():
    return yaml.unsafe_load(request.data)