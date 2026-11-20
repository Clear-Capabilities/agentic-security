from flask import Flask, request
from fastapi import FastAPI
import secrets
app = Flask(__name__)
api = FastAPI()


@api.get('/grid')
def grid(cells: int):
    return {'row': '.' * cells}


@app.route('/tokens')
def tokens():
    count = int(request.args.get('count', '1'))
    return secrets.token_bytes(count)



@app.route('/dedupe', methods=['POST'])
def dedupe():
    names = request.get_json()['names']
    seen = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return {'names': seen}
