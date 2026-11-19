from flask import Flask, request
from fastapi import FastAPI, Query
import secrets
app = Flask(__name__)
api = FastAPI()
MAX_COUNT = 4096


@api.get('/grid')
def grid(cells: int = Query(1, le=500)):
    return {'row': '.' * cells}


@app.route('/tokens')
def tokens():
    count = min(int(request.args.get('count', '1')), MAX_COUNT)
    return secrets.token_bytes(count)



@app.route('/dedupe', methods=['POST'])
def dedupe():
    names = request.get_json()['names']
    seen = set()
    for name in names:
        if name not in seen:
            seen.add(name)
    return {'names': sorted(seen)}
