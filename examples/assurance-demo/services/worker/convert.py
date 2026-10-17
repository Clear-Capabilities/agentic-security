import subprocess
from flask import Flask, request

app = Flask(__name__)


# command injection: the file name reaches a shell
@app.route('/convert')
def convert():
    name = request.args.get('file')
    subprocess.run('convert ' + name + ' out.png', shell=True)
    return 'ok'


# safe lookalike: an argument list, no shell
@app.route('/probe')
def probe():
    name = request.args.get('file')
    subprocess.run(['identify', name])
    return 'ok'
