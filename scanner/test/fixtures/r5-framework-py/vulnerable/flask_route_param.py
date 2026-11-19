from flask import Flask
app = Flask(__name__)

@app.route('/docs/<name>')
def doc(name):
    with open('/srv/docs/' + name) as fh:
        return fh.read()