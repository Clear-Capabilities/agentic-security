from flask import Flask
app = Flask(__name__)

@app.route('/docs/<int:doc_id>')
def doc(doc_id):
    with open('/srv/docs/%d.txt' % doc_id) as fh:
        return fh.read()