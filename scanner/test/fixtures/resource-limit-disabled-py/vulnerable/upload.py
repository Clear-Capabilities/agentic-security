import zipfile
import zlib
from flask import Flask, request

app = Flask(__name__)


@app.route('/import', methods=['POST'])
def import_archive():
    upload = request.files['archive']
    with zipfile.ZipFile(upload) as archive:
        archive.extractall('/srv/imports')
    return 'ok'


@app.route('/inflate', methods=['POST'])
def inflate():
    return zlib.decompress(request.get_data())
