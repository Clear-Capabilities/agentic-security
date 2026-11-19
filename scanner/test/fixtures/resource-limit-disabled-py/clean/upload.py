import zipfile
import zlib
from flask import Flask, abort, request

app = Flask(__name__)
MAX_TOTAL = 50 * 1024 * 1024


@app.route('/import', methods=['POST'])
def import_archive():
    upload = request.files['archive']
    with zipfile.ZipFile(upload) as archive:
        if sum(info.file_size for info in archive.infolist()) > MAX_TOTAL:
            abort(413)
        archive.extractall('/srv/imports')
    return 'ok'


@app.route('/inflate', methods=['POST'])
def inflate():
    d = zlib.decompressobj()
    out = d.decompress(request.get_data(), MAX_TOTAL)
    if d.unconsumed_tail:
        abort(413)
    return out
