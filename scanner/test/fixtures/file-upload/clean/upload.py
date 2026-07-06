import os
import uuid
from flask import request
from werkzeug.utils import secure_filename


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['doc']
    name = secure_filename(f.filename) or (uuid.uuid4().hex + '.bin')
    f.save(os.path.join('/var/uploads', name))
    return 'ok'
