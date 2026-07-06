from flask import request


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['doc']
    # Client-supplied filename used as the save path — unrestricted upload.
    f.save('/var/uploads/' + f.filename)
    return 'ok'
