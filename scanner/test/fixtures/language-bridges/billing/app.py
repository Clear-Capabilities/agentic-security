from flask import Flask, request
app = Flask(__name__)

@app.route('/health')
def health():
    return 'ok'

if __name__ == '__main__':
    app.run(port=9090)
