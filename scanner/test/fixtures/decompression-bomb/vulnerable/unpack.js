const zlib = require('zlib');

function readBlob(buf) {
  return zlib.gunzipSync(buf).toString('utf8');
}

class Extractor {
  start(sink) {
    this.inflater = zlib.createGunzip();
    this.inflater.on('data', (chunk) => sink.consume(chunk));
  }
}
module.exports = { readBlob, Extractor };
