const zlib = require('zlib');
const LIMIT = 64 * 1024 * 1024;

function readBlob(buf) {
  return zlib.gunzipSync(buf, { maxOutputLength: LIMIT }).toString('utf8');
}

class Extractor {
  start(sink) {
    this.seen = 0;
    this.inflater = zlib.createGunzip();
    this.inflater.on('data', (chunk) => {
      this.seen += chunk.length;
      if (this.seen > LIMIT) return this.inflater.destroy(new Error('too large'));
      sink.consume(chunk);
    });
  }
}
module.exports = { readBlob, Extractor };
