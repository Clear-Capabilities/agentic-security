const xml = require('acme-xml-lite');
const imaging = require('acme-img-tools');

// calls the function the local advisory names for acme-xml-lite
function importDocument(text) {
  return xml.parseUnsafe(text);
}

// acme-img-tools is imported for its safe helper only; resizeRaw, the advisory's function, is never called
function thumbnail(image) {
  return imaging.resizeSafe(image, 64);
}

module.exports = { importDocument, thumbnail };
