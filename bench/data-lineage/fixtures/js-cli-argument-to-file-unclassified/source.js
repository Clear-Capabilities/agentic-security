// NOTE: `sys.argv` is Python syntax written in a .js file on purpose —
// see this fixture's expected.json `notes`, and the same note in
// js-http-upload-to-object-storage-phi/source.js.
function main(fs) {
  const recordPath = sys.argv.record_path;
  fs.readFile(recordPath);
}
