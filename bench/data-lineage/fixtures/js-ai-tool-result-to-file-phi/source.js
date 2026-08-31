function loadNote(result, fs) {
  const diagnosis = result.content.diagnosis;
  fs.readFile('/var/notes/' + diagnosis + '.txt');
}
