const params = new URLSearchParams(window.location.search);
const note = params.get('note');

function showNote() {
  const box = document.getElementById('note');
  box.innerHTML = note;
}

showNote();
