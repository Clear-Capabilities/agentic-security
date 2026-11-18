const params = new URLSearchParams(window.location.search);
const note = params.get('note');

function resetNote() {
  const box = document.getElementById('note');
  box.innerHTML = '';
  for (const line of String(note).split('\n')) {
    const p = document.createElement('p');
    p.textContent = line;
    box.appendChild(p);
  }
}

resetNote();
