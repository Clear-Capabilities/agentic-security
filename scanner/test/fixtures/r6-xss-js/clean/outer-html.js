window.addEventListener('load', () => {
  const label = location.search.slice(1);
  const el = document.querySelector('#title');
  el.textContent = label;
});
