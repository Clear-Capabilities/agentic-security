window.addEventListener('load', () => {
  const label = location.search.slice(1);
  const el = document.querySelector('#title');
  el.outerHTML = '<h2>' + label + '</h2>';
});
