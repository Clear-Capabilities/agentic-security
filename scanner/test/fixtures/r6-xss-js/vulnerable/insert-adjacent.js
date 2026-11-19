document.addEventListener('DOMContentLoaded', () => {
  const msg = location.hash.substring(1);
  document.getElementById('notice').insertAdjacentHTML('beforeend', '<span>' + msg + '</span>');
});
