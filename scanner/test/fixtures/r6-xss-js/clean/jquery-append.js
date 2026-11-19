$(function () {
  const q = new URLSearchParams(location.search).get('q');
  $('#list').append($('<li>').text(q));
});
