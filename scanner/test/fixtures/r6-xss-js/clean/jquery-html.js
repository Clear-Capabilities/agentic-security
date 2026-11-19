$(function () {
  const fragment = decodeURIComponent(location.hash.slice(1));
  $('#banner').text(fragment);
});
