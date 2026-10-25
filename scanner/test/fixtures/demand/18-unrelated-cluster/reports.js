const cp = require('child_process');
function renderR(v) { cp.exec(v); }
function loadR(req) { renderR('static-report'); }
function misc() { cp.exec('whoami'); }
