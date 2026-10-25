const cp = require('child_process');
function level20(c) {
  cp.exec(c);
}
function level19(c) {
  level20(c);
}
function level18(c) {
  level19(c);
}
function level17(c) {
  level18(c);
}
function level16(c) {
  level17(c);
}
function level15(c) {
  level16(c);
}
function level14(c) {
  level15(c);
}
function level13(c) {
  level14(c);
}
function level12(c) {
  level13(c);
}
function level11(c) {
  level12(c);
}
function level10(c) {
  level11(c);
}
function level9(c) {
  level10(c);
}
function level8(c) {
  level9(c);
}
function level7(c) {
  level8(c);
}
function level6(c) {
  level7(c);
}
function level5(c) {
  level6(c);
}
function level4(c) {
  level5(c);
}
function level3(c) {
  level4(c);
}
function level2(c) {
  level3(c);
}
function level1(c) {
  level2(c);
}
function entry(req, res) {
  level1(req.query.cmd);
}
function entryClean(req, res) {
  level1('literal');
}
