export const id = 7979;
export const ids = [7979];
export const modules = {

/***/ 17979:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   makeIdentityTokenizer: () => (/* binding */ makeIdentityTokenizer)
/* harmony export */ });
/* harmony import */ var _posture_integrity_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(37455);
// A keyed-hash token for an authenticated identity (PRD 2 section 1, "authenticated identity"). The observation contract is closed-world
// and refuses raw identities, so what is stored is `idt_` + 16 hex of an HMAC under the per-install key:
//   * the same identity always yields the same token on this install, so "the same identity used these paths" can be answered;
//   * without the install key the token cannot be reversed or confirmed by guessing usernames (an unkeyed hash could);
//   * tokens from two installs do not match, which is deliberate: they are not a portable identifier.
// It is a pseudonym, not anonymity: someone who holds the install key and a candidate username can confirm a match.


function makeIdentityTokenizer() {
  return (raw) => (typeof raw === 'string' && raw.length > 0 ? `idt_${(0,_posture_integrity_js__WEBPACK_IMPORTED_MODULE_0__/* .signLastScan */ .lU)(`identity-token:v1:${raw}`).slice(0, 16)}` : null);
}


/***/ })

};
