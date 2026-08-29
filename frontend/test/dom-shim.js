// Minimal, dependency-free `document`/`window` shim for testing shell.js and
// dom.js without a jsdom dependency. Implements exactly the DOM surface these
// two modules actually use: createElement, createTextNode, appendChild,
// removeChild, setAttribute/getAttribute, className, addEventListener/
// removeEventListener, querySelectorAll (only the `[attr]` / `[attr="value"]`
// shape shell.js issues), and textContent. Shared by test/dom.test.js and
// test/shell.test.js rather than duplicated, since both need the identical
// shim (per the final-review finding covering both files).

class FakeNode {
  constructor() {
    this.childNodes = [];
    this.parentNode = null;
  }
  appendChild(child) {
    this.childNodes.push(child);
    child.parentNode = this;
    return child;
  }
  removeChild(child) {
    const i = this.childNodes.indexOf(child);
    if (i >= 0) this.childNodes.splice(i, 1);
    return child;
  }
  get firstChild() {
    return this.childNodes[0] ?? null;
  }
  get textContent() {
    return this.childNodes.map((c) => c.textContent).join('');
  }
}

class FakeTextNode extends FakeNode {
  constructor(data) {
    super();
    this.nodeType = 'text';
    this.data = String(data);
  }
  get textContent() {
    return this.data;
  }
}

class FakeElement extends FakeNode {
  constructor(tag) {
    super();
    this.nodeType = 'element';
    this.tagName = String(tag).toUpperCase();
    this.attrs = new Map();
    this.className = '';
    this.listeners = new Map();
  }
  setAttribute(name, value) {
    this.attrs.set(name, String(value));
  }
  getAttribute(name) {
    return this.attrs.has(name) ? this.attrs.get(name) : null;
  }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }
  removeEventListener(type, fn) {
    const fns = this.listeners.get(type);
    if (fns) this.listeners.set(type, fns.filter((f) => f !== fn));
  }
  // Test helper only (not a real DOM API) — fires a registered listener.
  dispatch(type, event = {}) {
    for (const fn of this.listeners.get(type) ?? []) fn(event);
  }
  // Supports exactly the selector shapes shell.js issues: `[attr]` and
  // `[attr="value"]`. Anything else throws so a broader use is never
  // silently mismatched.
  querySelectorAll(selector) {
    const m = /^\[([^=\]]+)(?:="([^"]*)")?\]$/.exec(String(selector).trim());
    if (!m) throw new Error(`dom-shim: unsupported selector "${selector}"`);
    const [, attr, value] = m;
    const results = [];
    const walk = (node) => {
      for (const child of node.childNodes) {
        if (child.nodeType === 'element') {
          if (child.attrs.has(attr) && (value === undefined || child.getAttribute(attr) === value)) {
            results.push(child);
          }
          walk(child);
        }
      }
    };
    walk(this);
    return results;
  }
}

export function createDomShim() {
  const document = {
    createElement: (tag) => new FakeElement(tag),
    createTextNode: (data) => new FakeTextNode(data),
  };

  let hashListeners = [];
  const window = {
    location: { hash: '' },
    addEventListener(type, fn) {
      if (type === 'hashchange') hashListeners.push(fn);
    },
    removeEventListener(type, fn) {
      if (type === 'hashchange') hashListeners = hashListeners.filter((f) => f !== fn);
    },
    // Test helper only — simulates the browser firing 'hashchange' (e.g. the
    // user navigating back/forward), invoking every currently-registered
    // listener.
    dispatchHashChange() {
      for (const fn of hashListeners) fn();
    },
    get hashListenerCount() {
      return hashListeners.length;
    },
  };

  return { document, window };
}
