// Reads a caption element back into an HTML string through markup only, or escapes the text arm.
const escapeHtml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export function captionHtml(caption) {
  const wrapper = document.createElement('div');
  for (const child of caption.childNodes) wrapper.appendChild(child.cloneNode(true));
  return wrapper.innerHTML;
}

export function captionParts(caption) {
  let html = '';
  for (const child of caption.childNodes) {
    html += child.nodeType === 3 ? escapeHtml(child.textContent) : child.outerHTML;
  }
  return html;
}

export function captionText(caption) {
  // text only: no markup is mixed in
  return [...caption.childNodes].map((c) => (c.nodeType === 3 ? c.textContent : c.innerText)).join('');
}
