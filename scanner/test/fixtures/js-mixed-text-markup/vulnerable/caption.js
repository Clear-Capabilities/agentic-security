// Reads a caption element back into an HTML string, one child node at a time.
export function captionHtml(caption) {
  let html = '';
  for (const child of caption.childNodes) {
    html += child.nodeType === Node.TEXT_NODE ? child.textContent : child.outerHTML;
  }
  return html;
}

export function captionParts(caption) {
  const parts = [];
  caption.childNodes.forEach((child) => {
    if (child.nodeType === 3) {
      parts.push(child.nodeValue);
    } else {
      parts.push(child.outerHTML);
    }
  });
  return parts.join('');
}
