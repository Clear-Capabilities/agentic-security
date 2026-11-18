// The id comes from the clicked node and is written into the panel as markup.
export function showPanel(node, panel) {
  const id = node.dataset.id;
  const label = 'Item ' + id;
  panel.innerHTML = label;
}
