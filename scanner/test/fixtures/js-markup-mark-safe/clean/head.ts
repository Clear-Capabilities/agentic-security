import { markHTMLString, escapeAttr, escapeCss, serializeForScript } from './html';

export function preloadLink(result: { head: string[] }, href: string) {
  result.head.push(markHTMLString(`<link rel="preload" href="${escapeAttr(href)}">`));
}

export function themeStyle(result: { head: string[] }, sheet: { toString(): string }) {
  const css = escapeCss(sheet.toString());
  result.head.push(markHTMLString(`<style>${css}</style>`));
}

export function closeTag(name: string) {
  return markHTMLString(`</${name}>`);
}

export function bootData(meta: Record<string, unknown>) {
  const children = `window.__boot_data__ = ${serializeForScript(meta)}`;
  return { children };
}
