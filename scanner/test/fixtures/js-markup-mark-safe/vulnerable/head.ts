import { markHTMLString } from './html';

export function preloadLink(result: { head: string[] }, href: string) {
  result.head.push(markHTMLString(`<link rel="preload" href="${href}">`));
}

export function themeStyle(result: { head: string[] }, sheet: { toString(): string }) {
  const css = sheet.toString();
  result.head.push(markHTMLString(`<style>${css}</style>`));
}

export function bootData(meta: Record<string, unknown>) {
  const children = `window.__boot_data__ = ${JSON.stringify(meta)}`;
  return { children };
}
