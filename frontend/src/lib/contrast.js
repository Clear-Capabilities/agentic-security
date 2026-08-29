// WCAG 2.x relative-luminance contrast ratio, from first principles
// (https://www.w3.org/TR/WCAG21/#dfn-relative-luminance /
// https://www.w3.org/TR/WCAG21/#dfn-contrast-ratio). No existing contrast
// checker exists anywhere in this repo — this is a small, dependency-free,
// directly-testable implementation rather than a new npm dependency.

function srgbChannelToLinear(c8) {
  const c = c8 / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

function hexToRgb(hex) {
  const m = /^#([0-9a-f]{6})$/i.exec(String(hex));
  if (!m) throw new Error(`hexToRgb: invalid hex color "${hex}" (expected #RRGGBB)`);
  const int = parseInt(m[1], 16);
  return [(int >> 16) & 255, (int >> 8) & 255, int & 255];
}

function relativeLuminance([r, g, b]) {
  const [rl, gl, bl] = [r, g, b].map(srgbChannelToLinear);
  return 0.2126 * rl + 0.7152 * gl + 0.0722 * bl;
}

export function contrastRatio(hexA, hexB) {
  const lumA = relativeLuminance(hexToRgb(hexA));
  const lumB = relativeLuminance(hexToRgb(hexB));
  const lighter = Math.max(lumA, lumB);
  const darker = Math.min(lumA, lumB);
  return (lighter + 0.05) / (darker + 0.05);
}

export function meetsAA(hexA, hexB, { largeText = false } = {}) {
  return contrastRatio(hexA, hexB) >= (largeText ? 3 : 4.5);
}
