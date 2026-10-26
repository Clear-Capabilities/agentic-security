// Seeded random sample of flagged sites per language (mulberry32, seed fixed before any labeling).
// Usage: node sample.mjs <flagged.json> <language> <n>
import fs from 'node:fs';
const [, , file, lang, n] = process.argv;
let a = 20261026 >>> 0;
const rnd = () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const all = JSON.parse(fs.readFileSync(file, 'utf8')).filter(s => s.language === lang);
const idx = all.map((_, i) => i);
for (let i = idx.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [idx[i], idx[j]] = [idx[j], idx[i]]; }
const pick = idx.slice(0, +n).sort((x, y) => x - y).map(i => all[i]);
fs.writeFileSync(`sample-${lang}.json`, JSON.stringify(pick, null, 1));
console.log(pick.length);
