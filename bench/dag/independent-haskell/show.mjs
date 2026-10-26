import fs from 'node:fs';
const [, , f, from, to, ctx = 6] = process.argv;
const s = JSON.parse(fs.readFileSync(f, 'utf8'));
for (let i = +from; i < Math.min(+to, s.length); i++) {
  const x = s[i]; const L = fs.readFileSync(`.cache/${x.project}/${x.file}`, 'utf8').split('\n');
  console.log(`\n##### [${i}] ${x.project}/${x.file}:${x.line} | ${x.vuln} | ${x.severity}`);
  for (let k = Math.max(1, x.line - ctx); k <= Math.min(L.length, x.line + +ctx); k++) console.log((k === x.line ? '>>' : '  ') + k + ': ' + L[k - 1].slice(0, 150));
}
