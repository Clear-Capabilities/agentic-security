// Parser for the TAP stream `node --test --test-reporter=tap` emits. The verifier
// trusts only parsed per-test results, never a reporter's final summary alone.
const LINE = /^(\s*)(not ok|ok) (\d+)(?: - (.*))?$/;

export function parseTap(text) {
  const tests = [];
  const summary = {};
  for (const raw of text.split('\n')) {
    const m = LINE.exec(raw);
    if (m) {
      let name = (m[4] ?? '').trim();
      let skip = false, todo = false;
      const dir = / # (SKIP|TODO)\b.*$/i.exec(name);
      if (dir) { if (dir[1].toUpperCase() === 'SKIP') skip = true; else todo = true; name = name.slice(0, dir.index).trim(); }
      tests.push({ name, ok: m[2] === 'ok', skip, todo, depth: Math.floor(m[1].length / 4) });
      continue;
    }
    const s = /^# (tests|suites|pass|fail|cancelled|skipped|todo) (\d+)\s*$/.exec(raw);
    if (s) summary[s[1]] = +s[2];
  }
  return { tests, summary };
}
