// Section 9.3 performance measurement: a mixed Haskell/Nix source fixture, cold and warm static scans with wall time and peak
// resident memory, and a 10-file incremental change. Deterministic fixture, no network, no model, no compiler.
//
//   node bench/language-support/perf.mjs [--out results/perf.json] [--files 2000] [--mib 20]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO } from './lib.mjs';

const CLI = path.join(REPO, 'scanner', 'bin', 'agentic-security.js');

/** A deterministic mixed fixture: `n` files totalling about `bytes`, half Haskell with realistic function density and half NixOS modules. */
export function generateFixture(root, n = 2000, bytes = 20 * 1024 * 1024) {
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  const perFile = Math.floor(bytes / n);
  let total = 0;
  for (let i = 0; i < n; i++) {
    const hs = i % 2 === 0;
    const dir = path.join(root, hs ? 'hs' : 'nix', `d${i % 40}`);
    fs.mkdirSync(dir, { recursive: true });
    let body;
    if (hs) {
      body = `module M${i} where\nimport System.Process (callCommand)\nimport qualified Data.Map as Map\n\n`;
      for (let k = 0; body.length < perFile; k++) {
        body += `-- | Compute the ${k}th adjusted total for an account.\n-- The rules follow the billing policy described in the design notes;\n-- adjustments are applied before rounding.\nadjust${k} :: Int -> Int -> Either String Int\nadjust${k} base rate\n  | base < 0 = Left "negative base"\n  | rate > 100 = Left "rate out of range"\n  | otherwise =\n      let scaled = base * rate\n          rounded = (scaled + 50) \`div\` 100\n      in Right (rounded + ${k})\n\n-- | Render the ${k}th status line.\nrender${k} :: String -> Int -> String\nrender${k} name n = case n of\n  0 -> name ++ ": none"\n  1 -> name ++ ": one"\n  _ -> name ++ ": " ++ show n ++ " items"\n\n`;
      }
      if (i % 50 === 0) body += 'danger :: String -> IO ()\ndanger n = callCommand ("echo " ++ n)\n';
      fs.writeFileSync(path.join(dir, `M${i}.hs`), body);
    } else {
      body = '{ config, lib, pkgs, ... }:\n{\n';
      for (let k = 0; body.length < perFile; k++) body += `  environment.etc."cfg${i}-${k}".text = "value ${k} ${'x'.repeat(40)}";\n  systemd.services.svc${i}x${k}.description = "service ${k}";\n`;
      if (i % 50 === 1) body += '  services.openssh.enable = true;\n  services.openssh.settings.PermitRootLogin = "yes";\n';
      body += '}\n';
      fs.writeFileSync(path.join(dir, `mod${i}.nix`), body);
    }
    total += body.length;
  }
  return { files: n, bytes: total };
}

const parseRss = (stderr) => {
  const mac = /^\s*(\d+)\s+maximum resident set size/m.exec(stderr);
  if (mac) return Number(mac[1]);
  const lin = /Maximum resident set size \(kbytes\):\s*(\d+)/.exec(stderr);
  return lin ? Number(lin[1]) * 1024 : null;
};

/** One CLI scan under /usr/bin/time: {ms, rssBytes, exit}. Peak RSS of the scan process (the scanner starts no child analyser). */
// The PRD's reference profile is a 4-core, 8 GiB machine, where V8 sizes its old-generation limit near 2 GiB by itself. On a larger host
// the same scan is allowed to let the heap grow (measured 1.7 to 2.6 GiB of peak RSS, mostly collectable garbage), so a measurement taken
// there says nothing about the reference profile. The scan is therefore measured under an explicit heap limit standing in for that
// profile, and the limit is recorded in the result. It is not applied to a user's scan.
export const REFERENCE_HEAP_LIMIT_MIB = 1792;
const withHeapLimit = (env) => ({ ...env, NODE_OPTIONS: `${env.NODE_OPTIONS || process.env.NODE_OPTIONS || ''} --max-old-space-size=${REFERENCE_HEAP_LIMIT_MIB}`.trim() });

export function timedScan(root, extra = [], env = {}) {
  env = withHeapLimit(env);
  const timeBin = fs.existsSync('/usr/bin/time') ? '/usr/bin/time' : null;
  const args = [CLI, 'scan', root, '--format', 'json', ...extra];
  const t0 = process.hrtime.bigint();
  const r = timeBin
    ? spawnSync(timeBin, [process.platform === 'darwin' ? '-l' : '-v', process.execPath, ...args], { encoding: 'utf8', maxBuffer: 1 << 28, env: { ...process.env, NO_COLOR: '1', ...env } })
    : spawnSync(process.execPath, args, { encoding: 'utf8', maxBuffer: 1 << 28, env: { ...process.env, NO_COLOR: '1', ...env } });
  const ms = Number((process.hrtime.bigint() - t0) / 1_000_000n);
  return { ms, rssBytes: timeBin ? parseRss(r.stderr) : null, exit: r.status };
}

export const p95 = (xs) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.ceil(0.95 * s.length) - 1)]; };

export function profile() {
  return { platform: process.platform, arch: process.arch, logicalCpus: os.cpus().length, memoryGiB: Math.round(os.totalmem() / 1073741824), node: process.version, heapLimitMiB: REFERENCE_HEAP_LIMIT_MIB, referenceProfile: { cores: 4, memoryGiB: 8, os: 'Linux/NixOS', note: 'the PRD reference; any other host is an operational profile' } };
}

/** Three cold and three warm scans plus a 10-file incremental change in a git checkout of the same fixture. */
export function measureAll(root, { n = 2000, bytes = 20 * 1024 * 1024 } = {}) {
  const gen = generateFixture(root, n, bytes);
  const cold = []; const warm = [];
  for (let i = 0; i < 3; i++) { fs.rmSync(path.join(root, '.agentic-security'), { recursive: true, force: true }); cold.push(timedScan(root)); }
  for (let i = 0; i < 3; i++) warm.push(timedScan(root));
  // incremental: commit, change 10 files, scan only what changed since HEAD
  const git = (a) => spawnSync('git', a, { cwd: root, encoding: 'utf8' });
  git(['init', '-q']); git(['-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '-A']); git(['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'base']);
  for (let i = 0; i < 10; i++) { const f = path.join(root, 'hs', `d${(i * 2) % 40}`, `M${i * 2}.hs`); fs.appendFileSync(f, `\nextra${i} :: Int\nextra${i} = ${i}\n`); }
  const incremental = timedScan(root, ['--changed-since', 'HEAD']);
  return { fixture: gen, cold, warm, incremental, coldMaxMs: Math.max(...cold.map((x) => x.ms)), coldP95Ms: p95(cold.map((x) => x.ms)), warmP95Ms: p95(warm.map((x) => x.ms)), peakRssBytes: Math.max(...[...cold, ...warm, incremental].map((x) => x.rssBytes || 0)) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d; };
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'perf-'));
  try {
    const r = measureAll(root, { n: Number(arg('files', 2000)), bytes: Number(arg('mib', 20)) * 1024 * 1024 });
    const out = { schema: 'agentic-security/language-support-perf@1', measuredAt: new Date().toISOString().slice(0, 10), profile: profile(), ...r };
    const body = `${JSON.stringify(out, null, 2)}\n`;
    const dest = arg('out', null);
    if (dest) fs.writeFileSync(dest, body); else process.stdout.write(body);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
