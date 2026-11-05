// Adverse history (GA-05, 0.195.27): forge metadata is configured but unavailable.
//
// A GitHub provider is configured through `.agentic-security/provenance-providers.yml` with a base URL on a loopback
// port that nothing listens on, and the fixture has an `origin` remote on github.com so the provider is asked. The
// request fails. The origin commit, its status and its confidence come from local history and must be exactly what
// they are without a provider; the record must say the enrichment was unavailable (a limitation naming the provider
// and the reason) rather than leave `providerEnrichment` null in silence, which before 0.195.27 was indistinguishable
// from "no pull request names this commit".
//
// No request leaves the machine: the base URL is a loopback address and the connection is refused at once.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

const SAFE = 'function h(req) {\n  return 1;\n}\n';
const VULN = 'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n';
const git = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

export const manifest = {
  id: 'provider-unavailable',
  scenario: 'Adverse history: configured provider cannot be reached',
  description: 'PR metadata enrichment is configured but the endpoint is down; the origin is unaffected and the record names the gap.',
  expect: 'commit',
  build(fx) {
    fx.writeFile('server.js', SAFE);
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('server.js', VULN);
    const shaA = fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    git(fx.root, ['remote', 'add', 'origin', 'https://github.com/example/app.git']);
    fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(fx.root, '.agentic-security', 'provenance-providers.yml'), 'github:\n  token: fixture-token\n  baseUrl: http://127.0.0.1:9\n');
    return { commit: shaA };
  },
  verify(fp) {
    if (fp.providerEnrichment !== null && fp.providerEnrichment !== undefined) return 'providerEnrichment should be null when the provider could not be reached';
    const lim = (fp.limitations || []).find((l) => /provider metadata unavailable \(github: /.test(l));
    if (!lim) return `no limitation names the unavailable provider; limitations were ${JSON.stringify(fp.limitations)}`;
    if (fp.confidence.level !== 'high') return `confidence should stay high, got ${fp.confidence.level}`;
    return null;
  },
  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },
};
