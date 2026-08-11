// Deployment-platform security checklist.
//
// Detects which hosting platform a project targets from config files and
// returns platform-specific security findings: missing headers, public previews,
// no health checks, unsafe infra settings.
//
// Platforms: Vercel, Railway, Fly.io, Netlify, Cloudflare.
// NOT implemented despite being previously listed here: Render, AWS Amplify
// (found via Stage-0 doc audit, 2026 — grepped for any render/amplify config
// path or platform key in this file; zero hits for either).

import * as fs from 'node:fs';
import * as path from 'node:path';

function _readJson(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch { return null; }
}
function _readText(filePath) {
  try { return fs.readFileSync(filePath, 'utf8'); } catch { return null; }
}
function _exists(filePath) {
  try { fs.accessSync(filePath); return true; } catch { return false; }
}

// ── Vercel ────────────────────────────────────────────────────────────────────

function checkVercel(root) {
  const cfgPath = path.join(root, 'vercel.json');
  const cfg = _readJson(cfgPath);
  const findings = [];

  // Check next.config.js / next.config.ts for security headers
  const nextCfgPath = ['next.config.js','next.config.ts','next.config.mjs'].map(f=>path.join(root,f)).find(_exists);
  const nextCfg = nextCfgPath ? _readText(nextCfgPath) : null;

  const hasSecurityHeaders = (cfg && cfg.headers && JSON.stringify(cfg.headers).includes('X-Frame-Options')) ||
    (nextCfg && /X-Frame-Options|Content-Security-Policy|X-Content-Type-Options/.test(nextCfg));

  if (!hasSecurityHeaders) {
    findings.push({
      id: `deploy-platform:VERCEL_NO_SECURITY_HEADERS:${cfgPath || 'vercel.json'}:1`,
      title: 'Vercel deployment missing security headers',
      severity: 'medium',
      file: cfgPath || 'vercel.json',
      line: 1,
      description: 'No X-Frame-Options, Content-Security-Policy, or X-Content-Type-Options headers are configured. These headers block clickjacking, MIME sniffing, and XSS attacks at the CDN layer for zero performance cost.',
      remediation: 'Add a `headers` array to vercel.json or a `headers()` function in next.config.js:\n  { key: "X-Frame-Options", value: "DENY" }\n  { key: "X-Content-Type-Options", value: "nosniff" }\n  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" }',
      cwe: 'CWE-693',
    });
  }

  // Preview deployments expose the app publicly by default
  const hasPasswordProtection = cfg && (cfg.password || (cfg.passwordProtection));
  if (!hasPasswordProtection && _exists(path.join(root, '.vercel'))) {
    findings.push({
      id: `deploy-platform:VERCEL_PUBLIC_PREVIEWS:vercel.json:1`,
      title: 'Vercel preview deployments are publicly accessible',
      severity: 'low',
      file: 'vercel.json',
      line: 1,
      description: 'Preview deployments on Vercel are publicly accessible by default. Staging data, admin interfaces, and unreleased features are visible to anyone with the URL.',
      remediation: 'Enable Vercel\'s Deployment Protection (passwordProtection or Vercel Authentication) for preview branches in your project settings, or add `"protection": { "deploymentType": "all" }` to vercel.json (Vercel Pro).',
      cwe: 'CWE-284',
    });
  }

  return findings;
}

// ── Railway ───────────────────────────────────────────────────────────────────

function checkRailway(root) {
  const cfgPath = path.join(root, 'railway.json');
  const tomlPath = path.join(root, 'railway.toml');
  const cfg = _readJson(cfgPath);
  const tomlRaw = _readText(tomlPath);
  const findings = [];

  const hasHealthCheck = (cfg && (cfg.deploy?.healthcheckPath || cfg.healthcheck)) ||
    (tomlRaw && /healthcheck/.test(tomlRaw));

  if (!hasHealthCheck && (cfg || tomlRaw)) {
    findings.push({
      id: `deploy-platform:RAILWAY_NO_HEALTHCHECK:${cfgPath || tomlPath}:1`,
      title: 'Railway deployment missing health check',
      severity: 'low',
      file: cfgPath || tomlPath || 'railway.json',
      line: 1,
      description: 'No health check endpoint is configured. Without one, Railway cannot detect a crashed or deadlocked process and will continue routing traffic to an unhealthy instance.',
      remediation: 'Add a health check to railway.json:\n  { "deploy": { "healthcheckPath": "/api/health", "healthcheckTimeout": 10 } }\nAnd implement a GET /api/health endpoint that returns 200 when the app is ready.',
      cwe: 'CWE-400',
    });
  }

  return findings;
}

// ── Fly.io ────────────────────────────────────────────────────────────────────

function checkFly(root) {
  const cfgPath = path.join(root, 'fly.toml');
  const raw = _readText(cfgPath);
  if (!raw) return [];
  const findings = [];

  // Check for services exposed without auto_stop_machines
  if (/\[services\]/.test(raw) && !/auto_stop_machines\s*=\s*true/.test(raw)) {
    findings.push({
      id: `deploy-platform:FLY_NO_SCALE_TO_ZERO:fly.toml:1`,
      title: 'Fly.io app keeps machines running indefinitely',
      severity: 'low',
      file: 'fly.toml',
      line: 1,
      description: 'auto_stop_machines is not enabled. Idle machines continue running and accumulating cost, and a compromised idle machine persists longer than necessary.',
      remediation: 'Set `auto_stop_machines = true` and `auto_start_machines = true` in the [http_service] section of fly.toml to enable scale-to-zero.',
      cwe: 'CWE-400',
    });
  }

  // Check for HTTP→HTTPS redirect
  if (!/force_https\s*=\s*true/.test(raw)) {
    findings.push({
      id: `deploy-platform:FLY_NO_HTTPS_REDIRECT:fly.toml:1`,
      title: 'Fly.io app does not enforce HTTPS',
      severity: 'medium',
      file: 'fly.toml',
      line: 1,
      description: 'force_https is not set. HTTP requests are served unencrypted, exposing session cookies and auth tokens to network interception.',
      remediation: 'Add `force_https = true` to the [[services]] section in fly.toml.',
      cwe: 'CWE-319',
    });
  }

  return findings;
}

// ── Netlify ───────────────────────────────────────────────────────────────────

function checkNetlify(root) {
  const cfgPath = path.join(root, 'netlify.toml');
  const raw = _readText(cfgPath);
  if (!raw) return [];
  const findings = [];

  if (!/X-Frame-Options|Content-Security-Policy/.test(raw)) {
    findings.push({
      id: `deploy-platform:NETLIFY_NO_SECURITY_HEADERS:netlify.toml:1`,
      title: 'Netlify deployment missing security headers',
      severity: 'medium',
      file: 'netlify.toml',
      line: 1,
      description: 'No security headers (X-Frame-Options, CSP) are configured in netlify.toml. These are free protections against clickjacking and XSS.',
      remediation: 'Add to netlify.toml:\n  [[headers]]\n    for = "/*"\n    [headers.values]\n      X-Frame-Options = "DENY"\n      X-Content-Type-Options = "nosniff"\n      Referrer-Policy = "strict-origin-when-cross-origin"',
      cwe: 'CWE-693',
    });
  }

  return findings;
}

// ── Cloudflare ────────────────────────────────────────────────────────────────

function checkCloudflare(root) {
  const wranglerPath = ['wrangler.toml','wrangler.json'].map(f=>path.join(root,f)).find(_exists);
  if (!wranglerPath) return [];
  const raw = _readText(wranglerPath);
  const findings = [];

  // Workers with no compatibility_date are using legacy APIs
  if (raw && !/compatibility_date/.test(raw)) {
    findings.push({
      id: `deploy-platform:CF_NO_COMPAT_DATE:${wranglerPath}:1`,
      title: 'Cloudflare Worker missing compatibility_date',
      severity: 'low',
      file: wranglerPath,
      line: 1,
      description: 'Without compatibility_date, your Worker uses Cloudflare\'s oldest runtime behaviour, which may include known-insecure APIs.',
      remediation: `Set compatibility_date = "${new Date().toISOString().slice(0,10)}" in wrangler.toml to opt into the latest, most secure runtime semantics.`,
      cwe: 'CWE-1104',
    });
  }

  return findings;
}

// ── Entry point ───────────────────────────────────────────────────────────────

function scanDeployPlatform(scanRoot) {
  const findings = [];
  if (!scanRoot) return findings;

  const vercelIndicators = ['vercel.json', '.vercel', 'next.config.js', 'next.config.ts', 'next.config.mjs'];
  const railwayIndicators = ['railway.json', 'railway.toml'];
  const flyIndicators = ['fly.toml'];
  const netlifyIndicators = ['netlify.toml'];
  const cfIndicators = ['wrangler.toml', 'wrangler.json'];

  if (vercelIndicators.some(f => _exists(path.join(scanRoot, f)))) findings.push(...checkVercel(scanRoot));
  if (railwayIndicators.some(f => _exists(path.join(scanRoot, f)))) findings.push(...checkRailway(scanRoot));
  if (flyIndicators.some(f => _exists(path.join(scanRoot, f)))) findings.push(...checkFly(scanRoot));
  if (netlifyIndicators.some(f => _exists(path.join(scanRoot, f)))) findings.push(...checkNetlify(scanRoot));
  if (cfIndicators.some(f => _exists(path.join(scanRoot, f)))) findings.push(...checkCloudflare(scanRoot));

  return findings;
}

export { scanDeployPlatform };
