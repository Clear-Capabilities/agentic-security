// Shared opt-in config resolution for provider enrichment (Finding
// Provenance PRD, M3 §3.4). Strictly opt-in: with neither an env var nor a
// config file present, resolveProviderConfig returns null and NEITHER
// providers/github.js nor providers/gitlab.js makes any network call —
// this is the property provenance-providers.test.js's hermeticity test
// proves. Modeled on llm-validator/index.js's existing
// AGENTIC_SECURITY_LLM_ENDPOINT precedent (opt-in via env var, degrades to
// a no-op when unset) rather than inventing a new convention.
import * as fs from 'node:fs';
import { statePath } from '../../state-dir.js';
import { load as loadYaml } from '../../../util/yaml.js';

const ENV_VAR_BY_PROVIDER = { github: 'AGENTIC_SECURITY_GITHUB_TOKEN', gitlab: 'AGENTIC_SECURITY_GITLAB_TOKEN' };

/**
 * `provider` is 'github' | 'gitlab'. Returns {token, baseUrl} or null.
 * Env var wins if both are present — the same "explicit beats inferred"
 * precedent config-resolution follows elsewhere in this codebase (e.g.
 * state-dir.js's caller-supplied-scanRoot-wins-over-cwd-walk).
 */
export function resolveProviderConfig(scanRoot, provider) {
  const envVar = ENV_VAR_BY_PROVIDER[provider];
  const envToken = envVar ? process.env[envVar] : undefined;
  if (envToken) return { token: envToken, baseUrl: null };

  // .agentic-security/provenance-providers.yml — NOT gated behind
  // stateWritesEnabled()/isSafeStateDir() the way STATE WRITES are; this is
  // a READ of an operator-authored config file, the same class of read
  // rules.yml already performs unconditionally.
  const configPath = statePath(scanRoot, 'provenance-providers.yml');
  let text;
  try { text = fs.readFileSync(configPath, 'utf8'); } catch { return null; }
  let doc;
  try { doc = loadYaml(text); } catch { return null; }
  if (!doc || typeof doc !== 'object') return null;
  const entry = doc[provider];
  if (!entry || !entry.token) return null;
  return { token: entry.token, baseUrl: entry.baseUrl || null };
}
