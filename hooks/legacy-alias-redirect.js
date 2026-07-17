#!/usr/bin/env node
// UserPromptSubmit hook: the v0.86.0 consolidation removed 44 single-purpose
// slash-command aliases in favour of 12 dispatchers. Users with muscle memory
// for `/status`, `/show-findings`, `/harden`, etc. would otherwise type a
// command that no longer resolves to anything. This hook detects a removed
// alias at the start of the prompt and injects context telling Claude the
// new dispatcher mode to run instead — turning the breaking change into a
// guided, one-step migration.
//
// Output: a UserPromptSubmit `additionalContext` block per the Claude Code
// hook spec. The hook is stateless, fast, and degrades to a silent no-op for
// any prompt that is not a removed alias.
'use strict';

// Removed alias  ->  dispatcher mode that now carries the capability.
const ALIAS_MAP = {
  'ai-bodyguard':        '/setup --bodyguard',
  'archaeology':         '/scan --archaeology',
  'audit':               '/compliance --audit',
  'auditor-walkthrough': '/compliance --walkthrough',
  'ci':                  '/setup --ci',
  'claude-vuln-audit':   '/labs --claude-audit',
  'compliance-fix':      '/fix --compliance',
  'compliance-report':   '/compliance --report',
  'cross-repo-recall':   '/labs --cross-repo',
  'cve-alerts':          '/supply --cve-alerts',
  'daily-checkin':       '/secure --daily',
  'destructive-guard':   '/setup --destructive-guard',
  'explain':             '/triage --explain',
  'exploit-builder':     '/triage --exploit',
  'generate':            '/fix --generate',
  'harden':              '/fix --harden',
  'harness-score':       '/posture --harness',
  'help':                '/secure --help',
  'install-hooks':       '/setup --hooks',
  'llm':                 '/labs --llm',
  'model-rescan':        '/labs --model-rescan',
  'posture-management':  '/posture --mgmt',
  'pr-augment':          '/compliance --pr',
  'query':               '/triage --query',
  'red-team':            '/triage --red-team',
  'report-card':         '/posture --report-card',
  'risk-dollars':        '/labs --risk-dollars',
  'rotate-secret':       '/fix --rotate-secret',
  'sbom-explore':        '/supply --sbom',
  'scanner':             '/scan --scanner-meta',
  'security-attestation':'/compliance --attestation',
  'security-trend':      '/posture --trend',
  'setup-ci':            '/setup --ci',
  'show-findings':       '/triage --show',
  'stack-playbook':      '/posture --playbook',
  'status':              '/posture --status',
  'supply-chain-check':  '/supply --check',
  'synthesize-rule':     '/labs --synthesize-rule',
  'three-agent-review':  '/triage --deep',
  'threat':              '/posture --threat',
  'time-to-fix':         '/labs --time-to-fix',
  'trim':                '/fix --trim',
  'tutorial':            '/secure --tour',
  'validate-findings':   '/triage --validate',
  'vault-wizard':        '/fix --vault',
  'watch':               '/scan --watch',
};

// Given a raw prompt string, return { alias, replacement, rest } if it begins
// with a removed alias slash-command, else null. Handles the optional
// `agentic-security:` plugin namespace and trailing arguments.
function resolveAlias(prompt) {
  if (typeof prompt !== 'string') return null;
  const trimmed = prompt.trim();
  if (!trimmed.startsWith('/')) return null;
  // First whitespace-delimited token, minus the leading slash + optional ns.
  const firstSpace = trimmed.search(/\s/);
  const head = (firstSpace === -1 ? trimmed : trimmed.slice(0, firstSpace)).slice(1);
  const rest = firstSpace === -1 ? '' : trimmed.slice(firstSpace + 1).trim();
  const name = head.replace(/^agentic-security:/, '');
  const replacement = ALIAS_MAP[name];
  if (!replacement) return null;
  return { alias: name, replacement, rest };
}

function buildContext({ alias, replacement, rest }) {
  const full = rest ? `${replacement} ${rest}` : replacement;
  return [
    `The user typed \`/${alias}\`, which is a legacy alias consolidated into a `,
    `dispatcher command. Its capability now lives at \`${replacement}\`. `,
    `Run \`${full}\` to fulfil the request, and mention the new path once so `,
    `the user learns it (e.g. "\`/${alias}\` is now \`${replacement}\`").`,
  ].join('');
}

function readStdinJSON() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    // Never hang the prompt submit if stdin is empty.
    setTimeout(() => resolve({}), 500).unref?.();
  });
}

async function main() {
  const input = await readStdinJSON();
  const hit = resolveAlias(input.prompt || '');
  if (!hit) process.exit(0);
  const out = {
    hookSpecificOutput: {
      hookEventName: 'UserPromptSubmit',
      additionalContext: buildContext(hit),
    },
  };
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
}

if (require.main === module) {
  main();
}

module.exports = { ALIAS_MAP, resolveAlias, buildContext };
