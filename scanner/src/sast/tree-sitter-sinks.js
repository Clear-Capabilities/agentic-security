// Tree-sitter-backed sinks for long-tail languages (roadmap #8).
//
// First AST-accurate detector for a language that has no first-class IR parser.
// Gated behind AGENTIC_SECURITY_TREE_SITTER=1 and the optional tree-sitter
// dependency; when either is absent it degrades to a no-op (the existing
// pattern detectors still run). Anchoring on real AST nodes (not regex over
// raw text) means comments and string literals can't produce false matches.
//
// Rust shell-spawn command injection: a `std::process::Command` that launches a
// shell (sh/bash/cmd/powershell) with -c / -Command AND a non-literal argument.
// That is the classic "build a shell string from input" injection; spawning a
// program directly (no shell) is not flagged.

import { getParserFor, treeSitterLangOf, walkNamed } from '../ir/tree-sitter-loader.js';

const SHELL_PROG = /Command::new\s*\(\s*[bB]?"(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?)"/;
const SHELL_FLAG = /\.args?\s*\(\s*\[?\s*[bB]?"(?:-c|\/c|\/C|-Command)"/;
// An .arg()/.args() whose argument does NOT start with a string literal → dynamic.
const DYNAMIC_ARG = /\.args?\s*\(\s*(?![bB]?["[])[A-Za-z_&*([]/;

export async function scanTreeSitterRust(fp, raw) {
  if (process.env.AGENTIC_SECURITY_TREE_SITTER !== '1') return [];
  if (treeSitterLangOf(fp) !== 'rust') return [];
  if (!raw || raw.length > 500_000) return [];
  if (!/Command::new/.test(raw)) return [];           // cheap pre-filter

  const parser = await getParserFor('rust');
  if (!parser) return [];                              // optional dep absent → degrade
  let tree;
  try { tree = parser.parse(raw); } catch { return []; }

  const findings = [];
  const seen = new Set();
  walkNamed(tree.rootNode, (n) => {
    if (n.type !== 'call_expression') return;
    const text = n.text;
    if (!SHELL_PROG.test(text) || !SHELL_FLAG.test(text) || !DYNAMIC_ARG.test(text)) return;
    const line = n.startPosition.row + 1;
    if (seen.has(line)) return;
    seen.add(line);
    findings.push({
      id: `ts-rust-cmdi:${fp}:${line}`,
      severity: 'high', file: fp, line,
      vuln: 'Command injection (Rust shell spawn with dynamic argument)',
      cwe: 'CWE-78', family: 'command-injection', parser: 'TREE-SITTER', confidence: 0.55,
      description: 'A std::process::Command spawns a shell (sh/bash/cmd/powershell) with -c/-Command and a non-literal argument. If that argument is attacker-influenced this is command injection.',
      remediation: 'Do not pass input to a shell. Invoke the program directly — Command::new(prog).arg(userArg) without a shell — and validate inputs.',
    });
  });
  return findings;
}

// Convenience: run every tree-sitter sink detector over a file-content map.
export async function scanTreeSitterSinks(fileContents) {
  if (process.env.AGENTIC_SECURITY_TREE_SITTER !== '1') return [];
  const out = [];
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (typeof c !== 'string') continue;
    try { out.push(...await scanTreeSitterRust(fp, c)); } catch { /* never fail the scan */ }
  }
  return out;
}
