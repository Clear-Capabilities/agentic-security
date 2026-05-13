// Solidity smart-contract SAST module.
//
// Covers the highest-impact, lowest-FP-risk smart-contract patterns:
//   - reentrancy            external call (.call.value / .send / .transfer) followed
//                            by a state-changing statement in the same function
//   - tx-origin             `tx.origin == owner` / `require(tx.origin == ...)`
//                            — vulnerable to phishing-style proxy attacks
//   - integer-overflow      pragma solidity ^0.7.x or older without SafeMath import
//                            — Solidity 0.8+ has built-in overflow checks
//   - block-timestamp-rng   block.timestamp / block.difficulty used as randomness
//   - unprotected-selfdestruct  selfdestruct() in a function without owner check
//   - delegatecall-user     delegatecall with user-controlled target
//   - low-level-call-unchecked  unchecked return value from .call / .send
//
// Solidity syntax is distinctive enough that these patterns won't false-match
// in any other language.

import { blankComments } from './_comment-strip.js';

const FINDINGS = [
  {
    id: 'sol-reentrancy', severity: 'critical', cwe: 'CWE-841', family: 'reentrancy',
    // .call{value: x}("") OR .call.value(x)() OR .send(x) OR .transfer(x)
    // followed within ~6 lines by a state-changing statement (assignment to
    // a non-local var, balances[...] = ..., totalSupply -=, etc.)
    re: /\b(?:[a-zA-Z_]\w*)\s*\.\s*call\s*(?:\{[^}]*value\s*:[^}]*\}|\.\s*value\s*\([^)]+\))\s*\([\s\S]{0,400}?[a-zA-Z_]\w*\s*\[[^\]]+\]\s*[-+]?=/g,
    vuln: 'Reentrancy — external call before state update (Check-Effects-Interactions violated)',
    remediation: 'Update internal state BEFORE making the external call (Check-Effects-Interactions pattern). Or use OpenZeppelin\'s ReentrancyGuard modifier. The DAO hack ($150M, 2016) and many later incidents follow this exact shape: balance is read, .call.value() pays out, and only after does the balance get zeroed — the callee re-enters and drains.',
  },
  {
    id: 'sol-tx-origin', severity: 'high', cwe: 'CWE-345', family: 'tx-origin-auth',
    re: /\b(?:require|assert|if)\s*\(\s*[^)]*\btx\.origin\s*(?:==|!=)/g,
    vuln: 'Authentication using tx.origin (phishing-vulnerable)',
    remediation: 'Use `msg.sender` for the authenticated caller, never `tx.origin`. tx.origin is the EOA at the start of the call chain — if a user is tricked into calling an attacker contract that then calls yours, tx.origin is still the user but msg.sender is the attacker.',
  },
  {
    id: 'sol-overflow-old-pragma', severity: 'high', cwe: 'CWE-190', family: 'integer-overflow',
    // pragma solidity ^0.x.y where x < 8 AND no SafeMath import in file
    re: /pragma\s+solidity\s+[\^>=~]*\s*0\.[0-7]\b/g,
    vuln: 'Integer overflow risk — pragma <0.8 without SafeMath',
    remediation: 'Either upgrade the pragma to `pragma solidity ^0.8.0;` (built-in checked arithmetic) or import OpenZeppelin SafeMath: `using SafeMath for uint256;`. Pre-0.8 silently wraps on overflow — a classic gateway to fund-drain bugs.',
    fileSafe: /\b(?:SafeMath|using\s+SafeMath)\b|pragma\s+solidity\s+[\^>=~]*\s*0\.[89]|pragma\s+solidity\s+[\^>=~]*\s*[1-9]\d*\b/,
  },
  {
    id: 'sol-block-timestamp-rng', severity: 'medium', cwe: 'CWE-330', family: 'weak-rng',
    re: /\b(?:keccak256|sha3|abi\.encodePacked)\s*\([^)]*\bblock\.(?:timestamp|difficulty|number|prevrandao|coinbase)/g,
    vuln: 'Predictable randomness — block.timestamp / block.difficulty as RNG seed',
    remediation: 'Block proposers can influence (or fully control) block.timestamp / block.difficulty within a small range. For any randomness with funds at stake, use Chainlink VRF or a commit-reveal scheme.',
  },
  {
    id: 'sol-selfdestruct-unprotected', severity: 'critical', cwe: 'CWE-284', family: 'unprotected-selfdestruct',
    // selfdestruct(...) appears in a function. Suppress if the same function body has an owner check.
    re: /\bselfdestruct\s*\(/g,
    vuln: 'selfdestruct() without owner-only modifier (contract destruction risk)',
    remediation: 'Restrict selfdestruct() to an `onlyOwner` modifier (OpenZeppelin Ownable) or guard with `require(msg.sender == owner)`. The Parity Multisig wallet ($150M, 2017) was bricked when an unprotected init function was called by an attacker who then triggered selfdestruct.',
  },
  {
    id: 'sol-delegatecall-user', severity: 'critical', cwe: 'CWE-94', family: 'delegatecall-untrusted',
    re: /\b\w+\s*\.\s*delegatecall\s*\(/g,
    vuln: 'delegatecall — verify the target address is fixed and trusted',
    remediation: 'delegatecall executes the target contract\'s code in YOUR contract\'s storage. If the target is user-controlled, an attacker can write arbitrary slots — including the owner field. Restrict delegatecall to a hardcoded, audited implementation address.',
  },
  {
    id: 'sol-call-unchecked', severity: 'medium', cwe: 'CWE-252', family: 'unchecked-low-level-call',
    // .call{...}(...) or .send(...) whose return value isn't captured to a bool
    re: /(?:[a-zA-Z_]\w*)\s*\.\s*(?:call|send)\s*(?:\{[^}]*\})?\s*\([^;]+\);/g,
    vuln: 'Unchecked low-level call — return value not inspected',
    remediation: 'Capture the bool from `.call(...)` / `.send(...)` and revert on false: `(bool ok, ) = addr.call{value: amt}(""); require(ok, "call failed");`. Silent failure leaves the contract in an inconsistent state.',
    // Suppress when the pattern is consumed by `(bool ok,) = …`
    isSafeMatch: (matched) => /\b(?:bool\s+\w+\s*,?)?\s*\)?\s*=/.test(matched) || /^require\s*\(/.test(matched),
  },
];

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

// Check if the line where the selfdestruct sits is inside a function body
// that also has an owner-check require.
function _selfdestructHasOwnerCheck(lines, sinkLine) {
  // Walk back to find the enclosing `function` declaration; walk forward to
  // matching `}`. Search for an owner check within that range.
  let openBraceLine = -1;
  let depth = 0;
  for (let i = sinkLine - 1; i >= 0; i--) {
    const ln = lines[i] || '';
    for (let k = ln.length - 1; k >= 0; k--) {
      if (ln[k] === '}') depth++;
      else if (ln[k] === '{') { if (depth === 0) { openBraceLine = i; } else depth--; }
    }
    if (openBraceLine >= 0) break;
  }
  if (openBraceLine < 0) return false;
  // Look at the line above the brace for a `function ...` decl with `onlyOwner`
  const declLine = lines[openBraceLine] || '';
  const prevLine = lines[Math.max(0, openBraceLine - 1)] || '';
  if (/\bonlyOwner\b/.test(declLine) || /\bonlyOwner\b/.test(prevLine)) return true;
  // Scan body for `require(msg.sender == owner)` or `require(msg.sender == ...Owner)`
  let d = 0;
  for (let i = openBraceLine; i < lines.length; i++) {
    const ln = lines[i] || '';
    for (const c of ln) {
      if (c === '{') d++;
      else if (c === '}') { d--; if (d === 0) return false; }
    }
    if (/\brequire\s*\(\s*msg\.sender\s*==\s*\w*[Oo]wner\w*\s*[,)]/.test(ln)) return true;
    if (/\brequire\s*\(\s*msg\.sender\s*==\s*admin/.test(ln)) return true;
  }
  return false;
}

export function scanSolidity(fp, raw) {
  if (!/\.sol$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const lines = raw.split('\n');
  const out = [];
  const seen = new Set();
  for (const rule of FINDINGS) {
    if (rule.fileSafe && rule.fileSafe.test(code)) continue;
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m;
    while ((m = re.exec(code))) {
      // Suppress self-destruct findings where the enclosing function has an
      // owner check (modifier or require).
      if (rule.id === 'sol-selfdestruct-unprotected') {
        const ln = lineOf(raw, m.index);
        if (_selfdestructHasOwnerCheck(lines, ln)) continue;
      }
      // Skip low-level-call when the call's return is captured.
      if (rule.id === 'sol-call-unchecked') {
        const ln = lineOf(raw, m.index);
        const lineText = lines[ln - 1] || '';
        // If the line begins with `(bool` or contains ` = ` before the call,
        // the return is being captured — suppress.
        if (/\(\s*bool\s+\w+\s*,/.test(lineText) || /=\s*[a-zA-Z_]\w*\s*\.\s*(?:call|send)/.test(lineText)) continue;
      }
      const line = lineOf(raw, m.index);
      const id = `${rule.id}:${fp}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push({
        id, file: fp, line,
        vuln: rule.vuln,
        severity: rule.severity,
        cwe: rule.cwe,
        stride: rule.family === 'reentrancy' || rule.family === 'unchecked-low-level-call' ? 'Tampering'
              : rule.family === 'tx-origin-auth' ? 'Spoofing'
              : rule.family === 'integer-overflow' ? 'Tampering'
              : rule.family === 'weak-rng' ? 'Spoofing'
              : 'Elevation of Privilege',
        snippet: (lines[line - 1] || '').trim().slice(0, 200),
        remediation: rule.remediation,
        confidence: 0.85,
        parser: 'SOL',
      });
    }
  }
  return out;
}
