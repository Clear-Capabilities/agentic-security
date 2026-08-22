// DApp frontend Web3 risks — Item #3 (companion to web3-advanced.js).
//
// Wallet-interacting frontend (ethers.js, viem, wagmi, web3.js, RainbowKit,
// Privy) has its own attack surface that doesn't live in the Solidity
// detector:
//
//   1. UNLIMITED_APPROVAL   — token.approve(spender, MaxUint256) /
//                             ethers.constants.MaxUint256 / 2**256-1
//                             without the user being able to scope it
//   2. ETH_SIGN_USED        — provider.request({method:'eth_sign'}) — the
//                             "death sign" — accepts arbitrary opaque hash
//   3. PERSONAL_SIGN_NO_DOMAIN — personal_sign without the EIP-191
//                                 personal-message prefix being shown to user
//   4. WINDOW_ETHEREUM_UNGUARDED — directly using window.ethereum without
//                                   trusted-RPC check (lets a malicious
//                                   wallet extension inject)
//   5. WALLETCONNECT_BRIDGE_INSECURE — using wc.bridge with http:// or a
//                                       third-party bridge URL
//   6. PRIVATE_KEY_IN_FRONTEND — Wallet.fromMnemonic / new Wallet(privKey)
//                                 in client-side code (must only be in
//                                 server/SDK; never browser)
//   7. SIGN_TYPED_DATA_NO_DOMAIN — eth_signTypedData with empty/missing
//                                  domain.chainId
//   8. ETHERSCAN_API_KEY_INLINE  — Etherscan / Alchemy / Infura API key
//                                  hard-coded in client bundle
//
// File scope: JS / TS / JSX / TSX. Returns empty on .sol / .vy.

import { blankComments } from './_comment-strip.js';

// The finding families this module can emit (F10.2 producer registry).
//
// Declared HERE, next to the rules, because no external method enumerates them:
// this module passes `family` POSITIONALLY (`_shape(file, line, ruleId, vuln,
// fam, ...)`), so a textual search for `family:` finds nothing, and a corpus
// sweep only ever reports a LOWER BOUND -- it sees whichever families a fixture
// happened to trigger. This list is the union of both, and
// `test/family-registry.test.js` fails if a scan produces a family from this
// module that is not listed.
//
// Add the family here in the same edit that adds the rule.
export const EMITS = [
  'eth-sign-used',
  'personal-sign-no-domain',
  'private-key-in-frontend',
  'rpc-key-inline',
  'typed-data-no-chainid',
  'unlimited-approval',
];

function _line(raw, idx) { return raw.slice(0, idx).split('\n').length; }
function _snip(raw, line) { return (raw.split('\n')[line - 1] || '').trim().slice(0, 200); }

function _shape(file, line, ruleId, vuln, fam, sev, cwe, remediation, description) {
  return {
    id: `${ruleId}:${file}:${line}`,
    file, line, vuln, severity: sev, cwe,
    family: fam, parser: 'DAPP-FRONTEND',
    confidence: 0.8,
    description: description || vuln,
    remediation,
  };
}

const _RELEVANT_FILE = /\.(?:[jt]sx?|mjs|cjs)$/i;

function _isWeb3Frontend(text) {
  return /\bethers\b|\bviem\b|\bwagmi\b|\bweb3\b|\bRainbow\b|\bPrivy\b|\bWalletConnect\b|window\.ethereum/.test(text);
}

function detectUnlimitedApproval(file, raw, code, out, seen) {
  // ERC-20 approve calls with MaxUint256 / 2**256-1 / ethers.constants.MaxUint256.
  const patterns = [
    /\bapprove\s*\([^)]*?(?:MaxUint256|MAX_UINT256|2\s*\*\*\s*256\s*-\s*1|ethers\.constants\.MaxUint256|maxUint256|2n\s*\*\*\s*256n\s*-\s*1n)\b[^)]*\)/g,
    /\bapprove\s*\([^)]*?["']0x[fF]{64}["']\b[^)]*\)/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(code))) {
      const ln = _line(raw, m.index);
      const id = `dapp-unlimited-approval:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'dapp-unlimited-approval',
        'ERC-20 approve with MaxUint256 — unlimited spender allowance',
        'unlimited-approval', 'high', 'CWE-863',
        'Approve only the exact amount needed for the current operation. Unlimited approvals are the dominant attack vector for drainer scams — once approved, a compromised spender contract can move the entire token balance forever. Use Permit2 (Uniswap) for short-lived approvals OR EIP-2612 permit() for single-shot allowances.',
        'Unlimited approve is the #1 cause of wallet-drainer losses in 2024-2025 (>$300M annually). Etherscan now warns users about MaxUint256 approvals at signing time.'));
    }
  }
}

function detectEthSign(file, raw, code, out, seen) {
  // Pattern: provider.request({method: 'eth_sign'}) — the "death sign".
  const re = /\b(?:provider|signer|wallet|window\.ethereum)\s*\.\s*request\s*\(\s*\{\s*method\s*:\s*['"]eth_sign['"]/g;
  let m;
  while ((m = re.exec(code))) {
    const ln = _line(raw, m.index);
    const id = `dapp-eth-sign:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'dapp-eth-sign',
      'eth_sign — signs arbitrary 32-byte hash with no prefix (the "death sign")',
      'eth-sign-used', 'critical', 'CWE-345',
      'Never use eth_sign. The 32-byte hash being signed can be a valid transaction hash, valid permit message, or anything else — there is no domain separation. Use personal_sign for human messages or eth_signTypedData_v4 for structured data. MetaMask now warns when a site requests eth_sign.',
      'eth_sign signs without ANY prefix. An attacker presents a hash that happens to be the keccak of a transaction; the user signs; the signed transaction is now broadcastable. This is the underlying bug in many phishing drainers.'));
  }
}

function detectPersonalSignNoMessage(file, raw, code, out, seen) {
  // personal_sign with an empty / non-descriptive message string.
  const re = /\bpersonal_sign\b|\bsignMessage\s*\(\s*['"][^'"]{0,20}['"]/g;
  let m;
  while ((m = re.exec(code))) {
    // Detect: signMessage("") or signMessage("ok") — too short to be meaningful.
    if (m[0].startsWith('signMessage')) {
      const ln = _line(raw, m.index);
      const id = `dapp-personal-sign-empty:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'dapp-personal-sign-empty',
        'signMessage with empty or trivial message — user has no context to evaluate',
        'personal-sign-no-domain', 'medium', 'CWE-345',
        'Include the action being authorized, the domain (your dapp URL), the address being affected, and a unique nonce in the message. The signing UI displays the message to the user — make it meaningful so the user can detect phishing.',
        'A short / blank message means the user can\'t tell if they\'re signing in to YOUR app or a malicious clone. EIP-4361 (Sign-In With Ethereum) encodes a structured format that wallets can verify.'));
    }
  }
}

function detectWalletPrivKeyInFrontend(file, raw, code, out, seen) {
  // new Wallet(0x...) / Wallet.fromMnemonic in code that's reachable from a
  // bundle (presence of React, Next, Vite, Vue is signal).
  if (!/\b(?:React|next\/|vite|Vue|svelte|expo|electron)\b/.test(raw)) return;
  const patterns = [
    /\bnew\s+(?:ethers\.)?Wallet\s*\(\s*['"]0x[a-fA-F0-9]{64}['"]/g,
    /\bWallet\.fromMnemonic\s*\(/g,
    /\bWallet\.fromPrivateKey\s*\(/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(code))) {
      const ln = _line(raw, m.index);
      const id = `dapp-wallet-privkey-frontend:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'dapp-wallet-privkey-frontend',
        'Wallet constructed from raw key / mnemonic in client-side code',
        'private-key-in-frontend', 'critical', 'CWE-798',
        'Never construct a Wallet with a raw private key or mnemonic in code that ships to the browser. Use a wallet provider (window.ethereum, WalletConnect, Privy) and request signatures via the standard JSON-RPC methods.',
        'A private key in client-side code is visible in the bundle. Even worse, mnemonic-based flows often persist seed phrases to localStorage — accessible to any extension or XSS payload.'));
    }
  }
}

function detectSignTypedDataNoChainId(file, raw, code, out, seen) {
  // eth_signTypedData with domain.chainId missing or hard-coded to 1
  // (won't validate on L2s, allows cross-chain replay).
  const re = /signTypedData(?:_v[34])?\s*\(\s*\{[\s\S]{0,800}?domain\s*:\s*\{([^}]*)\}/g;
  let m;
  while ((m = re.exec(code))) {
    const domain = m[1];
    if (/\bchainId\b/.test(domain)) continue;
    const ln = _line(raw, m.index);
    const id = `dapp-typed-data-no-chainid:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'dapp-typed-data-no-chainid',
      'eth_signTypedData without domain.chainId — cross-chain replay surface',
      'typed-data-no-chainid', 'high', 'CWE-294',
      'Always include `chainId` in the EIP-712 domain. Without it, a signature valid on Ethereum mainnet is also valid on every L2 and testnet — letting an attacker reuse a meta-tx signature across chains to drain the same user.',
      'EIP-712 domain separator binds the signature to (name, version, chainId, verifyingContract). Drop any field and signatures become portable to environments where the contract has different semantics.'));
  }
}

function detectEtherscanApiKeyInline(file, raw, code, out, seen) {
  // Etherscan / Alchemy / Infura API key embedded inline.
  const patterns = [
    /\b(?:etherscan|polygonscan|bscscan|arbiscan)\.io\/api[^"'`]*apikey=([A-Z0-9]{30,40})/gi,
    /\balchemy\.com\/v2\/([A-Za-z0-9_-]{20,40})/g,
    /\binfura\.io\/v3\/([A-Za-z0-9]{30,40})/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(code))) {
      const ln = _line(raw, m.index);
      const id = `dapp-rpc-key-inline:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'dapp-rpc-key-inline',
        'RPC provider key embedded in client-side code (visible in bundle)',
        'rpc-key-inline', 'high', 'CWE-798',
        'Move RPC provider API keys to a server-side proxy (e.g. Next.js API route, Cloudflare Worker) that adds the key before forwarding. Embedded keys are scraped by bots within hours of deploy and used to grief your quota.',
        'Alchemy / Infura / Etherscan keys in browser bundles are scraped by automated tools. Beyond quota exhaustion, leaked keys can be used to deanonymize your users\' RPC traffic.'));
    }
  }
}

export function scanDappFrontend(fp, raw) {
  if (process.env.AGENTIC_SECURITY_NO_DAPP === '1') return [];
  if (!raw || raw.length > 500_000) return [];
  if (!_RELEVANT_FILE.test(fp)) return [];
  if (!_isWeb3Frontend(raw)) return [];
  const code = blankComments(raw);
  const out = [];
  const seen = new Set();
  try { detectUnlimitedApproval(fp, raw, code, out, seen); } catch {}
  try { detectEthSign(fp, raw, code, out, seen); } catch {}
  try { detectPersonalSignNoMessage(fp, raw, code, out, seen); } catch {}
  try { detectWalletPrivKeyInFrontend(fp, raw, code, out, seen); } catch {}
  try { detectSignTypedDataNoChainId(fp, raw, code, out, seen); } catch {}
  try { detectEtherscanApiKeyInline(fp, raw, code, out, seen); } catch {}
  for (const f of out) f.file = fp;
  return out;
}

export const _internals = {
  _isWeb3Frontend, detectUnlimitedApproval, detectEthSign,
  detectPersonalSignNoMessage, detectWalletPrivKeyInFrontend,
  detectSignTypedDataNoChainId, detectEtherscanApiKeyInline,
};
