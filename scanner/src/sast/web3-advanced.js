// Web3 advanced SAST — Item #3 of the world-class+3 plan.
//
// Fills the gap between solidity.js (canonical CWE patterns) and defi-deep.js
// (AMM / vault / swap) with the bug classes that have dominated 2024-2026
// Web3 incident reports:
//
//   1. UPGRADEABLE_NO_DISABLE_INIT  — implementation contract leaves
//      initialize() callable; missing _disableInitializers() in constructor
//   2. UPGRADEABLE_NO_GAP           — UUPS/Transparent contracts without
//      __gap or storage-slot pinning; future upgrades brick storage
//   3. SIGREPLAY_NO_NONCE_CHAINID   — signed messages without nonce + chainId
//      + domain separator (cross-chain replay)
//   4. ECDSA_S_MALLEABILITY         — raw ecrecover without checks for
//      s in lower half (EIP-2; OpenZeppelin's ECDSA fixes this)
//   5. ORACLE_NO_STALENESS          — Chainlink latestRoundData() / answer
//      consumed without checking updatedAt freshness
//   6. ERC4337_NO_VALIDATION        — UserOperation entry without sig +
//      nonce verification, or paymaster missing prefund check
//   7. RO_REENTRANCY                — view function returns state that mutates
//      during reentrancy window (Curve-style read-only reentrancy bug)
//   8. MULTICALL_DELEGATECALL       — Multicall with delegatecall that
//      enables cross-function reentrancy / sig-replay
//   9. NFT_RECEIVER_UNTRUSTED       — _mint to address triggers
//      onERC721Received before state finalize (callback reentrancy)
//  10. FEE_ON_TRANSFER_VAULT        — deposit assumes amountIn = amountReceived
//      without balBefore/balAfter pair
//  11. SOLANA_NO_OWNER_CHECK        — Anchor Rust handler reads an account
//      without verifying owner == program_id (classic Anchor pitfall)
//  12. VYPER_RAW_CALL_UNSAFE        — Vyper raw_call without max_outsize,
//      gas, value sanity checks
//
// Each detector is family-tagged so reachability / calibration can be
// applied per-class. Files are routed by extension:
//   .sol   → detectors 1-10
//   .vy    → detector 12
//   .rs    → detector 11 (Anchor)
//
// Opt-out: AGENTIC_SECURITY_NO_WEB3_ADV=1 disables the whole module.

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
  'ecdsa-malleability',
  'erc4337-validation',
  'fee-on-transfer-vault',
  'multicall-delegatecall',
  'nft-receiver-reentrancy',
  'oracle-staleness',
  'read-only-reentrancy',
  'signature-replay',
  'solana-anchor-no-owner',
  'upgradeable-init',
  'upgradeable-storage',
  'vyper-raw-call',
];

function _line(raw, idx) { return raw.slice(0, idx).split('\n').length; }
function _snip(raw, line) { return (raw.split('\n')[line - 1] || '').trim().slice(0, 200); }

function _shape(file, line, ruleId, vuln, fam, sev, cwe, remediation, description) {
  return {
    id: `${ruleId}:${file}:${line}`,
    file, line, vuln, severity: sev, cwe,
    family: fam, parser: 'WEB3-ADV',
    confidence: 0.8,
    stride: fam.includes('reentrancy') || fam.includes('upgradeable') || fam.includes('replay') ? 'Tampering'
          : fam.includes('oracle') || fam.includes('staleness') ? 'Spoofing'
          : 'Elevation of Privilege',
    description: description || vuln,
    remediation,
  };
}

// ── Solidity detectors ─────────────────────────────────────────────────────

function detectUpgradeableNoDisableInit(file, raw, code, out, seen) {
  // Looking for: inherits *Upgradeable contract OR uses `initializer` modifier,
  // BUT the constructor does not call _disableInitializers().
  const isUpgradeable = /\bcontract\s+\w+\s+is\s+[^{]*Upgradeable\b/.test(code) ||
                        /\b(?:Initializable|UUPSUpgradeable|TransparentUpgradeableProxy)\b/.test(code);
  if (!isUpgradeable) return;
  const hasInitializerMod = /\binitializer\s*\{|\bonlyInitializing\s*\{/.test(code);
  if (!hasInitializerMod) return;
  // Look for constructor that includes _disableInitializers
  const ctor = /\bconstructor\s*\(\s*\)[^{]*\{([\s\S]*?)\}/.exec(code);
  const hasDisable = ctor && /_disableInitializers\s*\(/.test(ctor[1]);
  if (hasDisable) return;
  const m = /\binitializer\s*\{|\bcontract\s+\w+\s+is\s+[^{]*Upgradeable/.exec(code);
  const ln = _line(raw, m.index);
  const id = `web3-upgradeable-no-disable-init:${file}:${ln}`;
  if (seen.has(id)) return;
  seen.add(id);
  out.push(_shape(file, ln, 'web3-upgradeable-no-disable-init',
    'Upgradeable contract — implementation does not call _disableInitializers() in constructor',
    'upgradeable-init', 'high', 'CWE-665',
    'Add `constructor() { _disableInitializers(); }` to the implementation contract. Without it, anyone can call initialize() on the implementation contract itself and (in some configurations) take control of the proxy via selfdestruct delegatecall.',
    'OpenZeppelin warns: every upgradeable implementation MUST disable initializers in its constructor. The Wormhole and Audius incidents both stemmed from initialize() being callable post-deploy on an unfinished implementation.'));
}

function detectUpgradeableNoGap(file, raw, code, out, seen) {
  // Upgradeable contract without __gap variable or unstructured storage hint.
  if (!/Upgradeable\b|\bInitializable\b/.test(code)) return;
  if (/\b__gap\b|\bERC7201\b|\b@custom:storage-location\b/.test(code)) return;
  // Contract that declares state variables but no gap.
  const stateMatch = /\bcontract\s+(\w+)\s+is\s+[^{]*(?:Upgradeable|Initializable)[\s\S]*?\{/m.exec(code);
  if (!stateMatch) return;
  const ln = _line(raw, stateMatch.index);
  const id = `web3-upgradeable-no-gap:${file}:${ln}`;
  if (seen.has(id)) return;
  seen.add(id);
  out.push(_shape(file, ln, 'web3-upgradeable-no-gap',
    `Upgradeable contract ${stateMatch[1]} has no __gap or ERC-7201 storage namespace`,
    'upgradeable-storage', 'medium', 'CWE-665',
    'Add `uint256[50] private __gap;` at the end of every upgradeable contract, OR adopt ERC-7201 namespaced storage (`@custom:storage-location erc7201:...`). Without one, adding a state variable in a future version shifts every subsequent slot — corrupting all stored data.',
    'Storage layout drift across upgrades is the #1 cause of bricked proxy contracts. Compound III, OpenZeppelin Defender, and ERC-7201 all enforce explicit gap or namespacing.'));
}

function detectSigReplayNoNonceChainId(file, raw, code, out, seen) {
  // ecrecover(...) used in a function whose body does NOT reference both
  // nonce/nonces AND chainid/block.chainid AND a domain-separator hash.
  const re = /\becrecover\s*\(/g;
  let m;
  while ((m = re.exec(code))) {
    const ln = _line(raw, m.index);
    // Find enclosing function body
    const before = raw.slice(0, m.index);
    const fnStart = before.lastIndexOf('function ');
    if (fnStart < 0) continue;
    const bodyStart = raw.indexOf('{', fnStart);
    let depth = 1, bodyEnd = bodyStart + 1;
    for (let i = bodyStart + 1; i < Math.min(bodyStart + 6000, raw.length); i++) {
      if (raw[i] === '{') depth++;
      else if (raw[i] === '}') { depth--; if (depth === 0) { bodyEnd = i; break; } }
    }
    const body = raw.slice(bodyStart, bodyEnd + 1);
    const hasNonce = /\bnonces?\b|\busedSignatures?\b/.test(body);
    const hasChain = /\bblock\.chainid\b|\bchainid\(\)/.test(body) || /\bDOMAIN_SEPARATOR\b|\b_hashTypedDataV4\b/.test(body);
    if (hasNonce && hasChain) continue;
    const id = `web3-sig-replay:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'web3-sig-replay',
      `ecrecover used without ${hasNonce ? '' : 'nonce '}${hasChain ? '' : 'chainId/domain-separator '}— signature replay surface`,
      'signature-replay', 'high', 'CWE-294',
      'Bind signed messages to (a) a per-signer nonce, (b) the chainId, and (c) the contract address (EIP-712 domain separator). Use `_hashTypedDataV4()` from OpenZeppelin EIP712 to handle all three.',
      'Signature replay attacks have drained NFT marketplaces (LooksRare, OpenSea Wyvern), bridges, and meta-tx relayers. Cross-chain replay is the most common — same signed message accepted on Ethereum + every L2.'));
  }
}

function detectEcdsaSMalleability(file, raw, code, out, seen) {
  // Raw ecrecover without OpenZeppelin ECDSA wrapper AND no s ≤ secp256k1n/2 check.
  if (!/\becrecover\s*\(/.test(code)) return;
  if (/\bECDSA\.recover\b|\bECDSA\.tryRecover\b/.test(code)) return;
  // If we don't see the canonical low-s check, flag.
  if (/0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0/i.test(code)) return;
  const m = /\becrecover\s*\(/.exec(code);
  const ln = _line(raw, m.index);
  const id = `web3-ecdsa-malleability:${file}:${ln}`;
  if (seen.has(id)) return;
  seen.add(id);
  out.push(_shape(file, ln, 'web3-ecdsa-malleability',
    'Raw ecrecover without ECDSA s-malleability check — duplicate-signature attack',
    'ecdsa-malleability', 'medium', 'CWE-347',
    'Use `ECDSA.recover(...)` from `@openzeppelin/contracts/utils/cryptography/ECDSA.sol`. It rejects high-s signatures per EIP-2 and prevents the (v, r, s) ↔ (v ^ 1, r, secp256k1n - s) twin-signature problem.',
    'Without the lower-s check, every valid signature has a malleable twin — breaking any application that uses signatures as unique IDs (hash maps of signatures, signature-based replay protection).'));
}

function detectOracleNoStaleness(file, raw, code, out, seen) {
  // latestRoundData() destructured without `updatedAt` being checked.
  const re = /\.latestRoundData\s*\(\s*\)/g;
  let m;
  while ((m = re.exec(code))) {
    const ln = _line(raw, m.index);
    // Look at the next ~400 chars for a freshness check.
    const after = raw.slice(m.index, m.index + 400);
    const hasFresh = /\b(?:updatedAt|timestamp)\b[^;]{0,80}>\s*block\.timestamp\s*-/.test(after) ||
                     /require\s*\(\s*[^,)]*updatedAt[^)]*\)/.test(after) ||
                     /staleAfter|MAX_DELAY|HEARTBEAT/.test(after);
    if (hasFresh) continue;
    const id = `web3-oracle-staleness:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'web3-oracle-staleness',
      'Chainlink latestRoundData() consumed without checking updatedAt freshness',
      'oracle-staleness', 'high', 'CWE-672',
      'After destructuring latestRoundData(), assert `require(block.timestamp - updatedAt < HEARTBEAT, "Stale oracle");` where HEARTBEAT matches the feed (e.g. 3600 for ETH/USD on mainnet). Also check answeredInRound >= roundId and answer > 0.',
      'Stale oracle data has caused liquidation cascades and bad-debt accumulation across DeFi (Mango, Inverse Finance). A stuck price feed remains "fresh enough" to drain a protocol when reality has moved.'));
  }
}

function detectErc4337NoValidation(file, raw, code, out, seen) {
  // validateUserOp(...) without signature recovery + nonce check.
  const re = /\bvalidateUserOp\s*\(/g;
  let m;
  while ((m = re.exec(code))) {
    const ln = _line(raw, m.index);
    const after = raw.slice(m.index, m.index + 2000);
    const hasSig = /\b(?:ecrecover|ECDSA|isValidSignature)\b/.test(after);
    const hasNonce = /\bnonce\b/.test(after);
    if (hasSig && hasNonce) continue;
    const id = `web3-4337-no-validation:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'web3-4337-no-validation',
      `validateUserOp missing ${hasSig ? '' : 'signature '}${hasNonce ? '' : 'nonce '}validation`,
      'erc4337-validation', 'critical', 'CWE-287',
      'A ERC-4337 account MUST verify the userOp signature against its owning key and increment a per-account nonce inside validateUserOp. Without sig verification anyone executes ops on the account; without nonce the same op replays forever.',
      'ERC-4337 (account abstraction) is the foundation of every smart-account wallet. A flawed validateUserOp is the equivalent of "ECDSA verification removed" for an EOA.'));
  }
}

function detectReadOnlyReentrancy(file, raw, code, out, seen) {
  // view/pure function that returns a value derived from a state var that
  // mutates inside an external-call function. Heuristic: view function reads
  // `totalSupply()` / `balance` / `reserves` AND there's a write to the same
  // state in another function that contains `.call{value:` or `.transfer(`.
  const viewFns = [...code.matchAll(/\bfunction\s+(\w+)\s*\([^)]*\)\s+(?:external|public)\s+view\s+[^{]*\{([\s\S]*?)\}/g)];
  if (!viewFns.length) return;
  const writingFns = code.match(/\.call\s*\{[^}]*value\s*:|\.transfer\s*\(|\.send\s*\(/g);
  if (!writingFns) return;
  for (const v of viewFns) {
    const body = v[2];
    if (/\btotalSupply\s*\(\)|\bgetPricePerShare\s*\(|\bpricePerShare\s*\(|\bbalanceOf\s*\(/.test(body) ||
        /\breserves?\b|\bvirtualPrice\b/.test(body)) {
      const ln = _line(raw, v.index);
      const id = `web3-ro-reentrancy:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'web3-ro-reentrancy',
        `view function ${v[1]}() exposes mid-mutation state — read-only reentrancy surface`,
        'read-only-reentrancy', 'high', 'CWE-841',
        'View functions that return computed price / share / balance values must be wrapped in the same nonReentrant guard as the mutating functions, OR must read from a checkpointed snapshot that updates atomically. Use a `nonReentrantView` modifier (Curve / Yearn pattern).',
        'Read-only reentrancy bug pattern: integrator contracts read your view function during a mid-mutation external call (e.g. inside an ERC-777 callback) and get a stale or inflated value. Curve LP token pricing has been exploited via this exact pattern (multiple incidents).'));
    }
  }
}

function detectMulticallDelegatecall(file, raw, code, out, seen) {
  // Multicall implementation that delegatecalls each call.
  const re = /\bfunction\s+multicall\s*\([^)]*\)\s*[^{]*\{([\s\S]*?)\}/g;
  let m;
  while ((m = re.exec(code))) {
    const body = m[1];
    if (/\bdelegatecall\s*\(/.test(body)) {
      const ln = _line(raw, m.index);
      const id = `web3-multicall-delegatecall:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'web3-multicall-delegatecall',
        'multicall() uses delegatecall — enables msg.sender forwarding + sig-replay attacks',
        'multicall-delegatecall', 'high', 'CWE-863',
        'Multicall + delegatecall lets users batch arbitrary functions that read msg.sender — including transferFrom on tokens with a stale approval. Use the OpenZeppelin Multicall (which uses Address.functionDelegateCall on the same contract) and avoid combining it with any function that triggers external behavior on msg.sender.',
        'Critical bugs in Uniswap V3 SwapRouter and 0x protocol traced to multicall + delegatecall enabling unintended message-sender semantics.'));
    }
  }
}

function detectNftReceiverUntrusted(file, raw, code, out, seen) {
  // _mint or _safeMint to an arbitrary address before state finalize.
  // Pattern: `_safeMint(to, ...)` followed by `state_var = ...` in the same function.
  const re = /\b_(?:safeMint|safeTransferFrom)\s*\([^)]*\)\s*;\s*\n[^\n}]*\b\w+\s*\[[^\]]+\]\s*=/g;
  let m;
  while ((m = re.exec(code))) {
    const ln = _line(raw, m.index);
    const id = `web3-nft-receiver-untrusted:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'web3-nft-receiver-untrusted',
      '_safeMint / _safeTransferFrom triggers onERC721Received callback BEFORE state finalize',
      'nft-receiver-reentrancy', 'high', 'CWE-841',
      'Move all state updates BEFORE _safeMint/_safeTransferFrom. The receiver hook can re-enter your contract and observe partial state (CEI violation in NFT context). HashMasks, Meebits, and several NFT staking contracts have shipped this bug.',
      'ERC-721 safeTransfer triggers a callback on the receiver — if the receiver is itself a contract, it can call back into your contract before you finish updating local state. Same anti-pattern as ERC-777 hooks for ERC-20.'));
  }
}

function detectFeeOnTransferVault(file, raw, code, out, seen) {
  // deposit() / mint() that uses transferFrom amount as shares-in directly.
  const re = /\bfunction\s+(?:deposit|mint)\s*\([^)]*\)\s*[^{]*\{([\s\S]*?)\}/g;
  let m;
  while ((m = re.exec(code))) {
    const body = m[1];
    const usesTransferFrom = /\btransferFrom\s*\(/.test(body);
    const usesBalanceCheckpoint = /balBefore|balanceBefore|balPre|_before\b/.test(body) ||
                                  /balanceOf\s*\([^)]+\)\s*-\s*\w+Before/.test(body);
    if (usesTransferFrom && !usesBalanceCheckpoint) {
      const ln = _line(raw, m.index);
      const id = `web3-fee-on-transfer-vault:${file}:${ln}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(_shape(file, ln, 'web3-fee-on-transfer-vault',
        'Vault deposit/mint assumes amountIn == amountReceived (fee-on-transfer token mishandling)',
        'fee-on-transfer-vault', 'medium', 'CWE-682',
        'Bracket transferFrom with balBefore = balanceOf(...) / balAfter = balanceOf(...); use the delta as the real amountReceived for share math. Otherwise tokens like USDT (mainnet) or PAXG fees will silently mis-mint shares.',
        'Fee-on-transfer tokens (some L2 wrapped USDT, deflationary tokens) deduct a fee on transferFrom — leaving the vault under-collateralized for every deposit. The Beanstalk Wells V0 and several yield aggregators have shipped this.'));
    }
  }
}

// ── Solana / Anchor detector (Rust) ────────────────────────────────────────

function detectSolanaNoOwnerCheck(file, raw, code, out, seen) {
  // Anchor handler reads an AccountInfo without #[account(owner = ...)] or
  // a runtime owner check.
  if (!/\buse\s+anchor_lang\b/.test(code) && !/\bAccountInfo\b/.test(code)) return;
  // Look for handlers (Anchor): pub fn handler(ctx: Context<...>, ...)
  const re = /pub\s+fn\s+(\w+)\s*\(\s*ctx\s*:\s*Context<(\w+)>[^)]*\)[^{]*\{([\s\S]*?)\bOk\s*\(\s*\(\s*\)\s*\)/g;
  let m;
  while ((m = re.exec(code))) {
    const body = m[3];
    const accountsReferenced = body.match(/\bctx\.accounts\.(\w+)/g) || [];
    if (!accountsReferenced.length) continue;
    // Look for the matching Accounts struct.
    const accountsStruct = new RegExp(`#\\[derive\\(Accounts\\)\\][\\s\\S]*?struct\\s+${m[2]}\\b[\\s\\S]*?\\}`, 'g').exec(code);
    if (!accountsStruct) continue;
    const structBody = accountsStruct[0];
    if (/#\[account\s*\([^)]*owner\s*=/.test(structBody)) continue;
    if (/has_one\s*=/.test(structBody)) continue;
    if (/\bsigner\s*:|Signer<'info>/.test(structBody) && body.length < 500) continue;
    const ln = _line(raw, m.index);
    const id = `web3-solana-no-owner-check:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'web3-solana-no-owner-check',
      `Anchor handler ${m[1]} reads accounts without owner-check constraints`,
      'solana-anchor-no-owner', 'high', 'CWE-862',
      'Add `#[account(owner = program_id)]` or `has_one = X` constraints to the Accounts struct. Without explicit ownership checks Anchor will deserialize a malicious account that happens to match the struct shape — the canonical Solana "type confusion" attack class.',
      'Many high-profile Solana exploits (Wormhole bridge, Cashio, Audius governance) reduce to "account did not match the expected program owner". Anchor 0.20+ enforces this when you use the Account<\'info, T> type with constraints.'));
  }
}

// ── Vyper detector ─────────────────────────────────────────────────────────

function detectVyperRawCallUnsafe(file, raw, code, out, seen) {
  // raw_call(...) without max_outsize specified or with value > 0 inside @view.
  const re = /\braw_call\s*\(([^)]*)\)/g;
  let m;
  while ((m = re.exec(code))) {
    const args = m[1];
    const hasMax = /\bmax_outsize\s*=/.test(args);
    if (hasMax) continue;
    const ln = _line(raw, m.index);
    const id = `web3-vyper-raw-call:${file}:${ln}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(_shape(file, ln, 'web3-vyper-raw-call',
      'Vyper raw_call without explicit max_outsize — unbounded returndata',
      'vyper-raw-call', 'medium', 'CWE-1284',
      'Always pass `max_outsize=<expected_bytes>` to raw_call. Without it, callees can return arbitrarily large data and force gas-exhaustion DoS on the caller. Also gate `is_static_call=True` for read-only paths.',
      'Vyper raw_call exposes the same low-level primitives as Solidity .call; the safe default is to constrain return-data size and to enforce read-only semantics where applicable.'));
  }
}

// ── Entry points ───────────────────────────────────────────────────────────

export function scanWeb3Advanced(fp, raw) {
  if (process.env.AGENTIC_SECURITY_NO_WEB3_ADV === '1') return [];
  if (!raw || raw.length > 500_000) return [];
  const out = [];
  const seen = new Set();
  if (/\.sol$/i.test(fp)) {
    const code = blankComments(raw);
    try { detectUpgradeableNoDisableInit(fp, raw, code, out, seen); } catch {}
    try { detectUpgradeableNoGap(fp, raw, code, out, seen); } catch {}
    try { detectSigReplayNoNonceChainId(fp, raw, code, out, seen); } catch {}
    try { detectEcdsaSMalleability(fp, raw, code, out, seen); } catch {}
    try { detectOracleNoStaleness(fp, raw, code, out, seen); } catch {}
    try { detectErc4337NoValidation(fp, raw, code, out, seen); } catch {}
    try { detectReadOnlyReentrancy(fp, raw, code, out, seen); } catch {}
    try { detectMulticallDelegatecall(fp, raw, code, out, seen); } catch {}
    try { detectNftReceiverUntrusted(fp, raw, code, out, seen); } catch {}
    try { detectFeeOnTransferVault(fp, raw, code, out, seen); } catch {}
  } else if (/\.vy$/i.test(fp)) {
    const code = blankComments(raw, 'py');
    try { detectVyperRawCallUnsafe(fp, raw, code, out, seen); } catch {}
  } else if (/\.rs$/i.test(fp) && /\banchor_lang\b/.test(raw)) {
    const code = raw;
    try { detectSolanaNoOwnerCheck(fp, raw, code, out, seen); } catch {}
  }
  for (const f of out) f.file = fp;
  return out;
}

export const _internals = {
  detectUpgradeableNoDisableInit, detectUpgradeableNoGap,
  detectSigReplayNoNonceChainId, detectEcdsaSMalleability,
  detectOracleNoStaleness, detectErc4337NoValidation,
  detectReadOnlyReentrancy, detectMulticallDelegatecall,
  detectNftReceiverUntrusted, detectFeeOnTransferVault,
  detectSolanaNoOwnerCheck, detectVyperRawCallUnsafe,
};
