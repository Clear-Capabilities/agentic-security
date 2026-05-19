// FR-LOGIC-10 — Threat-model auto-derivation (STRIDE).
//
// Build a lightweight STRIDE-aligned threat model for the project from
// observed signals — data flows, trust boundaries, asset inventory. The
// output feeds two consumers:
//
//   1. The PR-comment bot, which uses the threat model to write a "what
//      the attacker would do here" paragraph next to high+ findings.
//   2. persona-prioritization.js (FR-ADV-2), which uses the asset list
//      to weight crown-jewel-adjacent findings higher for the personas
//      that care.
//
// We do NOT attempt a full STRIDE walkthrough — that would require running
// an LLM over the whole codebase. We DO emit a structured summary that an
// LLM can hydrate into a full narrative on demand.
//
// Output shape:
//   {
//     assets:        [{ name, file, line, category, exposure }],
//     trustBoundaries: [{ type, location, traffic }],
//     stride: {
//       spoofing:    [...]   // findings that bear on this STRIDE category
//       tampering:   [...]
//       repudiation: [...]
//       informationDisclosure: [...]
//       denialOfService: [...]
//       elevationOfPrivilege: [...]
//     },
//   }

const ASSET_PATTERNS = [
  // [regex, category, exposure]
  [/(?:stripe|paddle|braintree)\.\w+\.create/g, 'payment-method', 'public-api'],
  [/(?:User|users?)\.create\(|prisma\.user\.create/g, 'identity', 'public-api'],
  [/(?:session|token|jwt)\s*=\s*/g, 'session', 'internal'],
  [/process\.env\.([A-Z_]+(?:KEY|SECRET|TOKEN))/g, 'secret', 'internal'],
  [/(?:aws-sdk|@aws-sdk).*\.upload|s3\.put/g, 'object-storage', 'public-api'],
  [/(?:openai|anthropic|together|groq)\.(?:chat|messages|completions)/g, 'llm-egress', 'external-api'],
];

const TRUST_BOUNDARY_PATTERNS = [
  [/app\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g, 'http-route'],
  [/router\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g, 'http-route'],
  [/@(?:Get|Post|Put|Patch|Delete)Mapping\s*\(/g, 'http-route-java'],
  [/@(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g, 'http-route-py'],
  [/(?:kafka|pubsub|sqs|sns)\.consume|\.subscribe|\.receiveMessage/gi, 'queue-consumer'],
  [/(?:kafka|pubsub|sqs|sns)\.produce|\.publish|\.sendMessage/gi, 'queue-producer'],
  [/grpc\.Server|new\s+Server\s*\(\s*\)/g, 'grpc-server'],
  [/(?:db|pool|client)\.(?:query|execute|raw)\s*\(/g, 'db-edge'],
];

export function buildAssetInventory(fileContents) {
  const assets = [];
  if (!fileContents) return assets;
  for (const [fp, text] of Object.entries(fileContents)) {
    if (!text || typeof text !== 'string') continue;
    for (const [re, category, exposure] of ASSET_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) {
        const line = text.slice(0, m.index).split('\n').length;
        const name = m[1] || category;
        assets.push({ name, file: fp, line, category, exposure });
        if (assets.length >= 200) return assets;
      }
    }
  }
  return assets;
}

export function buildTrustBoundaries(fileContents) {
  const boundaries = [];
  if (!fileContents) return boundaries;
  for (const [fp, text] of Object.entries(fileContents)) {
    if (!text || typeof text !== 'string') continue;
    for (const [re, type] of TRUST_BOUNDARY_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) {
        const line = text.slice(0, m.index).split('\n').length;
        boundaries.push({ type, file: fp, line, label: m[1] || null });
        if (boundaries.length >= 500) return boundaries;
      }
    }
  }
  return boundaries;
}

function strideCategoryFor(f) {
  const v = (f.vuln || '').toLowerCase();
  if (/auth|jwt|session|csrf|spoof/.test(v)) return 'spoofing';
  if (/injection|deserial|tampered|prototype.pollution|toctou|race/.test(v)) return 'tampering';
  if (/log.injection|missing.audit|no.audit/.test(v)) return 'repudiation';
  if (/leak|disclos|info.expos|stack.trace|verbose.err/.test(v)) return 'informationDisclosure';
  if (/dos|denial|unbounded|max_tokens|rate.limit|redos/.test(v)) return 'denialOfService';
  if (/idor|missing.authz|broken.access|priv.esc|admin/.test(v)) return 'elevationOfPrivilege';
  if (/sql.injection|command.injection|ssrf|xxe|rce|code.injection/.test(v)) return 'tampering';
  if (/xss/.test(v)) return 'tampering';
  return null;
}

export function classifyFindingsByStride(findings) {
  const out = {
    spoofing: [], tampering: [], repudiation: [],
    informationDisclosure: [], denialOfService: [], elevationOfPrivilege: [],
  };
  if (!Array.isArray(findings)) return out;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const cat = strideCategoryFor(f);
    if (!cat) continue;
    out[cat].push({ vuln: f.vuln, file: f.file, line: f.line, severity: f.severity });
  }
  return out;
}

export function buildThreatModel(findings, fileContents) {
  const assets = buildAssetInventory(fileContents);
  const trustBoundaries = buildTrustBoundaries(fileContents);
  const stride = classifyFindingsByStride(findings || []);
  // Cap each STRIDE bucket so the model object stays compact in SARIF.
  for (const k of Object.keys(stride)) stride[k] = stride[k].slice(0, 25);
  return {
    summary: {
      assetCount: assets.length,
      boundaryCount: trustBoundaries.length,
      strideCounts: Object.fromEntries(Object.entries(stride).map(([k, v]) => [k, v.length])),
    },
    assets: assets.slice(0, 50),
    trustBoundaries: trustBoundaries.slice(0, 50),
    stride,
  };
}

// Compose: annotate each finding with its STRIDE category so consumers can
// pivot by attacker objective rather than by CWE.
export function annotateStrideCategory(findings) {
  if (!Array.isArray(findings)) return findings;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const cat = strideCategoryFor(f);
    if (cat) f.strideCategory = cat;
  }
  return findings;
}
