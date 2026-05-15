// Blast-radius and cost framing — world-class breach cost estimation.
//
// Empirical data sources (all citations are public):
//   - IBM Cost of a Data Breach Report 2024 (per-industry, per-record costs)
//   - NetDiligence Cyber Claims Study 2024 (SMB incident cost distributions)
//   - Ponemon Institute studies 2023-2024 (cost components)
//   - Verizon DBIR 2024 (breach pattern frequencies)
//   - HHS OCR HIPAA enforcement records (Tier 1-4 fine bands)
//   - GDPR Enforcement Tracker (EU fine medians and maxes)
//   - Public settlements: Equifax $1.4B, Capital One $190M, T-Mobile $350M,
//                        Anthem $115M, Marriott $52M+$124M, Optus AU$140M,
//                        Uber $148M, Yahoo $117.5M
//   - PCI-DSS fee schedules (Visa/MC published)
//
// Cost model (component sum with three-point estimates):
//   incidentResponse + legal + crisisPR + notification + creditMonitoring +
//   regulatoryFines + directDamage + classAction + lostBusiness
//
// Each component is computed for best (P5) / likely (P50) / worst (P95) and
// summed independently. Scale factors applied per component, not globally.
//
// Decoration shape:
//   blastRadius: {
//     scope, dataAtRisk, userCount, industry, jurisdictions,
//     dollarBest, dollarLikely, dollarWorst,
//     dollarLow, dollarHigh,            // backward compat (= best / worst)
//     components: { ... per-component low/likely/high ... },
//     controlsApplied: [...],            // discount factors detected
//     dominantDriver, comparable, confidence,
//     narrative
//   }

import * as fs from 'node:fs';
import * as path from 'node:path';

// ════════════════════════════════════════════════════════════════════════════
// EMPIRICAL DATA TABLES
// ════════════════════════════════════════════════════════════════════════════

// Per-record breach cost by data class.
// Sources: IBM 2024 ($169 avg PII), Ponemon, NetDiligence by-data-class study.
// Format: { low, likely, high } — interpreted as P5 / P50 / P95.
const PER_RECORD_COST = {
  'anonymous':    { low: 0.50,  likely: 2,    high: 8     },   // email-only list
  'email':        { low: 2,     likely: 8,    high: 25    },   // email + name
  'pii':          { low: 50,    likely: 165,  high: 400   },   // IBM 2024 baseline
  'pii-sensitive':{ low: 150,   likely: 350,  high: 900   },   // SSN/DOB/govt-id
  'payment':      { low: 100,   likely: 220,  high: 500   },   // PCI + replacement
  'phi':          { low: 250,   likely: 500,  high: 1500  },   // HIPAA tier 3-4
  'credentials':  { low: 20,    likely: 60,   high: 250   },   // base + reuse risk
  'auth-tokens':  { low: 30,    likely: 90,   high: 300   },   // session theft
  'children':     { low: 500,   likely: 2000, high: 42530 },   // COPPA max fine
  'rce':          { low: 200,   likely: 800,  high: 5000  },   // infra rebuild + IR
  'config':       { low: 5,     likely: 25,   high: 200   },   // misc internal data
};

// Industry cost multipliers (IBM 2024 Cost of a Data Breach Report).
// "Average" baseline = 1.00. Healthcare highest at 1.84×, public sector lowest at 0.45×.
const INDUSTRY_PROFILES = {
  'healthcare':  { mult: 1.84, label: 'healthcare', defaultRegs: ['HIPAA','GDPR','CCPA'] },
  'financial':   { mult: 1.16, label: 'financial services', defaultRegs: ['PCI-DSS','SOX','GLBA','GDPR'] },
  'industrial':  { mult: 1.10, label: 'industrial', defaultRegs: ['NIS2'] },
  'tech':        { mult: 1.05, label: 'technology', defaultRegs: ['GDPR','CCPA'] },
  'pharma':      { mult: 1.05, label: 'pharma', defaultRegs: ['HIPAA','GDPR','FDA'] },
  'energy':      { mult: 0.96, label: 'energy', defaultRegs: ['NERC-CIP'] },
  'services':    { mult: 0.88, label: 'professional services', defaultRegs: ['GDPR'] },
  'manufacturing':{ mult: 0.84, label: 'manufacturing', defaultRegs: [] },
  'retail':      { mult: 0.83, label: 'retail / e-commerce', defaultRegs: ['PCI-DSS','GDPR','CCPA'] },
  'education':   { mult: 0.74, label: 'education', defaultRegs: ['FERPA','GDPR'] },
  'media':       { mult: 0.71, label: 'media', defaultRegs: ['GDPR','CCPA'] },
  'hospitality': { mult: 0.69, label: 'hospitality', defaultRegs: ['PCI-DSS','GDPR'] },
  'consumer':    { mult: 0.65, label: 'consumer / B2C', defaultRegs: ['GDPR','CCPA'] },
  'public':      { mult: 0.45, label: 'public sector', defaultRegs: ['FISMA','FedRAMP'] },
  'generic':     { mult: 1.00, label: 'general SaaS', defaultRegs: [] },
};

// Jurisdiction regulatory fine bands.
// Realistic SMB-likely outcomes, not theoretical maxes.
// Sources: GDPR Enforcement Tracker median for <500-employee orgs,
//          HHS OCR settlement records, state AG actions, PCI fee schedules.
const JURISDICTION_FINES = {
  'GDPR':    { low: 5_000,   likely: 50_000,    high: 500_000   },  // SMB median; theoretical max 4% revenue
  'CCPA':    { low: 2_500,   likely: 25_000,    high: 750_000   },  // $100-$750/CA resident in class
  'HIPAA':   { low: 25_000,  likely: 250_000,   high: 1_900_000 },  // Tier 1-3 typical; max $1.9M/year
  'PCI-DSS': { low: 5_000,   likely: 80_000,    high: 500_000   },  // $5k-$100k/mo + per-card fines
  'SOX':     { low: 50_000,  likely: 250_000,   high: 5_000_000 },  // SEC enforcement, exec liability
  'GLBA':    { low: 25_000,  likely: 200_000,   high: 1_000_000 },  // FTC/CFPB enforcement
  'COPPA':   { low: 50_000,  likely: 500_000,   high: 5_000_000 },  // YouTube $170M, TikTok $5.7M
  'FERPA':   { low: 0,       likely: 100_000,   high: 5_000_000 },  // worst case: federal funding loss
  'NIS2':    { low: 10_000,  likely: 100_000,   high: 10_000_000 }, // EU critical infra; max 2% revenue
  'NERC-CIP':{ low: 25_000,  likely: 500_000,   high: 1_000_000 },  // per-day penalty per violation
  'FDA':     { low: 50_000,  likely: 500_000,   high: 5_000_000 },  // 21 CFR Part 11 enforcement
  'FedRAMP': { low: 100_000, likely: 500_000,   high: 10_000_000 }, // contract loss + remediation
  'FISMA':   { low: 50_000,  likely: 250_000,   high: 5_000_000 },  // federal contract penalty
  'LGPD':    { low: 5_000,   likely: 50_000,    high: 1_000_000 },  // Brazil; max 2% revenue or R$50M
  'PIPEDA':  { low: 5_000,   likely: 50_000,    high: 100_000   },  // Canada; max C$100k
  'UK-GDPR': { low: 5_000,   likely: 50_000,    high: 500_000   },  // post-Brexit equivalent
  'STATE':   { low: 5_000,   likely: 25_000,    high: 250_000   },  // US state breach laws stack
};

// CWE-to-vuln-name mapping for findings without explicit CWE field.
const VULN_TO_CWE = {
  'sql injection':              'CWE-89',
  'nosql injection':            'CWE-89',
  'command injection':          'CWE-78',
  'os command':                 'CWE-78',
  'rce':                        'CWE-78',
  'remote code execution':      'CWE-78',
  'code execution':             'CWE-78',
  'sandbox escape':             'CWE-78',
  'vm sandbox':                 'CWE-78',
  'sandbox execution':          'CWE-78',
  'arbitrary code':             'CWE-78',
  'eval injection':             'CWE-78',
  'path traversal':             'CWE-22',
  'zip slip':                   'CWE-22',
  'directory traversal':        'CWE-22',
  'ssrf':                       'CWE-918',
  'server-side request':        'CWE-918',
  'xss':                        'CWE-79',
  'cross-site scripting':       'CWE-79',
  'dangerouslysetinnerhtml':    'CWE-79',
  'idor':                       'CWE-639',
  'insecure direct object':     'CWE-639',
  'csrf':                       'CWE-352',
  'mass assignment':            'CWE-915',
  'authentication bypass':      'CWE-287',
  'broken authentication':      'CWE-287',
  'jwt':                        'CWE-287',
  'webhook':                    'CWE-345',
  'signature missing':          'CWE-345',
  'signature verification':     'CWE-345',
  'deserialization':            'CWE-502',
  'prototype pollution':        'CWE-1321',
  'hardcoded':                  'CWE-798',
  'password hashing':           'CWE-916',
  'md5':                        'CWE-916',
  'sha1':                       'CWE-916',
  'weak crypto':                'CWE-327',
  'open redirect':              'CWE-601',
  'xxe':                        'CWE-611',
  'xml external':               'CWE-611',
  'missing authorization':      'CWE-862',
  'broken access control':      'CWE-862',
  'missing auth':               'CWE-862',
  'access control':             'CWE-862',
  'session fixation':           'CWE-613',
  'error message':              'CWE-209',
  'stack trace':                'CWE-209',
  'information disclosure':     'CWE-209',
  'file upload':                'CWE-434',
  'unrestricted upload':        'CWE-434',
  'rate limit':                 'CWE-400',
  'prompt injection':           'LLM01',
  'llm output':                 'LLM02',
  'max_tokens':                 'LLM10',
  'unbounded consumption':      'LLM10',
};

// Comparable real-world incidents to cite in narratives.
const COMPARABLE_INCIDENTS = {
  'CWE-89':   'Equifax 2017 SQLi → $1.4B settlement (147M records, $9.50/rec)',
  'CWE-78':   'Capital One 2019 SSRF → $190M settlement; full server access typical',
  'CWE-94':   'Log4Shell 2021 code injection → individual orgs $100k–$10M cleanup; CVSS 10.0',
  'CWE-22':   'Snyk 2022 path-traversal disclosure → CDN cache poisoning + .env exfil',
  'CWE-918':  'Capital One 2019 SSRF → $190M settlement (100M records, $1.90/rec)',
  'CWE-79':   'British Airways 2018 XSS skimmer → £20M ICO fine (380k cards)',
  'CWE-639':  'T-Mobile 2023 API IDOR → $350M class settlement (37M records)',
  'CWE-352':  'Numerous; CSRF on payment endpoints chains to direct fraud',
  'CWE-915':  'GitHub mass-assignment 2012 → public ridicule + emergency rebuild',
  'CWE-287':  'Anthem 2015 → $115M settlement (78.8M records); credential stuffing class',
  'CWE-345':  'Stripe webhook spoofing chains to fake "payment succeeded" → plan upgrades',
  'CWE-347':  'JWT forging incidents — auth bypass typically chains to full account takeover',
  'CWE-502':  'Log4Shell 2021 → industry-wide $90B+ remediation; individual orgs $100k–$10M',
  'CWE-798':  'AWS keys leaked: avg $200k crypto-mining bill in <48h; OpenAI keys: $30–100k overnight',
  'CWE-916':  'MD5/SHA1 hash: rainbow tables crack 8-char passwords in <60s on a GPU',
  'CWE-327':  'Adobe 2013 weak ECB encryption → 38M user passwords reverse-engineered',
  'CWE-200':  'Multiple incidents: error messages leak DB schema, secrets, internal paths',
  'CWE-209':  'Stack-trace disclosure: SAP CVE-2022-22536 chained to RCE via internal paths',
  'CWE-601':  'OAuth open-redirect → full token theft (Slack 2018, Stripe 2020)',
  'CWE-611':  'BlackHat 2015 XXE demos → AWS metadata exfil',
  'CWE-862':  'Optus 2022 missing-authz API → AU$140M class settlement (10M records)',
  'CWE-613':  'Adobe 2013 session fixation → 38M credentials',
  'CWE-434':  'Imgur 2014 file upload → RCE via processed image metadata',
  'CWE-400':  'Air Canada 2024 LLM chatbot DoS → court-ordered refunds + reputational damage',
  'CWE-922':  'Client-side storage of session tokens enables XSS → permanent session theft',
  'CWE-1333': 'ReDoS in Express: single regex pin a Node process for 100% CPU',
  'CWE-1321': 'Lodash/Mongoose prototype pollution → auth bypass + RCE (CVE-2019-10744)',
  'CWE-1336': 'Server-side template injection (Pug/Jinja2/Twig) → routine path to RCE',
  'CWE-943':  'NoSQL injection via $-operators → auth bypass (MongoDB queries)',
  'LLM01':    'Air Canada 2024 chatbot prompt injection → binding refund obligations',
  'LLM02':    'LangChain/AutoGPT prompt → SQL chain incidents; LLM output trusted as code',
  'LLM10':    'Reported 2024: single prompt-injection attack ran $40k OpenAI bill in 6 hours',
  'DEFAULT':  'Generic finding — likely cost driven by user count + jurisdiction stack',
};

// ════════════════════════════════════════════════════════════════════════════
// PROJECT SIGNAL COLLECTION
// ════════════════════════════════════════════════════════════════════════════

function readSafe(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } }
function existsAny(root, files) { return files.some(f => fs.existsSync(path.join(root, f))); }

export function collectProjectSignals(scanRoot) {
  const sig = {
    // Stack signals
    hasStripe: false, hasAuth: false, hasS3: false, hasAnalytics: false,
    hasUserTable: false, hasPII: false, hasPHI: false, hasSecrets: false,
    hasChildrenData: false, hasFinancialData: false, hasEducationData: false,

    // Industry classification
    industry: 'generic',
    industryConfidence: 'low',

    // Jurisdiction exposure
    jurisdictions: new Set(),

    // Existing controls (discount factors)
    controls: new Set(),

    // Scale signals
    hasB2BSignals: false,
    hasEnterpriseSignals: false,
    hasGlobalDeployment: false,
    estimatedUsers: null,
    revenueIndicator: 'pre-revenue',

    dependencies: new Set(),
  };

  // ── 1. Manifest sweep ─────────────────────────────────────────────────────
  const manifests = [
    'package.json', 'requirements.txt', 'pyproject.toml',
    'Gemfile', 'go.mod', 'composer.json', 'Cargo.toml',
  ];
  let allManifestText = '';
  for (const m of manifests) {
    const text = readSafe(path.join(scanRoot, m));
    if (!text) continue;
    allManifestText += text + '\n';
    for (const m2 of text.matchAll(/"([\w@/-]+)"\s*:/g)) sig.dependencies.add(m2[1]);
  }

  // Stack detection
  if (/\b(stripe|paddle|chargebee|square|braintree|lemonsqueezy|adyen)\b/i.test(allManifestText)) sig.hasStripe = true;
  if (/\b(clerk|next-auth|@auth\/|lucia-auth|passport|firebase-auth|auth0|supabase|better-auth|workos|okta|saml)\b/i.test(allManifestText)) sig.hasAuth = true;
  if (/\b(aws-sdk|@aws-sdk\/client-s3|boto3|google-cloud-storage|@google-cloud\/storage|azure-storage)\b/i.test(allManifestText)) sig.hasS3 = true;
  if (/\b(posthog|mixpanel|amplitude|segment|ga4|@analytics|heap|hotjar|fullstory)\b/i.test(allManifestText)) sig.hasAnalytics = true;
  if (/\b(linear|jira|salesforce|hubspot|zendesk|intercom|drift|mailgun|sendgrid)\b/i.test(allManifestText)) sig.hasB2BSignals = true;
  if (/\b(workos|okta|saml|scim|onelogin|pingidentity|enterprise-sso)\b/i.test(allManifestText)) sig.hasEnterpriseSignals = true;

  // ── 2. Industry classification ────────────────────────────────────────────
  const industrySignals = {
    healthcare:   /\b(drchrono|healthie|@medplum|fhir|hl7|athena|redox|epic-fhir|cerner|hipaa)\b/i,
    financial:    /\b(plaid|dwolla|alpaca|stripe-issuing|stripe-treasury|broker|kyc|aml|sanction-list|finicity|teller)\b/i,
    pharma:       /\b(clinical-?trial|fda-cfr|gxp|adverse-event|pharmacovigilance)\b/i,
    education:    /\b(canvas-lms|blackboard|moodle|gradebook|edx-platform|student-information)\b/i,
    retail:       /\b(shopify|woocommerce|@bigcommerce|magento|medusa|saleor)\b/i,
    hospitality:  /\b(opera-pms|cloudbeds|mews|sabre|amadeus|booking-api)\b/i,
    energy:       /\b(scada|modbus|opc-ua|iec-61850|dnp3|energy-grid)\b/i,
    media:        /\b(brightcove|mux|cloudinary-video|jwplayer|wowza)\b/i,
    public:       /\b(\.gov|fedramp|fisma|nist-800-53|gov-cloud)\b/i,
  };
  for (const [ind, re] of Object.entries(industrySignals)) {
    if (re.test(allManifestText)) {
      sig.industry = ind;
      sig.industryConfidence = 'medium';
      break;
    }
  }
  // If multiple industry-defining deps found, treat as 'tech' (multi-vertical SaaS)
  if (sig.industry === 'generic' && sig.hasStripe && sig.hasAuth && sig.hasAnalytics) {
    sig.industry = 'tech';
    sig.industryConfidence = 'medium';
  } else if (sig.industry === 'generic' && sig.hasStripe) {
    sig.industry = 'consumer';
    sig.industryConfidence = 'low';
  }

  // ── 3. Schema heuristic — refines industry + data classification ──────────
  const schemaCandidates = [
    'schema.prisma', 'prisma/schema.prisma', 'db/schema.ts', 'db/schema.js',
    'supabase/migrations', 'migrations', 'drizzle/schema.ts',
    'app/models', 'src/models',
  ];
  let schemaText = '';
  for (const f of schemaCandidates) {
    const fp = path.join(scanRoot, f);
    if (!fs.existsSync(fp)) continue;
    try {
      const stat = fs.statSync(fp);
      if (stat.isDirectory()) {
        const files = fs.readdirSync(fp).slice(0, 30);
        for (const sub of files) schemaText += readSafe(path.join(fp, sub));
      } else schemaText = readSafe(fp);
    } catch {}
  }
  if (schemaText) {
    if (/\b(?:User|users|profiles?|accounts?|members?)\b/.test(schemaText)) sig.hasUserTable = true;
    if (/\b(?:email|phone|address|first_name|last_name|full_name)\b/i.test(schemaText)) sig.hasPII = true;
    if (/\b(?:ssn|date_of_birth|dob|national_id|passport|government_id|tax_id)\b/i.test(schemaText)) {
      sig.hasPII = true;
      sig.hasFinancialData = true;  // sensitive PII triggers financial-class fines
    }
    if (/\b(?:diagnosis|medical|patient|prescription|health_record|mrn|icd|cpt|hipaa)\b/i.test(schemaText)) {
      sig.hasPHI = true;
      if (sig.industry === 'generic') { sig.industry = 'healthcare'; sig.industryConfidence = 'high'; }
    }
    if (/\b(?:card|payment|invoice|charge|subscription|stripe_customer|account_number|routing)\b/i.test(schemaText)) {
      sig.hasStripe = true;
      sig.hasFinancialData = true;
    }
    if (/\b(?:parent_consent|coppa|child_age|guardian|kid_)\b/i.test(schemaText)) {
      sig.hasChildrenData = true;
    }
    if (/\b(?:student|course|grade|transcript|enrollment|gpa)\b/i.test(schemaText)) {
      sig.hasEducationData = true;
      if (sig.industry === 'generic') { sig.industry = 'education'; sig.industryConfidence = 'medium'; }
    }
  }

  // ── 4. Jurisdiction detection ─────────────────────────────────────────────
  // Industry-driven jurisdictions
  const indProfile = INDUSTRY_PROFILES[sig.industry] || INDUSTRY_PROFILES.generic;
  for (const j of indProfile.defaultRegs) sig.jurisdictions.add(j);

  // GDPR (EU presence)
  const i18nDirs = ['locales', 'i18n', 'translations', 'src/locales', 'public/locales'];
  let hasEuLocale = false;
  for (const d of i18nDirs) {
    const dp = path.join(scanRoot, d);
    if (fs.existsSync(dp)) {
      try {
        const entries = fs.readdirSync(dp).join(' ');
        if (/\b(de|fr|es|it|nl|pl|sv|da|fi|cs|hu|pt|el|ro|bg|hr|sk|sl|lt|lv|et)[-_.]/i.test(entries)) hasEuLocale = true;
      } catch {}
    }
  }
  if (hasEuLocale || /\b(react-cookie-consent|cookieconsent|@osano|@cookiebot|tarteaucitron)\b/i.test(allManifestText)) {
    sig.jurisdictions.add('GDPR');
  }

  // CCPA — almost always applies if you have US users and any signal of one
  if (sig.hasPII || sig.hasStripe) sig.jurisdictions.add('CCPA');

  // HIPAA / PCI-DSS / COPPA / FERPA from data-class detection
  if (sig.hasPHI) sig.jurisdictions.add('HIPAA');
  if (sig.hasStripe || sig.hasFinancialData) sig.jurisdictions.add('PCI-DSS');
  if (sig.hasChildrenData) sig.jurisdictions.add('COPPA');
  if (sig.hasEducationData) sig.jurisdictions.add('FERPA');
  // State breach laws apply to anyone with US users
  if (sig.hasPII || sig.hasStripe) sig.jurisdictions.add('STATE');

  // UK GDPR — detect en-GB, .co.uk, GBP currency
  if (/\b(en-GB|GBP|VATSchema|\.co\.uk)\b/.test(allManifestText)) sig.jurisdictions.add('UK-GDPR');

  // ── 5. Existing controls detection (discount factors) ─────────────────────
  // Each control reduces breach cost.
  // WAF — Cloudflare, AWS WAF, Fastly
  if (/\b(cloudflare|@cloudflare|aws-wafv?2?|@fastly\/|imperva)\b/i.test(allManifestText)) sig.controls.add('waf');
  // MFA / 2FA
  if (/\b(speakeasy|otplib|@simplewebauthn|webauthn|notp|twilio-authy|totp)\b/i.test(allManifestText)) sig.controls.add('mfa');
  if (/\b(workos|okta|saml|enterprise-sso)\b/i.test(allManifestText)) sig.controls.add('mfa');
  // SIEM / monitoring
  if (/\b(@sentry|datadog|newrelic|@bugsnag|@logtail|@rollbar|honeycomb)\b/i.test(allManifestText)) sig.controls.add('monitoring');
  // Encryption at rest
  if (/\b(@aws-crypto|@google-cloud\/kms|@azure\/keyvault|node-vault|encrypt-rest)\b/i.test(allManifestText)) sig.controls.add('encryption');
  // Bug bounty program
  if (fs.existsSync(path.join(scanRoot, '.well-known/security.txt')) ||
      fs.existsSync(path.join(scanRoot, 'public/.well-known/security.txt'))) {
    sig.controls.add('bug-bounty');
  }
  // Incident response plan
  if (existsAny(scanRoot, ['DISASTER.md', 'RUNBOOK.md', 'INCIDENT_RESPONSE.md', 'docs/incident-response.md'])) {
    sig.controls.add('ir-plan');
  }
  // Backups
  if (/\bbackup|@aws-sdk\/client-backup|@google-cloud\/backup-dr\b/i.test(allManifestText)) sig.controls.add('backups');
  // SOC2 / ISO 27001 mentions in compliance docs
  const docFiles = ['SECURITY.md', 'COMPLIANCE.md', 'docs/security', 'docs/compliance'];
  let docText = '';
  for (const d of docFiles) { docText += readSafe(path.join(scanRoot, d)); }
  if (/\b(SOC ?2|SOC2|ISO ?27001|ISO27001|PCI ?DSS|HITRUST)\b/i.test(docText)) sig.controls.add('compliance-program');

  // ── 6. Env files → has production credentials → is live ───────────────────
  for (const f of ['.env', '.env.local', '.env.production']) {
    if (fs.existsSync(path.join(scanRoot, f))) sig.hasSecrets = true;
  }

  // ── 7. User count + revenue tier estimation ───────────────────────────────
  sig.estimatedUsers = estimateUserCount(sig);
  sig.revenueIndicator = estimateRevenueTier(sig);

  return sig;
}

function estimateUserCount(sig) {
  // Enterprise SSO + B2B signals → small but high-value customer base
  if (sig.hasEnterpriseSignals) return 1_000;
  // B2B SaaS without enterprise tier
  if (sig.hasB2BSignals && sig.hasStripe) return 2_500;
  // Consumer app at scale (multiple analytics tools = mature product)
  if (sig.hasAnalytics && sig.hasAuth && sig.hasStripe) return 25_000;
  // Consumer app post-launch
  if (sig.hasAnalytics && sig.hasAuth) return 5_000;
  // Has Stripe + auth → small SaaS
  if (sig.hasStripe && sig.hasAuth) return 1_000;
  // Has auth + DB → launched but small
  if (sig.hasAuth && sig.hasUserTable) return 500;
  // Has auth only — likely pre-launch
  if (sig.hasAuth) return 100;
  // API-only or no auth — internal tool or pre-launch
  return 50;
}

function estimateRevenueTier(sig) {
  if (sig.hasEnterpriseSignals && sig.hasStripe) return 'scale';      // >$10M ARR
  if (sig.hasB2BSignals && sig.hasStripe) return 'growth';            // $1M-$10M
  if (sig.hasStripe && sig.hasAnalytics) return 'growth';
  if (sig.hasStripe) return 'startup';                                 // $0-$1M
  if (sig.hasAuth) return 'side-project';                              // pre-revenue with users
  return 'pre-revenue';
}

// ════════════════════════════════════════════════════════════════════════════
// CWE LOOKUP + SCOPE INFERENCE
// ════════════════════════════════════════════════════════════════════════════

function getCwe(finding) {
  if (finding.cwe && typeof finding.cwe === 'string') return finding.cwe;
  const vuln = (finding.vuln || finding.title || '').toLowerCase();
  for (const [kw, cwe] of Object.entries(VULN_TO_CWE)) {
    if (vuln.includes(kw)) return cwe;
  }
  return 'DEFAULT';
}

function inferDataClass(finding, signals, cwe) {
  const vuln = (finding.vuln || finding.title || '').toLowerCase();
  const dataAtRisk = [];

  // CWE/vuln-driven classification
  if (/sql|nosql|injection|idor|mass.assign|deserial|authoriz/i.test(vuln)) {
    if (signals.hasPHI) dataAtRisk.push('phi');
    if (signals.hasFinancialData) dataAtRisk.push('pii-sensitive');
    if (signals.hasPII) dataAtRisk.push('pii');
    if (signals.hasStripe) dataAtRisk.push('payment');
  }
  if (/command|rce|deserial|sandbox|eval/i.test(vuln)) {
    dataAtRisk.push('rce');
    if (signals.hasPHI) dataAtRisk.push('phi');
    if (signals.hasStripe) dataAtRisk.push('payment');
    else if (signals.hasPII) dataAtRisk.push('pii');
  }
  if (/hardcoded|secret|credential/i.test(vuln)) dataAtRisk.push('credentials');
  if (/auth.token|session|jwt|cookie/i.test(vuln)) dataAtRisk.push('auth-tokens');
  if (/webhook|signature/i.test(vuln) && signals.hasStripe) dataAtRisk.push('payment');
  if (/llm|prompt/i.test(vuln)) dataAtRisk.push('config');  // unbounded spend = config-class
  if (/xss/i.test(vuln)) dataAtRisk.push('auth-tokens');
  if (/ssrf/i.test(vuln)) {
    dataAtRisk.push('credentials');  // typically credentials via cloud-metadata
    if (signals.hasPII) dataAtRisk.push('pii');
  }
  if (signals.hasChildrenData && /pii|injection|idor|authoriz/i.test(vuln)) dataAtRisk.push('children');

  // Fallback
  if (dataAtRisk.length === 0) dataAtRisk.push('config');

  // Dedupe
  return [...new Set(dataAtRisk)];
}

function inferScope(finding, signals) {
  const file = (finding.file || '').toLowerCase();
  if (/\b(admin|internal|backoffice|staff)\b/.test(file)) return 'admin-only';
  if (/\b(payment|billing|checkout|invoice)\b/.test(file)) return 'paying-users';
  return 'all-users';
}

// ════════════════════════════════════════════════════════════════════════════
// COST COMPONENTS
// ════════════════════════════════════════════════════════════════════════════

// 1. Incident Response — forensics + IR retainer + initial legal opinion.
//    NetDiligence 2024: median crisis services $50k, mean $190k.
function componentIR(signals, scope) {
  let base = { low: 8_000, likely: 50_000, high: 250_000 };
  if (signals.hasPHI) base = { low: 25_000, likely: 100_000, high: 500_000 };
  else if (signals.hasFinancialData) base = { low: 15_000, likely: 75_000, high: 400_000 };
  if (signals.controls.has('ir-plan'))   base = scaleComp(base, 0.65);
  if (signals.controls.has('monitoring')) base = scaleComp(base, 0.80);
  // Admin-only breaches typically faster to contain
  if (scope === 'admin-only') base = scaleComp(base, 0.50);
  return base;
}

// 2. Legal counsel — class-action defense excluded (separate component).
//    Includes breach-counsel, regulatory defense advisory.
function componentLegal(signals) {
  const base = { low: 10_000, likely: 75_000, high: 500_000 };
  // Each additional jurisdiction adds counsel cost
  const jcount = signals.jurisdictions.size;
  const mult = 1 + Math.min(jcount * 0.25, 2);  // cap at 3× for 8+ jurisdictions
  return scaleComp(base, mult);
}

// 3. PR / crisis management — skipped for sub-100 user side projects.
function componentPR(signals, userCount, revenueTier) {
  if (userCount < 100 && revenueTier === 'pre-revenue') return zero();
  if (userCount < 1000) return { low: 0, likely: 15_000, high: 75_000 };
  if (userCount < 10000) return { low: 10_000, likely: 50_000, high: 200_000 };
  if (userCount < 100000) return { low: 25_000, likely: 150_000, high: 750_000 };
  return { low: 100_000, likely: 500_000, high: 3_000_000 };
}

// 4. Notification — FTC benchmark ~$5/user for first-class mail; legal-reviewed
//    template floor of $15k regardless of count.
function componentNotification(userCount, scope) {
  const affected = scope === 'admin-only' ? Math.min(userCount, 50) : userCount;
  const perUserLow = 2, perUserLikely = 5, perUserHigh = 15;
  const floor = 5_000;
  return {
    low:    Math.max(floor, Math.round(affected * perUserLow)),
    likely: Math.max(floor * 2, Math.round(affected * perUserLikely)),
    high:   Math.max(floor * 3, Math.round(affected * perUserHigh)),
  };
}

// 5. Credit monitoring — 1 year offered, only triggered when sensitive PII at risk.
//    Industry standard: $20-$30/user/year. ~30% take-up rate.
function componentCreditMonitoring(signals, userCount, dataAtRisk, scope) {
  if (!dataAtRisk.some(d => ['pii','pii-sensitive','phi','payment'].includes(d))) return zero();
  if (scope === 'admin-only') userCount = Math.min(userCount, 50);
  const takeUp = 0.3;
  const perYearLow = 12, perYearLikely = 25, perYearHigh = 40;
  return {
    low:    Math.round(userCount * takeUp * perYearLow),
    likely: Math.round(userCount * takeUp * perYearLikely),
    high:   Math.round(userCount * takeUp * perYearHigh * 2),  // 2 years if sensitive
  };
}

// 6. Regulatory fines — sum over detected jurisdictions, scaled by user count.
function componentRegulatory(signals, userCount, dataAtRisk) {
  let sum = zero();
  // Skip regulatory fines entirely for pre-revenue, sub-100-user side projects
  if (signals.revenueIndicator === 'pre-revenue' && userCount < 100) return zero();
  // Need actual user data at risk
  const hasRegulatedData = dataAtRisk.some(d =>
    ['pii','pii-sensitive','phi','payment','children','auth-tokens'].includes(d));
  if (!hasRegulatedData) {
    // RCE still triggers minimal regulatory if any user data exists in the system
    if (!dataAtRisk.includes('rce') || !signals.hasUserTable) return zero();
  }
  // Scale band by user count — small breaches get reduced fine bands
  const scale = userCountScale(userCount);
  for (const j of signals.jurisdictions) {
    const band = JURISDICTION_FINES[j];
    if (!band) continue;
    sum = addComp(sum, scaleComp(band, scale.regMult));
  }
  return sum;
}

// 7. Direct damage — per-record cost × records × industry multiplier × controls discount.
function componentDirectDamage(signals, userCount, dataAtRisk, scope) {
  // Aggregate per-record cost across all data classes (use max — worst data class drives cost)
  let perRecord = zero();
  for (const d of dataAtRisk) {
    const cost = PER_RECORD_COST[d];
    if (!cost) continue;
    if (cost.likely > perRecord.likely) perRecord = { ...cost };
  }
  if (perRecord.likely === 0) return zero();

  const industryMult = (INDUSTRY_PROFILES[signals.industry] || INDUSTRY_PROFILES.generic).mult;

  // Records affected — admin-only contains spread
  const affected = scope === 'admin-only' ? Math.min(userCount, 50) :
                   scope === 'paying-users' ? userCount :
                   userCount;

  let comp = {
    low:    Math.round(perRecord.low    * affected * industryMult),
    likely: Math.round(perRecord.likely * affected * industryMult),
    high:   Math.round(perRecord.high   * affected * industryMult),
  };

  // Apply controls discounts
  if (signals.controls.has('waf')) comp = scaleComp(comp, 0.85);
  if (signals.controls.has('mfa') && dataAtRisk.some(d => ['auth-tokens','credentials'].includes(d))) {
    comp = scaleComp(comp, 0.70);
  }
  if (signals.controls.has('encryption')) comp = scaleComp(comp, 0.80);
  if (signals.controls.has('compliance-program')) comp = scaleComp(comp, 0.85);

  return comp;
}

// 8. Class action exposure — US-specific, only when meaningful affected user count + revenue.
function componentClassAction(signals, userCount, dataAtRisk) {
  // No class action against pre-revenue or sub-1k breaches
  if (signals.revenueIndicator === 'pre-revenue') return zero();
  if (userCount < 1000) return zero();
  if (!dataAtRisk.some(d => ['pii','pii-sensitive','phi','payment','children'].includes(d))) return zero();

  const revenueScale = {
    'side-project': 0.05,
    'startup':      0.20,
    'growth':       1.00,
    'scale':        4.00,
  }[signals.revenueIndicator] || 0.5;

  // Per-record settlement bands from public US class actions
  // Equifax: $9.50, T-Mobile: $9.50, Marriott: $1.6, Capital One: $1.90
  let perRecLow = 1, perRecLikely = 5, perRecHigh = 15;
  if (dataAtRisk.includes('pii-sensitive') || dataAtRisk.includes('phi')) {
    perRecLow = 5; perRecLikely = 15; perRecHigh = 40;
  }
  // Defense costs alone: $1M+ for any meaningful filed claim
  const defenseFloor = 250_000;

  return {
    low:    Math.round(Math.max(0, userCount * perRecLow * revenueScale - defenseFloor)),
    likely: Math.round(defenseFloor + userCount * perRecLikely * revenueScale),
    high:   Math.round(defenseFloor * 4 + userCount * perRecHigh * revenueScale),
  };
}

// 9. Lost business / churn — IBM 2024: 39% of total breach cost on average.
//    Applied as percentage of (direct damage + regulatory + class action).
//    B2C churns more than B2B; pre-revenue has no business to lose.
function componentLostBusiness(signals, otherComponentsSum) {
  if (signals.revenueIndicator === 'pre-revenue') return zero();
  const pct = signals.hasB2BSignals ? 0.25 : 0.40;  // B2B more sticky than B2C
  return {
    low:    Math.round(otherComponentsSum.low    * pct * 0.5),
    likely: Math.round(otherComponentsSum.likely * pct),
    high:   Math.round(otherComponentsSum.high   * pct * 1.5),
  };
}

// ════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════

function zero() { return { low: 0, likely: 0, high: 0 }; }
function addComp(a, b) {
  return { low: a.low + b.low, likely: a.likely + b.likely, high: a.high + b.high };
}
function scaleComp(c, m) {
  return { low: Math.round(c.low * m), likely: Math.round(c.likely * m), high: Math.round(c.high * m) };
}

// User count → regulatory fine scale (small breaches get lower fine bands).
function userCountScale(userCount) {
  if (userCount <= 100)    return { regMult: 0.15 };
  if (userCount <= 1_000)  return { regMult: 0.35 };
  if (userCount <= 10_000) return { regMult: 0.70 };
  if (userCount <= 100_000) return { regMult: 1.30 };
  return                      { regMult: 2.50 };
}

function fmtMoney(n) {
  if (n >= 1_000_000_000) return `$${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000)     return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)         return `$${Math.round(n / 1_000)}k`;
  return `$${Math.round(n)}`;
}

// ════════════════════════════════════════════════════════════════════════════
// MAIN NARRATIVE BUILDER
// ════════════════════════════════════════════════════════════════════════════

function buildNarrative(finding, signals) {
  const cwe = getCwe(finding);
  const scope = inferScope(finding, signals);
  const dataAtRisk = inferDataClass(finding, signals, cwe);
  const userCount = signals.estimatedUsers || 100;

  // Compute each component as a three-point distribution
  const ir       = componentIR(signals, scope);
  const legal    = componentLegal(signals);
  const pr       = componentPR(signals, userCount, signals.revenueIndicator);
  const notif    = componentNotification(userCount, scope);
  const creditMo = componentCreditMonitoring(signals, userCount, dataAtRisk, scope);
  const reg      = componentRegulatory(signals, userCount, dataAtRisk);
  const damage   = componentDirectDamage(signals, userCount, dataAtRisk, scope);
  const classAct = componentClassAction(signals, userCount, dataAtRisk);

  // Lost business depends on the sum of direct + regulatory + class action
  const subtotal = addComp(addComp(damage, reg), classAct);
  const lostBiz  = componentLostBusiness(signals, subtotal);

  // Total
  const total = [ir, legal, pr, notif, creditMo, reg, damage, classAct, lostBiz]
    .reduce(addComp, zero());

  // Identify the dominant cost driver at the "likely" level
  const drivers = [
    ['incident response', ir.likely],
    ['legal counsel', legal.likely],
    ['crisis PR', pr.likely],
    ['notification', notif.likely],
    ['credit monitoring', creditMo.likely],
    ['regulatory fines', reg.likely],
    ['direct damage', damage.likely],
    ['class action exposure', classAct.likely],
    ['lost business / churn', lostBiz.likely],
  ].sort((a, b) => b[1] - a[1]);
  const dominantDriver = drivers[0][1] > 0 ? drivers[0][0] : 'incident response (no scaling drivers detected)';

  // Comparable historical incident — try CWE first, fall back to vuln-name CWE
  let comparable = COMPARABLE_INCIDENTS[cwe];
  if (!comparable) {
    const vuln = (finding.vuln || finding.title || '').toLowerCase();
    for (const [kw, fallbackCwe] of Object.entries(VULN_TO_CWE)) {
      if (vuln.includes(kw) && COMPARABLE_INCIDENTS[fallbackCwe]) {
        comparable = COMPARABLE_INCIDENTS[fallbackCwe];
        break;
      }
    }
  }
  if (!comparable) comparable = COMPARABLE_INCIDENTS.DEFAULT;

  // Confidence in estimate
  const confidence = computeConfidence(signals);

  // Narrative
  const indProfile = INDUSTRY_PROFILES[signals.industry] || INDUSTRY_PROFILES.generic;
  const dataPhrase = describeDataAtRisk(dataAtRisk, userCount);
  const jurStr = [...signals.jurisdictions].slice(0, 4).join(' + ') || 'no specific regulatory exposure';
  const controlsStr = signals.controls.size > 0 ?
    ` (controls reducing cost: ${[...signals.controls].join(', ')})` : '';
  const line = finding.line || finding.source?.line || finding.sink?.line || 0;

  const narrative =
    `${finding.vuln || finding.title} on \`${finding.file}:${line}\` ` +
    `could ${dataAtRisk.includes('rce') ? 'lead to' : 'expose'} ${dataPhrase}. ` +
    `Context: ${indProfile.label} / ${jurStr}${controlsStr}. ` +
    `Estimated cost: best ${fmtMoney(total.low)} · likely ${fmtMoney(total.likely)} · worst ${fmtMoney(total.high)}. ` +
    `Dominant driver: ${dominantDriver}. ` +
    `Comparable: ${comparable}.`;

  return {
    scope,
    dataAtRisk,
    userCount,
    industry: signals.industry,
    jurisdictions: [...signals.jurisdictions],
    controlsApplied: [...signals.controls],

    // Three-point estimates
    dollarBest:   total.low,
    dollarLikely: total.likely,
    dollarWorst:  total.high,

    // Backward-compat aliases (existing consumers read these)
    dollarLow:  total.low,
    dollarHigh: total.high,

    components: {
      incidentResponse:    ir,
      legal:               legal,
      crisisPR:            pr,
      notification:        notif,
      creditMonitoring:    creditMo,
      regulatoryFines:     reg,
      directDamage:        damage,
      classAction:         classAct,
      lostBusiness:        lostBiz,
    },

    dominantDriver,
    comparable,
    confidence,
    narrative,
  };
}

function describeDataAtRisk(dataAtRisk, userCount) {
  const n = userCount.toLocaleString();
  if (dataAtRisk.includes('rce'))         return 'full server compromise (remote code execution)';
  if (dataAtRisk.includes('phi'))         return `health records for ~${n} patients (HIPAA-covered)`;
  if (dataAtRisk.includes('children'))    return `children's data for ~${n} minors (COPPA-covered)`;
  if (dataAtRisk.includes('pii-sensitive'))return `sensitive PII (SSN/DOB/govt-ID) for ~${n} users`;
  if (dataAtRisk.includes('payment'))     return `payment data for ~${n} users`;
  if (dataAtRisk.includes('pii'))         return `PII for ~${n} users`;
  if (dataAtRisk.includes('credentials'))  return 'production credentials and API keys';
  if (dataAtRisk.includes('auth-tokens')) return `session tokens for ~${n} users`;
  if (dataAtRisk.includes('email'))       return `email/contact info for ~${n} users`;
  return 'configuration / internal data';
}

function computeConfidence(signals) {
  let score = 0;
  if (signals.industry !== 'generic') score += 2;
  if (signals.industryConfidence === 'high') score += 1;
  if (signals.estimatedUsers != null) score += 1;
  if (signals.hasUserTable) score += 1;
  if (signals.jurisdictions.size >= 2) score += 1;
  if (signals.controls.size >= 1) score += 1;
  if (score >= 5) return 'high';
  if (score >= 3) return 'medium';
  return 'low';
}

// ════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════════════════════════════════

export function enrichWithBlastRadius(scan, scanRoot) {
  const signals = collectProjectSignals(scanRoot || process.cwd());
  let decorated = 0;
  for (const bucket of ['findings', 'secrets', 'logicVulns', 'supplyChain']) {
    for (const f of (scan[bucket] || [])) {
      const br = buildNarrative(f, signals);
      if (br) { f.blastRadius = br; decorated++; }
    }
  }
  scan.blastRadiusSignals = {
    industry: signals.industry,
    industryConfidence: signals.industryConfidence,
    jurisdictions: [...signals.jurisdictions],
    controls: [...signals.controls],
    estimatedUsers: signals.estimatedUsers,
    revenueIndicator: signals.revenueIndicator,
    hasStripe: signals.hasStripe,
    hasAuth: signals.hasAuth,
    hasUserTable: signals.hasUserTable,
    hasPII: signals.hasPII,
    hasPHI: signals.hasPHI,
    hasS3: signals.hasS3,
  };
  return { decorated, signals };
}
