// Stack-specific security playbook detector.
//
// Reads package.json / requirements.txt / Cargo.toml etc. to identify
// the project's tech stack, then returns a structured playbook of the
// security items that matter most for that specific combination.
//
// Playbook entries are returned as info-severity findings so they appear
// in the report without polluting the critical/high counts.

import * as fs from 'node:fs';
import * as path from 'node:path';

function _readJson(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } }
function _readText(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }

function _detectStack(scanRoot) {
  const stack = new Set();
  const pkg = _readJson(path.join(scanRoot, 'package.json'));
  if (pkg) {
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    const d = k => Object.keys(deps).some(n => n.toLowerCase() === k.toLowerCase());
    const dPartial = k => Object.keys(deps).some(n => n.toLowerCase().includes(k));

    if (d('next')) stack.add('nextjs');
    if (d('react') || d('react-dom')) stack.add('react');
    if (d('express')) stack.add('express');
    if (d('fastify')) stack.add('fastify');
    if (d('hono')) stack.add('hono');
    if (dPartial('@supabase')) stack.add('supabase');
    if (d('prisma') || d('@prisma/client')) stack.add('prisma');
    if (d('mongoose') || d('mongodb')) stack.add('mongodb');
    if (d('drizzle-orm')) stack.add('drizzle');
    if (d('stripe')) stack.add('stripe');
    if (dPartial('clerk')) stack.add('clerk');
    if (d('next-auth') || d('@auth/core')) stack.add('nextauth');
    if (d('lucia')) stack.add('lucia');
    if (dPartial('openai')) stack.add('openai');
    if (dPartial('@anthropic-ai')) stack.add('anthropic');
    if (dPartial('langchain') || dPartial('@langchain')) stack.add('langchain');
    if (d('trpc') || d('@trpc/server')) stack.add('trpc');
    if (d('graphql')) stack.add('graphql');
    if (d('socket.io')) stack.add('socketio');
    if (d('redis') || d('ioredis') || dPartial('@upstash/redis')) stack.add('redis');
    if (d('resend') || d('nodemailer') || d('@sendgrid/mail')) stack.add('email');
    if (dPartial('firebase')) stack.add('firebase');
    if (d('@aws-sdk/client-s3') || dPartial('aws-sdk')) stack.add('aws');
  }

  const reqTxt = _readText(path.join(scanRoot, 'requirements.txt')) || '';
  if (reqTxt) {
    if (/fastapi/i.test(reqTxt)) stack.add('fastapi');
    if (/django/i.test(reqTxt)) stack.add('django');
    if (/flask/i.test(reqTxt)) stack.add('flask');
    if (/sqlalchemy/i.test(reqTxt)) stack.add('sqlalchemy');
    if (/openai/i.test(reqTxt)) stack.add('openai');
    if (/anthropic/i.test(reqTxt)) stack.add('anthropic');
  }

  return stack;
}

// Playbook entries: each is { title, items: string[] }
function _buildPlaybook(stack) {
  const sections = [];

  // Next.js
  if (stack.has('nextjs')) {
    sections.push({ title: 'Next.js', items: [
      'Add security headers in next.config.js headers() — X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin',
      'Use Server Actions or API Routes for all data mutations — never expose business logic in client components',
      'Set NEXTAUTH_URL / AUTH_URL in every environment to prevent host-header CSRF',
      'Wrap the entire app in middleware auth checks — do not rely on individual page-level checks',
      'Avoid `dangerouslySetInnerHTML` — use DOMPurify or a sanitizer if HTML rendering is required',
    ]});
  }

  // Supabase
  if (stack.has('supabase')) {
    sections.push({ title: 'Supabase', items: [
      'Enable Row-Level Security (RLS) on EVERY table — ALTER TABLE x ENABLE ROW LEVEL SECURITY',
      'Never use the service-role key client-side or in NEXT_PUBLIC_ env vars — server only',
      'Audit your RLS policies: SELECT policies should require `auth.uid() = user_id` or similar',
      'Enable email confirmation in the Auth settings before going live',
      'Restrict which auth providers are enabled — disable unused ones in the dashboard',
      'Use Supabase Vault for storing sensitive secrets instead of plain text in tables',
    ]});
  }

  // Clerk
  if (stack.has('clerk')) {
    sections.push({ title: 'Clerk', items: [
      'Use clerkMiddleware() in middleware.ts and protect all routes by default — list exceptions explicitly',
      'Do not put admin/settings/dashboard paths in publicRoutes',
      'Enable MFA in Clerk dashboard for your own admin account and for high-value users',
      'Validate the userId / orgId from auth() server-side — never trust client-passed IDs',
      'Set sessionMaxAge to a reasonable value (e.g., 7 days) in Clerk dashboard',
    ]});
  }

  // NextAuth
  if (stack.has('nextauth')) {
    sections.push({ title: 'NextAuth / Auth.js', items: [
      'Set NEXTAUTH_SECRET to a 32+ byte random value: `openssl rand -base64 32`',
      'Set NEXTAUTH_URL to your canonical production URL — prevents host-header CSRF',
      'Do not set trustHost: true in production',
      'Do not set allowDangerousEmailAccountLinking: true unless you fully understand the account-takeover risk',
      'Protect all API routes and pages with getServerSession() — the client session is not authoritative',
      'Use database sessions (adapter) rather than JWT sessions if you need immediate revocation',
    ]});
  }

  // Stripe
  if (stack.has('stripe')) {
    sections.push({ title: 'Stripe', items: [
      'Verify webhook signatures using stripe.webhooks.constructEvent() — never trust unverified webhook payloads',
      'Store STRIPE_SECRET_KEY server-side only — never client-side or in NEXT_PUBLIC_',
      'Use Stripe Checkout or Payment Element instead of rolling your own card form',
      'Enable Radar rules in the Stripe dashboard to block card-testing attacks',
      'Always fetch the current price from Stripe server-side — never trust the client-supplied price',
      'Test with Stripe CLI webhook forwarding locally — do not expose your dev server publicly',
    ]});
  }

  // Prisma / Drizzle
  if (stack.has('prisma') || stack.has('drizzle')) {
    const orm = stack.has('prisma') ? 'Prisma' : 'Drizzle';
    sections.push({ title: orm, items: [
      `Never use raw SQL (\`${stack.has('prisma') ? 'prisma.$queryRawUnsafe' : 'sql.raw'}\`) with user input — use parameterised queries only`,
      'Scope all queries to the authenticated user — add `where: { userId: session.userId }` to every user-data query',
      'Store DATABASE_URL in env only — use connection pooling (PgBouncer/Supabase pooler) in production',
      'Add `@@map` to rename table names if your schema column names match internal business logic you want to keep private',
    ]});
  }

  // MongoDB / Mongoose
  if (stack.has('mongodb')) {
    sections.push({ title: 'MongoDB', items: [
      'Sanitize all user input with mongoose-sanitize or express-mongo-sanitize to prevent NoSQL injection',
      'Never use `$where` with user-controlled expressions',
      'Enable MongoDB auth (username/password) even in development',
      'Scope queries to authenticated user: `{ _id: req.params.id, userId: session.userId }`',
      'Enable MongoDB Atlas IP allowlist to restrict which IPs can connect',
    ]});
  }

  // OpenAI / Anthropic / LangChain
  if (stack.has('openai') || stack.has('anthropic') || stack.has('langchain')) {
    sections.push({ title: 'AI / LLM', items: [
      'Rate-limit your AI endpoints — a single attacker can exhaust your monthly budget in minutes',
      'Never include other users\' data in prompts — prompt context must be scoped to the requesting user',
      'Set max_tokens on every API call to cap per-request cost',
      'Validate and sanitize AI output before rendering — treat it as untrusted user input',
      'Store OPENAI_API_KEY / ANTHROPIC_API_KEY server-side only — never in NEXT_PUBLIC_ or client bundles',
      'Add per-user spend limits and alert thresholds in the provider dashboard',
    ]});
  }

  // Email
  if (stack.has('email')) {
    sections.push({ title: 'Email / Transactional', items: [
      'Rate-limit email-sending endpoints — unlimited sign-up/contact forms are spam vectors',
      'Validate the To: address server-side — never let users supply arbitrary email recipients',
      'Store email API keys (Resend, SendGrid) server-side only',
      'Configure SPF, DKIM, and DMARC records to prevent email spoofing from your domain',
    ]});
  }

  // tRPC
  if (stack.has('trpc')) {
    sections.push({ title: 'tRPC', items: [
      'Apply auth middleware to all protected procedures — do not rely on client-side route guards',
      'Use `ctx.session.userId` for all data access — never trust input IDs without ownership check',
      'Enable CORS only for your own domains in the tRPC HTTP adapter',
    ]});
  }

  // FastAPI
  if (stack.has('fastapi')) {
    sections.push({ title: 'FastAPI', items: [
      'Use OAuth2PasswordBearer or a JWT dependency on every protected route',
      'Enable CORS middleware with an explicit allow_origins list — never ["*"] in production',
      'Set SECRET_KEY to a 32+ byte random value and store in environment, not in code',
      'Use Pydantic models for all request bodies to enforce input validation',
      'Disable the /docs and /redoc endpoints in production: `docs_url=None, redoc_url=None`',
    ]});
  }

  // Express
  if (stack.has('express')) {
    sections.push({ title: 'Express', items: [
      'Use helmet() to set security headers (X-Frame-Options, X-Content-Type-Options, HSTS) — Express sets none of these by default',
      'Never use body-parser / express.json() without a size limit — set `limit` explicitly to prevent request-body DoS',
      'Apply express-rate-limit to authentication and any expensive routes',
      'Validate and sanitize all req.params / req.query / req.body — Express does not validate input for you',
      'Set `app.disable(\'x-powered-by\')` so error responses and headers do not advertise the framework/version to attackers',
      'Use a CSRF middleware (e.g. csrf-csrf) on any route that relies on cookie-based sessions',
    ]});
  }

  // Django
  if (stack.has('django')) {
    sections.push({ title: 'Django', items: [
      'Set DEBUG=False in production — DEBUG mode exposes tracebacks with local variables',
      'Set SECRET_KEY from environment — never hardcode it in settings.py',
      'Configure ALLOWED_HOSTS — an empty list in production causes 500 errors on valid requests',
      'Use Django\'s built-in CSRF middleware — never exempt views unnecessarily',
      'Use `django.contrib.security` middleware stack in MIDDLEWARE setting',
    ]});
  }

  return sections;
}

function _findingFromItem(scanRoot, stackName, item, idx) {
  return {
    id: `stack-playbook:${stackName.replace(/\s+/g, '_').toUpperCase()}:${idx}`,
    // The findings schema requires `vuln` (root CLAUDE.md); this used to set
    // `title` instead, which isn't a schema field at all. engine.js's generic
    // no-vuln-name filter (`_shouldKeep`) treats any non-SCA finding with no
    // `vuln` string as unenriched noise and drops it — silently, for every
    // stack, confirmed live via a real scan whose logicVulns went from 6
    // playbook findings right after they were pushed to 0 by the time the
    // scan returned. `vuln` is now the actionable string this finding is
    // actually about; `description`/`remediation` (already correct) keep
    // the fuller text.
    vuln: `[${stackName} Security Checklist] ${item.slice(0, 80)}`,
    severity: 'info',
    file: 'package.json',
    line: 1,
    description: item,
    remediation: item,
    cwe: 'CWE-1008',
  };
}

function runStackPlaybook(scanRoot) {
  if (!scanRoot) return [];
  const stack = _detectStack(scanRoot);
  if (stack.size === 0) return [];
  const playbook = _buildPlaybook(stack);
  const findings = [];
  for (const section of playbook) {
    section.items.forEach((item, i) => {
      findings.push(_findingFromItem(scanRoot, section.title, item, i));
    });
  }
  return { stack: [...stack], playbook, findings };
}

export { runStackPlaybook, _detectStack, _buildPlaybook };
