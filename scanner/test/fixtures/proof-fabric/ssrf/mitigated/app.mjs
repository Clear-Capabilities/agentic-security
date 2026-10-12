// Mitigated: only an explicit allowlisted host may be requested.
const url = process.argv[2];
const ALLOWED = new Set(['example.invalid']);
try { const u = new URL(url); if (ALLOWED.has(u.hostname)) await fetch(url); } catch { /* ignore */ }
