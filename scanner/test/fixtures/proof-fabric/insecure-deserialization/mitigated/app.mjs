// Mitigated: parses as plain JSON only; the result is data, never code, and nothing is evaluated.
const payload = process.argv[2] || '';
try { JSON.parse(payload); } catch { /* ignore */ }
