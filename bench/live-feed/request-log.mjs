// Preloaded into the scanner process (node --import) so every outbound HTTP request the scan makes is counted from the outside.
// It records; it never blocks, rewrites or retries. One JSON object per line is appended to $LIVE_FEED_REQUEST_LOG.
// For the OSV batch query it also records how many packages were asked about, how many came back with advisory references and how many
// came back with a next-page token (the case the feed refuses to treat as covered).
import { appendFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';

const LOG = process.env.LIVE_FEED_REQUEST_LOG;
const note = (o) => { if (!LOG) return; try { appendFileSync(LOG, `${JSON.stringify(o)}\n`); } catch { /* the recorder must never break a scan */ } };

// The scanner's ordinary dependency checks (npm, PyPI, Maven, ...) also use api.osv.dev, so an OSV request is attributed to the Hackage feed
// only when it is a batch whose queries name the `Hackage` ecosystem, or a record fetch for an id that such a batch returned.
const hackageIds = new Set();
const realFetch = globalThis.fetch;
if (typeof realFetch === 'function') {
  globalThis.fetch = async function loggedFetch(input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    const method = (init && init.method) || (input && input.method) || 'GET';
    const t0 = Date.now();
    const batchEcosystems = (() => { if (!/\/v1\/querybatch$/.test(url)) return null; try { return [...new Set(JSON.parse(init.body).queries.map((x) => x && x.package && x.package.ecosystem))]; } catch { return []; } })();
    const hackageBatch = !!batchEcosystems && batchEcosystems.length === 1 && batchEcosystems[0] === 'Hackage';
    try {
      const resp = await realFetch.call(this, input, init);
      const entry = { via: 'fetch', method, url, status: resp.status, t0, t1: Date.now(), ...(batchEcosystems ? { feed: hackageBatch, ecosystems: batchEcosystems } : {}) };
      const recId = /\/v1\/vulns\/([^/?]+)$/.exec(url);
      if (recId) entry.feed = hackageIds.has(decodeURIComponent(recId[1]));
      if (/\/v1\/querybatch$/.test(url) && resp.status === 200) {
        try {
          const body = await resp.clone().json();
          const results = Array.isArray(body && body.results) ? body.results : [];
          const queries = (() => { try { return JSON.parse(init.body).queries; } catch { return []; } })();
          if (hackageBatch) for (const r of results) for (const v of (r && r.vulns) || []) if (v && typeof v.id === 'string') hackageIds.add(v.id);
          entry.batch = {
            queried: queries.length || null,
            results: results.length,
            withVulns: results.filter((r) => r && Array.isArray(r.vulns) && r.vulns.length).length,
            vulnRefs: results.reduce((n, r) => n + ((r && Array.isArray(r.vulns)) ? r.vulns.length : 0), 0),
            nextPage: results.filter((r) => r && r.next_page_token).length,
          };
        } catch { /* leave the batch summary out */ }
        entry.t1 = Date.now();
      }
      note(entry);
      return resp;
    } catch (e) {
      note({ via: 'fetch', method, url, status: null, error: String((e && e.message) || e).slice(0, 120), t0, t1: Date.now(), ...(batchEcosystems ? { feed: hackageBatch, ecosystems: batchEcosystems } : {}) });
      throw e;
    }
  };
}

for (const [mod, scheme] of [[http, 'http'], [https, 'https']]) {
  for (const fn of ['request', 'get']) {
    const real = mod[fn];
    mod[fn] = function loggedNodeRequest(...args) {
      try {
        const a0 = args[0];
        let url;
        if (typeof a0 === 'string') url = a0;
        else if (a0 instanceof URL) url = a0.href;
        else if (a0 && typeof a0 === 'object') url = `${scheme}://${a0.hostname || a0.host || '?'}${a0.path || ''}`;
        note({ via: `${scheme}.${fn}`, method: (a0 && a0.method) || 'GET', url: String(url).slice(0, 300), status: null, t0: Date.now(), t1: Date.now() });
      } catch { /* ignore */ }
      return real.apply(this, args);
    };
  }
}
syncBuiltinESMExports();
