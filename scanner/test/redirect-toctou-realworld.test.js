// Fixture-first rebuild of the T4.5 toctou-resolve rule against the actual
// vulnerable/fixed code from GHSA-ch52-px8q-f22j (TryGhost/Ghost). Written
// BEFORE the rule was touched — it failed on both counts, which is the
// evidence the original rule was written from the PRD's prose summary
// rather than this file.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanRedirectToctou } from '../src/sast/redirect-toctou.js';

// Trimmed verbatim from ghost/core/core/server/lib/request-external.js pre/.
const PRE = `
const dnsPromises = require('dns').promises;

async function errorIfHostnameResolvesToPrivateIp(options) {
    if (config.get('env') === 'development') {
        return;
    }

    const siteUrl = new URL(config.get('url'));
    const requestUrl = new URL(options.url.href);
    if (requestUrl.host === siteUrl.host) {
        return;
    }

    const result = await dnsPromises.lookup(options.url.hostname);

    if (isPrivateIp(result.address)) {
        return Promise.reject(new errors.InternalServerError({
            message: 'URL resolves to a non-permitted private IP block',
            code: 'URL_PRIVATE_INVALID',
            context: options.url.href
        }));
    }
}

const gotOpts = {
    hooks: {
        beforeRequest: [errorIfInvalidUrl, errorIfHostnameResolvesToPrivateIp],
        beforeRedirect: [errorIfHostnameResolvesToPrivateIp]
    }
};
const externalRequest = got.extend(gotOpts);
module.exports = externalRequest;
`;

// The real fix does NOT pin-and-reuse the resolved address (the shape the
// original rule's PIN_RE was written to expect). It installs a custom
// 'lookup' hook so the SAME resolution used at connect time is the one that
// gets validated — a connect-time revalidation gate, not a cache.
const POST = PRE.replace(
  'const gotOpts = {',
  `function installSafeDnsLookup(options) {
    if (config.get('env') === 'development') {
        return;
    }
    const siteUrl = new URL(config.get('url'));
    if (options.url.host === siteUrl.host) {
        return;
    }
    options.lookup = (hostname, dnsOpts, callback) => {
        dns.lookup(hostname, dnsOpts, (err, address, family) => {
            if (err) return callback(err, address, family);
            if (isPrivateIp(address)) {
                return callback(new errors.InternalServerError({
                    message: 'URL resolves to a non-permitted private IP block',
                    code: 'URL_PRIVATE_INVALID',
                    context: options.url.href
                }));
            }
            callback(null, address, family);
        });
    };
}

const gotOpts = {`,
).replace(
  'beforeRequest: [errorIfInvalidUrl, errorIfHostnameResolvesToPrivateIp],\n        beforeRedirect: [errorIfHostnameResolvesToPrivateIp]',
  'beforeRequest: [errorIfInvalidUrl, errorIfHostnameResolvesToPrivateIp, installSafeDnsLookup],\n        beforeRedirect: [errorIfHostnameResolvesToPrivateIp, installSafeDnsLookup]',
);

test('T4.5 fires on the real vulnerable request-external.js (dnsPromises.lookup, not dns.lookup)', () => {
  const findings = scanRedirectToctou('request-external.js', PRE);
  assert.ok(findings.some(f => f.subfamily === 'toctou-resolve'),
    'dnsPromises.lookup should be recognised as a resolve call, not just dns.lookup/gethostbyname');
});

test('T4.5 is silent on the real fixed request-external.js (connect-time lookup hook, not pin-and-reuse)', () => {
  const findings = scanRedirectToctou('request-external.js', POST);
  assert.ok(!findings.some(f => f.subfamily === 'toctou-resolve'),
    'a custom lookup hook that revalidates at connect time is a valid mitigation, not just literal pin-and-reuse');
});
