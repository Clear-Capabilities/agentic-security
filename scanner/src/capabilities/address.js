// Host and address helpers for network policy (X-504). Pure.
import net from 'node:net';

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Canonical host: lower case, one trailing dot removed, IPv6 brackets removed.
 * Returns `{ ok, host, kind }` with kind `ip4`, `ip6` or `name`. Numeric forms
 * that are not a strict dotted quad (`2130706433`, `0x7f.1`, `127.1`) are
 * rejected, because different parsers read them as different addresses and a
 * policy must not be decided on a reading the connecting stack may not share.
 */
export function normalizeHost(raw) {
  if (typeof raw !== 'string') return { ok: false };
  let h = raw.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (h.endsWith('.') && h.length > 1) h = h.slice(0, -1);
  if (!h || h.length > 253 || /[^\x21-\x7e]/.test(h)) return { ok: false };
  const family = net.isIP(h);
  if (family === 4) return { ok: true, host: h, kind: 'ip4' };
  if (family === 6) return { ok: true, host: h, kind: 'ip6' };
  const labels = h.split('.');
  // A top-level label is never numeric; one that is (or starts 0x) is an address in disguise.
  if (/^(?:0x[0-9a-f]*|[0-9]+)$/.test(labels[labels.length - 1])) return { ok: false };
  if (!labels.every((l) => LABEL.test(l))) return { ok: false };
  return { ok: true, host: h, kind: 'name' };
}

function v4Parts(ip) { return ip.split('.').map(Number); }

function classifyV4(ip) {
  const [a, b] = v4Parts(ip);
  if (ip === '169.254.169.254') return 'metadata';
  if (a === 127) return 'loopback';
  if (a === 0) return 'unspecified';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return 'private';
  if (a === 169 && b === 254) return 'link-local';
  if (a >= 224 && a <= 239) return 'multicast';
  if (a >= 240) return 'reserved';
  return 'public';
}

/**
 * Class of an address: loopback, private, link-local, metadata, unspecified,
 * multicast, reserved or public. IPv4-mapped IPv6 is judged as the IPv4
 * address it carries. Anything that is not an address is `invalid`.
 */
export function classifyAddress(ip) {
  const family = net.isIP(ip);
  if (family === 4) return classifyV4(ip);
  if (family !== 6) return 'invalid';
  const l = ip.toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(l);
  if (mapped) return classifyV4(mapped[1]);
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(l);
  if (hex) {
    const hi = parseInt(hex[1], 16); const lo = parseInt(hex[2], 16);
    return classifyV4(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
  }
  if (l === '::1') return 'loopback';
  if (l === '::') return 'unspecified';
  if (l.startsWith('fd00:ec2::254')) return 'metadata';
  const first = parseInt(l.split(':')[0] || '0', 16);
  if ((first & 0xfe00) === 0xfc00) return 'private';
  if ((first & 0xffc0) === 0xfe80) return 'link-local';
  if ((first & 0xff00) === 0xff00) return 'multicast';
  return 'public';
}

/** Non-public classes a host name must not resolve to unless declared. */
export function isNonPublicClass(cls) {
  return cls !== 'public';
}
