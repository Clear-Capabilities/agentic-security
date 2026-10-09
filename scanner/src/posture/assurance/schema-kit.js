// Small validation primitives shared by the assurance evidence contracts
// (CORE-002). Pure: no fs, no clock, no network. Every validator returns
// `{ ok, errors }` where each error is `{ code, path, message }`; nothing throws
// on bad input, because a validator that throws on hostile input is a denial of
// service on whatever called it.

export const ERROR_CODES = Object.freeze([
  'NOT_AN_OBJECT', 'SCHEMA_MISMATCH', 'UNSUPPORTED_MAJOR', 'BAD_VERSION', 'MISSING_FIELD', 'UNKNOWN_FIELD',
  'BAD_TYPE', 'UNKNOWN_ENUM', 'BAD_DIGEST', 'BAD_ID', 'ID_MISMATCH', 'DUPLICATE_ID', 'DANGLING_REF', 'RULE_VIOLATION',
]);

export const SUPPORTED_MAJOR = 1;
export const SCHEMA_VERSION = '1.0.0';

const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

export function makeCtx() {
  const errors = [];
  return {
    errors,
    err(code, path, message) { errors.push({ code, path, message }); },
  };
}

export function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

export function isDigest(v) { return typeof v === 'string' && DIGEST.test(v); }
export function isCommit(v) { return typeof v === 'string' && COMMIT.test(v); }
export function isNonEmptyString(v) { return typeof v === 'string' && v.trim().length > 0; }

/** Header check: `schema` must match and the major version must be supported. */
export function checkHeader(ctx, rec, schemaName) {
  if (rec.schema !== schemaName) {
    ctx.err('SCHEMA_MISMATCH', 'schema', `expected schema '${schemaName}', got ${JSON.stringify(rec.schema)}`);
    return false;
  }
  const m = typeof rec.schemaVersion === 'string' ? SEMVER.exec(rec.schemaVersion) : null;
  if (!m) {
    ctx.err('BAD_VERSION', 'schemaVersion', `schemaVersion must be a semantic version, got ${JSON.stringify(rec.schemaVersion)}`);
    return false;
  }
  if (Number(m[1]) !== SUPPORTED_MAJOR) {
    ctx.err('UNSUPPORTED_MAJOR', 'schemaVersion', `major version ${m[1]} is not supported (supported: ${SUPPORTED_MAJOR})`);
    return false;
  }
  return true;
}

/** Closed world: any field outside `allowed` is rejected, never silently carried. */
export function checkFields(ctx, rec, allowed, required) {
  for (const k of Object.keys(rec)) {
    if (!allowed.includes(k)) ctx.err('UNKNOWN_FIELD', k, `field '${k}' is not part of this schema`);
  }
  for (const k of required) {
    if (rec[k] === undefined) ctx.err('MISSING_FIELD', k, `required field '${k}' is missing`);
  }
  // `createdAt` is informational and never enters an id; it must still be a string.
  if (rec.createdAt !== undefined && typeof rec.createdAt !== 'string') ctx.err('BAD_TYPE', 'createdAt', 'must be a string');
}

export function checkEnum(ctx, path, value, allowed) {
  if (typeof value !== 'string' || !allowed.includes(value)) {
    ctx.err('UNKNOWN_ENUM', path, `${JSON.stringify(value)} is not one of: ${allowed.join(', ')}`);
    return false;
  }
  return true;
}

export function checkDigest(ctx, path, value, { nullable = false } = {}) {
  if (value === null && nullable) return true;
  if (!isDigest(value)) { ctx.err('BAD_DIGEST', path, `must be 'sha256:' followed by 64 lowercase hex characters`); return false; }
  return true;
}

export function checkCommit(ctx, path, value, { nullable = true } = {}) {
  if (value === null && nullable) return true;
  if (!isCommit(value)) { ctx.err('BAD_TYPE', path, 'must be a 40 or 64 character lowercase hex commit id'); return false; }
  return true;
}

export function checkString(ctx, path, value) {
  if (!isNonEmptyString(value)) { ctx.err('BAD_TYPE', path, 'must be a non-empty string'); return false; }
  return true;
}

export function checkId(ctx, rec, expectedId) {
  const prefix = expectedId.split(':')[0];
  if (typeof rec.id !== 'string' || !rec.id.startsWith(`${prefix}:`)) {
    ctx.err('BAD_ID', 'id', `id must start with '${prefix}:'`);
  } else if (rec.id !== expectedId) {
    ctx.err('ID_MISMATCH', 'id', `id does not match the record's semantic content (expected ${expectedId})`);
  }
}

export function result(ctx) {
  return { ok: ctx.errors.length === 0, errors: ctx.errors };
}

/** Reject non-object input with one typed error instead of throwing downstream. */
export function guardObject(rec) {
  const ctx = makeCtx();
  if (!isPlainObject(rec)) {
    ctx.err('NOT_AN_OBJECT', '', 'record must be a plain object');
    return { ctx, ok: false };
  }
  return { ctx, ok: true };
}
