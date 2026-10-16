// Tying runtime observations to the code that was deployed (E5-02).
//
// A runtime observation is evidence about ONE running build. A static finding is evidence about ONE source snapshot. The two are the same subject only
// when the build is known to have been made from that snapshot. Without that tie, "this route received traffic" says nothing about whether the code
// that received it contained the finding, and calling it corroboration would be a false claim.
//
// WHAT TIES THEM. Four identity fields, compared when both sides have them:
//   commit       the git commit (a full sha, or a prefix of at least 12 hex characters)
//   buildHash    a build or reproducibility hash
//   imageDigest  the container image digest (sha256:...)
//   sbomRef      an SBOM or artifact reference
// plus the environment the observation came from, which must equal the environment the snapshot's deployment record names when both are present.
//
// THE RULES (each is a test)
//   mismatched   a field both sides carry DIFFERS, or the environments differ. One disagreement is enough, however many fields agree.
//   matched      at least one STRONG field (commit, buildHash or imageDigest) is present on both sides and equal, and nothing disagrees
//   unknown      no strong field is present on both sides: the observation carries no identity, the snapshot carries none, or they carry different kinds
//   A snapshot with uncommitted changes cannot be tied to a commit: a commit match is downgraded to `unknown` with that reason, because the code that was
//   scanned is not the code the commit names.
// Only `matched` may be labelled corroborating. `unknown` is unattested evidence; `mismatched` is excluded and counted.
export const STRONG_FIELDS = Object.freeze(['commit', 'buildHash', 'imageDigest']);
export const IDENTITY_FIELDS = Object.freeze(['commit', 'buildHash', 'imageDigest', 'sbomRef']);
const ATTR = Object.freeze({ commit: 'deployment.commit', buildHash: 'deployment.build', imageDigest: 'deployment.image.digest', sbomRef: 'deployment.sbom.ref' });
export const IDENTITY_ATTRIBUTE_KEYS = Object.freeze(Object.values(ATTR));

const hex = (s) => (typeof s === 'string' && /^[0-9a-f]{12,64}$/i.test(s) ? s.toLowerCase() : null);
const digest = (s) => { const m = typeof s === 'string' ? /^(?:sha256:)?([0-9a-f]{64})$/i.exec(s) : null; return m ? `sha256:${m[1].toLowerCase()}` : null; };
const token = (s) => (typeof s === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(s) ? s : null);

/** Normalise an identity-bearing object ({commit, buildHash, imageDigest, sbomRef, environment, dirty}) to comparable values; an unusable value becomes null. */
export function normalizeIdentity(raw) {
  const r = raw && typeof raw === 'object' ? raw : {};
  return { commit: hex(r.commit), buildHash: token(r.buildHash), imageDigest: digest(r.imageDigest), sbomRef: token(r.sbomRef), environment: token(r.environment), dirty: r.dirty === true };
}

/** The identity an observation carries, from its approved attributes and its environment. */
export function observationIdentity(obs) {
  const a = (obs && obs.attributes) || {};
  return normalizeIdentity({ commit: a[ATTR.commit], buildHash: a[ATTR.buildHash], imageDigest: a[ATTR.imageDigest], sbomRef: a[ATTR.sbomRef], environment: obs && obs.environment });
}

const sameCommit = (a, b) => { const n = Math.min(a.length, b.length); return n >= 12 && a.slice(0, n) === b.slice(0, n); };

/**
 * @param {object} observation a runtime observation (or an identity object)
 * @param {object} snapshot    the static snapshot's identity: {commit, buildHash, imageDigest, sbomRef, environment, dirty}
 * @returns {{state:'matched'|'mismatched'|'unknown', compared:string[], agreed:string[], disagreed:string[], reasons:string[]}}
 */
export function linkObservationToSnapshot(observation, snapshot) {
  const o = observation && observation.attributes !== undefined ? observationIdentity(observation) : normalizeIdentity(observation);
  const s = normalizeIdentity(snapshot);
  const compared = []; const agreed = []; const disagreed = []; const reasons = [];
  for (const f of IDENTITY_FIELDS) {
    if (o[f] == null || s[f] == null) continue;
    compared.push(f);
    const eq = f === 'commit' ? sameCommit(o[f], s[f]) : o[f] === s[f];
    (eq ? agreed : disagreed).push(f);
  }
  if (o.environment != null && s.environment != null) {
    compared.push('environment');
    if (o.environment === s.environment) agreed.push('environment'); else disagreed.push('environment');
  }
  if (disagreed.length) return { state: 'mismatched', compared, agreed, disagreed, reasons: disagreed.map((f) => `${f} differs between the observation and the snapshot`) };
  const strong = agreed.filter((f) => STRONG_FIELDS.includes(f));
  if (!strong.length) {
    if (o.commit == null && o.buildHash == null && o.imageDigest == null) reasons.push('the observation carries no commit, build hash or image digest');
    else if (s.commit == null && s.buildHash == null && s.imageDigest == null) reasons.push('the snapshot carries no commit, build hash or image digest');
    else reasons.push('the observation and the snapshot carry different kinds of identity, so none can be compared');
    return { state: 'unknown', compared, agreed, disagreed, reasons };
  }
  if (s.dirty && strong.length === 1 && strong[0] === 'commit') return { state: 'unknown', compared, agreed, disagreed, reasons: ['the snapshot has uncommitted changes: the code that was analysed is not the code the commit names'] };
  return { state: 'matched', compared, agreed, disagreed, reasons: [`${strong.join(', ')} agree and nothing disagrees`] };
}

/** True only for a link that may be called corroboration. */
export const canCorroborate = (link) => !!link && link.state === 'matched';
