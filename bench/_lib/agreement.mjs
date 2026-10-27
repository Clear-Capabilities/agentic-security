// Inter-labeler agreement for the benches: percent agreement and Cohen's kappa for two labelers over a closed set of categories.
//
// Pure functions of the paired verdicts; nothing here reads a label file. Used by bench/dag/independent-haskell/lib.mjs for the two-labeler panel.
//
// kappa = (po - pe) / (1 - pe), where po is the observed agreement and pe the agreement expected if each labeler assigned categories independently
// at their own marginal rates. It is `null` (with a reason) when pe is 1: every verdict of both labelers is in one category, so agreement is
// guaranteed and says nothing (the "kappa paradox": high agreement with a skewed prevalence can still give a low or undefined kappa, which is why
// percent agreement and the confusion matrix are always reported beside it).

/**
 * @param {Array<[string,string]>} pairs [verdictA, verdictB] for each site both labelers saw
 * @param {string[]} categories every category that may appear (a verdict outside it is an error, never silently dropped)
 * @returns {{n:number, agreed:number, percentAgreement:number|null, expected:number|null, kappa:number|null, kappaUndefinedReason:string|null,
 *   matrix:Record<string,Record<string,number>>, marginalsA:Record<string,number>, marginalsB:Record<string,number>}}
 */
export function cohen(pairs, categories) {
  const cats = [...categories];
  const known = new Set(cats);
  const matrix = Object.fromEntries(cats.map((a) => [a, Object.fromEntries(cats.map((b) => [b, 0]))]));
  let agreed = 0;
  for (const [a, b] of pairs) {
    if (!known.has(a) || !known.has(b)) throw new Error(`verdict outside the category set: ${JSON.stringify([a, b])}`);
    matrix[a][b]++;
    if (a === b) agreed++;
  }
  const n = pairs.length;
  const marginalsA = Object.fromEntries(cats.map((c) => [c, cats.reduce((s, d) => s + matrix[c][d], 0)]));
  const marginalsB = Object.fromEntries(cats.map((c) => [c, cats.reduce((s, d) => s + matrix[d][c], 0)]));
  if (!n) return { n, agreed, percentAgreement: null, expected: null, kappa: null, kappaUndefinedReason: 'no paired verdicts', matrix, marginalsA, marginalsB };
  const po = agreed / n;
  const pe = cats.reduce((s, c) => s + (marginalsA[c] / n) * (marginalsB[c] / n), 0);
  const undefinedKappa = pe >= 1 - 1e-12;
  return {
    n, agreed, percentAgreement: po, expected: pe,
    kappa: undefinedKappa ? null : (po - pe) / (1 - pe),
    kappaUndefinedReason: undefinedKappa ? 'both labelers used a single category throughout, so agreement is guaranteed and kappa is undefined' : null,
    matrix, marginalsA, marginalsB,
  };
}
