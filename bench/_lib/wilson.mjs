// The one Wilson score interval for the benches. It used to be copied into three places under bench/dag/ (the development-set scorer, the fresh-set
// scorer and the independent Haskell set's lib), each free to drift from the others; a precision interval that differs by bench is a number nobody can
// compare. Importing this keeps them the same.
//
// wilson(k, n[, z]) -> [lower, upper] clamped to [0, 1], or null when n is 0 (no observations is not an interval). z defaults to 1.959964 (95%).
export function wilson(k, n, z = 1.959964) {
  if (!n) return null;
  const p = k / n;
  const d = 1 + z * z / n;
  const c = p + z * z / (2 * n);
  const m = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n));
  return [Math.max(0, (c - m) / d), Math.min(1, (c + m) / d)];
}
