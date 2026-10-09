// Behaviour preserved: both declared cases return what they always did.
export function applyDiscount(cents, code) {
  if (code === 'SAVE10') return Math.round(cents * 0.9);
  return cents;
}
