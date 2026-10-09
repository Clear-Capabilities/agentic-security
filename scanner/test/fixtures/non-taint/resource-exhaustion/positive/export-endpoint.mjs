// CSV export endpoint. The page size comes from the query string and is used as a loop bound with no ceiling.
// Vulnerable: a huge limit keeps the worker busy far past any request budget.
export function exportRows(limitParam) {
  const limit = Number(limitParam);
  let checksum = 0;
  for (let i = 0; i < limit; i++) checksum = (checksum + i * 31) % 1000003;
  return { rows: Math.min(limit, 1000), checksum };
}
