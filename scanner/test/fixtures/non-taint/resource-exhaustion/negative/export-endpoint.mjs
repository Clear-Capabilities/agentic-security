// Same endpoint with a ceiling on the page size.
const MAX_ROWS = 1000;

export function exportRows(limitParam) {
  const limit = Math.min(Number(limitParam), MAX_ROWS);
  let checksum = 0;
  for (let i = 0; i < limit; i++) checksum = (checksum + i * 31) % 1000003;
  return { rows: limit, checksum };
}
