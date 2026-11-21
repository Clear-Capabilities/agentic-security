export async function verifyCaller(header: string | undefined) {
  return { ok: Boolean(header), scopes: header ? header.split(",") : [] };
}
