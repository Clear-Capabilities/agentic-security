import { authenticateHttpRequest, requireScopeForAction } from "./auth.js";

export async function handleInvoicesRequest(req: any, res: any) {
  const auth = await authenticateHttpRequest(req);
  if (!auth.ok) {
    res.statusCode = 401;
    return res.end();
  }
  const scope = requireScopeForAction("invoices.read", auth.scopes);
  if (!scope.allowed) {
    res.statusCode = 403;
    return res.end();
  }
  res.end(JSON.stringify({ invoices: [] }));
}
