import { Hono } from "hono";

export function registerRoutes(app: Hono) {
  app.get("/health", (c) => c.json({ ok: true }));

  app.get("/v1/teams/:teamId/billing", async (c) => {
    const teamId = c.req.param("teamId");
    const denied = await requireTeamAccess(c, teamId);
    if (denied) return denied;
    return c.json(await loadBilling(teamId));
  });

  app.post("/v1/teams/:teamId/invites", async (c) => {
    const teamId = c.req.param("teamId");
    const denied = await requireTeamAccess(c, teamId);
    if (denied) return denied;
    return c.json(await createInvite(teamId, await c.req.json()));
  });

  app.delete("/v1/teams/:teamId", async (c) => {
    const teamId = c.req.param("teamId");
    const denied = await requireTeamAccess(c, teamId);
    if (denied) return denied;
    await deleteTeam(teamId);
    return c.body(null, 204);
  });

  app.get("/v1/teams/:teamId/audit-log", async (c) => {
    const teamId = c.req.param("teamId");
    return c.json(await loadAuditLog(teamId));
  });
}
