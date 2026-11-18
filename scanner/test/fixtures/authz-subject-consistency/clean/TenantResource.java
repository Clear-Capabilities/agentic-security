// Synthetic fixture: every handler that takes a tenant checks that the caller may act in it.
public class TenantResource {
    public void rename(String tenant, String deviceId, String name) {
        throwIfCannotManageTenant(tenant);
        devices.rename(tenant, deviceId, name);
    }

    public void remove(String tenant, String deviceId) {
        throwIfCannotManageTenant(tenant);
        devices.remove(tenant, deviceId);
    }

    public void create(String tenant, Device device) {
        throwIfCannotManageTenant(tenant);
        devices.create(tenant, device);
    }

    public void move(String tenant, String deviceId, String group) {
        throwIfCannotManageTenant(tenant);
        devices.move(tenant, deviceId, group);
    }

    public void renameAll(String tenant, String prefix) {
        rename(tenant, "*", prefix);
    }

    public Device get(String tenant, String deviceId) {
        throwIfCannotReadTenant(tenant);
        boolean admin = hasResourceRole(Roles.READ_ADMIN);
        if (!admin && !owns(deviceId)) {
            throw new ForbiddenException("not yours");
        }
        return devices.get(deviceId);
    }

    public String[] getUserRoles(String tenant, String userId) {
        throwIfCannotReadTenant(tenant);
        boolean admin = hasResourceRole(Roles.READ_ADMIN);
        if (!admin) {
            throw new ForbiddenException("admin only");
        }
        return users.roles(tenant, userId);
    }

    public void updateMine(String name) {
        String tenant = authContext.getAuthenticatedTenant();
        devices.renameOwn(tenant, name);
    }

    protected void throwIfCannotManageTenant(String tenant) {
        if (!authContext.canManage(tenant)) {
            throw new ForbiddenException("other tenant");
        }
    }

    protected void throwIfCannotReadTenant(String tenant) {
        if (!authContext.canRead(tenant)) {
            throw new ForbiddenException("other tenant");
        }
    }
}
