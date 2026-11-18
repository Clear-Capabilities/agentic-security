// Synthetic fixture: the add handler enforces the predicate the listing filters with.
public class GroupRolesResource {
    @GET
    public Stream<RoleRep> available() {
        view.require();
        return roles.all().filter(perms::canGrantRole).map(RoleRep::of);
    }

    @POST
    public void addRoles(List<RoleRep> picked) {
        manage.require();
        for (RoleRep rep : picked) {
            Role role = roles.byName(rep.getName());
            if (role == null) throw new NotFoundException();
            perms.requireGrantRole(role);
            group.grantRole(role);
        }
    }
}
