// Synthetic fixture: the listing filters by a per-role predicate, the add handler does not enforce it.
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
            group.grantRole(role);
        }
    }
}
