// Synthetic fixture: the siblings' only "guard" is a null check, which is
// shape validation, not security handling, so it establishes no convention.
package example.oauth;

import java.util.Objects;

public class ProfileService {
    private final ProfileRepository repo;

    public Profile rename(long id, String displayName) {
        Objects.requireNonNull(displayName);
        Profile p = repo.findById(id);
        p.setDisplayName(displayName);
        return repo.save(p);
    }

    public Profile create(String displayName) {
        Preconditions.checkNotNull(displayName);
        Profile p = new Profile();
        p.setDisplayName(displayName);
        return repo.save(p);
    }

    public Profile importProfile(String displayName) {
        Profile p = new Profile();
        p.setDisplayName(displayName);
        return repo.save(p);
    }
}
