// Synthetic fixture, fixed twin: every path validates the redirect URI.
package example.oauth;

public class OAuthClientService {
    private final ClientRepository repo;

    public OAuthClientService(ClientRepository repo) {
        this.repo = repo;
    }

    @Transactional
    public OAuthClient register(String name, String redirectUri) {
        UriPolicy.validateRedirectUri(redirectUri);
        OAuthClient c = new OAuthClient(name);
        c.setRedirectUri(redirectUri);
        return repo.save(c);
    }

    public OAuthClient reissue(long id, String redirectUri) {
        UriPolicy.validateRedirectUri(redirectUri);
        OAuthClient c = repo.findById(id);
        c.setRedirectUri(redirectUri);
        c.rotateSecret();
        return repo.save(c);
    }

    public OAuthClient update(long id, String redirectUri) {
        UriPolicy.validateRedirectUri(redirectUri);
        OAuthClient c = repo.findById(id);
        c.setRedirectUri(redirectUri);
        return repo.save(c);
    }
}
