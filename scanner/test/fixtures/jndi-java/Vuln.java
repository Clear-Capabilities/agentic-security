import javax.naming.InitialContext;
import javax.naming.Context;

public class Vuln {
    public Object lookup(String name) throws Exception {
        InitialContext ctx = new InitialContext();
        return ctx.lookup(name);
    }

    public void logSomething(String userInput) {
        org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Vuln.class);
        log.info("user requested: ${jndi:ldap://localhost/x}");
    }

    public Object buildLookup(String userHost) throws Exception {
        InitialContext c = new InitialContext();
        String uri = "ldap://" + req.params.host + "/cn=admin";
        return c.lookup(uri);
    }
}
