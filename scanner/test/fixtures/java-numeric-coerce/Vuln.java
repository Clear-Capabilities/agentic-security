// Vulnerable — no numeric coercion, raw String concatenation.
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class Vuln {
    public void load(HttpServletRequest request, Statement stmt) throws Exception {
        String name = request.getParameter("name");
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
