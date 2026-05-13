// Safe SQL — Integer.parseInt coerces the user value to an int before
// interpolation, so injection is impossible. The Tier-2 Java sanitizer
// extension should suppress the SQL-injection finding here.
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class Safe {
    public void load(HttpServletRequest request, Statement stmt) throws Exception {
        String param = request.getParameter("id");
        int id = Integer.parseInt(param);
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
}
