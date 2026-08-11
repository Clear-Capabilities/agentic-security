import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class Handler {
  public void handle(HttpServletRequest req, Statement stmt) throws Exception {
    String q = req.getParameter("q");
    String sql = "SELECT * FROM users WHERE name = '" + q + "'";
    stmt.executeUpdate(sql);
  }
}
