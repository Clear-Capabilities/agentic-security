import java.sql.Statement;

public class Handler {
  public void handle(Statement stmt) throws Exception {
    String name = "admin";
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    stmt.executeUpdate(sql);
  }
}
