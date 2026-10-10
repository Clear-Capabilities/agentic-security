import java.sql.Connection;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserApi {
  private final Connection conn;
  public UserApi(Connection conn) { this.conn = conn; }

  @GetMapping("/users")
  public String find(String name) throws Exception {
    Statement st = conn.createStatement();
    st.execute("SELECT * FROM users WHERE name='" + name + "'");
    return "ok";
  }
}
