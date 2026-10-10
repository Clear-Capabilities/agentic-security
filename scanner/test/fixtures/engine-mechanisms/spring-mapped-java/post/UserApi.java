import java.sql.Connection;
import java.sql.PreparedStatement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserApi {
  private final Connection conn;
  public UserApi(Connection conn) { this.conn = conn; }

  @GetMapping("/users")
  public String find(String name) throws Exception {
    PreparedStatement st = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
    st.setString(1, name);
    st.execute();
    return "ok";
  }
}
