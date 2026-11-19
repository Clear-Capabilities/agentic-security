import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;

@RestController
public class UserQuery {
  private JdbcTemplate jdbcTemplate;

  @GetMapping("/users")
  public Object users(@RequestParam String name) {
    return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
  }
}