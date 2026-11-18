import org.springframework.web.bind.annotation.*;
import java.nio.file.*;

@RestController
public class DocReader {
  @GetMapping("/doc")
  public String doc(@RequestParam String name) throws Exception {
    Path base = Path.of("/srv/docs").toRealPath();
    Path target = base.resolve(name).normalize();
    if (!target.startsWith(base)) throw new IllegalArgumentException("bad path");
    return Files.readString(target);
  }
}