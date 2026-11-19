import org.springframework.web.bind.annotation.*;
import java.nio.file.*;

@RestController
public class DocReader {
  @GetMapping("/doc")
  public String doc(@RequestParam String name) throws Exception {
    return Files.readString(Path.of("/srv/docs", name));
  }
}