import org.springframework.web.bind.annotation.*;
import java.util.regex.Pattern;

@RestController
public class PatternSearch {
  @GetMapping("/search")
  public boolean search(@RequestParam String pattern) {
    Pattern p = Pattern.compile(Pattern.quote(pattern));
    return p.matcher("some text").find();
  }
}