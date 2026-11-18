import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class Redirector {
  @GetMapping("/go")
  public RedirectView go(@RequestParam String next) {
    return new RedirectView(next);
  }
}