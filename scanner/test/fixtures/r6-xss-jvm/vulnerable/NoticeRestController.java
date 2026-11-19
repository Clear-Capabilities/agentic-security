import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NoticeRestController {
    @GetMapping("/notice")
    public String notice(@RequestParam("msg") String msg) {
        return "<p class=\"notice\">" + msg + "</p>";
    }
}
