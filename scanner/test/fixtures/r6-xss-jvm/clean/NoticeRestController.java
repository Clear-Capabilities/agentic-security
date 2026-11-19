import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NoticeRestController {
    @GetMapping(value = "/notice", produces = "application/json")
    public String notice(@RequestParam("msg") String msg) {
        return "{\"msg\": \"<p>\" }" + msg;
    }

    @GetMapping("/notice/map")
    public Map<String, String> noticeMap(@RequestParam("msg") String msg) {
        return Map.of("msg", "<p>" + msg + "</p>");
    }
}
