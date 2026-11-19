import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.stereotype.Controller;
import org.springframework.web.util.HtmlUtils;

@Controller
public class BannerController {
    @GetMapping("/banner")
    @ResponseBody
    public String banner(@RequestParam("text") String text) {
        return "<div class=\"banner\">" + HtmlUtils.htmlEscape(text) + "</div>";
    }
}
