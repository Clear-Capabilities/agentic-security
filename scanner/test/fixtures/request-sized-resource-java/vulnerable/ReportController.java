package demo;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
public class ReportController {

    @GetMapping("/buffer")
    public int buffer(@RequestParam int size) {
        byte[] data = new byte[size];
        return data.length;
    }

    @GetMapping("/rows")
    public int rows(HttpServletRequest request) {
        int rows = Integer.parseInt(request.getParameter("rows"));
        int total = 0;
        for (int i = 0; i < rows; i++) {
            total += i;
        }
        return total;
    }

    @PostMapping("/join")
    public String join(@RequestBody List<String> parts) {
        String out = "";
        for (String p : parts) {
            out += p;
        }
        return out;
    }
}
