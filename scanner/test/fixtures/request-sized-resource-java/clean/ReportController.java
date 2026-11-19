package demo;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.Max;
import org.springframework.web.bind.annotation.*;

@RestController
public class ReportController {
    private static final int MAX_ROWS = 10_000;

    @GetMapping("/buffer")
    public int buffer(@RequestParam @Max(65536) int size) {
        byte[] data = new byte[size];
        return data.length;
    }

    @GetMapping("/rows")
    public int rows(HttpServletRequest request) {
        int rows = Integer.parseInt(request.getParameter("rows"));
        if (rows > MAX_ROWS) {
            throw new IllegalArgumentException("too many rows");
        }
        int total = 0;
        for (int i = 0; i < rows; i++) {
            total += i;
        }
        return total;
    }

    @PostMapping("/join")
    public String join(@RequestBody List<String> parts) {
        StringBuilder out = new StringBuilder();
        for (String p : parts) {
            out.append(p);
        }
        return out.toString();
    }
}
