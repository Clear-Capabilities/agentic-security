import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
public class RestProxy {
  private final RestTemplate restTemplate = new RestTemplate();

  @GetMapping("/proxy")
  public String proxy(@RequestParam String url) {
    return restTemplate.getForObject(url, String.class);
  }
}