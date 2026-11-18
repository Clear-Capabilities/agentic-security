import org.springframework.web.bind.annotation.*

@RestController
class PingController {
  @GetMapping("/ping")
  fun ping(@RequestParam("host") host: String): String {
    ProcessBuilder("ping", "-c", "1", host).start()
    return "ok"
  }
}