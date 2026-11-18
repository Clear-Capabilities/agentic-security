using Microsoft.AspNetCore.Mvc;
public class ProxyController : Controller {
  public IActionResult Get([FromQuery] string id) {
    var resp = _httpClient.GetAsync("https://api.internal.test/status").Result;
    return Ok(id);
  }
}