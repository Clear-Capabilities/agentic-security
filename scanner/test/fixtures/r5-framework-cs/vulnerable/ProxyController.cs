using Microsoft.AspNetCore.Mvc;
public class ProxyController : Controller {
  public IActionResult Get([FromQuery] string url) {
    var resp = _httpClient.GetAsync(url).Result;
    return Ok();
  }
}