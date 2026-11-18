using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;
public class SearchController : Controller {
  public IActionResult Find([FromQuery] string pattern) {
    return Ok(Regex.IsMatch("some text", pattern));
  }
}