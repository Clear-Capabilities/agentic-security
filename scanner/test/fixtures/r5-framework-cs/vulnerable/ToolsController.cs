using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
public class ToolsController : Controller {
  public IActionResult Run([FromQuery] string dir) {
    var psi = new ProcessStartInfo("cmd.exe", "/c dir " + dir);
    Process.Start(psi);
    return Ok();
  }
}