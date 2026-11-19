using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
public class ToolsController : Controller {
  public IActionResult Run([FromQuery] string dir) {
    var psi = new ProcessStartInfo("git");
    psi.ArgumentList.Add("log");
    Process.Start(psi);
    return Ok(dir);
  }
}
