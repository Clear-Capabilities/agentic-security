using Microsoft.AspNetCore.Mvc;
public class FilesController : Controller {
  public IActionResult Get() {
    var name = System.IO.Path.GetFileName(Request.Query["name"]);
    return File(System.IO.File.ReadAllBytes("/srv/files/" + name), "application/octet-stream");
  }
}