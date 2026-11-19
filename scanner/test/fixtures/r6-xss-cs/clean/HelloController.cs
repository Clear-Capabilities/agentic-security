using Microsoft.AspNetCore.Mvc;

public class HelloController : Controller
{
    [HttpGet("/hello")]
    public IActionResult Hello()
    {
        string name = Request.Query["name"];
        return Content("Hello " + name, "text/plain");
    }

    [HttpGet("/hello.json")]
    public IActionResult HelloJson()
    {
        string name = Request.Query["name"];
        return Json(new { hello = name });
    }
}
