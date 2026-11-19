using Microsoft.AspNetCore.Mvc;

public class HelloController : Controller
{
    [HttpGet("/hello")]
    public IActionResult Hello()
    {
        string name = Request.Query["name"];
        return Content("<h1>Hello " + name + "</h1>", "text/html");
    }
}
