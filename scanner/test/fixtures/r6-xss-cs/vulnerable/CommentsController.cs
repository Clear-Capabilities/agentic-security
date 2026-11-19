using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;

public class CommentsController : Controller
{
    public IActionResult Preview(string body)
    {
        ViewBag.Preview = new HtmlString("<blockquote>" + body + "</blockquote>");
        return View();
    }
}
