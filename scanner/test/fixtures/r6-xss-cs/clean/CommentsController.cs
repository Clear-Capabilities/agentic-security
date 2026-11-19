using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;

public class CommentsController : Controller
{
    public IActionResult Preview(string body)
    {
        var safe = HtmlEncoder.Default.Encode(body);
        ViewBag.Preview = new HtmlString("<blockquote>" + safe + "</blockquote>");
        return View();
    }
}
