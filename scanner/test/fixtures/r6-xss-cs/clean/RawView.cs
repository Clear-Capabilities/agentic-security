using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

public class RawViewController : Controller
{
    public IActionResult Show(string title)
    {
        ViewData["Title"] = Html.Raw("<em>" + HttpUtility.HtmlEncode(title) + "</em>");
        return View();
    }

    private IHtmlHelper Html => null;
}
