using Microsoft.AspNetCore.Mvc;
public class ProfileController : Controller {
  public IActionResult Bio([FromQuery] string bio) {
    ViewBag.Bio = new Microsoft.AspNetCore.Html.HtmlString(bio);
    return View();
  }
}