using Microsoft.AspNetCore.Mvc;
public class ProfileController : Controller {
  public IActionResult Bio([FromQuery] string bio) {
    ViewBag.Bio = bio;
    return View();
  }
}