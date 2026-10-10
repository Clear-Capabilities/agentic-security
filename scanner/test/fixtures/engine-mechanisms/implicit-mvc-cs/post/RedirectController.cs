using Microsoft.AspNetCore.Mvc;

public class RedirectController : Controller {
    public IActionResult Go(string next) {
        return LocalRedirect(Url.IsLocalUrl(next) ? next : "/");
    }
}
