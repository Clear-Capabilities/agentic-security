using Microsoft.AspNetCore.Mvc;
public class UsersController : Controller {
  public IActionResult Find([FromQuery] string name) {
    var users = _db.Users.Where(u => u.Name == name).ToList();
    return Ok(users);
  }
}