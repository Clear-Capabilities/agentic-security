// Servlet-style handler: request parameter flows into a JDBC statement.
class UserController {
  fun handle(req: HttpServletRequest, stmt: Statement) {
    val q = req.getParameter("q")
    val sql = "SELECT * FROM users WHERE name = '" + q + "'"
    stmt.executeUpdate(sql)
  }
}
