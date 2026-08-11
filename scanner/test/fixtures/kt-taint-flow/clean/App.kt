// Same shape, no user input: the SQL is built from a constant.
class UserController {
  fun handle(stmt: Statement) {
    val name = "admin"
    val sql = "SELECT * FROM users WHERE name = '" + name + "'"
    stmt.executeUpdate(sql)
  }
}
