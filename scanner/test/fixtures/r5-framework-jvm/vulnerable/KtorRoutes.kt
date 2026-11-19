import io.ktor.server.application.*

fun Application.routes() {
  routing {
    get("/go") {
      val next = call.request.queryParameters["next"]
      call.respondRedirect(next!!)
    }
  }
}